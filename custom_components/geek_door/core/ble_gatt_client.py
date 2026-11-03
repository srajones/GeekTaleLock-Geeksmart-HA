"""Direct Bluetooth Low Energy (BLE) GATT Client for Tuya/GeekSmart Smart Locks.

Supports:
- Tuya BLE protocol (jtmspro GATT service 0xFD50 / 0000fd50-0000-1000-8000-00805f9b34fb)
- Write characteristic 00000001-0000-1001-8001-00805f9b07d0
- Notify characteristic 00000002-0000-1001-8001-00805f9b07d0
- CRC16-MODBUS integrity checks
- Session key derivation: login_key = MD5(local_key[:6]), session_key = MD5(local_key[:6] + srand)
- AES-128-CBC encryption and decryption
- 19-byte DP 71 ble_unlock_check frame builder
- DP TLV codec (RAW, BOOL, VALUE, STRING, ENUM, BITMAP)
- MockBleGattTransport for headless simulation and CI testing without BLE radio
- HomeAssistantBleAdapter for native Home Assistant Bluetooth stack and ESPHome proxies
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import struct
import time
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger("geeksmart.ble")

# Primary Tuya BLE GATT UUIDs
TUYA_BLE_SERVICE_UUID = "0000fd50-0000-1000-8000-00805f9b34fb"
TUYA_BLE_WRITE_CHAR_UUID = "00000001-0000-1001-8001-00805f9b07d0"
TUYA_BLE_NOTIFY_CHAR_UUID = "00000002-0000-1001-8001-00805f9b07d0"

# Fallback UUIDs for SIG compliance
TUYA_BLE_SIG_SERVICE_UUID = "0000a201-0000-1000-8000-00805f9b34fb"
TUYA_BLE_SIG_WRITE_CHAR_UUID = "00002b11-0000-1000-8000-00805f9b34fb"
TUYA_BLE_SIG_NOTIFY_CHAR_UUID = "00002b10-0000-1000-8000-00805f9b34fb"


class TuyaBleCmd(IntEnum):
    """Tuya BLE command identifiers."""
    DEVICE_INFO = 0x0000
    PAIR = 0x0001
    DP_PUBLISH = 0x0002
    STATUS_QUERY = 0x0003
    UNBIND = 0x0005
    RESET = 0x0006
    DP_PUBLISH_V4 = 0x0027
    DP_REPORT = 0x8001
    DP_TIME_REPORT = 0x8003
    TIME1_REQ = 0x8011
    TIME2_REQ = 0x8012


class DpType(IntEnum):
    """Tuya Data Point data types."""
    RAW = 0
    BOOL = 1
    VALUE = 2
    STRING = 3
    ENUM = 4
    BITMAP = 5


class TuyaBlePacketEngine:
    """Handles byte-level encryption, CRC16, framing, and TLV encoding."""

    @staticmethod
    def calc_crc16(data: bytes) -> int:
        """Computes standard CRC16-MODBUS over input bytes."""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte & 0xFF
            for _ in range(8):
                tmp = crc & 1
                crc >>= 1
                if tmp != 0:
                    crc ^= 0xA001
        return crc

    @staticmethod
    def derive_login_key(local_key: str) -> bytes:
        """Derives 16-byte login key from first 6 characters of local_key."""
        prefix = local_key[:6].encode("utf-8") if isinstance(local_key, str) else bytes(local_key[:6])
        return hashlib.md5(prefix).digest()

    @staticmethod
    def derive_session_key(local_key: str, srand: bytes) -> bytes:
        """Derives 16-byte session key from local_key[:6] and 6-byte peripheral srand."""
        prefix = local_key[:6].encode("utf-8") if isinstance(local_key, str) else bytes(local_key[:6])
        return hashlib.md5(prefix + srand).digest()

    @staticmethod
    def build_dp71_frame(
        slot_id: int = 1,
        member_key: str = "12345678",
        unlock: bool = True,
        timestamp: Optional[int] = None,
        header_prefix: Optional[bytes] = None,
    ) -> bytes:
        """Constructs 19-byte ble_unlock_check frame.

        Layout:
        - Bytes 0..1: Slot ID (uint16 big-endian)
        - Bytes 2..3: Mask/permission flags (uint16 big-endian, 0xFFFF)
        - Bytes 4..11: Member key ASCII token (8 bytes)
        - Byte 12: Action (0x01 = unlock, 0x00 = lock)
        - Bytes 13..16: Unix timestamp (uint32 big-endian)
        - Bytes 17..18: Trailer bytes (0x0000)
        """
        if header_prefix and len(header_prefix) == 12:
            prefix = header_prefix
        else:
            slot_bytes = int(slot_id).to_bytes(2, byteorder="big")
            key_bytes = (
                member_key.encode("ascii")
                if isinstance(member_key, str)
                else bytes(member_key)
            )[:8].ljust(8, b"\x00")
            prefix = slot_bytes + b"\xff\xff" + key_bytes

        ts = int(timestamp if timestamp is not None else time.time())
        op = b"\x01" if unlock else b"\x00"
        return prefix + op + ts.to_bytes(4, byteorder="big") + b"\x00\x00"

    @staticmethod
    def encode_dp_tlv(dp_id: int, dp_type: DpType, value: Union[bytes, bool, int, str]) -> bytes:
        """Encodes a Data Point into [ID: 1B][Type: 1B][Len: 1B][Value: Len B]."""
        if dp_type == DpType.BOOL:
            val_bytes = b"\x01" if value else b"\x00"
        elif dp_type == DpType.VALUE:
            val_bytes = int(value).to_bytes(4, byteorder="big", signed=True)
        elif dp_type == DpType.ENUM:
            val_bytes = int(value).to_bytes(1, byteorder="big")
        elif dp_type == DpType.STRING:
            val_bytes = str(value).encode("utf-8")
        else:
            val_bytes = bytes(value) if not isinstance(value, bytes) else value
        return bytes([int(dp_id), int(dp_type), len(val_bytes)]) + val_bytes

    @staticmethod
    def decode_dp_tlv(data: bytes) -> Dict[str, Any]:
        """Decodes raw TLV stream into dictionary of DP values."""
        result: Dict[str, Any] = {}
        pos = 0
        while pos + 3 <= len(data):
            dp_id = str(data[pos])
            dp_type = data[pos + 1]
            dp_len = data[pos + 2]
            pos += 3
            if pos + dp_len > len(data):
                break
            val_raw = data[pos:pos + dp_len]
            pos += dp_len

            if dp_type == DpType.BOOL:
                val: Any = val_raw[0] != 0 if len(val_raw) > 0 else False
            elif dp_type == DpType.VALUE:
                val = int.from_bytes(val_raw, byteorder="big", signed=True) if val_raw else 0
            elif dp_type == DpType.ENUM:
                val = int.from_bytes(val_raw, byteorder="big") if val_raw else 0
            elif dp_type == DpType.STRING:
                val = val_raw.decode("utf-8", errors="ignore")
            else:
                val = val_raw
            result[dp_id] = val
        return result

    @staticmethod
    def decode_uleb128(data: bytes, offset: int = 0) -> Tuple[int, int]:
        """Decodes a ULEB128 integer starting at offset, returning (value, next_offset)."""
        value = 0
        shift = 0
        pos = offset
        while pos < len(data):
            b = data[pos]
            pos += 1
            value |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return value, pos

    @classmethod
    def pack_payload(
        cls,
        seq_num: int,
        cmd: Union[TuyaBleCmd, int],
        data: bytes,
        key: bytes,
        security_flag: int = 5,
        response_to: int = 0,
    ) -> bytes:
        """Frames and encrypts an inner message into a raw wire payload."""
        inner = struct.pack(">IIHH", seq_num, response_to, int(cmd), len(data)) + data
        crc = cls.calc_crc16(inner)
        padded = inner + struct.pack(">H", crc)
        while len(padded) % 16 != 0:
            padded += b"\x00"

        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        return bytes([security_flag]) + iv + enc.update(padded) + enc.finalize()

    @classmethod
    def pack_message(
        cls,
        seq_num: int,
        cmd: Union[TuyaBleCmd, int],
        data: bytes,
        key: bytes,
        security_flag: int = 5,
        response_to: int = 0,
        mtu: int = 20,
        version: int = 2,
    ) -> List[bytes]:
        """Frames, encrypts, and chunks an outbound packet."""
        encrypted = cls.pack_payload(
            seq_num=seq_num,
            cmd=cmd,
            data=data,
            key=key,
            security_flag=security_flag,
            response_to=response_to,
        )

        chunks: List[bytes] = []
        pos = 0
        total_len = len(encrypted)
        chunk_idx = 0
        while pos < total_len:
            hdr = bytearray()
            # ULEB128 chunk_idx
            val = chunk_idx
            while True:
                b = val & 0x7F
                val >>= 7
                if val:
                    hdr.append(b | 0x80)
                else:
                    hdr.append(b)
                    break
            if chunk_idx == 0:
                # ULEB128 total_len
                tval = total_len
                while True:
                    tb = tval & 0x7F
                    tval >>= 7
                    if tval:
                        hdr.append(tb | 0x80)
                    else:
                        hdr.append(tb)
                        break
                hdr.append((version << 4) & 0xF0)

            available = max(1, mtu - len(hdr))
            slice_data = encrypted[pos:pos + available]
            chunks.append(bytes(hdr) + slice_data)
            pos += len(slice_data)
            chunk_idx += 1
        return chunks

    @classmethod
    def unpack_message(
        cls,
        payload: bytes,
        key: bytes,
    ) -> Tuple[int, int, TuyaBleCmd, bytes]:
        """Decrypts and verifies incoming concatenated payload.

        Payload: [Security Flag: 1B] + [IV: 16B] + [Ciphertext: N*16B]
        """
        if len(payload) < 17:
            raise ValueError(f"Payload too short ({len(payload)} bytes < 17)")
        iv = payload[1:17]
        encrypted = payload[17:]
        if len(encrypted) % 16 != 0:
            raise ValueError(f"Ciphertext length {len(encrypted)} is not a multiple of 16")

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        plain = dec.update(encrypted) + dec.finalize()

        if len(plain) < 14:
            raise ValueError("Decrypted frame too short for header")

        seq, resp, cmd_code, dlen = struct.unpack(">IIHH", plain[:12])
        if len(plain) < 12 + dlen + 2:
            raise ValueError(f"Corrupt frame length (expected >= {14 + dlen}, got {len(plain)})")

        data = plain[12:12 + dlen]
        calc_crc = cls.calc_crc16(plain[:12 + dlen])
        recv_crc = struct.unpack(">H", plain[12 + dlen:12 + dlen + 2])[0]
        if calc_crc != recv_crc:
            raise ValueError(f"CRC mismatch: expected {hex(calc_crc)}, got {hex(recv_crc)}")

        try:
            cmd = TuyaBleCmd(cmd_code)
        except ValueError:
            cmd = cmd_code  # type: ignore[assignment]
        return seq, resp, cmd, data


class MockBleGattTransport:
    """In-memory BLE GATT peripheral emulator for testing and simulation."""

    def __init__(
        self,
        mac: str = "DC:23:4F:00:00:90",
        local_key: str = "TU:ESBz-3TXkj-Bq",
        uuid: str = "uuidfake1a2b3c01",
        dev_id: str = "ebexamplelock001",
        initial_is_locked: bool = True,
        initial_auto_lock: bool = True,
        initial_auto_lock_time: int = 5,
        initial_battery: int = 85,
    ) -> None:
        self.mac = mac.upper()
        self.local_key = local_key
        self.uuid = uuid
        self.dev_id = dev_id
        self.is_connected = False
        self.is_paired = False
        self.srand = secrets.token_bytes(6)
        self.login_key = TuyaBlePacketEngine.derive_login_key(local_key)
        self.session_key = TuyaBlePacketEngine.derive_session_key(local_key, self.srand)

        # Internal Lock State
        self.is_locked = initial_is_locked
        self.auto_lock = initial_auto_lock
        self.auto_lock_time = initial_auto_lock_time
        self.battery = initial_battery
        self.last_unlocked_ts = 0.0

        self.inbound_chunks: List[bytes] = []
        self.notify_callback: Optional[Callable[[bytes], None]] = None
        self._seq = 100

    def register_notify_callback(self, callback: Callable[[bytes], None]) -> None:
        self.notify_callback = callback

    async def connect(self) -> bool:
        self.is_connected = True
        return True

    async def disconnect(self) -> None:
        self.is_connected = False
        self.is_paired = False

    def _send_notify(self, cmd: TuyaBleCmd, data: bytes, key: bytes, flag: int = 5, resp_to: int = 0) -> None:
        self._seq += 1
        chunks = TuyaBlePacketEngine.pack_message(
            seq_num=self._seq,
            cmd=cmd,
            data=data,
            key=key,
            security_flag=flag,
            response_to=resp_to,
        )
        if self.notify_callback:
            # Reconstruct concatenated payload for listener
            payload = bytearray()
            for chunk in chunks:
                # Strip ULEB128 chunk header in emulator or emit chunk directly
                # In standard client, chunks are reassembled
                pass
            # For simplicity in mock, emit raw concatenated payload
            # Build full concatenated payload
            inner = struct.pack(">IIHH", self._seq, resp_to, int(cmd), len(data)) + data
            crc = TuyaBlePacketEngine.calc_crc16(inner)
            padded = inner + struct.pack(">H", crc)
            while len(padded) % 16 != 0:
                padded += b"\x00"
            iv = secrets.token_bytes(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            enc = cipher.encryptor()
            raw_payload = bytes([flag]) + iv + enc.update(padded) + enc.finalize()
            self.notify_callback(raw_payload)

    def write_payload(self, raw_payload: bytes) -> None:
        """Processes an incoming decrypted/reassembled frame written by Central."""
        flag = raw_payload[0] if raw_payload else 0
        key = self.login_key if flag == 4 else self.session_key
        try:
            seq, resp, cmd, data = TuyaBlePacketEngine.unpack_message(raw_payload, key)
        except Exception as exc:
            logger.warning("Mock peripheral failed to unpack message: %s", exc)
            return

        if cmd == TuyaBleCmd.DEVICE_INFO:
            # Respond with protocol version 4 and 6-byte srand
            dev_info = bytes([0x00, 0x04]) + self.srand
            self._send_notify(TuyaBleCmd.DEVICE_INFO, dev_info, self.login_key, flag=4, resp_to=seq)
        elif cmd == TuyaBleCmd.PAIR:
            self.is_paired = True
            # Respond with pair success (0x00)
            self._send_notify(TuyaBleCmd.PAIR, b"\x00", self.session_key, flag=5, resp_to=seq)
        elif cmd in (TuyaBleCmd.DP_PUBLISH, TuyaBleCmd.DP_PUBLISH_V4):
            tlvs = TuyaBlePacketEngine.decode_dp_tlv(data)
            if "71" in tlvs:
                dp71 = tlvs["71"]
                if len(dp71) >= 13:
                    action_byte = dp71[12]
                    if action_byte == 1:
                        self.is_locked = False
                        self.last_unlocked_ts = time.time()
                    else:
                        self.is_locked = True
            if "33" in tlvs:
                self.auto_lock = bool(tlvs["33"])
            if "36" in tlvs:
                self.auto_lock_time = int(tlvs["36"])

            # Acknowledge with DP_REPORT
            report_tlv = TuyaBlePacketEngine.encode_dp_tlv(47, DpType.BOOL, not self.is_locked)
            report_tlv += TuyaBlePacketEngine.encode_dp_tlv(33, DpType.BOOL, self.auto_lock)
            report_tlv += TuyaBlePacketEngine.encode_dp_tlv(36, DpType.VALUE, self.auto_lock_time)
            report_tlv += TuyaBlePacketEngine.encode_dp_tlv(8, DpType.VALUE, self.battery)
            self._send_notify(TuyaBleCmd.DP_REPORT, report_tlv, self.session_key, flag=5, resp_to=seq)
        elif cmd == TuyaBleCmd.STATUS_QUERY:
            report_tlv = TuyaBlePacketEngine.encode_dp_tlv(47, DpType.BOOL, not self.is_locked)
            report_tlv += TuyaBlePacketEngine.encode_dp_tlv(33, DpType.BOOL, self.auto_lock)
            report_tlv += TuyaBlePacketEngine.encode_dp_tlv(36, DpType.VALUE, self.auto_lock_time)
            report_tlv += TuyaBlePacketEngine.encode_dp_tlv(8, DpType.VALUE, self.battery)
            self._send_notify(TuyaBleCmd.DP_REPORT, report_tlv, self.session_key, flag=5, resp_to=seq)


def normalize_ble_mac(mac: Optional[str]) -> str:
    """Normalizes 12-hex-char Tuya MACs (e.g. 'dc234d1a2b3c') to 'DC:23:4D:1A:2B:3C'."""
    if not mac:
        return ""
    raw = str(mac).strip().upper()
    cleaned = raw.replace(":", "").replace("-", "").replace(".", "")
    if len(cleaned) == 12 and all(c in "0123456789ABCDEF" for c in cleaned):
        return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
    return raw


class BleGattClient:
    """Async client managing GATT connection, session negotiation, and DP actuation."""

    def __init__(
        self,
        mac: str = "",
        local_key: str = "000000",
        uuid: str = "",
        dev_id: str = "",
        ble_device: Optional[Any] = None,
        transport: Optional[Any] = None,
    ) -> None:
        self.mac = normalize_ble_mac(mac)
        self.local_key = local_key or "000000"
        self.uuid = uuid
        self.dev_id = dev_id
        self.ble_device = ble_device
        self._transport = transport
        self._login_key = TuyaBlePacketEngine.derive_login_key(self.local_key)
        self._session_key: Optional[bytes] = None
        self._is_connected = False
        self._is_paired = False
        self._lock: Optional[asyncio.Lock] = None
        self._seq = 1
        self._pending_responses: Dict[int, asyncio.Future[Tuple[TuyaBleCmd, bytes]]] = {}
        self._bleak_client: Optional[Any] = None
        self._rx_buffer = bytearray()
        self._rx_expected_len = 0

    def configure_for_lock(
        self,
        mac: Optional[str] = None,
        local_key: Optional[str] = None,
        uuid: Optional[str] = None,
        dev_id: Optional[str] = None,
        ble_device: Optional[Any] = None,
    ) -> None:
        """Dynamically binds or updates target lock BLE identity and credentials."""
        norm_mac = normalize_ble_mac(mac) if mac else self.mac
        key_changed = bool(local_key and local_key != self.local_key)
        mac_changed = bool(norm_mac and norm_mac != self.mac)
        if norm_mac:
            self.mac = norm_mac
        if local_key:
            self.local_key = local_key
            self._login_key = TuyaBlePacketEngine.derive_login_key(local_key)
        if uuid is not None and uuid != "":
            self.uuid = uuid
        if dev_id is not None and dev_id != "":
            self.dev_id = dev_id
        if ble_device is not None:
            self.ble_device = ble_device
        if key_changed or mac_changed:
            self._is_paired = False
            self._session_key = None

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    @property
    def is_connected(self) -> bool:
        return self._is_connected

    @property
    def is_paired(self) -> bool:
        return self._is_paired

    def _dispatch_assembled_payload(self, payload: bytes) -> None:
        """Unpacks a complete Tuya BLE frame and resolves any waiting future."""
        flag = payload[0] if payload else 0
        key = self._login_key if (flag == 4 or not self._session_key) else self._session_key
        try:
            seq, resp, cmd, data = TuyaBlePacketEngine.unpack_message(payload, key)
        except Exception as exc:
            logger.debug("Failed to unpack notification: %s", exc)
            return

        if resp in self._pending_responses:
            fut = self._pending_responses.pop(resp)
            if not fut.done():
                fut.set_result((cmd, data))
        elif 0 in self._pending_responses:
            fut = self._pending_responses.pop(0)
            if not fut.done():
                fut.set_result((cmd, data))

    def _handle_notify_payload(self, payload: bytes) -> None:
        """Callback invoked when peripheral sends raw or ULEB128-chunked notification."""
        if not payload:
            return
        raw_bytes = bytes(payload)

        # Case 1: Un-chunked full frame (from MockBleGattTransport or high-MTU notify)
        if raw_bytes[0] in (4, 5) and len(raw_bytes) >= 33 and (len(raw_bytes) - 17) % 16 == 0:
            self._dispatch_assembled_payload(raw_bytes)
            return

        # Case 2: ULEB128 GATT 20-byte chunked notification from physical 0xFD50 lock
        try:
            pkt_no, pos = TuyaBlePacketEngine.decode_uleb128(raw_bytes, 0)
            if pkt_no == 0:
                total_len, pos = TuyaBlePacketEngine.decode_uleb128(raw_bytes, pos)
                # Skip 1-byte protocol version header (e.g. 0x40 for v4)
                if pos < len(raw_bytes):
                    pos += 1
                self._rx_buffer = bytearray(raw_bytes[pos:])
                self._rx_expected_len = total_len
            else:
                self._rx_buffer.extend(raw_bytes[pos:])

            if self._rx_expected_len > 0 and len(self._rx_buffer) >= self._rx_expected_len:
                complete = bytes(self._rx_buffer[: self._rx_expected_len])
                self._rx_buffer.clear()
                self._rx_expected_len = 0
                self._dispatch_assembled_payload(complete)
        except Exception as exc:
            logger.debug("Chunk reassembly fallback: %s", exc)
            self._dispatch_assembled_payload(raw_bytes)

    async def _write_frame(
        self,
        seq_num: int,
        cmd: TuyaBleCmd,
        data: bytes,
        key: bytes,
        security_flag: int,
    ) -> None:
        """Writes an encrypted Tuya BLE frame over either MockTransport or real Bleak GATT."""
        if self._transport:
            out_payload = TuyaBlePacketEngine.pack_payload(
                seq_num=seq_num,
                cmd=cmd,
                data=data,
                key=key,
                security_flag=security_flag,
            )
            self._transport.write_payload(out_payload)
        elif self._bleak_client:
            chunks = TuyaBlePacketEngine.pack_message(
                seq_num=seq_num,
                cmd=cmd,
                data=data,
                key=key,
                security_flag=security_flag,
            )
            for chunk in chunks:
                await self._bleak_client.write_gatt_char(
                    TUYA_BLE_WRITE_CHAR_UUID,
                    chunk,
                    response=False,
                )
        else:
            raise RuntimeError("No active BLE transport available")

    async def connect(self, timeout: float = 6.0) -> bool:
        """Connects GATT session, negotiates srand, and completes pairing."""
        async with self._get_lock():
            if self._is_paired and self._session_key:
                return True

            try:
                if self._transport:
                    # Use provided transport (e.g. MockBleGattTransport)
                    self._transport.register_notify_callback(self._handle_notify_payload)
                    await self._transport.connect()
                    self._is_connected = True
                else:
                    # Real bleak transport (supports Home Assistant bleak_retry_connector + ESPHome proxies)
                    try:
                        import bleak
                    except ImportError:
                        raise RuntimeError("bleak is not installed; direct BLE requires bleak or MockBleGattTransport")

                    client_target = self.ble_device if self.ble_device else self.mac
                    if not client_target:
                        raise RuntimeError("Cannot connect Direct BLE: lock MAC address or BLEDevice is not set")

                    connected_client = None
                    if self.ble_device is not None:
                        try:
                            from bleak_retry_connector import establish_connection
                            connected_client = await establish_connection(
                                bleak.BleakClient,
                                self.ble_device,
                                self.dev_id or self.mac or "geek_door_lock",
                            )
                        except Exception:
                            connected_client = None

                    if connected_client is not None:
                        self._bleak_client = connected_client
                    else:
                        self._bleak_client = bleak.BleakClient(client_target, timeout=timeout)
                        await self._bleak_client.connect()

                    self._is_connected = True
                    await self._bleak_client.start_notify(
                        TUYA_BLE_NOTIFY_CHAR_UUID,
                        lambda sender, data: self._handle_notify_payload(bytes(data)),
                    )

                # 1. Send DEVICE_INFO (0x0000) encrypted with login_key (flag=4)
                self._seq += 1
                seq_dev_info = self._seq
                fut: asyncio.Future[Tuple[TuyaBleCmd, bytes]] = asyncio.get_running_loop().create_future()
                self._pending_responses[seq_dev_info] = fut

                try:
                    await self._write_frame(
                        seq_num=seq_dev_info,
                        cmd=TuyaBleCmd.DEVICE_INFO,
                        data=b"",
                        key=self._login_key,
                        security_flag=4,
                    )
                    cmd, resp_data = await asyncio.wait_for(fut, timeout=timeout)
                finally:
                    self._pending_responses.pop(seq_dev_info, None)
                    if not fut.done():
                        fut.cancel()

                # Expect version (2B) + srand (6B)
                if len(resp_data) >= 8:
                    srand = resp_data[2:8]
                else:
                    srand = secrets.token_bytes(6)
                self._session_key = TuyaBlePacketEngine.derive_session_key(self.local_key, srand)

                # 2. Send PAIR (0x0001) encrypted with session_key (flag=5)
                self._seq += 1
                seq_pair = self._seq
                fut = asyncio.get_running_loop().create_future()
                self._pending_responses[seq_pair] = fut

                pair_payload = self.uuid.encode("utf-8").ljust(16, b"\x00")[:16]
                pair_payload += self.local_key[:6].encode("utf-8").ljust(6, b"\x00")[:6]
                pair_payload += self.dev_id.encode("utf-8").ljust(22, b"\x00")[:22]

                try:
                    await self._write_frame(
                        seq_num=seq_pair,
                        cmd=TuyaBleCmd.PAIR,
                        data=pair_payload,
                        key=self._session_key,
                        security_flag=5,
                    )
                    await asyncio.wait_for(fut, timeout=timeout)
                finally:
                    self._pending_responses.pop(seq_pair, None)
                    if not fut.done():
                        fut.cancel()

                self._is_paired = True
                return True
            except (Exception, asyncio.CancelledError):
                await self._disconnect_locked()
                raise

    async def _disconnect_locked(self) -> None:
        """Internal cleanup helper while self._get_lock() is already acquired."""
        try:
            for seq, fut in list(self._pending_responses.items()):
                if not fut.done():
                    fut.cancel()
            self._pending_responses.clear()
            self._rx_buffer.clear()
            self._rx_expected_len = 0

            if self._transport:
                try:
                    await self._transport.disconnect()
                except Exception as exc:
                    logger.debug("Error disconnecting transport: %s", exc)
            elif self._bleak_client:
                try:
                    await self._bleak_client.disconnect()
                except Exception as exc:
                    logger.debug("Error disconnecting bleak client: %s", exc)
        finally:
            self._bleak_client = None
            self._is_connected = False
            self._is_paired = False
            self._session_key = None

    async def disconnect(self) -> None:
        """Disconnects GATT session and releases all resources."""
        async with self._get_lock():
            await self._disconnect_locked()

    async def async_disconnect_all(self) -> None:
        """Async teardown alias for lifecycle cleanup on integration unload."""
        await self.disconnect()

    def disconnect_all(self) -> None:
        """Synchronous teardown helper for non-async teardown contexts."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            loop.create_task(self.disconnect())
        else:
            try:
                asyncio.run(self.disconnect())
            except (Exception, asyncio.CancelledError):
                pass

    async def _send_dps(self, tlv_data: bytes, timeout: float = 5.0) -> Dict[str, Any]:
        """Encapsulates TLV data, encrypts with session key, and waits for peripheral ack."""
        if not self._is_paired or not self._session_key:
            await self.connect(timeout=timeout)

        assert self._session_key is not None
        self._seq += 1
        seq = self._seq
        fut: asyncio.Future[Tuple[TuyaBleCmd, bytes]] = asyncio.get_running_loop().create_future()
        self._pending_responses[seq] = fut

        try:
            await self._write_frame(
                seq_num=seq,
                cmd=TuyaBleCmd.DP_PUBLISH,
                data=tlv_data,
                key=self._session_key,
                security_flag=5,
            )
            cmd, ack_data = await asyncio.wait_for(fut, timeout=timeout)
            return TuyaBlePacketEngine.decode_dp_tlv(ack_data)
        finally:
            self._pending_responses.pop(seq, None)
            if not fut.done():
                fut.cancel()

    async def unlock(
        self,
        slot_id: int = 1,
        member_key: str = "12345678",
        header_prefix: Optional[bytes] = None,
        timeout: float = 5.0,
    ) -> Dict[str, Any]:
        """Sends DP 71 unlock frame via BLE GATT."""
        dp71 = TuyaBlePacketEngine.build_dp71_frame(
            slot_id=slot_id,
            member_key=member_key,
            unlock=True,
            header_prefix=header_prefix,
        )
        tlv = TuyaBlePacketEngine.encode_dp_tlv(71, DpType.RAW, dp71)
        return await self._send_dps(tlv, timeout=timeout)

    async def lock(
        self,
        slot_id: int = 1,
        member_key: str = "12345678",
        header_prefix: Optional[bytes] = None,
        timeout: float = 5.0,
    ) -> Dict[str, Any]:
        """Sends DP 71 lock frame and DP 33=True via BLE GATT."""
        dp71 = TuyaBlePacketEngine.build_dp71_frame(
            slot_id=slot_id,
            member_key=member_key,
            unlock=False,
            header_prefix=header_prefix,
        )
        tlv = TuyaBlePacketEngine.encode_dp_tlv(71, DpType.RAW, dp71)
        tlv += TuyaBlePacketEngine.encode_dp_tlv(33, DpType.BOOL, True)
        return await self._send_dps(tlv, timeout=timeout)

    async def keep_unlocked(self, timeout: float = 5.0) -> Dict[str, Any]:
        """Enables Passage Mode (sets DP 33 = False) via BLE GATT."""
        tlv = TuyaBlePacketEngine.encode_dp_tlv(33, DpType.BOOL, False)
        return await self._send_dps(tlv, timeout=timeout)

    async def set_auto_lock(
        self,
        enabled: bool,
        seconds: int = 5,
        delay_seconds: Optional[int] = None,
        timeout: float = 5.0,
    ) -> Dict[str, Any]:
        """Sets DP 33 (automatic_lock) and optional DP 36 (auto_lock_time)."""
        effective_sec = delay_seconds if delay_seconds is not None else seconds
        tlv = TuyaBlePacketEngine.encode_dp_tlv(33, DpType.BOOL, enabled)
        if effective_sec > 0:
            tlv += TuyaBlePacketEngine.encode_dp_tlv(36, DpType.VALUE, effective_sec)
        return await self._send_dps(tlv, timeout=timeout)

    async def get_status(self, timeout: float = 5.0) -> Dict[str, Any]:
        """Queries lock DP state via STATUS_QUERY (0x0003)."""
        if not self._is_paired or not self._session_key:
            await self.connect(timeout=timeout)

        assert self._session_key is not None
        self._seq += 1
        seq = self._seq
        fut: asyncio.Future[Tuple[TuyaBleCmd, bytes]] = asyncio.get_running_loop().create_future()
        self._pending_responses[seq] = fut

        try:
            await self._write_frame(
                seq_num=seq,
                cmd=TuyaBleCmd.STATUS_QUERY,
                data=b"",
                key=self._session_key,
                security_flag=5,
            )
            cmd, ack_data = await asyncio.wait_for(fut, timeout=timeout)
            return TuyaBlePacketEngine.decode_dp_tlv(ack_data)
        finally:
            self._pending_responses.pop(seq, None)
            if not fut.done():
                fut.cancel()


class HomeAssistantBleAdapter:
    """Adapts Home Assistant Bluetooth stack and ESPHome proxies for BleGattClient."""

    def __init__(
        self,
        local_key: str = "",
        hass: Optional[Any] = None,
        transport: Optional[Any] = None,
    ) -> None:
        self.local_key = local_key
        self.hass = hass
        self.transport = transport
        self._clients: Dict[str, BleGattClient] = {}

    def async_get_ble_client(
        self,
        ble_device: Any,
        local_key: Optional[str] = None,
        uuid: str = "",
        dev_id: str = "",
        transport: Optional[Any] = None,
    ) -> BleGattClient:
        key = local_key or self.local_key
        address = normalize_ble_mac(getattr(ble_device, "address", str(ble_device)))
        cache_key = dev_id or address
        if cache_key and cache_key in self._clients:
            client = self._clients[cache_key]
            client.configure_for_lock(
                mac=address,
                local_key=key,
                uuid=uuid,
                dev_id=dev_id,
                ble_device=ble_device,
            )
            return client

        client = BleGattClient(
            mac=address,
            local_key=key,
            uuid=uuid,
            dev_id=dev_id,
            ble_device=ble_device,
            transport=transport or self.transport,
        )
        client_key = cache_key or f"client_{id(client)}"
        self._clients[client_key] = client
        return client

    @classmethod
    def resolve_ble_device(
        cls,
        hass: Any,
        mac_or_address: str,
        uuid: str = "",
    ) -> Any:
        """Resolves BLEDevice from Home Assistant Bluetooth coordinator (local adapter or ESPHome proxy)."""
        if hass is None:
            return None
        norm_mac = normalize_ble_mac(mac_or_address)
        raw_hex = norm_mac.replace(":", "")
        try:
            from homeassistant.components.bluetooth import async_ble_device_from_address
            if norm_mac:
                ble_dev = async_ble_device_from_address(hass, norm_mac, connectable=True)
                if ble_dev is not None:
                    return ble_dev
                if mac_or_address and mac_or_address.upper() != norm_mac:
                    ble_dev = async_ble_device_from_address(hass, mac_or_address.upper(), connectable=True)
                    if ble_dev is not None:
                        return ble_dev
        except Exception as exc:
            logger.debug("Could not resolve BLEDevice by address from HA Bluetooth coordinator: %s", exc)

        # Fallback: scan discovered service infos for matching stripped MAC or Tuya 0xFD50 UUID advertisement
        try:
            from homeassistant.components.bluetooth import async_discovered_service_info
            uuid_bytes = uuid.encode("utf-8") if uuid else b""
            for info in async_discovered_service_info(hass, connectable=True):
                addr_hex = str(getattr(info, "address", "")).upper().replace(":", "").replace("-", "")
                if raw_hex and addr_hex == raw_hex:
                    return getattr(info, "device", None)
                service_uuids = [str(u).lower() for u in (getattr(info, "service_uuids", None) or [])]
                service_data = getattr(info, "service_data", None) or {}
                if TUYA_BLE_SERVICE_UUID.lower() in service_uuids or any("fd50" in str(k).lower() for k in service_data):
                    if uuid_bytes:
                        for s_bytes in service_data.values():
                            if isinstance(s_bytes, (bytes, bytearray)) and uuid_bytes in s_bytes:
                                return getattr(info, "device", None)
        except Exception as exc:
            logger.debug("Could not scan HA Bluetooth service_info: %s", exc)

        return None

    @classmethod
    def from_ha_bluetooth(
        cls,
        hass: Any,
        mac_or_address: str,
        local_key: str,
        uuid: str = "",
        dev_id: str = "",
        transport: Optional[Any] = None,
    ) -> BleGattClient:
        """Discovers BLEDevice from homeassistant.components.bluetooth and returns BleGattClient."""
        norm_mac = normalize_ble_mac(mac_or_address)
        ble_device = cls.resolve_ble_device(hass, norm_mac, uuid=uuid)
        return BleGattClient(
            mac=norm_mac,
            local_key=local_key,
            uuid=uuid,
            dev_id=dev_id,
            ble_device=ble_device,
            transport=transport,
        )

    def get_client_for_lock(self, lock: Any) -> BleGattClient:
        """Returns a configured BleGattClient for a LockDevice instance."""
        dev_id = str(getattr(lock, "dev_id", "") or "")
        mac = normalize_ble_mac(getattr(lock, "mac", "") or "")
        local_key = str(getattr(lock, "local_key", "") or self.local_key or "000000")
        uuid = str(getattr(lock, "uuid", "") or "")
        cache_key = dev_id or mac
        ble_device = self.resolve_ble_device(self.hass, mac, uuid=uuid) if self.hass else None

        if cache_key and cache_key in self._clients:
            client = self._clients[cache_key]
            client.configure_for_lock(
                mac=mac,
                local_key=local_key,
                uuid=uuid,
                dev_id=dev_id,
                ble_device=ble_device,
            )
            return client

        client = BleGattClient(
            mac=mac,
            local_key=local_key,
            uuid=uuid,
            dev_id=dev_id,
            ble_device=ble_device,
            transport=self.transport,
        )
        if cache_key:
            self._clients[cache_key] = client
        return client

    async def async_disconnect_all(self) -> None:
        """Disconnects all cached BleGattClient instances concurrently and clears registry."""
        clients = list(self._clients.values())
        self._clients.clear()
        if not clients:
            return
        disconnect_coros = [
            client.disconnect() for client in clients if hasattr(client, "disconnect")
        ]
        if disconnect_coros:
            results = await asyncio.gather(*disconnect_coros, return_exceptions=True)
            for res in results:
                if isinstance(res, (Exception, asyncio.CancelledError)):
                    logger.debug("Error during adapter async_disconnect_all: %s", res)

    def disconnect_all(self) -> None:
        """Synchronous wrapper for async_disconnect_all."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            loop.create_task(self.async_disconnect_all())
        else:
            try:
                asyncio.run(self.async_disconnect_all())
            except (Exception, asyncio.CancelledError):
                pass
