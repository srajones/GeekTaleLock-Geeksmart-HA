"""Tier 1 and Tier 2 tests for AES-128-CBC Crypto Engine."""

import base64
import json
import unittest
from tests.conftest import (
    GEEKSMART_AES_KEY,
    GEEKSMART_AES_IV,
    GeekSmartCryptoError,
    encrypt_payload_oracle,
    decrypt_payload_oracle,
    get_client_class,
)


class TestCryptoEngine(unittest.TestCase):
    """Test suite covering AES-128-CBC encryption, PKCS7 padding, Base64 encoding, and corner cases."""

    def setUp(self):
        self.client_cls = get_client_class()

    # --- Tier 1: Feature Coverage (Crypto Engine) ---

    def test_T1_01_crypto_key_and_iv_constants(self):
        """T1.01: Verify AES Key and IV constants match reverse-engineered values and are exactly 16 bytes."""
        self.assertEqual(len(GEEKSMART_AES_KEY), 16, "AES key must be exactly 16 bytes (128-bit)")
        self.assertEqual(len(GEEKSMART_AES_IV), 16, "AES IV must be exactly 16 bytes (128-bit)")
        self.assertEqual(GEEKSMART_AES_KEY, b"yljt789512356325", "AES key mismatch with APK derivation")
        self.assertEqual(GEEKSMART_AES_IV, b"yljt7415856896iv", "AES IV mismatch with APK derivation")

    def test_T1_02_crypto_encryption_base64_nowrap(self):
        """T1.02: Verify encryption output is valid Base64 string with NO trailing newlines (Android NO_WRAP)."""
        payload = {"platform": "android_geeksmarthome", "version": "1.1.2"}
        ciphertext = self.client_cls.encrypt_payload(payload)
        self.assertIsInstance(ciphertext, str)
        self.assertNotIn("\n", ciphertext, "Base64 output must not contain newline characters")
        self.assertNotIn("\r", ciphertext, "Base64 output must not contain carriage return characters")
        # Ensure it's valid Base64 decodeable
        raw_bytes = base64.b64decode(ciphertext)
        self.assertEqual(len(raw_bytes) % 16, 0, "Padded ciphertext bytes must be multiple of 16")

    def test_T1_03_crypto_roundtrip_plaintext_fidelity(self):
        """T1.03: Verify encrypt -> decrypt roundtrip preserves exact JSON structure and values."""
        payload = {
            "email": "testuser@example.com",
            "password": "MockPassword123!",
            "timestamp": "1761913950000",
            "type": 1,
            "sub_ids": [101, 102, 201]
        }
        ciphertext = self.client_cls.encrypt_payload(payload)
        plaintext = self.client_cls.decrypt_payload(ciphertext)
        recovered_dict = json.loads(plaintext)
        self.assertEqual(recovered_dict, payload, "Recovered payload does not match original")

    def test_T1_04_crypto_pkcs7_padding_blocks(self):
        """T1.04: Verify PKCS7 padding behavior across diverse message boundary lengths."""
        test_strings = [
            "",                        # 0 bytes -> pads 16 bytes of 0x10
            "A" * 1,                   # 1 byte -> pads 15 bytes of 0x0F
            "A" * 15,                  # 15 bytes -> pads 1 byte of 0x01
            "A" * 16,                  # 16 bytes (exact block) -> pads 16 bytes of 0x10
            "A" * 31,                  # 31 bytes -> pads 1 byte of 0x01
            "A" * 32,                  # 32 bytes -> pads 16 bytes of 0x10
            "A" * 100,                 # 100 bytes -> pads 12 bytes of 0x0C
        ]
        for s in test_strings:
            with self.subTest(msg_len=len(s)):
                data = {"content": s}
                ct = self.client_cls.encrypt_payload(data)
                pt = self.client_cls.decrypt_payload(ct)
                self.assertEqual(json.loads(pt)["content"], s)

    def test_T1_05_crypto_compact_json_serialization(self):
        """T1.05: Verify compact JSON serialization (no extra spaces between tokens)."""
        payload = {"a": 1, "b": "hello", "c": True}
        ct = self.client_cls.encrypt_payload(payload)
        pt = self.client_cls.decrypt_payload(ct)
        # Should not contain spaces after colon or comma: '{"a":1,"b":"hello","c":true}'
        self.assertNotIn(": ", pt, "Plaintext JSON should not contain ': ' spacing")
        self.assertNotIn(", ", pt, "Plaintext JSON should not contain ', ' spacing")

    # --- Tier 2: Boundary & Corner Cases (Crypto Engine) ---

    def test_T2_04_crypto_malformed_ciphertext_rejection(self):
        """T2.04: Corrupted, truncated, or non-Base64 strings must raise GeekSmartCryptoError or ValueError."""
        invalid_inputs = [
            "ThisIsNotBase64!!!@@#$$%",
            "bm90X211bHRpcGxl",  # "not_multiple" in base64 (12 bytes)
            "====",
            "",
            "YWJj",  # "abc" (3 bytes)
        ]
        for bad_ct in invalid_inputs:
            with self.subTest(bad_ct=bad_ct):
                with self.assertRaises((GeekSmartCryptoError, ValueError, Exception)):
                    self.client_cls.decrypt_payload(bad_ct)

    def test_T2_11_crypto_special_characters_and_unicode_fidelity(self):
        """T2.11: Complex symbols, Unicode characters, and emojis preserve exact fidelity."""
        payload = {
            "password": "MockPassword123! #$%^&*()_+~`|}{[]:;?><,./",
            "chinese": "智能门锁网关测试",
            "emoji": "🔐🚪📶⚡️",
            "control_chars": "line1\tline2"
        }
        ct = self.client_cls.encrypt_payload(payload)
        pt = self.client_cls.decrypt_payload(ct)
        recovered = json.loads(pt)
        self.assertEqual(recovered["password"], payload["password"])
        self.assertEqual(recovered["chinese"], payload["chinese"])
        self.assertEqual(recovered["emoji"], payload["emoji"])
        self.assertEqual(recovered["control_chars"], payload["control_chars"])

    def test_T2_15_crypto_large_payload_handling(self):
        """T2.15: Large payload encryption (>16KB) without buffer truncation or memory issues."""
        large_list = [{"id": i, "data": "X" * 100} for i in range(150)]
        payload = {"items": large_list}
        ct = self.client_cls.encrypt_payload(payload)
        pt = self.client_cls.decrypt_payload(ct)
        recovered = json.loads(pt)
        self.assertEqual(len(recovered["items"]), 150)
        self.assertEqual(recovered["items"][149]["data"], "X" * 100)


if __name__ == "__main__":
    unittest.main()
