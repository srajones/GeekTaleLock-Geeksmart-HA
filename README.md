# GeekTale Lock / GeekSmart Home Assistant Integration (HACS)

[![HACS Custom](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://hacs.xyz/docs/faq/custom_repositories/)
[![Home Assistant](https://img.shields.io/badge/Home%20Assistant-2024.1%2B-18BCF2.svg?logo=homeassistant&logoColor=white)](https://www.home-assistant.io/)
[![GitHub Release](https://img.shields.io/github/v/release/srajones/GeekTaleLock-Geeksmart-HA)](https://github.com/srajones/GeekTaleLock-Geeksmart-HA/releases/latest)
[![IoT class](https://img.shields.io/badge/IoT%20class-cloud__polling%20%2B%20BLE-informational.svg)](#how-it-works)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/srajones)

**The first HACS integration for GeekSmart / GeekTale smart locks.** Sign in with the same account you use in the **GeekSmart app**, and your GeekTale / GeekSmart door locks and GeekSmart smart plugs show up in **Home Assistant** as native `lock`, `switch`, `sensor`, and `binary_sensor` entities, through the **Tuya Direct Cloud** path the GeekSmart app itself uses. **No TTLock OAuth app, client ID, or developer account is required.**

> **HACS custom repository URL:** `https://github.com/srajones/GeekTaleLock-Geeksmart-HA` (category: **Integration**)

> [!WARNING]
> **⚠️ The GeekSmart phone app and this integration fight over the same cloud session — you generally cannot use both logged in at the same time.**
> Logging in on the app can kick Home Assistant off (and HA can kick the app), and you may see rate limits or `USER_SESSION_INVALID` errors.
> **Workaround:** when you need the phone app, **disable** the GeekDoor config entry in Home Assistant (*Settings → Devices & services → GeekDoor → ⋮ → Disable*), use the app, then **re-enable** the entry afterward.

---

## Why this exists

GeekTale and GeekSmart locks are sold as TTLock-compatible, but the **GeekSmart app** signs you in with a GeekSmart account that is backed by Tuya, not by a TTLock Open Platform account. Integrations like `hass-ttlock` expect a TTLock developer client ID/secret and a TTLock login, so they often **don't fit a GeekSmart-app login** at all.

This integration takes the GeekSmart-app route instead:

1. You enter your **GeekSmart account email, password, and country code** in the Home Assistant UI.
2. The integration performs the same **GeekSmart → Tuya Direct Cloud** sign-in the app does, then discovers your homes, locks, and gateways automatically.
3. Lock state, battery, and controls flow into Home Assistant, with local **Bluetooth (BLE)** used when a lock is in range.

## Features

- 🔐 **Home Assistant lock entity** for each GeekTale / GeekSmart lock: lock, unlock, and a `geek_door.keep_unlocked` service (Passage Mode).
- ☁️ **Tuya Direct Cloud mode** (GeekSmart-app login). No TTLock OAuth, no extra server, no developer keys.
- 📶 **Local Bluetooth first:** uses Home Assistant's Bluetooth stack and **ESPHome Bluetooth proxies** (BLE GATT `0xFD50`), and falls back to the cloud gateway when the lock is out of range.
- 🔌 **GeekSmart smart plug outlet switch:** the plug that doubles as the lock's Wi-Fi/BLE gateway (Tuya category `cz`, **DP 1** / `switch_1`) appears as a `switch` with `device_class: outlet`, so you can turn the mains outlet on and off from Home Assistant.
- 🔁 **Auto-Lock / Passage Mode switch** (DP 33) plus a configurable auto-relock delay (DP 36).
- 🔋 **Sensors:** battery %, gateway Wi-Fi RSSI, BLE link state, and a BLE connectivity binary sensor.
- 👥 **Multi-account, multi-home discovery** with no hardcoded device IDs. Works with 0, 1, or many gateways.
- 📱 **Coexists with the GeekSmart phone app:** cache-first polling and rate limiting so you aren't logged out of the app.
- 🛡️ **5-layer safety barrier:** destructive cloud endpoints (unbind, factory reset, deleting fingerprints/cards/passcodes) are permanently blocked.
- 🧰 **Optional extras:** a Home Assistant OS add-on, a self-hosted web dashboard with TOTP 2FA, a REST/webhook API, and a CLI.

## Supported devices

| Device family | What you get in Home Assistant |
| :--- | :--- |
| **GeekTale / GeekSmart Bluetooth smart locks** (GeekSmart app, Tuya `jtmspro` / `ms` category; e.g. K01-series, K11 and compatible) | `lock`, Auto-Lock `switch`, battery / signal `sensor`s, BLE `binary_sensor` |
| **GeekSmart smart plug BLE gateway** (Tuya `cz`, outlet on DP 1) | Outlet `switch` (mains relay), gateway Wi-Fi signal |
| Locks without a gateway | Direct BLE through HA Bluetooth or an ESPHome proxy |

If your lock pairs in the **GeekSmart** app, it's very likely supported. Please open an [issue](https://github.com/srajones/GeekTaleLock-Geeksmart-HA/issues) with your model if it isn't.

---

## Installation (HACS custom repository)

1. In Home Assistant open **HACS → ⋮ (top right) → Custom repositories**.
2. Add:
   - **Repository:** `https://github.com/srajones/GeekTaleLock-Geeksmart-HA`
   - **Category:** `Integration`
3. Search HACS for **GeekSmart Door Lock**, click **Download**, then **restart Home Assistant**.

<details>
<summary>Manual install (without HACS)</summary>

Copy `custom_components/geek_door/` from this repository into your Home Assistant `config/custom_components/` folder and restart Home Assistant.
</details>

## Configuration (Direct Cloud)

1. Go to **Settings → Devices & services → Add integration** and search for **GeekSmart Door Lock**.
2. Choose **Direct Tuya / GeekSmart Cloud**.
3. Enter your **GeekSmart app** email, password, and country calling code (e.g. `1` for US/Canada).
4. Your locks and GeekSmart plugs are discovered automatically.

**Options** (Configure on the integration card): polling interval, prefer Home Assistant Bluetooth / ESPHome proxy, BLE fallback, and the default auto-lock delay.

> **Server Bridge mode** is also available if you run the optional self-hosted `geek-door` server (see [Advanced](#advanced-self-hosted-server-add-on-and-cli)).

### Entities per lock

| Entity | Type | Description |
| :--- | :---: | :--- |
| `lock.<lock_name>` | `lock` | Lock / unlock; service `geek_door.keep_unlocked` for Passage Mode |
| `switch.<lock_name>_auto_lock` | `switch` | Auto-Lock (DP 33): `on` = auto-relock, `off` = keep unlocked |
| `sensor.<lock_name>_battery` | `sensor` | Battery % (DP 8) |
| `sensor.<lock_name>_wifi_signal` | `sensor` | Gateway Wi-Fi signal (dBm) |
| `sensor.<lock_name>_ble_signal_state` | `sensor` | BLE link diagnostic |
| `binary_sensor.<lock_name>_ble_connection` | `binary_sensor` | BLE GATT connected / disconnected |

### Entity per GeekSmart smart plug

| Entity | Type | Description |
| :--- | :---: | :--- |
| `switch.<plug_name>_outlet` | `switch` (`outlet`) | Mains outlet relay (Tuya `cz`, DP 1 / `switch_1`). Requires Direct Cloud mode. |

> ⚠️ Turning the outlet **off** cuts power to whatever is plugged into it. If the plug is also your lock's gateway, cloud control of the lock pauses until it's back on. Local BLE control keeps working.

### Example automation

```yaml
automation:
  - alias: "Lock front door at night"
    trigger:
      - platform: time
        at: "23:00:00"
    action:
      - service: lock.lock
        target:
          entity_id: lock.front_door
```

---

## How it works

- **Direct Cloud:** the GeekSmart account login is exchanged for a Tuya session, just like the GeekSmart app does. The session is cached in Home Assistant's config folder and refreshed automatically.
- **BLE:** when a lock is in range of Home Assistant's Bluetooth adapter or an ESPHome proxy, commands go over BLE GATT `0xFD50` (AES-128-CBC). Otherwise they go through the smart plug gateway via the cloud.
- **Polling:** `cloud_polling`, with a configurable interval and rate limiting to stay friendly with the vendor cloud and the phone app.

## Security & privacy

- **No secrets in this repository.** All IDs, keys, MACs, emails, and tokens in the code, tests, and docs are fake examples. Your real devices are discovered from your own account at runtime.
- Your credentials are stored only in Home Assistant's config entry, and the session cache stays on your HA instance.
- Destructive vendor operations (unbind, factory reset, deleting users/fingerprints/cards/passcodes, password changes) are hard-blocked in code.
- Never paste your password, tokens, or device keys into issues. Redact logs before sharing them.
- Physical-security reminder: a smart lock is a door. Test automations carefully and keep a physical key.

---

## Advanced: self-hosted server, add-on, and CLI

### Home Assistant OS add-on
**Settings → Add-ons → Add-on Store → ⋮ → Repositories**, add `https://github.com/srajones/GeekTaleLock-Geeksmart-HA`, then install **GeekSmart & Tuya BLE Door Lock Bridge**.

### Docker Compose (VPS or home server)
```bash
git clone https://github.com/srajones/GeekTaleLock-Geeksmart-HA.git
cd GeekTaleLock-Geeksmart-HA
cp .env.example .env && chmod 600 .env && nano .env
docker compose up -d --build
```
It binds to `127.0.0.1:5050` by default and runs as non-root with `read_only`, `cap_drop: [ALL]`, and `no-new-privileges`. Open `http://127.0.0.1:5050/setup` for the setup wizard (admin login + TOTP 2FA, account discovery, optional DNS/SSL/Nginx).

### Failsafe installer
```bash
sudo bash scripts/install.sh --dry-run --verbose   # pre-flight only, no changes
sudo bash scripts/install.sh --verbose             # install with automatic rollback on failure
sudo bash scripts/install.sh --restore-nginx       # revert Nginx to pre-install state
```

### CLI and tests
```bash
pip install -r requirements.txt
python3 tests/run_tests.py                 # offline test suite, no live actuations
python3 door_lock_control.py list
python3 door_lock_control.py unlock --device-id <lock_name_or_id> --dry-run
```

## 🌐 HTTP REST API & Home Assistant Endpoints

Authenticate requests using either a logged-in 2FA browser session cookie or `Authorization: Bearer <GEEK_DOOR_API_KEY>` (or `X-API-Key: <GEEK_DOOR_API_KEY>`).

### Core Device & Control Endpoints
| Method & Route | Description |
| :--- | :--- |
| `GET /api/health` | Unauthenticated container/service health check |
| `GET /api/status` | Multi-hop account status, session cache & 5-Layer Safety Barrier summary |
| `GET /api/devices` | Cached device inventory (`?refresh=1` or `POST /api/devices/refresh` for rate-limited live cloud sync) |
| `GET /api/devices/<id>/status` | Detailed device telemetry, battery `%`, Wi-Fi RSSI, BLE status & DPs |
| `GET /api/capabilities` | Supported read-only queries, safe actuations & 45 blocked destructive routes |
| `POST /api/devices/<id>/unlock` | Momentary unlock (`{"confirmed": true}` or `{"dry_run": true}`, optional `"keep_unlocked": true`) |
| `POST /api/devices/<id>/keep_unlocked` | Enable Passage Mode / Keep Unlocked (`DP 33 = false`, `{"confirmed": true}`) |
| `POST /api/devices/<id>/auto_lock` | Toggle Auto-Lock (`{"enabled": true\|false, "auto_lock_time": 5, "confirmed": true}`) |
| `POST /api/devices/<id>/lock` | Lock deadbolt (`DP 71`) and re-enable Auto-Lock (`DP 33 = true`, `{"confirmed": true}`) |

### Home Assistant Bridge Endpoints (`/api/ha/*`)
| Method & Route | Description |
| :--- | :--- |
| `GET /api/ha/status` | Full Home Assistant bridge telemetry for all discovered locks & gateways |
| `GET /api/ha/lock/<id>/state` | Single-lock state & attributes for Home Assistant REST sensors |
| `POST /api/ha/lock/<id>/unlock` | Momentary unlock with non-blocking outgoing webhook dispatch |
| `POST /api/ha/lock/<id>/lock` | Lock door with non-blocking outgoing webhook dispatch |
| `POST /api/ha/lock/<id>/keep_unlocked` | Keep Unlocked / Passage Mode (`DP 33 = false`) |
| `POST /api/ha/lock/<id>/auto_lock` | Toggle `DP 33` Auto-Lock (`{"enabled": true\|false}`) without actuating the deadbolt motor |
| `POST /api/ha/webhook` | Incoming HMAC/constant-time token-verified webhook receiver |
| `GET /api/ha/config.yaml` | Generates ready-to-paste Home Assistant `configuration.yaml` package |

---

## 🔬 Reverse-Engineered Protocol Reference (`jtmspro` & BLE GATT `0xFD50`)

| Data Point / Layer | Identifier | Type | Description |
| :--- | :---: | :---: | :--- |
| **Motor / Clutch State** | `DP 47` (`lock_motor_state`) | `Boolean (ro)` | `true` = **UNLOCKED** (*"Click to lock"*), `false` = **LOCKED** (*"Click to unlock"*) |
| **Auto-Lock / Passage Mode** | `DP 33` (`automatic_lock`) | `Boolean (rw)` | `true` = Auto-Relocks after `DP 36` seconds; `false` = **Keep Unlocked (Passage Mode)** |
| **Auto-Lock Countdown** | `DP 36` (`auto_lock_time`) | `Integer (rw)` | Auto-relock delay in seconds (`1–1800s`) |
| **Remote Unlock/Lock Frame** | `DP 71` (`ble_unlock_check`) | `Raw 19-Byte Base64` | `ff ff <0001=unlock \| 0000=lock> <8-byte ASCII key seed from DP 73> 00 00 00 00 00 00 52` |
| **Remote Key Seed** | `DP 73` (`remote_pd_setkey_check`) | `Raw 16-Byte Base64` | Contains member ID + 8-byte ASCII key seed configured by the app |
| **Battery Level** | `DP 8` (`residual_electricity`) | `Integer (ro)` | Remaining battery capacity (`0–100%`) |
| **Direct BLE GATT Service** | `0xFD50` (`0000fd50-...`) | `BLE GATT` | Write char `00000001-...`, Notify char `00000002-...`, AES-128-CBC (`MD5(local_key[:6] + srand)`), CRC16-MODBUS |

---

## 🛡️ 5-Layer Safety Barrier (`custom_components/geek_door/core/safety.py`)

Every cloud and BLE operation passes through `SafetyBarrierGuard`:
1. **Layer 1 — Immutable Hard Denylist**: Permanently blocks 45 destructive endpoints (`deleteClientEquipment`, `unbind`, `resetFactory`, fingerprint/IC card/passcode deletions).
2. **Layer 2 — Destructive Keyword Regex Filter**: Rejects non-allowlisted routes matching `delete|remove|unbind|reset|factory|format|wipe|clear|destroy|revoke|erase|drop|purge`.
3. **Layer 3 — Operational Mode Gating**: `READ_ONLY` vs. `SAFE_CONTROL`.
4. **Layer 4 — Parameter-Level Inspection Guard**: Blocks password mutations (`newPassword`, `alterPassword`) and destructive TTLock wipe `authType` codes (`5`, `6`, `7`).
5. **Layer 5 — Explicit Confirmation & Dry-Run Gate**: Zero automated physical actuations; supports full `--dry-run` simulation across CLI, REST API, and tests.

---

## Contributing & support

Issues and pull requests are welcome: https://github.com/srajones/GeekTaleLock-Geeksmart-HA/issues. Please include your lock/plug model, Home Assistant version, and **redacted** debug logs.

If this integration helped get your GeekTale / GeekSmart locks and smart plugs into Home Assistant, consider buying me a coffee!

[![Buy Me A Coffee](https://img.shields.io/badge/☕_Buy_Me_a_Coffee-srajones-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/srajones)

- **Buy Me a Coffee:** [https://buymeacoffee.com/srajones](https://buymeacoffee.com/srajones)

## Disclaimer

This is an independent community project. It is not affiliated with or endorsed by GeekSmart, GeekTale, Tuya, or TTLock. All trademarks belong to their owners. Use at your own risk.

**Keywords:** GeekSmart Home Assistant, GeekTale lock Home Assistant, GeekSmart HACS, TTLock-compatible GeekSmart lock, Tuya Direct Cloud lock, Home Assistant smart lock integration, GeekSmart smart plug outlet, ESPHome Bluetooth proxy lock.
