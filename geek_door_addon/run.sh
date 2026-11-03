#!/usr/bin/env bash
set -euo pipefail

echo "============================================================"
echo " 🚪 GeekSmart Door Lock Bridge — Home Assistant OS Add-on"
echo "============================================================"

OPTIONS_FILE="/data/options.json"
ENV_FILE="/data/.env"

EMAIL=""
PASSWORD=""
COUNTRY_CODE="1"
API_KEY=""
ENABLE_2FA="false"
LOG_LEVEL="info"
DRY_RUN="false"
SERVER_PID=""

term_handler() {
    echo "[INFO] Received termination signal. Shutting down cleanly..."
    if [ -n "${SERVER_PID:-}" ]; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    exit 0
}
trap term_handler SIGTERM SIGINT SIGHUP

get_option() {
    local key="${1:-}"
    local default_val="${2:-}"
    if [ -f "$OPTIONS_FILE" ]; then
        if command -v jq >/dev/null 2>&1; then
            if jq -e "has(\"$key\") and (.\"$key\" != null) and (.\"$key\" != \"\")" "$OPTIONS_FILE" >/dev/null 2>&1; then
                jq -r ".\"$key\"" "$OPTIONS_FILE"
            else
                echo "$default_val"
            fi
        else
            python3 -c '
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    v = data.get(sys.argv[2], None)
    if v is None or v == "":
        print(sys.argv[3])
    elif isinstance(v, bool):
        print(str(v).lower())
    else:
        print(v)
except Exception:
    print(sys.argv[3])
' "$OPTIONS_FILE" "$key" "$default_val"
        fi
    else
        echo "$default_val"
    fi
}

if [ -f "$OPTIONS_FILE" ]; then
    echo "[INFO] Loading configuration from $OPTIONS_FILE..."
    EMAIL=$(get_option "email" "")
    PASSWORD=$(get_option "password" "")
    COUNTRY_CODE=$(get_option "country_code" "1")
    API_KEY=$(get_option "api_key" "")
    ENABLE_2FA=$(get_option "enable_2fa" "false")
    LOG_LEVEL=$(get_option "log_level" "info")
    DRY_RUN=$(get_option "dry_run" "false")
else
    echo "[WARN] No options.json found at $OPTIONS_FILE, using environment defaults"
fi

# Input validation
if [[ ! "$COUNTRY_CODE" =~ ^[0-9]+$ ]]; then
    COUNTRY_CODE="1"
fi

if [[ ! "$LOG_LEVEL" =~ ^(debug|info|warning|error)$ ]]; then
    LOG_LEVEL="info"
fi

if [[ "$ENABLE_2FA" =~ ^(true|1|yes)$ ]]; then
    ENABLE_2FA="true"
else
    ENABLE_2FA="false"
fi

if [[ "$DRY_RUN" =~ ^(true|1|yes)$ ]]; then
    DRY_RUN="true"
else
    DRY_RUN="false"
fi

# Safely write $ENV_FILE using Python without bash variable interpolation risks
python3 -c '
import sys
keys = [
    ("GEEK_DOOR_SESSION_CACHE", "/data/.session_cache.json"),
    ("TUYA_USERNAME", sys.argv[2]),
    ("TUYA_PASSWORD", sys.argv[3]),
    ("TUYA_COUNTRY_CODE", sys.argv[4]),
    ("HA_BEARER_TOKEN", sys.argv[5]),
    ("GEEK_DOOR_API_KEY", sys.argv[5]),
    ("LOG_LEVEL", sys.argv[6]),
    ("ENABLE_2FA", sys.argv[7]),
    ("AUTH_ENABLED", sys.argv[7]),
    ("DRY_RUN", sys.argv[8]),
    ("PORT", "5050"),
    ("HOST", "0.0.0.0"),
]
with open(sys.argv[1], "w", encoding="utf-8") as f:
    for k, v in keys:
        f.write(f"{k}={v}\n")
' "$ENV_FILE" "$EMAIL" "$PASSWORD" "$COUNTRY_CODE" "$API_KEY" "$LOG_LEVEL" "$ENABLE_2FA" "$DRY_RUN"
chmod 600 "$ENV_FILE"

export GEEK_DOOR_SESSION_CACHE="/data/.session_cache.json"
export TUYA_USERNAME="${EMAIL}"
export TUYA_PASSWORD="${PASSWORD}"
export TUYA_COUNTRY_CODE="${COUNTRY_CODE}"
export HA_BEARER_TOKEN="${API_KEY}"
export GEEK_DOOR_API_KEY="${API_KEY}"
export LOG_LEVEL="${LOG_LEVEL}"
export ENABLE_2FA="${ENABLE_2FA}"
export AUTH_ENABLED="${ENABLE_2FA}"
export DRY_RUN="${DRY_RUN}"
export PORT=5050
export HOST="0.0.0.0"

echo "[INFO] Add-on initialized successfully. Starting Web UI & REST Server on port 5050..."
python3 /app/door_lock_control.py serve --host 0.0.0.0 --port 5050 --cache /data/.session_cache.json &
SERVER_PID=$!
wait "$SERVER_PID"
