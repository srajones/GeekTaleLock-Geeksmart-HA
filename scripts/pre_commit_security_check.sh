#!/usr/bin/env bash
# =============================================================================
# Git Pre-Commit Security Hook & Fast CI Gate
# Verifies zero credentials, 127.0.0.1 binding, and executes security scanner.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

echo "🔒 [SECURITY-CI] Running Pre-Commit Security Checks..."

# 1. Fast regex scanner for critical credentials, emails, physical location, and account IDs
FORBIDDEN_REGEX="REDACTED_TEST""_PASSWORD|EXAMPLE_UID""_REDACTED|000000000|0000000|deadbeef0000"
# Optional maintainer-only denylist of personal identifiers (one ERE per line).
# Never commit it: set GEEKDOOR_PRIVATE_DENYLIST or create an untracked .private-denylist.
PRIVATE_DENYLIST="${GEEKDOOR_PRIVATE_DENYLIST:-$REPO_ROOT/.private-denylist}"
if [ -f "$PRIVATE_DENYLIST" ]; then
  EXTRA=$(grep -vE '^\s*(#|$)' "$PRIVATE_DENYLIST" | paste -sd'|' -)
  [ -n "$EXTRA" ] && FORBIDDEN_REGEX="$FORBIDDEN_REGEX|$EXTRA"
fi

LEAK_VIOLATIONS=$(grep -rniIE "$FORBIDDEN_REGEX" \
  --exclude-dir={.git,.agents,__pycache__,.venv,venv,rea-main} \
  --exclude="test_security_audit.py" \
  --exclude="test_adversarial_security.py" \
  --exclude="pre_commit_security_check.sh" \
  --exclude=".private-denylist" \
  --exclude="proposed_*" \
  --exclude="*.md" \
  --exclude="*.zip" \
  --exclude="*.apks" \
  "$REPO_ROOT" | grep -vE "re\.compile|forbidden_regexes|personal_ids|banned" || true)

if [ -n "$LEAK_VIOLATIONS" ]; then
  echo "❌ [SECURITY-CI FAILED] Critical credential or identity leak detected:"
  echo "$LEAK_VIOLATIONS"
  echo "Commit rejected. Please purge all plaintext passwords, emails, GPS, and personal account IDs."
  exit 1
fi

# 2. Check docker-compose.yml port binding
COMPOSE_FILE="$REPO_ROOT/docker-compose.yml"
if [ -f "$COMPOSE_FILE" ]; then
  if grep -q "\${GEEK_DOOR_BIND_IP:-0\.0\.0\.0}" "$COMPOSE_FILE"; then
    echo "❌ [SECURITY-CI FAILED] docker-compose.yml binds to 0.0.0.0 by default!"
    echo "It must bind to 127.0.0.1 by default to prevent Docker UFW firewall bypass on VPS."
    exit 1
  fi
fi

# 3. Check .env.example
ENV_EXAMPLE="$REPO_ROOT/.env.example"
if [ -f "$ENV_EXAMPLE" ]; then
  if grep -q "^GEEK_DOOR_BIND_IP=0\.0\.0\.0" "$ENV_EXAMPLE"; then
    echo "❌ [SECURITY-CI FAILED] .env.example sets GEEK_DOOR_BIND_IP=0.0.0.0!"
    echo "Default binding must be 127.0.0.1 for secure VPS deployment."
    exit 1
  fi
fi

# 4. Execute test suite for security audit if test file exists
if [ -f "$REPO_ROOT/tests/test_security_audit.py" ]; then
  echo "🔒 [SECURITY-CI] Running tests/test_security_audit.py..."
  python3 -m unittest tests/test_security_audit.py
fi

echo "✅ [SECURITY-CI PASSED] Zero security violations found."
exit 0
