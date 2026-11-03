#!/usr/bin/env bash
# ==============================================================================
# GeekSmart / mydoor Production Installer & VPS Hardening Script
# Milestone 10 / Requirement R2 Implementation
# ==============================================================================
# Failsafe verbose installation script with pre-flight matrix, dedicated unprivileged
# user isolation, sandboxed systemd service, safe Nginx management, and transactional
# LIFO rollback on failure or interrupt.
# ==============================================================================
set -eE -o pipefail

# --- Global Defaults ---
DEFAULT_PORT=5050
DEFAULT_INSTALL_DIR="/opt/mydoor"
DEFAULT_SERVICE_NAME="mydoor.service"
DEFAULT_USER="geekdoor"
DEFAULT_GROUP="geekdoor"

# --- Runtime Configuration ---
PORT="${MYDOOR_PORT:-$DEFAULT_PORT}"
INSTALL_DIR="${MYDOOR_INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
DOMAIN="${MYDOOR_DOMAIN:-}"
DRY_RUN=false
VERBOSE=false
NO_NGINX=false
RESTORE_NGINX=false
RESTORE_BACKUP_ID=""
FORCE=false
COLOR_ENABLED=true

# Disable colors if terminal does not support them
if [ ! -t 1 ] || [ "${TERM:-}" = "dumb" ]; then
  COLOR_ENABLED=false
fi

# --- Logging Helpers ---
log_info() {
  if [ "$COLOR_ENABLED" = true ]; then
    printf "\033[1;34m[INFO]\033[0m %s\n" "$*"
  else
    printf "[INFO] %s\n" "$*"
  fi
}

log_pass() {
  if [ "$COLOR_ENABLED" = true ]; then
    printf "\033[1;32m[PASS]\033[0m %s\n" "$*"
  else
    printf "[PASS] %s\n" "$*"
  fi
}

log_warn() {
  if [ "$COLOR_ENABLED" = true ]; then
    printf "\033[1;33m[WARN]\033[0m %s\n" "$*"
  else
    printf "[WARN] %s\n" "$*"
  fi
}

log_fail() {
  if [ "$COLOR_ENABLED" = true ]; then
    printf "\033[1;31m[FAIL]\033[0m %s\n" "$*" >&2
  else
    printf "[FAIL] %s\n" "$*" >&2
  fi
}

log_dryrun() {
  if [ "$COLOR_ENABLED" = true ]; then
    printf "\033[1;35m[DRY-RUN]\033[0m %s\n" "$*"
  else
    printf "[DRY-RUN] %s\n" "$*"
  fi
}

# ==============================================================================
# Transactional LIFO Rollback Subsystem
# ==============================================================================
declare -a ROLLBACK_STACK=()
INSTALL_SUCCESS=0
ROLLBACK_IN_PROGRESS=0

rollback_push() {
  local action="$1"
  ROLLBACK_STACK+=("${action}")
  if [ "$VERBOSE" = true ]; then
    log_info "[ROLLBACK_TRACK] Registered: ${action}"
  fi
}

rollback_exec() {
  local exit_code=$?

  # Normal successful termination -> do nothing
  if [ "${INSTALL_SUCCESS:-0}" -eq 1 ]; then
    exit 0
  fi

  # Prevent recursive trap execution
  if [ "${ROLLBACK_IN_PROGRESS:-0}" -eq 1 ]; then
    return
  fi
  ROLLBACK_IN_PROGRESS=1

  # Disable traps during rollback execution
  trap - EXIT ERR INT TERM

  local stack_size=${#ROLLBACK_STACK[@]}
  if [ "$stack_size" -gt 0 ]; then
    echo "" >&2
    echo "=================================================================" >&2
    echo " [!] INSTALLATION FAILED OR INTERRUPTED (Exit Code: ${exit_code})" >&2
    echo " [*] Initiating Transactional LIFO Rollback of host mutations..." >&2
    echo "=================================================================" >&2
    echo " [*] Reverting ${stack_size} recorded mutations in reverse order..." >&2

    local idx
    for (( idx=stack_size-1; idx>=0; idx-- )); do
      local action="${ROLLBACK_STACK[idx]}"
      echo " [ROLLBACK $((stack_size - idx))/${stack_size}] ${action}" >&2
      eval "${action}" >&2 || {
        echo " [WARN] Rollback step encountered error (continuing remaining steps): ${action}" >&2
      }
    done

    echo "=================================================================" >&2
    echo " [*] Transactional rollback complete. Host state safely restored." >&2
    echo "=================================================================" >&2
  else
    if [ "$exit_code" -ne 0 ]; then
      log_fail "Installation failed before any host mutations were recorded (exit code: ${exit_code})."
    fi
  fi

  if [ "$exit_code" -eq 0 ]; then
    exit 1
  else
    exit "${exit_code}"
  fi
}

# Trap ERR, INT (Ctrl+C), TERM, and EXIT
trap 'rollback_exec' ERR INT TERM EXIT

# ==============================================================================
# Usage & Help Display
# ==============================================================================
show_help() {
  cat <<'EOF'
================================================================================
  GeekSmart / mydoor Production Installer (Milestone 10)
================================================================================

Usage:
  sudo ./scripts/install.sh [OPTIONS]

Options:
  --dry-run                 Simulate pre-flight inspections and installation steps
                            without making any host mutations.
  -v, --verbose             Enable verbose debugging and execution tracing.
  -p, --port <PORT>         Override backend web server port (default: 5050).
  -d, --domain <DOMAIN>     Configure Nginx reverse proxy with FQDN (e.g. door.example.com).
  --no-nginx                Skip Nginx reverse proxy configuration.
  --restore-nginx [ID]      Restore Nginx configuration to a previous timestamped backup.
  --force                   Bypass non-critical host prerequisite warnings.
  --install-dir <DIR>       Destination directory for mydoor (default: /opt/mydoor).
  -h, --help                Display this help documentation and exit.

Environment Variables:
  MYDOOR_PORT               Default port override if --port is omitted.
  MYDOOR_DOMAIN             Default domain override if --domain is omitted.
  MYDOOR_INSTALL_DIR        Default install dir override if --install-dir is omitted.
  EMAIL                     Email address for automated Certbot SSL certificate registration.

Examples:
  # Dry-run inspection
  ./scripts/install.sh --dry-run

  # Standard installation on default port 5050
  sudo ./scripts/install.sh

  # Installation with custom port and Nginx domain
  sudo ./scripts/install.sh --port 8080 --domain door.myhouse.com --verbose

  # Single-action Nginx restore
  sudo ./scripts/install.sh --restore-nginx
================================================================================
EOF
}

# ==============================================================================
# CLI Argument Parsing
# ==============================================================================
parse_arguments() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)
        DRY_RUN=true
        shift
        ;;
      -v|--verbose)
        VERBOSE=true
        shift
        ;;
      -p|--port)
        if [[ -z "${2:-}" || "$2" =~ ^- ]]; then
          log_fail "Option --port requires a port number argument (e.g. --port 5050)"
          exit 2
        fi
        PORT="$2"
        if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
          log_fail "Invalid port number: '$PORT'. Must be an integer between 1 and 65535."
          exit 2
        fi
        shift 2
        ;;
      -d|--domain)
        if [[ -z "${2:-}" || "$2" =~ ^- ]]; then
          log_fail "Option --domain requires a domain name argument (e.g. --domain door.example.com)"
          exit 2
        fi
        DOMAIN="$2"
        # Validate RFC 1123 domain syntax
        if ! [[ "$DOMAIN" =~ ^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$ ]]; then
          log_fail "Invalid domain name syntax: '$DOMAIN'. Must be a valid FQDN."
          exit 2
        fi
        shift 2
        ;;
      --no-nginx)
        NO_NGINX=true
        shift
        ;;
      --restore-nginx)
        RESTORE_NGINX=true
        if [[ -n "${2:-}" && ! "$2" =~ ^- ]]; then
          RESTORE_BACKUP_ID="$2"
          shift 2
        else
          shift 1
        fi
        ;;
      --force)
        FORCE=true
        shift
        ;;
      --install-dir)
        if [[ -z "${2:-}" || "$2" =~ ^- ]]; then
          log_fail "Option --install-dir requires a directory path"
          exit 2
        fi
        INSTALL_DIR="$2"
        shift 2
        ;;
      -h|--help)
        show_help
        INSTALL_SUCCESS=1
        exit 0
        ;;
      *)
        log_fail "Unknown option: $1"
        echo "Run '$0 --help' for usage instructions." >&2
        exit 2
        ;;
    esac
  done
}

# ==============================================================================
# Standalone Nginx Restore Handler
# ==============================================================================
handle_nginx_restore() {
  log_info "Single-action Nginx configuration restore requested."

  if [ "$(id -u)" -ne 0 ]; then
    log_fail "Restoring Nginx configuration requires root privileges (sudo)."
    exit 1
  fi

  local python_exec="python3"
  if [ -x "$INSTALL_DIR/venv/bin/python3" ]; then
    python_exec="$INSTALL_DIR/venv/bin/python3"
  fi

  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  local repo_dir
  repo_dir="$(cd "${script_dir}/.." && pwd)"
  export PYTHONPATH="${repo_dir}:${INSTALL_DIR}:${PYTHONPATH:-}"

  local restore_args=("-m" "server.nginx_manager" "--restore")
  if [ -n "$RESTORE_BACKUP_ID" ]; then
    restore_args+=("$RESTORE_BACKUP_ID")
  fi

  log_info "Executing: $python_exec ${restore_args[*]}"
  if "$python_exec" "${restore_args[@]}"; then
    log_pass "Nginx configuration restored successfully to prior working state."
    INSTALL_SUCCESS=1
    exit 0
  else
    local status=$?
    log_fail "Nginx restore failed with exit code $status."
    exit "$status"
  fi
}

# ==============================================================================
# Privilege Validation
# ==============================================================================
validate_privileges() {
  if [ "$DRY_RUN" = true ]; then
    log_dryrun "=== RUNNING IN DRY-RUN MODE: ZERO HOST MUTATIONS WILL BE APPLIED ==="
    if [ "$(id -u)" -ne 0 ]; then
      log_dryrun "Running as unprivileged user ($(whoami)). Host inspections will proceed in simulation mode."
    fi
    return 0
  fi

  if [ "$(id -u)" -ne 0 ]; then
    log_fail "Root privileges required. scripts/install.sh must be executed as root (or with sudo)."
    log_fail "Please re-run: sudo $0 $*"
    exit 1
  fi
}

# ==============================================================================
# Pre-Flight Host Inspection Matrix
# ==============================================================================

# --- 1. OS & Platform Detection ---
check_os() {
  log_info "Inspecting operating system..."
  local distro_id="unknown"
  local distro_version="unknown"
  local distro_name="Unknown"

  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    distro_id="${ID:-unknown}"
    distro_version="${VERSION_ID:-unknown}"
    distro_name="${PRETTY_NAME:-$distro_id}"
  elif [ "$(uname -s)" = "Darwin" ]; then
    distro_id="darwin"
    distro_version="$(sw_vers -productVersion 2>/dev/null || echo "macOS")"
    distro_name="macOS $distro_version"
  else
    distro_name="$(uname -s) $(uname -r)"
  fi

  log_info "Detected OS: $distro_name (ID: $distro_id, Version: $distro_version)"

  if [ "$distro_id" = "darwin" ]; then
    if [ "$DRY_RUN" = true ]; then
      log_dryrun "macOS detected in dry-run mode. Linux systemd service will be simulated."
      return 0
    else
      log_fail "Production deployment with systemd is only supported on Linux (Debian 11+, Ubuntu 20.04+)."
      log_fail "For local development on macOS, use: python3 door_lock_control.py serve"
      exit 1
    fi
  fi

  # Validate Debian >= 11 or Ubuntu >= 20.04
  if [ "$distro_id" = "ubuntu" ]; then
    local major_ver
    major_ver=$(echo "$distro_version" | cut -d. -f1)
    if [ "$major_ver" -lt 20 ] 2>/dev/null; then
      log_warn "Ubuntu version $distro_version is older than recommended 20.04 LTS."
    else
      log_pass "Supported OS: Ubuntu $distro_version"
    fi
  elif [ "$distro_id" = "debian" ]; then
    local major_ver
    major_ver=$(echo "$distro_version" | cut -d. -f1)
    if [ "$major_ver" -lt 11 ] 2>/dev/null; then
      log_warn "Debian version $distro_version is older than recommended 11 (Bullseye)."
    else
      log_pass "Supported OS: Debian $distro_version"
    fi
  else
    log_info "Generic Linux distribution detected ($distro_name). Proceeding with standard checks."
  fi

  return 0
}

# --- 2. Memory Inspection (RAM >= 384MB) ---
# Memory inspection: check /proc/meminfo, free -m, or RAM
check_memory() {
  log_info "Inspecting system memory (RAM)..."
  local mem_mb=0

  if [ -f /proc/meminfo ]; then
    local mem_kb
    mem_kb=$(awk '/MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null || true)
    if [ -z "$mem_kb" ]; then
      mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || true)
    fi
    mem_mb=$((mem_kb / 1024))
  elif command -v free >/dev/null 2>&1; then
    mem_mb=$(free -m 2>/dev/null | awk '/^Mem:/{print $2}')
  elif [ "$(uname -s)" = "Darwin" ]; then
    mem_mb=$(sysctl -n hw.memsize 2>/dev/null | awk '{print int($1/1024/1024)}')
  fi

  local min_ram_mb=384
  if [ "$mem_mb" -ge "$min_ram_mb" ]; then
    log_pass "RAM check passed: ${mem_mb}MB RAM available (required >= ${min_ram_mb}MB)."
    return 0
  else
    if [ "$FORCE" = true ]; then
      log_warn "Low RAM: ${mem_mb}MB available (< ${min_ram_mb}MB). Continuing due to --force."
      return 0
    else
      log_fail "Insufficient RAM: ${mem_mb}MB available. Minimum required is ${min_ram_mb}MB."
      return 1
    fi
  fi
}

# --- 3. Disk Space Inspection (df >= 1GB) ---
check_disk_space() {
  log_info "Inspecting available disk space with df..."
  local check_path="$INSTALL_DIR"
  while [ ! -d "$check_path" ] && [ "$check_path" != "/" ]; do
    check_path="$(dirname "$check_path")"
  done

  local avail_kb
  avail_kb=$(df -k "$check_path" 2>/dev/null | awk 'NR==2 {print $(NF-2)}')
  if [ -z "$avail_kb" ] || ! [[ "$avail_kb" =~ ^[0-9]+$ ]]; then
    avail_kb=$(df -P "$check_path" 2>/dev/null | awk 'NR==2 {print $4}')
  fi

  local avail_mb=$((avail_kb / 1024))
  local min_disk_mb=1024 # 1 GB

  if [ "$avail_mb" -ge "$min_disk_mb" ]; then
    log_pass "Disk space check passed: ${avail_mb}MB available in $check_path (required >= ${min_disk_mb}MB / 1GB)."
    return 0
  else
    if [ "$FORCE" = true ]; then
      log_warn "Low disk space: ${avail_mb}MB available in $check_path (< ${min_disk_mb}MB). Continuing due to --force."
      return 0
    else
      log_fail "Insufficient disk space: ${avail_mb}MB available in $check_path. Minimum required is ${min_disk_mb}MB (1GB)."
      return 1
    fi
  fi
}

# --- 4. Port Collision Probing (5050, 80, 443) ---
probe_port() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -tuln 2>/dev/null | grep -E -q "[:.]$port[[:space:]]" && return 0
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tuln 2>/dev/null | grep -E -q "[:.]$port[[:space:]]" && return 0
  elif command -v lsof >/dev/null 2>&1; then
    lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 && return 0
  else
    (exec 3<>/dev/tcp/127.0.0.1/"$port") 2>/dev/null && { exec 3>&-; return 0; }
  fi
  return 1
}

check_ports() {
  log_info "Probing network ports: $PORT (App), 80 (HTTP), 443 (HTTPS)..."

  # Probe App Port (default 5050)
  if probe_port "$PORT"; then
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet mydoor 2>/dev/null; then
      log_warn "Port $PORT is currently held by active mydoor service (upgrade/reinstall detected)."
    else
      log_warn "Port $PORT is currently in use by another process. Use --port <PORT> to override."
      if [ "$DRY_RUN" = false ] && [ "$FORCE" = false ]; then
        log_fail "Port collision detected on port $PORT (default 5050)."
        return 1
      fi
    fi
  else
    log_pass "Port $PORT (default 5050) is free and ready for binding."
  fi

  # Probe Port 80
  if probe_port 80; then
    log_info "Port 80 is occupied (standard for existing Nginx/web server)."
  else
    log_pass "Port 80 is free."
  fi

  # Probe Port 443
  if probe_port 443; then
    log_info "Port 443 is occupied (standard for SSL/TLS reverse proxy)."
  else
    log_pass "Port 443 is free."
  fi

  return 0
}

# --- 5. Dependency Validation & Broken Nginx Check ---
check_dependencies() {
  log_info "Verifying required binary and package dependencies..."
  local missing=()

  # Python 3 >= 3.8
  if command -v python3 >/dev/null 2>&1; then
    local py_ok
    py_ok=$(python3 -c 'import sys; print("OK" if sys.version_info >= (3, 8) else "FAIL")' 2>/dev/null || echo "FAIL")
    if [ "$py_ok" = "OK" ]; then
      local py_ver
      py_ver=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")' 2>/dev/null || echo "3.x")
      log_pass "Python $py_ver detected (meets requirement >= 3.8)."
    else
      log_fail "Installed python3 is below requirement (>= 3.8)."
      missing+=("python3 (>= 3.8)")
    fi
  else
    log_fail "python3 is not installed."
    missing+=("python3")
  fi

  # python3-venv module
  if python3 -m venv --help >/dev/null 2>&1; then
    log_pass "python3 venv module is available."
  else
    log_fail "python3-venv module is missing."
    missing+=("python3-venv")
  fi

  # systemd / systemctl
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    log_pass "systemd is active and systemctl is available."
  else
    if [ "$DRY_RUN" = true ] || [ "$(uname -s)" = "Darwin" ]; then
      log_warn "systemd daemon not active (simulated in dry-run/Darwin/container)."
    else
      log_fail "systemd is not running. Production service installation requires systemd."
      missing+=("systemd")
    fi
  fi

  # curl
  if command -v curl >/dev/null 2>&1; then
    log_pass "curl is available."
  else
    log_fail "curl is missing."
    missing+=("curl")
  fi

  # openssl
  if command -v openssl >/dev/null 2>&1; then
    log_pass "openssl is available."
  else
    log_fail "openssl is missing."
    missing+=("openssl")
  fi

  # Pre-existing broken Nginx check
  if command -v nginx >/dev/null 2>&1; then
    log_info "Testing host Nginx syntax prior to configuration (nginx -t)..."
    if ! nginx -t >/dev/null 2>&1; then
      log_fail "Host Nginx configuration test (nginx -t) failed BEFORE mydoor modification!"
      log_fail "Refusing to proceed to protect existing host VPS services. Repair /etc/nginx first."
      if [ "$DRY_RUN" = false ]; then
        exit 1
      fi
    else
      log_pass "Host Nginx syntax test clean."
    fi
  fi

  if [ ${#missing[@]} -gt 0 ]; then
    log_fail "Missing mandatory dependencies: ${missing[*]}"
    echo "" >&2
    echo "Install dependencies on Debian/Ubuntu with:" >&2
    echo "  sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip curl openssl systemd" >&2
    echo "" >&2
    return 1
  fi

  return 0
}

# ==============================================================================
# Host Mutation Stages (With Transactional LIFO Rollback)
# ==============================================================================

# --- Stage 1: Dedicated Unprivileged User & Group ---
create_user_and_group() {
  log_info "Configuring isolated system user and group ($DEFAULT_USER:$DEFAULT_GROUP)..."

  if ! getent group "$DEFAULT_GROUP" >/dev/null 2>&1; then
    groupadd --system "$DEFAULT_GROUP" 2>/dev/null || true
    rollback_push "groupdel $DEFAULT_GROUP 2>/dev/null || true"
  else
    log_info "System group $DEFAULT_GROUP already exists."
  fi

  if ! id -u "$DEFAULT_USER" >/dev/null 2>&1; then
    useradd --system --shell /usr/sbin/nologin --gid "$DEFAULT_GROUP" --home-dir "$INSTALL_DIR" --no-create-home "$DEFAULT_USER" 2>/dev/null || \
    useradd -r -s /usr/sbin/nologin -g "$DEFAULT_GROUP" -d "$INSTALL_DIR" -M "$DEFAULT_USER" 2>/dev/null || \
    useradd --system --shell /bin/false --gid "$DEFAULT_GROUP" --home-dir "$INSTALL_DIR" --no-create-home "$DEFAULT_USER"
    rollback_push "userdel $DEFAULT_USER 2>/dev/null || true"
  else
    log_info "System user $DEFAULT_USER already exists."
  fi

  log_pass "User isolation configured ($DEFAULT_USER:$DEFAULT_GROUP)."
}

# --- Stage 2: Sandboxed Installation Directory ---
setup_install_directory() {
  log_info "Configuring installation directory ($INSTALL_DIR)..."
  if [ ! -d "$INSTALL_DIR" ]; then
    mkdir -p "$INSTALL_DIR"
    rollback_push "rm -rf \"$INSTALL_DIR\""
  else
    log_info "Directory $INSTALL_DIR already exists."
  fi

  chmod 0750 "$INSTALL_DIR"
  chown "$DEFAULT_USER:$DEFAULT_GROUP" "$INSTALL_DIR" 2>/dev/null || true
  log_pass "Installation directory permissions set to 0750 ($DEFAULT_USER:$DEFAULT_GROUP)."
}

# --- Stage 3: Project Files Deployment ---
copy_project_files() {
  log_info "Deploying project files to $INSTALL_DIR..."
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  local repo_dir
  repo_dir="$(cd "${script_dir}/.." && pwd)"

  if [ "$repo_dir" = "$INSTALL_DIR" ]; then
    log_info "Current repository is already in $INSTALL_DIR; skipping file copy."
    return 0
  fi

  for dir in client server custom_components geek_door_addon templates; do
    if [ -d "$repo_dir/$dir" ]; then
      cp -r "$repo_dir/$dir" "$INSTALL_DIR/"
    fi
  done

  for file in door_lock_control.py requirements.txt hacs.json repository.json docker-compose.yml README.md; do
    if [ -f "$repo_dir/$file" ]; then
      cp -p "$repo_dir/$file" "$INSTALL_DIR/"
    fi
  done

  find "$INSTALL_DIR" -maxdepth 3 -type d -exec chmod 0750 {} + 2>/dev/null || true
  find "$INSTALL_DIR" -maxdepth 3 -type f -exec chmod 0640 {} + 2>/dev/null || true
  chmod 0750 "$INSTALL_DIR/door_lock_control.py" 2>/dev/null || true
  chown -R "$DEFAULT_USER:$DEFAULT_GROUP" "$INSTALL_DIR" 2>/dev/null || true
  log_pass "Project files staged with secure permissions (0750 dirs, 0640 files)."
}

# --- Stage 4: Virtualenv Setup & Requirements ---
setup_virtualenv() {
  log_info "Creating isolated Python virtual environment ($INSTALL_DIR/venv)..."

  if [ -d "$INSTALL_DIR/venv" ]; then
    cp -rp "$INSTALL_DIR/venv" "$INSTALL_DIR/venv.install_backup.$$" 2>/dev/null || true
    rollback_push "rm -rf \"$INSTALL_DIR/venv\"; mv \"$INSTALL_DIR/venv.install_backup.$$\" \"$INSTALL_DIR/venv\" 2>/dev/null || true"
  else
    rollback_push "rm -rf \"$INSTALL_DIR/venv\""
  fi

  python3 -m venv "$INSTALL_DIR/venv"
  "$INSTALL_DIR/venv/bin/pip" install --upgrade pip >/dev/null 2>&1 || true

  if [ -f "$INSTALL_DIR/requirements.txt" ]; then
    log_info "Installing Python dependencies from requirements.txt..."
    "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
  fi

  chown -R "$DEFAULT_USER:$DEFAULT_GROUP" "$INSTALL_DIR/venv" 2>/dev/null || true
  log_pass "Virtual environment created and dependencies installed."
}

# --- Stage 5: Environment File Configuration ---
configure_env() {
  log_info "Configuring environment file ($INSTALL_DIR/.env)..."
  local env_file="$INSTALL_DIR/.env"

  if [ -f "$env_file" ]; then
    log_info "Existing .env file detected; preserving existing configuration and secrets."
    cp -p "$env_file" "${env_file}.install_backup.$$"
    rollback_push "mv -f \"${env_file}.install_backup.$$\" \"$env_file\""
  else
    rollback_push "rm -f \"$env_file\""
    local secret_key
    if command -v openssl >/dev/null 2>&1; then
      secret_key=$(openssl rand -hex 32)
    else
      secret_key=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || openssl rand -hex 32)
    fi

    cat <<EOF > "$env_file"
# mydoor Production Environment Configuration
# Auto-generated by scripts/install.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
PORT=${PORT}
HOST=127.0.0.1
GEEK_DOOR_BIND_IP=127.0.0.1
SECRET_KEY=${secret_key}
EOF
  fi

  chmod 0600 "$env_file"
  chown "$DEFAULT_USER:$DEFAULT_GROUP" "$env_file" 2>/dev/null || true
  log_pass "Environment configuration secured with mode 0600."
}

# --- Stage 6: Hardened Sandboxed Systemd Service Unit ---
install_systemd_service() {
  log_info "Generating hardened sandboxed systemd service unit..."
  local unit_path="/etc/systemd/system/mydoor.service"

  if [ -f "$unit_path" ]; then
    cp -p "$unit_path" "${unit_path}.install_backup.$$"
    rollback_push "mv -f \"${unit_path}.install_backup.$$\" \"$unit_path\"; systemctl daemon-reload 2>/dev/null || true"
  else
    rollback_push "rm -f \"$unit_path\"; systemctl daemon-reload 2>/dev/null || true"
  fi

  cat <<'EOF' > "$unit_path"
[Unit]
Description=GeekSmart Door Lock Control & Discovery Service
After=network.target

[Service]
Type=simple
User=geekdoor
Group=geekdoor
WorkingDirectory=/opt/mydoor
ExecStart=/opt/mydoor/venv/bin/python3 -m server.flask_app
Restart=always
RestartSec=5

# Security Sandboxing Directives (Requirement R2 / INST.05)
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelLogs=true
RestrictRealtime=true
RestrictSUIDSGID=true
RemoveIPC=true
LockPersonality=true
CapabilityBoundingSet=
LimitNOFILE=65536
ReadWritePaths=/opt/mydoor /var/backups/mydoor-nginx

[Install]
WantedBy=multi-user.target
EOF

  # If custom INSTALL_DIR was chosen, adjust WorkingDirectory, ExecStart, and ReadWritePaths
  if [ "$INSTALL_DIR" != "/opt/mydoor" ]; then
    sed -i "s|/opt/mydoor/venv/bin/python3|${INSTALL_DIR}/venv/bin/python3|g" "$unit_path" 2>/dev/null || true
    sed -i "s|WorkingDirectory=/opt/mydoor|WorkingDirectory=${INSTALL_DIR}|g" "$unit_path" 2>/dev/null || true
    sed -i "s|ReadWritePaths=/opt/mydoor|ReadWritePaths=${INSTALL_DIR}|g" "$unit_path" 2>/dev/null || true
  fi

  chmod 0644 "$unit_path"
  log_pass "Hardened systemd unit written to $unit_path."

  # Verify unit syntax if systemd-analyze is present
  if command -v systemd-analyze >/dev/null 2>&1; then
    log_info "Verifying systemd unit syntax with systemd-analyze verify..."
    if systemd-analyze verify "$unit_path" >/dev/null 2>&1; then
      log_pass "systemd-analyze verification passed cleanly."
    else
      log_warn "systemd-analyze reported unit warnings (non-fatal)."
    fi
  fi

  # Reload daemon and enable service if systemd is active
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable --now mydoor.service
    rollback_push "systemctl disable --now mydoor.service 2>/dev/null || true"
    log_pass "mydoor.service enabled and started via systemd."
  else
    log_warn "systemd daemon is not active in this environment. Unit file installed at $unit_path."
  fi
}

# --- Stage 7: Observational Health Check (Zero Deadbolt Actuation) ---
verify_service_health() {
  if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
    log_info "Skipping HTTP health probe because systemd is not active in this environment."
    return 0
  fi

  log_info "Awaiting service startup and probing read-only health endpoint..."
  local health_url="http://127.0.0.1:${PORT}/api/health"
  local attempts=0
  local max_attempts=15
  local healthy=false

  while [ "$attempts" -lt "$max_attempts" ]; do
    attempts=$((attempts + 1))
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "$health_url" 2>/dev/null || echo "000")
    if [ "$http_code" = "200" ]; then
      healthy=true
      break
    fi
    sleep 1
  done

  if [ "$healthy" = true ]; then
    log_pass "Service health check passed: $health_url returned HTTP 200."
  else
    log_warn "Service did not respond with HTTP 200 within ${max_attempts}s. Check: journalctl -u mydoor -n 50"
  fi
}

# --- Stage 8: Safe Nginx & Certbot SSL Integration ---
setup_nginx_proxy() {
  if [ "$NO_NGINX" = true ] || [ -z "$DOMAIN" ]; then
    return 0
  fi

  log_info "Configuring Nginx reverse proxy for domain: $DOMAIN..."
  local python_runner="$INSTALL_DIR/venv/bin/python3"
  if [ ! -x "$python_runner" ]; then
    python_runner="python3"
  fi

  export PYTHONPATH="${INSTALL_DIR}:${PYTHONPATH:-}"

  local nginx_output
  nginx_output=$("$python_runner" -m server.nginx_manager --apply --domain "$DOMAIN" --port "$PORT" 2>&1)
  local nginx_status=$?

  if [ $nginx_status -ne 0 ]; then
    log_fail "NginxManager configuration failed: $nginx_output"
    return 1
  fi

  local backup_id
  backup_id=$(echo "$nginx_output" | grep -o 'backup_[a-zA-Z0-9_]*' | head -n 1 || true)
  if [ -n "$backup_id" ]; then
    log_pass "Staged and applied Nginx reverse proxy. Backup created: $backup_id"
    rollback_push "\"$python_runner\" -m server.nginx_manager --restore \"$backup_id\""
  fi

  # Certbot SSL with DNS Pre-Flight Shield
  if command -v certbot >/dev/null 2>&1; then
    log_info "Checking DNS resolution for $DOMAIN before requesting SSL certificate..."
    local host_public_ip
    host_public_ip=$(curl -s -4 --max-time 5 https://ifconfig.me 2>/dev/null || curl -s -4 --max-time 5 https://api.ipify.org 2>/dev/null || true)
    local resolved_ips
    resolved_ips=$(getent ahosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u || true)
    if [ -z "$resolved_ips" ] && command -v host >/dev/null 2>&1; then
      resolved_ips=$(host -t A "$DOMAIN" 2>/dev/null | awk '/has address/ {print $NF}' | sort -u || true)
    fi

    local dns_valid=false
    if [ -n "$host_public_ip" ] && [ -n "$resolved_ips" ]; then
      if echo "$resolved_ips" | grep -q -F "$host_public_ip"; then
        dns_valid=true
      fi
    fi

    if [ "$dns_valid" = true ]; then
      log_pass "DNS verified: $DOMAIN points to host public IP ($host_public_ip)."
      log_info "Requesting Let's Encrypt SSL certificate via webroot challenge..."
      mkdir -p /var/www/letsencrypt
      chmod 0755 /var/www/letsencrypt

      local email_arg=("--register-unsafely-without-email")
      if [ -n "${EMAIL:-}" ]; then
        email_arg=("--email" "$EMAIL")
      fi

      if certbot certonly --webroot -w /var/www/letsencrypt -d "$DOMAIN" --non-interactive --agree-tos "${email_arg[@]}" --deploy-hook "systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null || true"; then
        log_pass "SSL certificate issued. Upgrading Nginx reverse proxy to HTTPS..."
        local ssl_output
        ssl_output=$("$python_runner" -m server.nginx_manager --apply --domain "$DOMAIN" --port "$PORT" --ssl 2>&1)
        local ssl_backup_id
        ssl_backup_id=$(echo "$ssl_output" | grep -o 'backup_[a-zA-Z0-9_]*' | head -n 1 || true)
        if [ -n "$ssl_backup_id" ]; then
          rollback_push "\"$python_runner\" -m server.nginx_manager --restore \"$ssl_backup_id\""
        fi
        log_pass "HTTPS reverse proxy successfully configured with SSL."
      else
        log_warn "Certbot SSL issuance failed. Preserving working HTTP reverse proxy."
      fi
    else
      log_warn "DNS check: $DOMAIN does not yet resolve to host public IP (${host_public_ip:-unknown})."
      log_warn "Skipping automated Certbot SSL to prevent Let's Encrypt rate limit lockouts (5 failures/hour)."
      log_info "HTTP reverse proxy is active. You can issue SSL certificates via Setup Wizard once DNS propagates."
    fi
  else
    log_info "Certbot is not installed. HTTP reverse proxy is active."
  fi

  return 0
}

# ==============================================================================
# Main Orchestration Flow
# ==============================================================================
main() {
  parse_arguments "$@"

  # Handle standalone Nginx restore if requested
  if [ "$RESTORE_NGINX" = true ]; then
    handle_nginx_restore
  fi

  # Validate root privileges (bypassed in dry-run mode)
  validate_privileges

  echo "================================================================="
  echo " GeekSmart / mydoor Failsafe Production Installer (Milestone 10)"
  echo "================================================================="

  # Pre-Flight Host Inspection Matrix
  check_os
  check_memory
  check_disk_space
  check_ports
  check_dependencies

  # Dry-run termination after pre-flight inspections
  if [ "$DRY_RUN" = true ]; then
    echo ""
    log_dryrun "=== PRE-FLIGHT HOST INSPECTIONS COMPLETED CLEANLY ==="
    log_dryrun "Target Directory:   ${INSTALL_DIR} (Permissions: 0750, User: ${DEFAULT_USER}:${DEFAULT_GROUP})"
    log_dryrun "Backend Web Port:   ${PORT}"
    if [ -n "$DOMAIN" ] && [ "$NO_NGINX" = false ]; then
      log_dryrun "Nginx Reverse Proxy: ${DOMAIN} -> http://127.0.0.1:${PORT}"
    fi
    log_dryrun "Systemd Unit:       /etc/systemd/system/mydoor.service (Hardened Sandbox)"
    log_dryrun "DRY-RUN SIMULATION COMPLETE: Zero host modifications were made."
    INSTALL_SUCCESS=1
    exit 0
  fi

  # Execute Host Mutation Stages
  create_user_and_group
  setup_install_directory
  copy_project_files
  setup_virtualenv
  configure_env
  install_systemd_service
  verify_service_health
  setup_nginx_proxy

  # Mark success and disable rollback trap
  INSTALL_SUCCESS=1
  ROLLBACK_STACK=()
  trap - EXIT ERR INT TERM

  echo ""
  log_pass "================================================================="
  log_pass " GeekSmart / mydoor installation completed successfully!"
  log_pass "================================================================="
  log_info " Service:       mydoor.service (systemd)"
  log_info " Local URL:     http://127.0.0.1:${PORT}"
  if [ -n "$DOMAIN" ] && [ "$NO_NGINX" = false ]; then
    log_info " Public Domain: http://${DOMAIN} (or https://${DOMAIN})"
  fi
  log_info " Install Dir:   ${INSTALL_DIR}"
  log_info " User Isolation: ${DEFAULT_USER}:${DEFAULT_GROUP} (mode 0750)"
  log_info " Service Status: sudo systemctl status mydoor"
  log_info " View Logs:     sudo journalctl -u mydoor -f"
  log_info " Restore Nginx: sudo $0 --restore-nginx"
  log_pass "================================================================="
  exit 0
}

main "$@"
