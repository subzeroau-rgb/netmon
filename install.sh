#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Network Monitor — Installation Script
# Installs and configures all prerequisites, database, application and nginx
# Ubuntu 20.04 / 22.04 / 24.04
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

print_header() { echo -e "\n${CYAN}${BOLD}══ $1 ══${NC}"; }
print_ok()     { echo -e "${GREEN}  ✓${NC} $1"; }
print_warn()   { echo -e "${YELLOW}  ⚠${NC}  $1"; }
print_err()    { echo -e "${RED}  ✗${NC} $1" >&2; }
print_info()   { echo -e "  ${CYAN}→${NC} $1"; }
print_note()   { echo -e "  ${DIM}$1${NC}"; }

die() { print_err "$1"; exit 1; }

# ── Must run as root ──────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "This script must be run as root: sudo bash install.sh"

# ── OS check ─────────────────────────────────────────────────────────────────
if [[ ! -f /etc/os-release ]]; then
  die "Cannot detect OS. This script supports Ubuntu 20.04 / 22.04 / 24.04."
fi
source /etc/os-release
if [[ "$ID" != "ubuntu" ]]; then
  print_warn "This script was written for Ubuntu. Detected: $PRETTY_NAME"
  echo -ne "  Continue anyway? (y/N): "
  read -r CONTINUE_ANYWAY
  [[ "$CONTINUE_ANYWAY" =~ ^[Yy]$ ]] || exit 0
fi

# ══════════════════════════════════════════════════════════════════════════════
# BANNER
# ══════════════════════════════════════════════════════════════════════════════
clear
echo -e "${CYAN}${BOLD}"
echo "  ███╗   ██╗███████╗████████╗███╗   ███╗ ██████╗ ███╗   ██╗"
echo "  ████╗  ██║██╔════╝╚══██╔══╝████╗ ████║██╔═══██╗████╗  ██║"
echo "  ██╔██╗ ██║█████╗     ██║   ██╔████╔██║██║   ██║██╔██╗ ██║"
echo "  ██║╚██╗██║██╔══╝     ██║   ██║╚██╔╝██║██║   ██║██║╚██╗██║"
echo "  ██║ ╚████║███████╗   ██║   ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║"
echo "  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝"
echo -e "${NC}"
echo -e "  ${BOLD}Network Monitor — Installation Script${NC}"
echo -e "  ${DIM}Aruba CX + MikroTik monitoring platform${NC}"
echo
echo -e "  Installs and configures:"
echo    "    • Node.js 20.x"
echo    "    • MySQL Server"
echo    "    • Nginx (HTTPS reverse proxy with self-signed certificate)"
echo    "    • Network Monitor application"
echo    "    • Dedicated service account"
echo    "    • Systemd service"
echo
echo -e "  ${YELLOW}Press ENTER to begin or Ctrl+C to abort${NC}"
read -r

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

# prompt_default VAR "Question" "default"
# Prints "[default]" hint, uses default if user presses ENTER
prompt_default() {
  local __var="$1" __prompt="$2" __default="$3"
  echo -ne "  ${BOLD}${__prompt}${NC} ${DIM}[${__default}]${NC}: "
  read -r __val
  printf -v "$__var" '%s' "${__val:-$__default}"
}

# prompt_required VAR "Question"
# Loops until a non-empty value is entered
prompt_required() {
  local __var="$1" __prompt="$2" __val=""
  while [[ -z "$__val" ]]; do
    echo -ne "  ${BOLD}${__prompt}${NC}: "
    read -r __val
    [[ -z "$__val" ]] && print_warn "This field is required"
  done
  printf -v "$__var" '%s' "$__val"
}

# prompt_password VAR "Label" [min_length]
# Prompts twice and validates match and minimum length
prompt_password() {
  local __var="$1" __label="$2" __min="${3:-1}" __a="" __b=""
  while true; do
    echo -ne "  ${BOLD}${__label}${NC}: "
    read -rs __a; echo
    if [[ ${#__a} -lt $__min ]]; then
      print_warn "Password must be at least ${__min} characters"; continue
    fi
    echo -ne "  ${BOLD}Confirm ${__label}${NC}: "
    read -rs __b; echo
    if [[ "$__a" != "$__b" ]]; then
      print_warn "Passwords do not match, try again"; continue
    fi
    break
  done
  printf -v "$__var" '%s' "$__a"
}

# prompt_optional_password VAR "Label"
# Like prompt_password but allows empty (press ENTER twice to skip)
prompt_optional_password() {
  local __var="$1" __label="$2" __a="" __b=""
  while true; do
    echo -ne "  ${BOLD}${__label}${NC} ${DIM}(ENTER to skip)${NC}: "
    read -rs __a; echo
    if [[ -z "$__a" ]]; then printf -v "$__var" '%s' ""; return; fi
    echo -ne "  ${BOLD}Confirm ${__label}${NC}: "
    read -rs __b; echo
    [[ "$__a" == "$__b" ]] && break
    print_warn "Passwords do not match, try again"
  done
  printf -v "$__var" '%s' "$__a"
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — COLLECT CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════
print_header "Configuration"

# ─────────────────────────────────────────────────────────────────────────────
# 1a. Service account
# FHS / Linux convention: system services run as a dedicated system account
# with no login shell, no home directory in /home, no password.
# Default: netmon  (uid < 1000, shell=/usr/sbin/nologin)
# ─────────────────────────────────────────────────────────────────────────────
echo
echo -e "  ${BOLD}Service account${NC}"
echo -e "  ${DIM}The application runs as a dedicated system account (no login shell, no"
echo -e "  password). A new system account will be created if it doesn't exist.${NC}"
prompt_default SVC_USER "Service account username" "netmon"

# Validate: must be a valid unix username
if [[ ! "$SVC_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
  die "Invalid username '${SVC_USER}'. Must start with a letter or underscore and contain only lowercase letters, numbers, hyphens or underscores."
fi

# ─────────────────────────────────────────────────────────────────────────────
# 1b. File system layout
#
# FHS (Filesystem Hierarchy Standard) conventions:
#   /opt/<package>        — self-contained third-party packages (our choice)
#   /usr/local/           — locally compiled/installed software
#   /srv/<service>        — service data (e.g. /srv/netmon)
#   /var/lib/<service>    — persistent application state
#
# We default to /opt/netmon which is the most common convention for
# self-contained applications distributed outside the distro package manager.
# The application code goes in /opt/netmon, runtime data (exports, backups,
# logs) stays within the same tree for simplicity.
# ─────────────────────────────────────────────────────────────────────────────
echo
echo -e "  ${BOLD}Installation directory${NC}"
echo -e "  ${DIM}FHS convention for self-contained third-party applications is /opt/<name>."
echo -e "  The application will be installed to the directory you specify.${NC}"
prompt_default INSTALL_DIR "Application directory" "/opt/netmon"

BACKEND_DIR="${INSTALL_DIR}/backend"
FRONTEND_DIR="${INSTALL_DIR}/frontend"

echo
echo -e "  ${BOLD}Data directories${NC}"
echo -e "  ${DIM}Runtime data (exports, backups, logs) is stored separately from the"
echo -e "  application code. /var/lib is the FHS standard for persistent app data.${NC}"
prompt_default DATA_DIR   "Data directory (exports, backups)" "/var/lib/netmon"
prompt_default LOG_DIR    "Log directory" "/var/log/netmon"

# ─────────────────────────────────────────────────────────────────────────────
# 1c. Application port
# ─────────────────────────────────────────────────────────────────────────────
echo
echo -e "  ${BOLD}Application port${NC}"
echo -e "  ${DIM}Internal port Node.js listens on. Not exposed externally — nginx proxies to it.${NC}"
prompt_default APP_PORT "Internal port" "3001"
if ! [[ "$APP_PORT" =~ ^[0-9]+$ ]] || [[ "$APP_PORT" -lt 1024 ]] || [[ "$APP_PORT" -gt 65535 ]]; then
  die "Port must be a number between 1024 and 65535"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 1d. Network / nginx
# ─────────────────────────────────────────────────────────────────────────────
echo
echo -e "  ${BOLD}Network access${NC}"
echo -e "  ${DIM}Used as the nginx server_name and SSL certificate CN."
echo -e "  Can be an IP address or a DNS hostname (e.g. netmon.lan).${NC}"
DETECTED_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || hostname -I | awk '{print $1}' || echo "")
prompt_default SERVER_HOST "Server IP or hostname" "${DETECTED_IP:-$(hostname -f)}"

# ─────────────────────────────────────────────────────────────────────────────
# 1e. MySQL database
# ─────────────────────────────────────────────────────────────────────────────
echo
echo -e "  ${BOLD}MySQL database${NC}"
echo -e "  ${DIM}A dedicated database and user will be created for the application.${NC}"
prompt_default DB_NAME "Database name"          "aruba_monitor"
prompt_default DB_USER "Database username"      "netmon"
prompt_password DB_PASS "Database user password"

echo
echo -e "  ${BOLD}MySQL root access${NC}"
echo -e "  ${DIM}Required only for initial database and user creation."
echo -e "  On a fresh MySQL install, root typically has no password — press ENTER to try.${NC}"
prompt_optional_password MYSQL_ROOT_PASS "MySQL root password"

# ─────────────────────────────────────────────────────────────────────────────
# 1f. Application admin account
# ─────────────────────────────────────────────────────────────────────────────
echo
echo -e "  ${BOLD}Application admin account${NC}"
echo -e "  ${DIM}Initial administrator login for the web interface.${NC}"
prompt_default ADMIN_USER "Admin username" "admin"
prompt_password ADMIN_PASS "Admin password (min 15 characters)" 15

# Generate session secret
SESSION_SECRET=$(openssl rand -hex 32)

# ─────────────────────────────────────────────────────────────────────────────
# 1g. Summary
# ─────────────────────────────────────────────────────────────────────────────
echo
echo -e "  ${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}Installation summary${NC}"
echo -e "  ${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo
echo -e "  ${DIM}System${NC}"
echo -e "    Service account   : ${CYAN}${SVC_USER}${NC} ${DIM}(system account, no login shell)${NC}"
echo -e "    Application dir   : ${CYAN}${INSTALL_DIR}${NC}"
echo -e "    Data dir          : ${CYAN}${DATA_DIR}${NC}"
echo -e "    Log dir           : ${CYAN}${LOG_DIR}${NC}"
echo -e "    Internal port     : ${CYAN}${APP_PORT}${NC}"
echo
echo -e "  ${DIM}Network${NC}"
echo -e "    Server host       : ${CYAN}${SERVER_HOST}${NC}"
echo -e "    Access URL        : ${CYAN}https://${SERVER_HOST}${NC}"
echo -e "    SSL cert          : ${CYAN}/etc/ssl/certs/netmon.crt${NC} ${DIM}(self-signed, 10yr)${NC}"
echo
echo -e "  ${DIM}Database${NC}"
echo -e "    Database name     : ${CYAN}${DB_NAME}${NC}"
echo -e "    Database user     : ${CYAN}${DB_USER}@localhost${NC}"
echo
echo -e "  ${DIM}Application${NC}"
echo -e "    Admin username    : ${CYAN}${ADMIN_USER}${NC}"
echo
echo -e "  ${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo
echo -ne "  ${YELLOW}Proceed with installation? (y/N)${NC}: "
read -r CONFIRM
[[ "$CONFIRM" =~ ^[Yy]$ ]] || { echo "Installation aborted."; exit 0; }

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — SYSTEM PACKAGES
# ══════════════════════════════════════════════════════════════════════════════
print_header "Installing system packages"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
print_ok "Package lists updated"

apt-get install -y -qq curl gnupg2 ca-certificates lsb-release openssl ufw \
  mysql-server nginx
print_ok "Base packages installed (mysql-server, nginx, openssl, ufw)"

# Node.js 20.x — install via NodeSource if not present or too old
if ! command -v node &>/dev/null || \
   [[ $(node --version | cut -d. -f1 | tr -d 'v') -lt 18 ]]; then
  print_info "Installing Node.js 20.x via NodeSource..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
  apt-get install -y -qq nodejs
  print_ok "Node.js $(node --version) installed"
else
  print_ok "Node.js $(node --version) already installed (meets ≥18 requirement)"
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — SERVICE ACCOUNT
# FHS / security best practice:
#   --system       uid < 1000, no aging, locked password
#   --no-create-home  no /home/<user> entry
#   --home-dir     set to application dir (created later)
#   --shell /usr/sbin/nologin  prevents interactive login entirely
# ══════════════════════════════════════════════════════════════════════════════
print_header "Service account"

if id "$SVC_USER" &>/dev/null; then
  # Existing account — verify it is a system account
  SVC_UID=$(id -u "$SVC_USER")
  if [[ $SVC_UID -ge 1000 ]]; then
    print_warn "User '${SVC_USER}' exists but is a regular user account (uid=${SVC_UID})."
    print_warn "For security, the application should run as a system account (uid < 1000)."
    echo -ne "  Continue using this account anyway? (y/N): "
    read -r USE_EXISTING
    [[ "$USE_EXISTING" =~ ^[Yy]$ ]] || die "Aborted. Choose a different service account name and re-run."
    print_warn "Proceeding with regular user account '${SVC_USER}'"
  else
    print_ok "System account '${SVC_USER}' (uid=${SVC_UID}) already exists"
  fi
else
  # Create new system account
  useradd \
    --system \
    --no-create-home \
    --home-dir "${INSTALL_DIR}" \
    --shell /usr/sbin/nologin \
    --comment "Network Monitor service account" \
    "$SVC_USER"
  SVC_UID=$(id -u "$SVC_USER")
  print_ok "Created system account '${SVC_USER}' (uid=${SVC_UID}, shell=nologin, no home dir)"
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — DIRECTORY STRUCTURE
# FHS layout:
#   /opt/netmon/          — application code (read-only at runtime)
#     backend/            — Node.js server
#     frontend/           — static HTML
#   /var/lib/netmon/      — persistent runtime data (writable by service account)
#     exports/            — CSV exports
#     backups/            — config backups
#   /var/log/netmon/      — application logs
# ══════════════════════════════════════════════════════════════════════════════
print_header "Creating directory structure"

# Application directories (owned by root, readable by service account)
mkdir -p "${BACKEND_DIR}" "${FRONTEND_DIR}"
chown -R root:root "${INSTALL_DIR}"
chmod 755 "${INSTALL_DIR}" "${BACKEND_DIR}" "${FRONTEND_DIR}"
print_ok "${INSTALL_DIR}/ (owner: root, mode: 755)"

# Data directory (writable by service account)
mkdir -p "${DATA_DIR}"/{exports,backups}
chown -R "${SVC_USER}:${SVC_USER}" "${DATA_DIR}"
chmod 750 "${DATA_DIR}"
print_ok "${DATA_DIR}/ (owner: ${SVC_USER}, mode: 750)"

# Log directory (writable by service account)
mkdir -p "${LOG_DIR}"
chown -R "${SVC_USER}:${SVC_USER}" "${LOG_DIR}"
chmod 750 "${LOG_DIR}"
print_ok "${LOG_DIR}/ (owner: ${SVC_USER}, mode: 750)"

# ── Copy application files ────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ -f "${SCRIPT_DIR}/server.js"    ]] || die "server.js not found in ${SCRIPT_DIR}"
[[ -f "${SCRIPT_DIR}/package.json" ]] || die "package.json not found in ${SCRIPT_DIR}"
[[ -f "${SCRIPT_DIR}/reset-admin.js" ]] || die "reset-admin.js not found in ${SCRIPT_DIR}"

if [[ -f "${SCRIPT_DIR}/index.html" ]]; then
  cp "${SCRIPT_DIR}/index.html" "${FRONTEND_DIR}/index.html"
elif [[ -f "${SCRIPT_DIR}/frontend/index.html" ]]; then
  cp "${SCRIPT_DIR}/frontend/index.html" "${FRONTEND_DIR}/index.html"
else
  die "index.html not found in ${SCRIPT_DIR} or ${SCRIPT_DIR}/frontend/"
fi

cp "${SCRIPT_DIR}/server.js"      "${BACKEND_DIR}/server.js"
cp "${SCRIPT_DIR}/package.json"   "${BACKEND_DIR}/package.json"
cp "${SCRIPT_DIR}/reset-admin.js" "${BACKEND_DIR}/reset-admin.js"

# Application files owned by root (immutable to service account)
chown -R root:root "${INSTALL_DIR}"
chmod 644 "${BACKEND_DIR}/server.js" "${BACKEND_DIR}/package.json" \
           "${BACKEND_DIR}/reset-admin.js" "${FRONTEND_DIR}/index.html"
chmod 755 "${BACKEND_DIR}" "${FRONTEND_DIR}"
print_ok "Application files copied and permissions set"

# ── Symlink data dirs so the app can use relative paths ──────────────────────
ln -sfn "${DATA_DIR}/exports" "${BACKEND_DIR}/exports"
ln -sfn "${DATA_DIR}/backups" "${BACKEND_DIR}/backups"
ln -sfn "${LOG_DIR}"          "${BACKEND_DIR}/logs"
print_ok "Symlinks created (exports → ${DATA_DIR}/exports, backups → ${DATA_DIR}/backups)"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — NPM DEPENDENCIES
# Install as root, but chown node_modules to service account afterward
# ══════════════════════════════════════════════════════════════════════════════
print_header "Installing Node.js dependencies"

cd "${BACKEND_DIR}"
npm install --omit=dev --silent
chown -R root:root "${BACKEND_DIR}/node_modules"
chmod -R a+rX "${BACKEND_DIR}/node_modules"
print_ok "npm packages installed ($(ls node_modules | wc -l) packages)"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — MYSQL
# ══════════════════════════════════════════════════════════════════════════════
print_header "Configuring MySQL"

systemctl start mysql
systemctl enable mysql >/dev/null 2>&1

# Build auth args
if [[ -n "$MYSQL_ROOT_PASS" ]]; then
  MYSQL_ARGS=(-u root -p"${MYSQL_ROOT_PASS}")
else
  MYSQL_ARGS=(-u root)
fi

# Test connection
mysql "${MYSQL_ARGS[@]}" -e "SELECT 1" >/dev/null 2>&1 || \
  die "Cannot connect to MySQL. Check the root password and try again."

mysql "${MYSQL_ARGS[@]}" <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost'
  IDENTIFIED BY '${DB_PASS}';

GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';

FLUSH PRIVILEGES;
SQL

print_ok "Database '${DB_NAME}' created (utf8mb4)"
print_ok "User '${DB_USER}'@'localhost' created and granted privileges"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — ENVIRONMENT FILE
# Stored in /etc/netmon/env — not inside the application tree
# /etc is the correct FHS location for system-wide configuration files
# ══════════════════════════════════════════════════════════════════════════════
print_header "Writing configuration"

mkdir -p /etc/netmon
cat > /etc/netmon/env <<ENV
# Network Monitor — Environment Configuration
# Generated by install.sh on $(date)
# Edit this file to change application settings, then restart:
#   sudo systemctl restart netmon

# Application
PORT=${APP_PORT}
NODE_ENV=production

# Database
DB_HOST=localhost
DB_PORT=3306
DB_USER=${DB_USER}
DB_PASS=${DB_PASS}
DB_NAME=${DB_NAME}

# Session security (do not share — regenerate with: openssl rand -hex 32)
SESSION_SECRET=${SESSION_SECRET}

# Initial admin account credentials
# These are only used on first startup to seed the users table.
# Remove or comment out after the first login.
ADMIN_USERNAME=${ADMIN_USER}
ADMIN_PASSWORD=${ADMIN_PASS}

# Data and log paths (used by the application for all runtime files)
DATA_DIR=${DATA_DIR}
LOG_DIR=${LOG_DIR}
ENV

# Copy env file as .env in backend dir (dotenv may not follow symlinks)
cp /etc/netmon/env "${BACKEND_DIR}/.env"
chown root:"${SVC_USER}" "${BACKEND_DIR}/.env"
chmod 640 "${BACKEND_DIR}/.env"
print_ok ".env written to ${BACKEND_DIR}/.env"

# Keep /etc/netmon/env as the canonical config — remind user to sync after edits
print_note "Note: edit /etc/netmon/env to change settings, then run:"
print_note "  sudo cp /etc/netmon/env ${BACKEND_DIR}/.env && sudo systemctl restart netmon"

chown -R root:"${SVC_USER}" /etc/netmon
chmod 750 /etc/netmon
chmod 640 /etc/netmon/env
print_ok "Configuration written to /etc/netmon/env (owner: root:${SVC_USER}, mode: 640)"
print_ok "Symlinked ${BACKEND_DIR}/.env → /etc/netmon/env"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — SSL CERTIFICATE
# ══════════════════════════════════════════════════════════════════════════════
print_header "Generating SSL certificate"

SSL_CERT="/etc/ssl/certs/netmon.crt"
SSL_KEY="/etc/ssl/private/netmon.key"

openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout "$SSL_KEY" \
  -out    "$SSL_CERT" \
  -subj   "/CN=${SERVER_HOST}/O=Network Monitor/C=AU" \
  2>/dev/null

chmod 644 "$SSL_CERT"
chmod 640 "$SSL_KEY"
# Allow nginx (www-data) to read the private key
chown root:www-data "$SSL_KEY"

print_ok "Certificate : ${SSL_CERT}"
print_ok "Private key : ${SSL_KEY} (owner: root:www-data, mode: 640)"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — NGINX
# ══════════════════════════════════════════════════════════════════════════════
print_header "Configuring Nginx"

rm -f /etc/nginx/sites-enabled/default

cat > /etc/nginx/sites-available/netmon <<NGINX
# Network Monitor — Nginx reverse proxy
# Generated by install.sh on $(date)

server {
    listen 443 ssl;
    server_name ${SERVER_HOST};

    ssl_certificate      ${SSL_CERT};
    ssl_certificate_key  ${SSL_KEY};
    ssl_protocols        TLSv1.2 TLSv1.3;
    ssl_ciphers          HIGH:!aNULL:!MD5;
    ssl_session_cache    shared:SSL:10m;
    ssl_session_timeout  10m;

    # Security headers
    add_header X-Frame-Options         "SAMEORIGIN"    always;
    add_header X-Content-Type-Options  "nosniff"       always;
    add_header X-XSS-Protection        "1; mode=block" always;
    add_header Referrer-Policy         "strict-origin-when-cross-origin" always;

    # Proxy to Node.js application
    location / {
        proxy_pass            http://127.0.0.1:${APP_PORT};
        proxy_http_version    1.1;
        proxy_set_header      Upgrade            \$http_upgrade;
        proxy_set_header      Connection         "upgrade";
        proxy_set_header      Host               \$host;
        proxy_set_header      X-Real-IP          \$remote_addr;
        proxy_set_header      X-Forwarded-For    \$proxy_add_x_forwarded_for;
        proxy_set_header      X-Forwarded-Proto  \$scheme;
        proxy_cache_bypass    \$http_upgrade;
        proxy_read_timeout    60s;
        proxy_connect_timeout 10s;
        proxy_send_timeout    60s;
    }
}

# Redirect HTTP → HTTPS
server {
    listen 80;
    server_name ${SERVER_HOST};
    return 301 https://\$host\$request_uri;
}
NGINX

ln -sf /etc/nginx/sites-available/netmon /etc/nginx/sites-enabled/netmon

nginx -t >/dev/null 2>&1 || { nginx -t; die "Nginx configuration test failed"; }
systemctl enable nginx >/dev/null 2>&1
systemctl reload nginx
print_ok "Nginx site config written and enabled"
print_ok "Nginx reloaded"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 10 — SYSTEMD SERVICE
# Uses EnvironmentFile to load /etc/netmon/env without embedding secrets
# in the service unit file (which is world-readable)
# ══════════════════════════════════════════════════════════════════════════════
print_header "Creating systemd service"

cat > /etc/systemd/system/netmon.service <<SERVICE
# Network Monitor — systemd service unit
# Generated by install.sh on $(date)

[Unit]
Description=Network Monitor (Aruba CX + MikroTik)
Documentation=https://github.com/yourorg/netmon
After=network.target mysql.service
Wants=mysql.service

[Service]
Type=simple
User=${SVC_USER}
Group=${SVC_USER}
WorkingDirectory=${BACKEND_DIR}
ExecStart=$(command -v node) server.js
Restart=on-failure
RestartSec=5
TimeoutStartSec=30

# Load environment variables from config file
# The file is readable only by root and the service account (mode 640)
EnvironmentFile=/etc/netmon/env

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netmon

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR} ${LOG_DIR}
ReadOnlyPaths=${INSTALL_DIR}

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable netmon >/dev/null 2>&1
print_ok "Service unit: /etc/systemd/system/netmon.service"
print_ok "Service enabled (starts automatically on boot)"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 11 — FIREWALL
# ══════════════════════════════════════════════════════════════════════════════
print_header "Configuring firewall (UFW)"

if ! ufw status | grep -q "Status: active"; then
  print_info "UFW not active — enabling (keeping SSH open)"
  ufw --force enable >/dev/null
  ufw allow ssh comment "SSH" >/dev/null
fi

ufw allow 80/tcp  comment "Netmon HTTP → HTTPS redirect" >/dev/null
ufw allow 443/tcp comment "Netmon HTTPS"                 >/dev/null
ufw reload >/dev/null
print_ok "Firewall rules added (80/tcp, 443/tcp)"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 12 — START AND VERIFY
# ══════════════════════════════════════════════════════════════════════════════
print_header "Starting application"

systemctl start netmon

print_info "Waiting for application to respond..."
READY=false
for i in {1..20}; do
  if curl -sk "http://127.0.0.1:${APP_PORT}/api/auth/setup-status" >/dev/null 2>&1; then
    READY=true; break
  fi
  sleep 2
done

if $READY; then
  print_ok "Application is running and responding on port ${APP_PORT}"
  # Verify through nginx too
  if curl -sk --connect-timeout 5 "https://127.0.0.1/api/auth/setup-status" \
     --resolve "${SERVER_HOST}:443:127.0.0.1" >/dev/null 2>&1; then
    print_ok "Nginx proxy is working (HTTPS → Node.js)"
  else
    print_warn "Nginx proxy check inconclusive — verify manually"
  fi
else
  print_warn "Application did not respond in time. Check: journalctl -u netmon -n 30"
fi

# ══════════════════════════════════════════════════════════════════════════════
# DONE
# ══════════════════════════════════════════════════════════════════════════════
echo
echo -e "${GREEN}${BOLD}"
echo "  ╔═══════════════════════════════════════════════════════════════╗"
echo "  ║                 Installation complete!                       ║"
echo "  ╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "  ${BOLD}Access the application${NC}"
echo -e "    ${CYAN}https://${SERVER_HOST}${NC}"
echo
echo -e "  ${BOLD}Login credentials${NC}"
echo -e "    Username : ${CYAN}${ADMIN_USER}${NC}"
echo -e "    Password : ${CYAN}${ADMIN_PASS}${NC}"
echo -e "    ${YELLOW}⚠  Change this password immediately after first login!${NC}"
echo
echo -e "  ${BOLD}File locations${NC}"
echo -e "    Application : ${CYAN}${INSTALL_DIR}${NC}"
echo -e "    Config      : ${CYAN}/etc/netmon/env${NC}"
echo -e "    Data        : ${CYAN}${DATA_DIR}${NC}"
echo -e "    Logs        : ${CYAN}${LOG_DIR}${NC}"
echo -e "    Nginx       : ${CYAN}/etc/nginx/sites-available/netmon${NC}"
echo -e "    Service     : ${CYAN}/etc/systemd/system/netmon.service${NC}"
echo -e "    SSL cert    : ${CYAN}${SSL_CERT}${NC}"
echo
echo -e "  ${BOLD}Service management${NC}"
echo -e "    View logs   : ${CYAN}journalctl -u netmon -f${NC}"
echo -e "    Restart     : ${CYAN}sudo systemctl restart netmon${NC}"
echo -e "    Status      : ${CYAN}sudo systemctl status netmon${NC}"
echo -e "    Reset admin : ${CYAN}sudo -u ${SVC_USER} node ${BACKEND_DIR}/reset-admin.js${NC}"
echo
echo -e "  ${BOLD}Browser certificate warning${NC}"
echo    "    Browsers will warn about the self-signed certificate on first visit."
echo    "    Click Advanced → Accept the Risk (Firefox)"
echo    "          Advanced → Proceed (Chrome/Edge)"
echo    "    To permanently trust it, install ${SSL_CERT} as a"
echo    "    trusted root certificate on each client device."
echo
echo -e "  ${DIM}Service account '${SVC_USER}' has no login shell and cannot be used"
echo -e "  for interactive logins — this is by design.${NC}"
echo
