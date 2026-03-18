# Network Monitor

A self-hosted network monitoring application for **Aruba CX switches** (REST API) and **MikroTik routers** (SNMP v2c).

---

## Features

### Monitoring
- **Live bandwidth** — real-time per-interface RX/TX with chart
- **History** — per-interface bandwidth graphs (15 min to 7 days)
- **Averages** — hourly/daily/weekly averages per interface
- **Overview** — aggregate bandwidth summary across all devices
- **Topology** — interactive network map with live link traffic

### Devices
- **Aruba CX switches** — managed via REST API
- **MikroTik routers** — managed via SNMP v2c
- **System Info modal** — hostname, firmware, serial, base MAC, uptime, contact, location (both device types)
- **MikroTik Tools modal** — Routes, ARP, Neighbours, DHCP Leases tabs
- **Device preferences** — per-interface hiding, custom labels
- **Network scan** — discover devices on a subnet

### Logs
- **Switch Logs** — Aruba switch logs stored in DB, persisted across reboots, background sync every 5 min
  - Configurable retention (default 90 days), daily purge
  - Deduplication via SHA1 hash — no duplicate entries ever stored
  - Filters: severity, search, device selector
- **App Logs** — internal application log with level/category filters and live mode

### Search
- Search by MAC address or IP across all Aruba switches and MikroTik routers simultaneously
- Shows device name, type badge (Aruba CX / MikroTik), port and VLAN

### CVE / Vulnerability Checking
- Queries the NIST National Vulnerability Database (NVD) API for known CVEs
- Checks Aruba firmware version against `device_info` DB
- Checks MikroTik firmware version against `mikrotik_info` DB
- Scheduled checks (default every 24 hours)
- Optional NVD API key for higher rate limits
- Results show CVSS score, severity, description and reference links
- Results stored in `cve-results.json`, survive restarts

### CSV Export
- **Aruba export** — Label, Hostname, Management IP, Product, Firmware, Serial, Base MAC, SNMP Name, Location, Contact, Interface Count, Last Updated
- **MikroTik export** — Label, Host, Community, Hostname, Board/Model, Firmware, Software ID, Uptime, Contact, Location, Description
- Manual browser download or scheduled server-side export
- Configurable output directory and interval

### Settings
- **System Status** — CPU load, memory, disk, process memory, DB table sizes and row counts
- **CSV Export** — schedule configuration and saved file management
- **User Management** — add/disable/delete users, reset passwords (admin only)
- **Change password** — self-service password change (minimum 15 characters)
- **Log retention** — configure how long switch logs are kept

### Authentication & Authorisation
- Session-based login with bcrypt password hashing (cost 12)
- Two roles: `admin` (full access) and `viewer` (read-only)
- 8-hour rolling sessions
- Passwords minimum 15 characters

---

## Stack

| Component | Technology |
|-----------|-----------|
| Backend   | Node.js + Express |
| Database  | MySQL (`aruba_monitor`) |
| Auth      | express-session + bcryptjs |
| Aruba API | HTTPS REST (AOS-CX REST API v10.x) |
| MikroTik  | SNMP v2c (net-snmp) |
| Frontend  | Single-page HTML/CSS/JS (no build step) |
| Web proxy | Nginx (HTTPS with self-signed certificate) |

---

## Directory Structure

```
~/aruba-cx-monitor/
  backend/
    server.js               — main application
    package.json
    .env                    — environment config
    devices.json            — device list
    topology.json           — topology node positions and links
    scan-config.json        — Aruba scan settings
    mt-scan-config.json     — MikroTik scan settings
    backup-schedule.json    — config backup schedule
    export-schedule.json    — CSV export schedule
    cve-config.json         — CVE check settings
    cve-results.json        — last CVE check results
    log-retention.json      — switch log retention days
    hidden-interfaces.json  — per-device hidden interfaces
    reset-admin.js          — master admin password reset CLI
    app.log                 — application log file
    exports/                — CSV export output (default)
    backups/                — config backup output (default)
  frontend/
    index.html              — single-page application
```

---

## Installation

### 1. Prerequisites

```bash
sudo apt update
sudo apt install nodejs npm mysql-server nginx -y
```

Verify Node.js version (18+ required):

```bash
node --version
```

### 2. Database

```bash
sudo mysql
```

```sql
CREATE DATABASE aruba_monitor;
CREATE USER 'netmon'@'localhost' IDENTIFIED BY 'yourpassword';
GRANT ALL PRIVILEGES ON aruba_monitor.* TO 'netmon'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

All tables are created automatically on first application startup.

### 3. Application

```bash
cd ~/aruba-cx-monitor/backend
npm install
```

Create `backend/.env`:

```env
PORT=3001
DB_HOST=localhost
DB_PORT=3306
DB_USER=netmon
DB_PASS=yourpassword
DB_NAME=aruba_monitor
SESSION_SECRET=change-this-to-a-long-random-string
ADMIN_PASSWORD=changeme
```

> Generate a good SESSION_SECRET with:
> `node -e "require('crypto').randomBytes(32).toString('hex') |> console.log"`
> or: `openssl rand -hex 32`

### 4. Systemd Service

Create `/etc/systemd/system/netmon.service`:

```ini
[Unit]
Description=Network Monitor
After=network.target mysql.service

[Service]
Type=simple
User=gonzo
WorkingDirectory=/home/gonzo/aruba-cx-monitor/backend
ExecStart=/usr/bin/node server.js
Restart=on-failure
RestartSec=5
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable netmon
sudo systemctl start netmon

# Verify it started correctly
journalctl -u netmon -n 20 --no-pager
```

You should see:
```
[auth] Default admin created — username: admin, password: changeme
[server] Listening on http://localhost:3001
```

### 5. Nginx with HTTPS (self-signed certificate)

This makes the app available to LAN clients over HTTPS on the standard port 443.

**Generate the self-signed certificate** (valid 10 years):

```bash
sudo openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout /etc/ssl/private/netmon.key \
  -out /etc/ssl/certs/netmon.crt \
  -subj "/CN=192.168.1.x"
```

Replace `192.168.1.x` with your server's actual LAN IP address. If you have a local DNS hostname (e.g. `netmon.lan`) use that instead.

**Create the nginx site config:**

```bash
sudo nano /etc/nginx/sites-available/netmon
```

Paste the following, replacing `192.168.1.x` with your server's IP:

```nginx
server {
    listen 443 ssl;
    server_name 192.168.1.x;

    ssl_certificate     /etc/ssl/certs/netmon.crt;
    ssl_certificate_key /etc/ssl/private/netmon.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
        proxy_pass             http://localhost:3001;
        proxy_http_version     1.1;
        proxy_set_header       Upgrade $http_upgrade;
        proxy_set_header       Connection 'upgrade';
        proxy_set_header       Host $host;
        proxy_set_header       X-Real-IP $remote_addr;
        proxy_set_header       X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header       X-Forwarded-Proto $scheme;
        proxy_cache_bypass     $http_upgrade;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name 192.168.1.x;
    return 301 https://$host$request_uri;
}
```

**Enable the site and reload nginx:**

```bash
# Disable the default nginx site
sudo rm -f /etc/nginx/sites-enabled/default

# Enable the netmon site
sudo ln -s /etc/nginx/sites-available/netmon /etc/nginx/sites-enabled/

# Test the configuration
sudo nginx -t

# Reload nginx
sudo systemctl reload nginx
sudo systemctl enable nginx
```

**Open firewall ports:**

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw reload

# Verify rules
sudo ufw status
```

**Accepting the self-signed certificate in browsers:**

Since the certificate is self-signed, browsers will show a security warning on first visit. To proceed:
- **Firefox**: Click *Advanced* → *Accept the Risk and Continue*
- **Chrome/Edge**: Click *Advanced* → *Proceed to 192.168.1.x*

To permanently trust the certificate on a device, install `netmon.crt` as a trusted root certificate:

```bash
# Copy cert to a location browsers can access
cat /etc/ssl/certs/netmon.crt
```

- **Windows**: Double-click the `.crt` file → Install Certificate → Local Machine → Trusted Root Certification Authorities
- **macOS**: Double-click the `.crt` file → Keychain Access → set to Always Trust
- **Linux (Chrome/Edge)**: Settings → Privacy → Manage Certificates → Authorities → Import
- **Android**: Settings → Security → Install from storage
- **iOS**: Settings → General → VPN & Device Management → install profile, then Settings → General → About → Certificate Trust Settings → enable

**Verify the setup:**

```bash
# Test from the server itself
curl -k https://localhost/api/auth/setup-status

# Check nginx is proxying correctly
sudo nginx -t
sudo systemctl status nginx
```

Access the app from any LAN device at `https://192.168.1.x`.

---

## First Login

Default credentials: **admin / changeme** (or whatever `ADMIN_PASSWORD` is set to in `.env`).

**Change the password immediately** — Settings → Change my password (minimum 15 characters).

---

## Admin Password Reset

If you lose access to the admin account, three recovery methods are available:

### Method 1 — CLI utility (recommended)

```bash
cd ~/aruba-cx-monitor/backend
node reset-admin.js
# or with password as argument:
node reset-admin.js mynewpassword
```

### Method 2 — Environment variable at startup

```bash
sudo systemctl stop netmon
RESET_ADMIN_PASSWORD=mynewpassword sudo -E node server.js
# Once confirmed, remove the env var and restart normally
sudo systemctl start netmon
```

### Method 3 — Direct database update

```bash
# Generate bcrypt hash
node -e "require('bcryptjs').hash('mynewpassword', 12).then(h => console.log(h))"

# Apply to DB
mysql -u netmon -p aruba_monitor -e \
  "UPDATE users SET password_hash='<hash>', enabled=1 WHERE is_master=1;"
```

---

## Database Tables

| Table | Contents |
|-------|---------|
| `bandwidth_samples` | Raw per-interface bandwidth samples |
| `bandwidth_hourly_avg` | Pre-aggregated hourly averages |
| `device_info` | Aruba switch sysinfo (firmware, serial, MAC, etc.) |
| `mikrotik_info` | MikroTik router sysinfo (firmware, board, uptime, etc.) |
| `switch_logs` | Aruba switch event logs with deduplication |
| `users` | User accounts with bcrypt-hashed passwords |
| `sessions` | Session metadata |

---

## API Endpoints

All endpoints require authentication. Viewer role can access GET endpoints only.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/switches` | List all devices |
| POST | `/api/switches` | Add device |
| PUT | `/api/switches/:id` | Update device |
| DELETE | `/api/switches/:id` | Remove device |
| POST | `/api/switches/:id/toggle` | Enable / disable |
| POST | `/api/switches/:id/test` | Test credentials / SNMP |
| GET | `/api/live?switch=id` | Latest interface samples |
| GET | `/api/history?switch=id&interface=&minutes=` | Historical data |
| GET | `/api/overview` | Aggregate per device |
| GET | `/api/topology` | Topology graph |
| GET | `/api/device-info` | Aruba sysinfo from DB |
| GET | `/api/sysinfo?switch=id` | Fetch live Aruba sysinfo |
| GET | `/api/mikrotik-info` | MikroTik sysinfo from DB |
| GET | `/api/mikrotik-tools?switch=id` | MikroTik routes/ARP/neighbours/DHCP |
| GET | `/api/switch-logs?switch=id` | Switch logs from DB |
| POST | `/api/switch-logs/sync` | Manual log sync |
| PUT | `/api/switch-logs/retention` | Set log retention days |
| GET | `/api/search?q=` | Search MAC/IP across all devices |
| GET | `/api/status` | Server/DB/system status |
| GET | `/api/cve/results` | Last CVE check results |
| POST | `/api/cve/run` | Trigger CVE check |
| PUT | `/api/cve/config` | CVE check settings |
| POST | `/api/export/run` | Run CSV export |
| GET | `/api/export/schedule` | Export schedule config |
| PUT | `/api/export/schedule` | Save export schedule |
| POST | `/api/auth/login` | Login (public) |
| POST | `/api/auth/logout` | Logout |
| GET | `/api/auth/me` | Current user |
| GET | `/api/auth/users` | List users (admin only) |
| POST | `/api/auth/users` | Add user (admin only) |
| PUT | `/api/auth/users/:id` | Update user (admin only) |
| DELETE | `/api/auth/users/:id` | Delete user (admin only) |
| POST | `/api/auth/change-password` | Change own password |

---

## NVD API Key

Without an API key the CVE checker is rate-limited to 5 requests per 30 seconds (~6.5s delay per query). With a free API key the limit increases to 50 requests per 30 seconds (~0.7s delay).

Register at: https://nvd.nist.gov/developers/request-an-api-key

Enter the key in **Settings → CVE → NVD API key**.

---

## Troubleshooting

**App won't start — missing module**
```bash
cd ~/aruba-cx-monitor/backend
npm install
```

**Can't connect from LAN clients**
```bash
# Check firewall
sudo ufw status
sudo ufw allow 443/tcp

# Check nginx is running
sudo systemctl status nginx

# Check the app is running
sudo systemctl status netmon
journalctl -u netmon -n 20 --no-pager
```

**Browser shows infinite loading / no switches after login**
- Open browser developer tools → Network tab
- Check if API calls return 401 — session cookie may not be sending
- Ensure you are accessing via `https://` not `http://`
- Clear browser cookies for the site and log in again

**Nginx returns 502 Bad Gateway**
```bash
# Check the app is running on port 3001
curl http://localhost:3001/api/auth/setup-status
sudo systemctl status netmon
```

**Certificate warning every visit**
- Install `netmon.crt` as a trusted root certificate on each client device (see certificate trust instructions above)
