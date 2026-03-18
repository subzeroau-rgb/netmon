require('dotenv').config();
const express  = require('express');
const session      = require('express-session');
const bcrypt       = require('bcryptjs');
const crypto   = require('crypto');
const cors     = require('cors');
const https    = require('https');
const axios    = require('axios');
const mysql    = require('mysql2/promise');
const snmp     = require('net-snmp');
const fs       = require('fs');
const path     = require('path');
const os       = require('os');

// ─── Constants ────────────────────────────────────────────────────────────────
const PORT           = parseInt(process.env.PORT || '3001', 10);
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_MAX_AGE= parseInt(process.env.SESSION_MAX_AGE || (8 * 3600 * 1000)); // 8 hours
// Data directory — use env var if set (production install), otherwise
// fall back to __dirname (development / direct run)
const DATA_DIR     = process.env.DATA_DIR     || __dirname;
const LOG_DIR      = process.env.LOG_DIR      || __dirname;

const DEVICES_FILE          = path.join(DATA_DIR, 'devices.json');
const TOPO_FILE             = path.join(DATA_DIR, 'topology.json');
const SCAN_FILE             = path.join(DATA_DIR, 'scan-config.json');
const HIDDEN_FILE           = path.join(DATA_DIR, 'hidden-interfaces.json');
const EXPORT_SCHEDULE_FILE  = path.join(DATA_DIR, 'export-schedule.json');
const BACKUPS_DIR           = path.join(DATA_DIR, 'backups');
const EXPORT_DIR            = path.join(DATA_DIR, 'exports');
const APP_LOG_FILE          = path.join(LOG_DIR,  'app.log');
const MAX_LOG_LINES = 5000;

// ─── SNMP OIDs (IF-MIB / RFC 2863) ───────────────────────────────────────────
const OID = {
  sysName:       '1.3.6.1.2.1.1.5.0',
  ifDescr:       '1.3.6.1.2.1.2.2.1.2',
  ifOperStatus:  '1.3.6.1.2.1.2.2.1.8',    // 1=up 2=down
  ifHighSpeed:   '1.3.6.1.2.1.31.1.1.1.15', // Mbps (64-bit preferred)
  ifAlias:       '1.3.6.1.2.1.31.1.1.1.18', // interface description/alias
  ifHCInOctets:  '1.3.6.1.2.1.31.1.1.1.6',  // 64-bit RX byte counter
  ifHCOutOctets: '1.3.6.1.2.1.31.1.1.1.10', // 64-bit TX byte counter
  ifInOctets:    '1.3.6.1.2.1.2.2.1.10',    // 32-bit RX fallback
  ifOutOctets:   '1.3.6.1.2.1.2.2.1.16',    // 32-bit TX fallback
  // Bridge / FDB (MAC address table) — dot1dTpFdbTable
  dot1dTpFdbAddress:  '1.3.6.1.2.1.17.4.3.1.1', // MAC address (OID encoded)
  dot1dTpFdbPort:     '1.3.6.1.2.1.17.4.3.1.2', // bridge port number
  dot1dBasePortIfIndex:'1.3.6.1.2.1.17.1.4.1.2', // bridge port -> ifIndex
  // ARP table — ipNetToMediaTable
  ipNetToMediaIfIndex:'1.3.6.1.2.1.4.22.1.1',    // ifIndex
  ipNetToMediaPhysAddr:'1.3.6.1.2.1.4.22.1.2',   // MAC (buffer)
  ipNetToMediaNetAddr: '1.3.6.1.2.1.4.22.1.3',   // IP address
  // LLDP neighbour table (if MikroTik has LLDP enabled)
  lldpRemSysName:     '1.0.8802.1.1.2.1.4.1.1.9',
  lldpRemPortDesc:    '1.0.8802.1.1.2.1.4.1.1.8',
  lldpRemSysDesc:     '1.0.8802.1.1.2.1.4.1.1.10',
  lldpLocPortDesc:    '1.0.8802.1.1.2.1.3.7.1.4',  // local port desc
  // MikroTik neighbor discovery table (1.3.6.1.4.1.14988.1.1.11)
  // Key: index.  Columns: 2=ipAddr, 3=mac, 6=sysName, 8=ifIndex
  mtNbrIp:     '1.3.6.1.4.1.14988.1.1.11.1.1.2',
  mtNbrMac:    '1.3.6.1.4.1.14988.1.1.11.1.1.3',
  mtNbrName:   '1.3.6.1.4.1.14988.1.1.11.1.1.6',
  mtNbrIfIdx:  '1.3.6.1.4.1.14988.1.1.11.1.1.8',
  // MikroTik system resources (1.3.6.1.4.1.14988.1.1.3)
  // Note: .3.4/.3.5/.3.6/.3.7 not available on all firmware versions
  // MikroTik system info scalars (confirmed working OIDs)
  mtSoftId:       '1.3.6.1.4.1.14988.1.1.4.1.0',   // software ID e.g. "IKF8-1PQU"
  mtFirmware:     '1.3.6.1.4.1.14988.1.1.4.4.0',   // firmware version e.g. "7.4.1"
  // Older firmware OIDs (may not be present)
  mtSysVersion:   '1.3.6.1.4.1.14988.1.1.3.4.0',
  mtSysBoardName: '1.3.6.1.4.1.14988.1.1.3.7.0',
  // Standard system MIB
  sysDescr:    '1.3.6.1.2.1.1.1.0',
  sysUpTime:   '1.3.6.1.2.1.1.3.0',
  sysContact:  '1.3.6.1.2.1.1.4.0',
  sysLocation: '1.3.6.1.2.1.1.6.0',
  // Route table — ipRouteTable (RFC 1213)
  ipRouteDest:    '1.3.6.1.2.1.4.21.1.1',
  ipRouteIfIndex: '1.3.6.1.2.1.4.21.1.2',
  ipRouteMetric:  '1.3.6.1.2.1.4.21.1.3',
  ipRouteNextHop: '1.3.6.1.2.1.4.21.1.7',
  ipRouteMask:    '1.3.6.1.2.1.4.21.1.11',
  ipRouteType:    '1.3.6.1.2.1.4.21.1.8',  // 1=other,2=invalid,3=direct,4=indirect
  ipRouteProto:   '1.3.6.1.2.1.4.21.1.9',  // 1=other,2=local,3=netmgmt,4=icmp,8=ospf,9=bgp,13=rip
  // DHCP server leases — MikroTik DHCP MIB
  mtDhcpServerLeaseAddr:    '1.3.6.1.4.1.14988.1.1.7.1.1.2',
  mtDhcpServerLeaseHostname:'1.3.6.1.4.1.14988.1.1.7.1.1.6',
  mtDhcpServerLeaseMac:     '1.3.6.1.4.1.14988.1.1.7.1.1.3',
  mtDhcpServerLeaseServer:  '1.3.6.1.4.1.14988.1.1.7.1.1.4',
  mtDhcpServerLeaseStatus:  '1.3.6.1.4.1.14988.1.1.7.1.1.7',
};

// ─── Aruba CX HTTPS agent (allow self-signed certs) ──────────────────────────
const httpsAgent  = new https.Agent({ rejectUnauthorized: false });
const axiosDevice = axios.create({ httpsAgent });

// ─── Application logger ──────────────────────────────────────────────────────
// Capture original console methods FIRST before any patching
const _clog  = console.log.bind(console);
const _cwarn = console.warn.bind(console);
const _cerr  = console.error.bind(console);

const appLogBuffer = [];
let   _appLogging  = false; // re-entrancy guard

function appLog(level, category, message) {
  // Use original console methods to avoid re-entrant patched calls
  const entry = {
    ts:       new Date().toISOString(),
    level,
    category,
    message:  String(message),
  };
  appLogBuffer.push(entry);
  if (appLogBuffer.length > MAX_LOG_LINES) appLogBuffer.shift();
  // Write to log file async (fire-and-forget, never throws)
  try {
    const line = JSON.stringify(entry) + '\n';
    fs.appendFile(APP_LOG_FILE, line, () => {});
  } catch(e) {}
  // Mirror to original console (not patched versions — avoids infinite loop)
  const pfx = `[${entry.ts.slice(11,19)}][${level.toUpperCase().padEnd(5)}][${category}]`;
  if      (level === 'error') _cerr(pfx, message);
  else if (level === 'warn')  _cwarn(pfx, message);
  else                        _clog(pfx, message);
}

// Patch console methods so existing log statements flow into appLog.
// The re-entrancy guard (_appLogging) prevents infinite loops if appLog
// itself triggers a console call.
console.log   = (...a) => { _clog(...a);  if (!_appLogging) { _appLogging=true; try { appLog('info',  'app', a.join(' ')); } finally { _appLogging=false; } } };
console.warn  = (...a) => { _cwarn(...a); if (!_appLogging) { _appLogging=true; try { appLog('warn',  'app', a.join(' ')); } finally { _appLogging=false; } } };
console.error = (...a) => { _cerr(...a);  if (!_appLogging) { _appLogging=true; try { appLog('error', 'app', a.join(' ')); } finally { _appLogging=false; } } };

// ─── MySQL connection pool ────────────────────────────────────────────────────
let db;
async function initDB() {
  db = await mysql.createPool({
    host:               process.env.DB_HOST  || 'localhost',
    port:               parseInt(process.env.DB_PORT || '3306', 10),
    user:               process.env.DB_USER  || 'root',
    password:           process.env.DB_PASS  || '',
    database:           process.env.DB_NAME  || 'aruba_monitor',
    waitForConnections: true,
    connectionLimit:    10,
    namedPlaceholders:  true,
  });
  console.log('[db] MySQL pool ready');
  // Ensure device_info table exists (auto-migrate)
  await db.execute(`
    CREATE TABLE IF NOT EXISTS device_info (
      device_id        VARCHAR(64)   NOT NULL PRIMARY KEY,
      switch_host      VARCHAR(128)  NOT NULL,
      label            VARCHAR(128)  NOT NULL,
      hostname         VARCHAR(128)  NULL,
      platform         VARCHAR(128)  NULL,
      software_version VARCHAR(64)   NULL,
      serial_number    VARCHAR(64)   NULL,
      base_mac         VARCHAR(17)   NULL,
      snmp_name        VARCHAR(128)  NULL,
      snmp_location    VARCHAR(256)  NULL,
      snmp_contact     VARCHAR(128)  NULL,
      management_ip    VARCHAR(64)   NULL,
      interface_count  SMALLINT      NULL,
      primary_image    VARCHAR(256)  NULL,
      uptime_seconds   BIGINT        NULL,
      raw_json         MEDIUMTEXT    NULL,
      fetched_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_di_host (switch_host)
    ) ENGINE=InnoDB
  `);
  console.log('[db] device_info table ready');

  // Ensure mikrotik_info table exists
  await db.execute(`
    CREATE TABLE IF NOT EXISTS mikrotik_info (
      device_id       VARCHAR(64)   NOT NULL PRIMARY KEY,
      switch_host     VARCHAR(128)  NOT NULL,
      label           VARCHAR(128)  NOT NULL,
      hostname        VARCHAR(128)  NULL,
      board_name      VARCHAR(128)  NULL,
      firmware        VARCHAR(64)   NULL,
      soft_id         VARCHAR(64)   NULL,
      sys_descr       VARCHAR(256)  NULL,
      uptime          VARCHAR(64)   NULL,
      contact         VARCHAR(128)  NULL,
      location        VARCHAR(256)  NULL,
      snmp_community  VARCHAR(64)   NULL,
      snmp_port       SMALLINT      NULL,
      fetched_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_mi_host (switch_host)
    ) ENGINE=InnoDB
  `);
  console.log('[db] mikrotik_info table ready');

  // Switch log storage table
  await db.execute(`
    CREATE TABLE IF NOT EXISTS switch_logs (
      id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      device_id     VARCHAR(64)   NOT NULL,
      switch_host   VARCHAR(128)  NOT NULL,
      switch_label  VARCHAR(128)  NOT NULL,
      log_timestamp DATETIME(3)   NOT NULL,
      severity      VARCHAR(16)   NOT NULL DEFAULT 'info',
      category      VARCHAR(128)  NOT NULL DEFAULT '',
      message       TEXT          NOT NULL,
      source        VARCHAR(128)  NOT NULL DEFAULT '',
      dedup_hash    VARCHAR(64)   NOT NULL,
      UNIQUE KEY uk_dedup (device_id, dedup_hash),
      INDEX idx_sl_device   (device_id),
      INDEX idx_sl_ts       (log_timestamp),
      INDEX idx_sl_severity (severity)
    ) ENGINE=InnoDB
  `);
  console.log('[db] switch_logs table ready');

  // Auth tables
  await db.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      username      VARCHAR(64)   NOT NULL UNIQUE,
      password_hash VARCHAR(128)  NOT NULL,
      role          ENUM('admin','viewer') NOT NULL DEFAULT 'viewer',
      created_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_login    DATETIME      NULL,
      enabled       TINYINT(1)    NOT NULL DEFAULT 1,
      is_master     TINYINT(1)    NOT NULL DEFAULT 0
    ) ENGINE=InnoDB
  `);
  await db.execute(`
    CREATE TABLE IF NOT EXISTS sessions (
      session_id    VARCHAR(128)  NOT NULL PRIMARY KEY,
      expires       DATETIME      NOT NULL,
      data          MEDIUMTEXT    NULL
    ) ENGINE=InnoDB
  `);
  console.log('[db] auth tables ready');

  console.log('[db] MySQL session store ready');

  // Create default admin if no users exist
  const [[userCount]] = await db.execute('SELECT COUNT(*) AS n FROM users');
  if (userCount.n === 0) {
    const defaultPass = process.env.ADMIN_PASSWORD || 'admin';
    const hash = await bcrypt.hash(defaultPass, 12);
    await db.execute(
      'INSERT INTO users (username, password_hash, role, is_master) VALUES (?,?,?,1)',
      ['admin', hash, 'admin']
    );
    console.log('[auth] Default admin created — username: admin, password:', defaultPass);
    console.log('[auth] CHANGE THIS PASSWORD IMMEDIATELY via the user management page!');
  }
}

// Upsert device info into DB
async function saveDeviceInfoToDB(devId, devLabel, devHost, info) {
  if (!db) return;
  try {
    await db.execute(`
      INSERT INTO device_info
        (device_id, switch_host, label, hostname, platform, software_version,
         serial_number, base_mac, snmp_name, snmp_location, snmp_contact,
         management_ip, interface_count, primary_image, uptime_seconds,
         raw_json, fetched_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NOW())
      ON DUPLICATE KEY UPDATE
        switch_host=VALUES(switch_host), label=VALUES(label),
        hostname=VALUES(hostname), platform=VALUES(platform),
        software_version=VALUES(software_version),
        serial_number=VALUES(serial_number), base_mac=VALUES(base_mac),
        snmp_name=VALUES(snmp_name), snmp_location=VALUES(snmp_location),
        snmp_contact=VALUES(snmp_contact), management_ip=VALUES(management_ip),
        interface_count=VALUES(interface_count), primary_image=VALUES(primary_image),
        uptime_seconds=VALUES(uptime_seconds), raw_json=VALUES(raw_json),
        fetched_at=NOW()
    `, [
      devId, devHost, devLabel,
      info.hostname         || null,
      info.platform         || null,
      info.softwareVersion  || null,
      info.serialNumber     || null,
      info.baseMac          || null,
      info.snmpName         || null,
      info.snmpLocation     || null,
      info.snmpContact      || null,
      info.managementIp     || null,
      info.interfaceCount   || null,
      info.primaryImage     || null,
      info.uptimeSeconds    || null,
      JSON.stringify(info),
    ]);
    appLog('debug', 'db', `${devLabel}: device_info saved to DB`);
  } catch(e) {
    appLog('warn', 'db', `${devLabel}: failed to save device_info: ${e.message}`);
  }
}

// ─── Device registry ──────────────────────────────────────────────────────────
// Aruba CX  : { id, type:'aruba',    label, host, port, username, password, interval, enabled }
// MikroTik  : { id, type:'mikrotik', label, host, snmpCommunity, snmpPort,  interval, enabled }
let devices = [];

function loadDevices() {
  if (!fs.existsSync(DEVICES_FILE)) {
    // Migrate from legacy switches.json if present
    const legacy = path.join(DATA_DIR, 'switches.json');
    if (fs.existsSync(legacy)) {
      try {
        devices = JSON.parse(fs.readFileSync(legacy, 'utf8'))
                    .map(s => ({ ...s, type: s.type || 'aruba' }));
        saveDevices();
        console.log(`[devices] Migrated ${devices.length} device(s) from switches.json`);
        return;
      } catch (e) { console.warn('[devices] Migration failed:', e.message); }
    }
    // Seed from .env
    if (process.env.SWITCH_HOST) {
      devices = [{
        id: 'default', type: 'aruba',
        label:    process.env.SWITCH_HOST,
        host:     process.env.SWITCH_HOST,
        port:     process.env.SWITCH_PORT || '443',
        username: process.env.SWITCH_USER || 'admin',
        password: process.env.SWITCH_PASS || '',
        interval: parseInt(process.env.POLL_INTERVAL_SECONDS || '30', 10),
        enabled:  true,
      }];
      saveDevices();
      console.log('[devices] Seeded from .env');
    }
    return;
  }
  try {
    devices = JSON.parse(fs.readFileSync(DEVICES_FILE, 'utf8'));
    console.log(`[devices] Loaded ${devices.length} device(s)`);
  } catch (e) {
    console.warn('[devices] Could not parse devices.json:', e.message);
    devices = [];
  }
}

function saveDevices() {
  fs.writeFileSync(DEVICES_FILE, JSON.stringify(devices, null, 2));
}

function getDeviceById(id) {
  return devices.find(d => d.id === id) || null;
}

// ─── Per-device poller state ──────────────────────────────────────────────────
const pollerState = new Map();

function getState(id) {
  if (!pollerState.has(id)) {
    pollerState.set(id, {
      cookie:       null,
      lastRx:       {},
      lastTx:       {},
      lastPollTime: null,
      timer:        null,
      status:       'idle',
      lastError:    null,
      lastPollAt:   null,
    });
  }
  return pollerState.get(id);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ARUBA CX REST POLLER
// ═══════════════════════════════════════════════════════════════════════════════

// API version discovered at login time, stored per device host
// so all subsequent calls use the right version automatically.
const deviceApiVersion = {};  // host -> 'v10.15' etc.

// Ordered list of API versions to try for login — newest first
const ARUBA_LOGIN_VERSIONS = [
  'v10.15','v10.14','v10.13','v10.12','v10.11','v10.10','v10.09','v10.08','v1'
];

function apiVer(dev) {
  return deviceApiVersion[dev.host] || 'v10.10';
}

function apiBase(dev) {
  return `https://${dev.host}:${dev.port}/rest/${apiVer(dev)}`;
}

// AOS-CX login changed across firmware versions:
//   <= 10.12  POST /rest/vX/login?username=x&password=y   (query params, returns session cookie)
//   >= 10.13  POST /rest/vX/login  {"username":"x","password":"y"}  (JSON body)
//
// Cookie handling note: on 10.13+ the switch may return multiple Set-Cookie headers.
// All of them must be sent back on subsequent requests — the switch validates the full
// cookie jar, not just a single token. We collect ALL name=value pairs and join them.
//
// Validation: after obtaining a cookie we make a lightweight test request to confirm
// the session is actually authenticated before storing it.

function extractCookies(headers) {
  const raw = headers['set-cookie'];
  if (!raw || !raw.length) return null;
  const pairs = raw.map(c => c.split(';')[0].trim()).filter(Boolean);
  return pairs.length ? pairs.join('; ') : null;
}

// Also remember which login METHOD worked per host so we never retry others
const deviceLoginMethod = {};  // host -> 'json' | 'params' | 'form'

async function arubaLogin(dev) {
  // If we already know the working version and method, use them directly —
  // no discovery loop, no wasted sessions.
  const knownVer    = deviceApiVersion[dev.host];
  const knownMethod = deviceLoginMethod[dev.host];

  if (knownVer && knownMethod) {
    try {
      const cookie = await arubaLoginWithMethod(dev, knownVer, knownMethod);
      if (cookie) {
        appLog('info', 'switch', `${dev.label}: re-authenticated via ${knownVer}/${knownMethod}`);
        return cookie;
      }
    } catch(e) {
      if (e.response && e.response.status === 401) {
        throw new Error(`Login failed for ${dev.label} — check username and password (HTTP 401)`);
      }
      // Known combo stopped working (firmware update?) — fall through to discovery
      appLog('warn', 'switch', `${dev.label}: known login ${knownVer}/${knownMethod} failed, rediscovering…`);
      delete deviceApiVersion[dev.host];
      delete deviceLoginMethod[dev.host];
    }
  }

  // Discovery: try versions and methods until one works.
  // Stop immediately when the first one succeeds — open exactly ONE session.
  const versionsToTry = knownVer ? [knownVer, ...ARUBA_LOGIN_VERSIONS.filter(v => v !== knownVer)]
                                 : ARUBA_LOGIN_VERSIONS;
  const methods = ['json', 'params', 'form'];

  for (const ver of versionsToTry) {
    for (const method of methods) {
      try {
        const cookie = await arubaLoginWithMethod(dev, ver, method);
        if (!cookie) continue;
        // Success — store both version and method to skip discovery next time
        deviceApiVersion[dev.host]  = ver;
        deviceLoginMethod[dev.host] = method;
        appLog('info', 'switch', `${dev.label}: authenticated via ${ver}/${method}`);
        return cookie;
      } catch(e) {
        if (!e.response) throw e;
        if (e.response.status === 401) {
          throw new Error(`Login failed for ${dev.label} — check username and password (HTTP 401)`);
        }
        // 404/405/400/415 = wrong version or method, try next
        if ([400, 404, 405, 415].includes(e.response.status)) continue;
        throw e;
      }
    }
  }
  throw new Error(`Could not authenticate to ${dev.label} — no working login format found`);
}

// Send a single login attempt with a specific method — returns cookie or null
async function arubaLoginWithMethod(dev, ver, method) {
  const url = `https://${dev.host}:${dev.port}/rest/${ver}/login`;
  let res;
  if (method === 'json') {
    res = await axiosDevice.post(url,
      { username: dev.username, password: dev.password },
      { headers: { 'Content-Type': 'application/json' }, timeout: 8000 }
    );
  } else if (method === 'params') {
    res = await axiosDevice.post(url, null, {
      params:  { username: dev.username, password: dev.password },
      timeout: 8000,
    });
  } else {
    const form = new URLSearchParams();
    form.append('username', dev.username);
    form.append('password', dev.password);
    res = await axiosDevice.post(url, form, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 8000,
    });
  }
  return extractCookies(res.headers) || null;
}

async function arubaLogout(dev, cookie) {
  if (!cookie) return;
  await axiosDevice.post(
    `${apiBase(dev)}/logout`, null,
    { headers: { Cookie: cookie } }
  ).catch(() => {});
}

// Fetch full interface config (link_state, description, speed) — no selector

// ── Shared session helper ─────────────────────────────────────────────────────
// All API endpoints should call this instead of arubaLogin() directly.
// It reuses the existing poller session if available, only logging in if needed.
// This prevents session exhaustion by ensuring one session per device at a time.
async function getDeviceCookie(dev) {
  const state = getState(dev.id);
  if (state.cookie) return state.cookie;
  // Log out any lingering session before creating a new one (defensive)
  const newCookie = await arubaLogin(dev);
  state.cookie = newCookie;
  return newCookie;
}

// Re-login helper: always logs out old session first, then creates a new one
async function reloginDevice(dev) {
  const state = getState(dev.id);
  if (state.cookie) {
    await arubaLogout(dev, state.cookie).catch(() => {});
    state.cookie = null;
  }
  state.cookie = await arubaLogin(dev);
  return state.cookie;
}

async function arubaFetchConfig(dev, cookie) {
  const res = await axiosDevice.get(
    `${apiBase(dev)}/system/interfaces`,
    { headers: { Cookie: cookie }, params: { depth: 2 } }
  );
  return res.data;
}

// Fetch only the statistics counters — lightweight, used every poll
async function arubaFetchStats(dev, cookie) {
  const res = await axiosDevice.get(
    `${apiBase(dev)}/system/interfaces`,
    { headers: { Cookie: cookie }, params: { depth: 2, selector: 'statistics' } }
  );
  return res.data;
}

// Extract the best available speed value from an Aruba interface object.
// The API returns speed in different fields depending on firmware version:
//   - link_speed        : actual negotiated speed (e.g. "1000") in Mbps — most reliable
//   - max_speed         : configured/max speed
//   - admin_speeds[]    : list of allowed speeds
// We try them in order and format as a human-readable string.
function arubaParseSpeed(iface) {
  // link_speed is the actual negotiated speed in Mbps (present when link is up)
  if (iface.link_speed)  return String(iface.link_speed) + 'M';
  // max_speed is in Mbps as well
  if (iface.max_speed)   return String(iface.max_speed)  + 'M';
  // admin_speeds is an array like ["1000", "100"] — take the first/highest
  if (Array.isArray(iface.admin_speeds) && iface.admin_speeds.length) {
    return String(iface.admin_speeds[0]) + 'M';
  }
  // user_config sometimes holds the speed config block
  if (iface.user_config && iface.user_config.speeds) {
    const sp = iface.user_config.speeds;
    if (Array.isArray(sp) && sp.length) return String(sp[0]) + 'M';
  }
  return '';
}

// Extract link status — field name varies slightly across AOS-CX versions
function arubaParseStatus(iface) {
  // link_state is the standard field: 'up' or 'down'
  if (iface.link_state) return iface.link_state;
  // Some versions use link_status
  if (iface.link_status) return iface.link_status;
  // Fallback: if admin_state is 'up' and there is traffic, assume up
  return 'unknown';
}

async function pollAruba(dev) {
  const state = getState(dev.id);
  state.status = 'polling';

  if (!state.cookie) {
    try {
      state.cookie = await arubaLogin(dev);
      console.log(`[${dev.label}] Aruba login OK`);
    } catch (err) {
      state.status    = 'error';
      state.lastError = 'Login failed: ' + err.message;
      console.error(`[${dev.label}] Login error:`, err.message);
      return;
    }
  }

  // Fetch config (status/speed) and stats (counters) in parallel.
  // Config is cached after the first successful fetch and only refreshed
  // every 5 polls to reduce API load — link state changes are still detected
  // because we always re-fetch it on every poll.
  let configData, statsData;
  try {
    [configData, statsData] = await Promise.all([
      arubaFetchConfig(dev, state.cookie),
      arubaFetchStats(dev, state.cookie),
    ]);
  } catch (err) {
    // Session may have expired — log out the old session before creating a new one
    console.warn(`[${dev.label}] Poll failed, re-logging in…`);
    if (state.cookie) {
      await arubaLogout(dev, state.cookie).catch(() => {});
      state.cookie = null;
    }
    try {
      state.cookie = await arubaLogin(dev);
      [configData, statsData] = await Promise.all([
        arubaFetchConfig(dev, state.cookie),
        arubaFetchStats(dev, state.cookie),
      ]);
    } catch (err2) {
      state.status    = 'error';
      state.lastError = err2.message;
      console.error(`[${dev.label}] Re-login failed:`, err2.message);
      return;
    }
  }

  const now      = new Date();
  const deltaSec = state.lastPollTime ? (now - state.lastPollTime) / 1000 : null;
  state.lastPollTime = now;
  state.lastPollAt   = now.toISOString();
  state.lastError    = null;

  const rows = [];
  // Iterate over all interfaces returned by the config call (has all fields)
  for (const [ifaceName, iface] of Object.entries(configData)) {
    // Merge statistics from the stats call (may be a nested object or flat)
    const statsIface = statsData[ifaceName] || {};
    const stats      = statsIface.statistics || statsIface || {};
    const rxBytes    = Number(stats.rx_bytes || 0);
    const txBytes    = Number(stats.tx_bytes || 0);

    let rxMbps = 0, txMbps = 0;
    if (deltaSec && deltaSec > 0 && state.lastRx[ifaceName] !== undefined) {
      rxMbps = (Math.max(0, rxBytes - state.lastRx[ifaceName]) * 8) / (deltaSec * 1e6);
      txMbps = (Math.max(0, txBytes - state.lastTx[ifaceName]) * 8) / (deltaSec * 1e6);
    }
    state.lastRx[ifaceName] = rxBytes;
    state.lastTx[ifaceName] = txBytes;

    rows.push({
      sampled_at:  now,
      switch_host: dev.host,
      interface:   ifaceName,
      description: (iface.description || iface.name || '').slice(0, 128),
      link_status: arubaParseStatus(iface),
      speed:       arubaParseSpeed(iface),
      rx_mbps:     rxMbps,
      tx_mbps:     txMbps,
    });
  }

  await storeRows(dev.label, rows);
  state.status = 'ok';
  console.log(`[${dev.label}] Aruba stored ${rows.length} interfaces`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// MIKROTIK SNMP v2c POLLER
// ═══════════════════════════════════════════════════════════════════════════════

function snmpWalk(session, oidPrefix) {
  return new Promise((resolve, reject) => {
    const result = {};
    session.subtree(oidPrefix, 20,
      (varbinds) => {
        for (const vb of varbinds) {
          if (snmp.isVarbindError(vb)) continue;
          // Use substring so the index is always the ifIndex integer,
          // regardless of how many dots are in the prefix
          const idx = vb.oid.substring(oidPrefix.length + 1);
          // net-snmp returns Buffers for OCTET STRING (names/aliases) and
          // plain JS numbers for INTEGER/Gauge32/Counter64 etc.
          // Coerce Buffers to clean UTF-8 strings; leave numbers as-is.
          result[idx] = Buffer.isBuffer(vb.value)
            ? vb.value         // preserve raw Buffer — callers use String() for text OIDs
            : vb.value;
        }
      },
      (err) => { if (err) reject(err); else resolve(result); }
    );
  });
}

function snmpGetSingle(session, oid) {
  return new Promise((resolve, reject) => {
    session.get([{ oid }], (err, varbinds) => {
      if (err) return reject(err);
      if (snmp.isVarbindError(varbinds[0])) return resolve(null);
      resolve(varbinds[0].value);
    });
  });
}

function makeSnmpSession(dev) {
  return snmp.createSession(dev.host, dev.snmpCommunity || 'public', {
    version: snmp.Version2c,
    port:    dev.snmpPort || 161,
    retries: 1,
    timeout: 5000,
  });
}


// Upsert MikroTik sysinfo into DB — called after every successful poll
async function saveMikrotikInfoToDB(dev, info) {
  if (!db) return;
  try {
    await db.execute(`
      INSERT INTO mikrotik_info
        (device_id, switch_host, label, hostname, board_name, firmware,
         soft_id, sys_descr, uptime, contact, location,
         snmp_community, snmp_port, fetched_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,NOW())
      ON DUPLICATE KEY UPDATE
        switch_host=VALUES(switch_host), label=VALUES(label),
        hostname=VALUES(hostname), board_name=VALUES(board_name),
        firmware=VALUES(firmware), soft_id=VALUES(soft_id),
        sys_descr=VALUES(sys_descr), uptime=VALUES(uptime),
        contact=VALUES(contact), location=VALUES(location),
        snmp_community=VALUES(snmp_community), snmp_port=VALUES(snmp_port),
        fetched_at=NOW()
    `, [
      dev.id, dev.host, dev.label,
      info.hostname  || null,
      info.boardName || null,
      info.firmware  || null,
      info.softId    || null,
      info.sysDescr  || null,
      info.uptime    || null,
      info.contact   || null,
      info.location  || null,
      dev.snmpCommunity || 'public',
      dev.snmpPort      || 161,
    ]);
  } catch(e) {
    appLog('warn', 'db', `${dev.label}: failed to save mikrotik_info: ${e.message}`);
  }
}

async function pollMikrotik(dev) {
  const state   = getState(dev.id);
  state.status  = 'polling';
  const session = makeSnmpSession(dev);

  try {
    const now      = new Date();
    const deltaSec = state.lastPollTime ? (now - state.lastPollTime) / 1000 : null;

    // Walk all needed tables in parallel
    const [descrMap, statusMap, speedMap, aliasMap, hcRxMap, hcTxMap] = await Promise.all([
      snmpWalk(session, OID.ifDescr),
      snmpWalk(session, OID.ifOperStatus),
      snmpWalk(session, OID.ifHighSpeed),
      snmpWalk(session, OID.ifAlias),
      snmpWalk(session, OID.ifHCInOctets).catch(() => ({})),
      snmpWalk(session, OID.ifHCOutOctets).catch(() => ({})),
    ]);

    // Fall back to 32-bit counters if 64-bit HC not available
    let rxMap = hcRxMap, txMap = hcTxMap;
    if (!Object.keys(hcRxMap).length) {
      [rxMap, txMap] = await Promise.all([
        snmpWalk(session, OID.ifInOctets),
        snmpWalk(session, OID.ifOutOctets),
      ]);
    }

    state.lastPollTime = now;
    state.lastPollAt   = now.toISOString();
    state.lastError    = null;

    // Log raw values on first successful poll to aid debugging
    if (!state.debugLogged) {
      state.debugLogged = true;
      const sample = Object.keys(descrMap)[0];
      if (sample) {
        console.log(`[${dev.label}] SNMP sample idx=${sample} descr=${JSON.stringify(descrMap[sample])} status=${JSON.stringify(statusMap[sample])} speed=${JSON.stringify(speedMap[sample])}`);
      }
    }

    const rows = [];
    for (const idx of Object.keys(descrMap)) {
      const _dr = descrMap[idx]; const ifaceName = Buffer.isBuffer(_dr) ? _dr.toString('utf8').replace(/\x00/g,'').trim() : String(_dr || `if${idx}`);
      const rxBytes   = Number(rxMap[idx]    || 0);
      const txBytes   = Number(txMap[idx]    || 0);
      // statusMap values are plain integers (1=up, 2=down) after Buffer coercion
      const opStatus  = Number(statusMap[idx] != null ? statusMap[idx] : 2);
      // speedMap: ifHighSpeed in Mbps, already a number
      const speedMbps = Number(speedMap[idx]  || 0);
      const _ar = aliasMap[idx]; const alias = Buffer.isBuffer(_ar) ? _ar.toString('utf8').replace(/\x00/g,'').trim() : String(_ar || '');

      let rxMbps = 0, txMbps = 0;
      if (deltaSec && deltaSec > 0 && state.lastRx[idx] !== undefined) {
        // Handle 64-bit counter wrap
        const rxDelta = rxBytes >= state.lastRx[idx]
          ? rxBytes - state.lastRx[idx]
          : rxBytes + (Number.MAX_SAFE_INTEGER - state.lastRx[idx]);
        const txDelta = txBytes >= state.lastTx[idx]
          ? txBytes - state.lastTx[idx]
          : txBytes + (Number.MAX_SAFE_INTEGER - state.lastTx[idx]);
        rxMbps = (rxDelta * 8) / (deltaSec * 1e6);
        txMbps = (txDelta * 8) / (deltaSec * 1e6);
      }
      state.lastRx[idx] = rxBytes;
      state.lastTx[idx] = txBytes;

      // Skip loopback-style interfaces with no traffic
      if (ifaceName.toLowerCase().startsWith('lo') && rxMbps === 0 && txMbps === 0) continue;

      rows.push({
        sampled_at:  now,
        switch_host: dev.host,
        interface:   ifaceName,
        description: alias.slice(0, 128),
        link_status: opStatus === 1 ? 'up' : 'down',
        speed:       speedMbps ? `${speedMbps}M` : '',
        rx_mbps:     rxMbps,
        tx_mbps:     txMbps,
      });
    }

    await storeRows(dev.label, rows);

    // Fetch and store sysinfo every poll (lightweight — 7 OIDs in one GET)
    try {
      const info = await fetchMikrotikSysinfo(dev);
      await saveMikrotikInfoToDB(dev, info);
      appLog('debug', 'mikrotik', `${dev.label}: sysinfo saved — fw=${info.firmware} board=${info.boardName}`);
    } catch(e) {
      appLog('warn', 'mikrotik', `${dev.label}: sysinfo fetch failed: ${e.message} ${e.stack||''}`);
    }

    state.status = 'ok';
    console.log(`[${dev.label}] SNMP stored ${rows.length} interfaces`);
  } catch (err) {
    state.status    = 'error';
    state.lastError = err.message;
    console.error(`[${dev.label}] SNMP error:`, err.message);
  } finally {
    session.close();
  }
}

async function testSnmp(dev) {
  const session = makeSnmpSession(dev);
  try {
    const name = await snmpGetSingle(session, OID.sysName);
    return { ok: true, message: `Reachable — sysName: ${name || '(empty)'}` };
  } catch (err) {
    return { ok: false, message: err.message };
  } finally {
    session.close();
  }
}

// ─── Shared DB writer ─────────────────────────────────────────────────────────
async function storeRows(label, rows) {
  if (!rows.length || !db) return;
  const sql = `INSERT INTO bandwidth_samples
    (sampled_at, switch_host, interface, description, link_status, speed, rx_mbps, tx_mbps)
    VALUES (:sampled_at, :switch_host, :interface, :description, :link_status, :speed, :rx_mbps, :tx_mbps)`;
  await Promise.all(rows.map(r => db.execute(sql, r)));
  console.log(`[${label}] Stored ${rows.length} samples`);
}

// ─── Unified poll dispatch ────────────────────────────────────────────────────
function pollDevice(dev) {
  return dev.type === 'mikrotik' ? pollMikrotik(dev) : pollAruba(dev);
}

// ─── Poller lifecycle ─────────────────────────────────────────────────────────
function startDevicePoller(dev) {
  const state = getState(dev.id);
  if (state.timer) clearInterval(state.timer);
  if (!dev.enabled) { state.status = 'disabled'; return; }
  const ms = (dev.interval || 30) * 1000;
  console.log(`[poller] ${dev.type}:${dev.label} every ${dev.interval}s`);
  pollDevice(dev).catch(console.error);
  state.timer = setInterval(() => pollDevice(dev).catch(console.error), ms);
}

function stopDevicePoller(id) {
  const state = getState(id);
  if (state.timer) { clearInterval(state.timer); state.timer = null; }
  if (state.cookie) {
    const dev = getDeviceById(id);
    if (dev && dev.type === 'aruba') arubaLogout(dev, state.cookie).catch(() => {});
    state.cookie = null;
  }
  state.status = 'idle';
}

// ─── Topology helpers ─────────────────────────────────────────────────────────
function loadTopo() {
  if (fs.existsSync(TOPO_FILE)) {
    try { return JSON.parse(fs.readFileSync(TOPO_FILE, 'utf8')); }
    catch (e) {}
  }
  return { nodes: {}, links: [] };
}

function saveTopo(topo) {
  fs.writeFileSync(TOPO_FILE, JSON.stringify(topo, null, 2));
}

// ─── Express app ──────────────────────────────────────────────────────────────
const app = express();
app.use(cors({
  credentials: true,
  origin: (origin, cb) => cb(null, true),  // reflect request origin
}));
app.use(express.json());

// Session middleware — uses MySQL session store to survive restarts
// Trust nginx reverse proxy — required for X-Forwarded-Proto detection
app.set('trust proxy', 1);

// Determine if we should use secure cookies
// true  = HTTPS only (set when behind nginx/HTTPS proxy)
// false = allow HTTP (for direct local access without proxy)
const SECURE_COOKIES = process.env.NODE_ENV === 'production';

// MySQL session store — dedicated pool, initialised at startup
// Sessions stored in DB survive service restarts and deploys

const _SessionStore = session.Store;
class MySQLSessionStore extends _SessionStore {
  constructor() {
    super();
    setInterval(() => this._clearExpired(), 15 * 60 * 1000);
  }
  _fmt(ms) { return new Date(ms).toISOString().slice(0,19).replace('T',' '); }
  _clearExpired() {
    pool.execute('DELETE FROM sessions WHERE expires < NOW()').catch(()=>{});
  }
  get(sid, cb) {
    pool.execute(
      'SELECT data FROM sessions WHERE session_id=? AND expires>NOW()', [sid]
    ).then(([rows]) => {
      if (!rows.length) return cb(null, null);
      try { cb(null, JSON.parse(rows[0].data)); } catch(e) { cb(null, null); }
    }).catch(e => cb(e));
  }
  set(sid, data, cb) {
    const exp = this._fmt(
      data?.cookie?.expires ? new Date(data.cookie.expires).getTime() : Date.now() + SESSION_MAX_AGE
    );
    pool.execute(
      `INSERT INTO sessions (session_id, expires, data) VALUES (?,?,?)
       ON DUPLICATE KEY UPDATE expires=VALUES(expires), data=VALUES(data)`,
      [sid, exp, JSON.stringify(data)]
    ).then(() => cb(null)).catch(e => cb(e));
  }
  destroy(sid, cb) {
    pool.execute('DELETE FROM sessions WHERE session_id=?', [sid])
      .then(() => cb(null)).catch(e => cb(e));
  }
  touch(sid, data, cb) {
    const exp = this._fmt(
      data?.cookie?.expires ? new Date(data.cookie.expires).getTime() : Date.now() + SESSION_MAX_AGE
    );
    pool.execute(
      'UPDATE sessions SET expires=? WHERE session_id=?', [exp, sid]
    ).then(() => cb(null)).catch(e => cb(e));
  }
}

app.use(session({
  secret:            SESSION_SECRET,
  resave:            false,
  saveUninitialized: false,
  rolling:           true,
  store:             new MySQLSessionStore(),
  name:              'netmon.sid',
  cookie: {
    httpOnly: true,
    maxAge:   SESSION_MAX_AGE,
    sameSite: 'lax',
    secure:   SECURE_COOKIES,
    path:     '/',
  },
}));

// ── Auth middleware ───────────────────────────────────────────────────────────
const PUBLIC_PATHS = ['/', '/login', '/api/auth/login', '/api/auth/setup-status'];

function requireAuth(req, res, next) {
  if (PUBLIC_PATHS.includes(req.path) || req.path.startsWith('/api/auth/')) return next();
  if (req.session?.userId) return next();
  // Log why auth failed to help diagnose
  const sid = req.session?.id ? req.session.id.slice(0,8) : 'none';
  const cookie = req.headers['cookie'] ? 'present' : 'MISSING';
  appLog('warn', 'auth', `Auth failed: ${req.method} ${req.path} — session=${sid} cookie=${cookie}`);
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Not authenticated', path: req.path });
  }
  res.redirect('/login');
}

function requireAdmin(req, res, next) {
  if (req.session?.role !== 'admin') {
    if (req.path.startsWith('/api/')) return res.status(403).json({ error: 'Admin required' });
    return res.redirect('/login');
  }
  next();
}

// Read-only safe methods — viewers can do GET but not POST/PUT/DELETE
function requireWrite(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  if (req.session?.role === 'admin') return next();
  return res.status(403).json({ error: 'Write access requires admin role' });
}

app.use(requireAuth);

// ── Auth routes ───────────────────────────────────────────────────────────────


const LOGIN_PAGE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Monitor — Login</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;display:flex;align-items:center;justify-content:center;min-height:100vh;color:#e2e8f0}
  .card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:2.5rem;width:100%;max-width:380px}
  h1{font-size:20px;font-weight:700;margin-bottom:.25rem}
  .sub{font-size:13px;color:#64748b;margin-bottom:2rem}
  label{display:block;font-size:12px;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.35rem}
  input{width:100%;padding:.65rem .9rem;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:14px;outline:none;margin-bottom:1.25rem}
  input:focus{border-color:#0ea5e9}
  button{width:100%;padding:.75rem;background:#0ea5e9;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;margin-top:.5rem}
  button:hover{background:#0284c7}
  button:disabled{background:#334155;cursor:not-allowed}
  .err{color:#f87171;font-size:13px;margin-top:.75rem;text-align:center;min-height:20px}
  .brand{display:flex;align-items:center;gap:10px;margin-bottom:1.5rem}
  .brand-dot{width:10px;height:10px;border-radius:50%;background:#0ea5e9}
</style>
</head>
<body>
<div class="card">
  <div class="brand"><div class="brand-dot"></div><h1>Network Monitor</h1></div>
  <div class="sub">Sign in to continue</div>
  <form id="form" onsubmit="doLogin(event)">
    <label>Username</label>
    <input type="text" id="user" autocomplete="username" autocapitalize="none" autofocus>
    <label>Password</label>
    <input type="password" id="pass" autocomplete="current-password">
    <button type="submit" id="btn">Sign in</button>
    <div class="err" id="err"></div>
  </form>
</div>
<script>
async function doLogin(e) {
  e.preventDefault();
  const btn = document.getElementById('btn');
  const err = document.getElementById('err');
  btn.disabled = true; btn.textContent = 'Signing in…'; err.textContent = '';
  try {
    const res = await fetch('/api/auth/login', {
      method:'POST', headers:{'Content-Type':'application/json'},
      credentials: 'include',
      body: JSON.stringify({ username: document.getElementById('user').value,
                             password: document.getElementById('pass').value })
    });
    const data = await res.json();
    if (res.ok) { window.location = '/'; }
    else { err.textContent = data.error || 'Login failed'; btn.disabled=false; btn.textContent='Sign in'; }
  } catch(ex) { err.textContent = 'Connection error'; btn.disabled=false; btn.textContent='Sign in'; }
}
</script>
</body>
</html>`;

app.get('/login', (req, res) => {
  if (req.session?.userId) return res.redirect('/');
  res.send(LOGIN_PAGE_HTML);
});

// Serve the main app
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

app.get('/api/auth/setup-status', async (req, res) => {
  if (!db) return res.json({ ready: false });
  const [[r]] = await db.execute('SELECT COUNT(*) AS n FROM users');
  res.json({ ready: true, hasUsers: r.n > 0 });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  try {
    const [[user]] = await db.execute(
      'SELECT * FROM users WHERE username = ? AND enabled = 1', [username]
    );
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    // Regenerate session to prevent fixation
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Session error' });
      req.session.userId   = user.id;
      req.session.username = user.username;
      req.session.role     = user.role;
      req.session.save((saveErr) => {
        if (saveErr) return res.status(500).json({ error: 'Session save failed: ' + saveErr.message });
        db.execute('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);
        appLog('info', 'auth', `Login: ${username} (${user.role}) secure=${SECURE_COOKIES}`);
        res.json({ ok: true, username: user.username, role: user.role });
      });
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/logout', (req, res) => {
  const username = req.session?.username;
  req.session.destroy(() => {
    appLog('info', 'auth', `Logout: ${username}`);
    res.json({ ok: true });
  });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session?.userId) return res.status(401).json({ error: 'Not authenticated' });
  res.json({ username: req.session.username, role: req.session.role });
});

// ── User management (admin only) ──────────────────────────────────────────────

app.get('/api/auth/users', requireAdmin, async (req, res) => {
  const [rows] = await db.execute(
    'SELECT id, username, role, created_at, last_login, enabled, is_master FROM users ORDER BY username'
  );
  res.json(rows);
});

app.post('/api/auth/users', requireAdmin, async (req, res) => {
  const { username, password, role = 'viewer' } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (!['admin','viewer'].includes(role)) return res.status(400).json({ error: 'Invalid role' });
  try {
    const hash = await bcrypt.hash(password, 12);
    await db.execute(
      'INSERT INTO users (username, password_hash, role) VALUES (?,?,?)',
      [username, hash, role]
    );
    appLog('info', 'auth', `User created: ${username} (${role}) by ${req.session.username}`);
    res.status(201).json({ ok: true });
  } catch(e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Username already exists' });
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/auth/users/:id', requireAdmin, async (req, res) => {
  const { password, role, enabled } = req.body || {};
  const [[user]] = await db.execute('SELECT * FROM users WHERE id = ?', [req.params.id]);
  if (!user) return res.status(404).json({ error: 'User not found' });
  // Cannot demote or disable the master admin via API
  if (user.is_master && (role === 'viewer' || enabled === false || enabled === 0)) {
    return res.status(403).json({ error: 'Cannot demote or disable the master admin account' });
  }
  const updates = [];
  const params  = [];
  if (password) { updates.push('password_hash = ?'); params.push(await bcrypt.hash(password, 12)); }
  if (role)     { updates.push('role = ?');          params.push(role); }
  if (enabled !== undefined) { updates.push('enabled = ?'); params.push(enabled ? 1 : 0); }
  if (!updates.length) return res.status(400).json({ error: 'Nothing to update' });
  params.push(req.params.id);
  await db.execute(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params);
  appLog('info', 'auth', `User updated: ${user.username} by ${req.session.username}`);
  res.json({ ok: true });
});

app.delete('/api/auth/users/:id', requireAdmin, async (req, res) => {
  const [[user]] = await db.execute('SELECT * FROM users WHERE id = ?', [req.params.id]);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.is_master) return res.status(403).json({ error: 'Cannot delete the master admin account' });
  if (user.id === req.session.userId) return res.status(403).json({ error: 'Cannot delete your own account' });
  await db.execute('DELETE FROM users WHERE id = ?', [req.params.id]);
  appLog('info', 'auth', `User deleted: ${user.username} by ${req.session.username}`);
  res.json({ ok: true });
});

app.post('/api/auth/change-password', async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both passwords required' });
  if (newPassword.length < 15) return res.status(400).json({ error: 'Password must be at least 15 characters' });
  const [[user]] = await db.execute('SELECT * FROM users WHERE id = ?', [req.session.userId]);
  const ok = await bcrypt.compare(currentPassword, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Current password incorrect' });
  await db.execute('UPDATE users SET password_hash = ? WHERE id = ?',
    [await bcrypt.hash(newPassword, 12), req.session.userId]);
  appLog('info', 'auth', `Password changed: ${user.username}`);
  res.json({ ok: true });
});

// ── Master admin reset (CLI only) ─────────────────────────────────────────────
// This is deliberately NOT exposed via HTTP — run from server CLI:
//   node reset-admin.js
// Or via env variable at startup:
//   RESET_ADMIN_PASSWORD=newpassword node server.js



// ── Device CRUD ───────────────────────────────────────────────────────────────

// GET /api/switches — list all devices (passwords redacted)
app.get('/api/switches', (req, res) => {
  res.json(devices.map(d => {
    const st = getState(d.id);
    return {
      id: d.id, type: d.type || 'aruba', label: d.label, host: d.host,
      port:          d.port,
      username:      d.username,
      snmpCommunity: d.type === 'mikrotik' ? d.snmpCommunity : undefined,
      snmpPort:      d.type === 'mikrotik' ? (d.snmpPort || 161) : undefined,
      interval: d.interval, enabled: d.enabled,
      status: st.status, lastError: st.lastError, lastPollAt: st.lastPollAt,
    };
  }));
});

// POST /api/switches — add a device
app.post('/api/switches', (req, res) => {
  const { type = 'aruba', label, host, port, username, password,
          snmpCommunity, snmpPort, interval, enabled } = req.body;
  if (!host)
    return res.status(400).json({ error: 'host is required' });
  if (type === 'aruba' && (!username || !password))
    return res.status(400).json({ error: 'username and password required for Aruba devices' });
  if (type === 'mikrotik' && !snmpCommunity)
    return res.status(400).json({ error: 'snmpCommunity required for MikroTik devices' });

  const id  = 'dev_' + Date.now();
  const dev = {
    id, type, label: label || host,
    host, enabled: enabled !== false,
    interval: Math.max(5, parseInt(interval || 30, 10)),
    ...(type === 'aruba'    ? { port: String(port || '443'), username, password } : {}),
    ...(type === 'mikrotik' ? { snmpCommunity, snmpPort: parseInt(snmpPort || 161, 10) } : {}),
  };
  devices.push(dev);
  saveDevices();
  if (dev.enabled) startDevicePoller(dev);
  res.status(201).json({ id, label: dev.label, type: dev.type });
});

// PUT /api/switches/:id — update a device
app.put('/api/switches/:id', (req, res) => {
  const dev = getDeviceById(req.params.id);
  if (!dev) return res.status(404).json({ error: 'Not found' });
  const { label, host, port, username, password,
          snmpCommunity, snmpPort, interval, enabled } = req.body;
  if (label    !== undefined) dev.label    = label;
  if (host     !== undefined) dev.host     = host;
  if (interval !== undefined) dev.interval = Math.max(5, parseInt(interval, 10));
  if (enabled  !== undefined) dev.enabled  = !!enabled;
  if (dev.type === 'aruba') {
    if (port     !== undefined) dev.port     = String(port);
    if (username !== undefined) dev.username = username;
    if (password && password !== '') dev.password = password;
  }
  if (dev.type === 'mikrotik') {
    if (snmpCommunity !== undefined) dev.snmpCommunity = snmpCommunity;
    if (snmpPort      !== undefined) dev.snmpPort      = parseInt(snmpPort, 10);
  }
  saveDevices();
  stopDevicePoller(dev.id);
  if (dev.enabled) startDevicePoller(dev);
  res.json({ ok: true });
});

// DELETE /api/switches/:id
app.delete('/api/switches/:id', (req, res) => {
  const idx = devices.findIndex(d => d.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  stopDevicePoller(req.params.id);
  devices.splice(idx, 1);
  saveDevices();
  res.json({ ok: true });
});

// POST /api/switches/:id/test — verify credentials / SNMP reachability
app.post('/api/switches/:id/test', async (req, res) => {
  const dev = getDeviceById(req.params.id);
  if (!dev) return res.status(404).json({ error: 'Not found' });
  try {
    if (dev.type === 'mikrotik') {
      const result = await testSnmp(dev);
      return res.status(result.ok ? 200 : 400).json(result);
    }
    const cookie = await arubaLogin(dev);
    await arubaLogout(dev, cookie);
    res.json({ ok: true, message: 'Login successful' });
  } catch (err) {
    res.status(400).json({ ok: false, message: err.message });
  }
});

// POST /api/switches/:id/toggle — pause / resume polling
app.post('/api/switches/:id/toggle', (req, res) => {
  const dev = getDeviceById(req.params.id);
  if (!dev) return res.status(404).json({ error: 'Not found' });
  dev.enabled = !dev.enabled;
  saveDevices();
  if (dev.enabled) startDevicePoller(dev);
  else stopDevicePoller(dev.id);
  res.json({ ok: true, enabled: dev.enabled });
});

// ── Data endpoints ────────────────────────────────────────────────────────────

// GET /api/live?switch=id — latest sample per interface
app.get('/api/live', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB not ready' });
    const dev = req.query.switch ? getDeviceById(req.query.switch) : devices[0];
    if (!dev) return res.status(400).json({ error: 'No devices configured' });
    const [rows] = await db.execute(`
      SELECT s.* FROM bandwidth_samples s
      INNER JOIN (
        SELECT interface, MAX(sampled_at) AS latest
        FROM bandwidth_samples WHERE switch_host = ? GROUP BY interface
      ) t ON s.interface = t.interface AND s.sampled_at = t.latest
      WHERE s.switch_host = ? ORDER BY s.interface
    `, [dev.host, dev.host]);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/history?switch=id&interface=x&minutes=60
app.get('/api/history', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB not ready' });
    const dev   = req.query.switch ? getDeviceById(req.query.switch) : devices[0];
    if (!dev)   return res.status(400).json({ error: 'No devices configured' });
    const iface = req.query.interface;
    const mins  = parseInt(req.query.minutes || '60', 10);
    if (!iface) return res.status(400).json({ error: 'interface param required' });
    const [rows] = await db.execute(`
      SELECT sampled_at, rx_mbps, tx_mbps FROM bandwidth_samples
      WHERE switch_host = ? AND interface = ?
        AND sampled_at >= DATE_SUB(NOW(), INTERVAL ? MINUTE)
      ORDER BY sampled_at ASC
    `, [dev.host, iface, mins]);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/summary?switch=id&period=hour|day|week — averages per interface
app.get('/api/summary', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB not ready' });
    const dev = req.query.switch ? getDeviceById(req.query.switch) : devices[0];
    if (!dev) return res.status(400).json({ error: 'No devices configured' });
    const lh = req.query.period === 'week' ? 168 : req.query.period === 'hour' ? 1 : 24;
    const [rows] = await db.execute(`
      SELECT interface, MAX(description) AS description,
        AVG(rx_mbps) AS avg_rx, AVG(tx_mbps) AS avg_tx,
        MAX(rx_mbps) AS peak_rx, MAX(tx_mbps) AS peak_tx,
        COUNT(*) AS samples
      FROM bandwidth_samples
      WHERE switch_host = ? AND sampled_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
      GROUP BY interface ORDER BY (AVG(rx_mbps) + AVG(tx_mbps)) DESC
    `, [dev.host, lh]);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/overview — one aggregate row per device (for the overview tab)
app.get('/api/overview', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB not ready' });
    const lh = req.query.period === 'week' ? 168 : req.query.period === 'hour' ? 1 : 24;
    // Two separate queries:
    // 1. Current state — latest sample per interface for active port count
    // 2. Historical stats — averages/peaks over the selected period
    const [currentRows] = await db.execute(`
      SELECT s.switch_host,
        COUNT(DISTINCT s.interface)                                   AS total_interfaces,
        SUM(CASE WHEN s.link_status = 'up' THEN 1 ELSE 0 END)        AS active_interfaces,
        MAX(s.sampled_at)                                             AS last_seen
      FROM bandwidth_samples s
      INNER JOIN (
        SELECT interface, switch_host, MAX(id) AS max_id
        FROM bandwidth_samples
        GROUP BY interface, switch_host
      ) latest ON s.id = latest.max_id
      GROUP BY s.switch_host
    `);

    const [statsRows] = await db.execute(`
      SELECT
        switch_host,
        ROUND(AVG(rx_mbps), 4) AS avg_rx,
        ROUND(AVG(tx_mbps), 4) AS avg_tx,
        ROUND(MAX(rx_mbps), 4) AS peak_rx,
        ROUND(MAX(tx_mbps), 4) AS peak_tx
      FROM bandwidth_samples
      WHERE sampled_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
      GROUP BY switch_host
    `, [lh]);

    // Merge current state with historical stats
    const statsMap = {};
    statsRows.forEach(r => { statsMap[r.switch_host] = r; });
    const rows = currentRows.map(r => ({
      ...r,
      ...(statsMap[r.switch_host] || { avg_rx:0, avg_tx:0, peak_rx:0, peak_tx:0 }),
    }));
    res.json(rows.map(r => {
      const dev = devices.find(d => d.host === r.switch_host);
      const st  = dev ? getState(dev.id) : null;
      return {
        ...r,
        switch_id:  dev?.id,
        label:      dev?.label || r.switch_host,
        deviceType: dev?.type  || 'aruba',
        pollStatus: st?.status || 'unknown',
        lastError:  st?.lastError || null,
      };
    }));
  } catch (err) { res.status(500).json({ error: err.message }); }
});


// ── MAC address table + ARP table (Aruba CX only) ────────────────────────────
// GET /api/mac-table?switch=id&interface=optional
// Returns: [{ interface, mac, vlan, ip, ip6, type }]
//
// Aruba CX REST endpoints used:
//   GET /rest/v10.10/system/mac-table         — layer-2 MAC table (all VLANs)
//   GET /rest/v10.10/system/vrfs/default/neighbors  — ARP/neighbour table
//
// Both endpoints return a large flat object keyed by compound strings.
// We join them on MAC address to produce a unified per-port client list.

// Fetch VLAN list for a device
async function arubaFetchVlans(dev, cookie) {
  // AOS-CX 10.15 returns /system/vlans as a JSON array of VLAN ID strings: ["1","10","20"]
  // Older firmware returns an object keyed by VLAN ID: {"1":{...},"10":{...}}
  // We handle both.
  const paramVariants = [{}, { depth: 1 }, { depth: 2 }, { attributes: 'id,name' }];

  for (const params of paramVariants) {
    try {
      const res = await axiosDevice.get(`${apiBase(dev)}/system/vlans`, {
        headers: { Cookie: cookie }, params, timeout: 8000,
      });
      if (!res.data) continue;

      // Array format (10.15+): ["1","10","20"]
      if (Array.isArray(res.data) && res.data.length > 0) {
        const ids = res.data.map(String);
        appLog('info', 'mac', `${dev.label}: ${ids.length} VLAN(s) (array format): ${ids.slice(0,10).join(',')}`);
        return ids;
      }

      // Object format (older): {"1":{...},"10":{...}}
      if (typeof res.data === 'object' && !Array.isArray(res.data)) {
        const ids = Object.keys(res.data).filter(k => !isNaN(parseInt(k)));
        if (ids.length > 0) {
          appLog('info', 'mac', `${dev.label}: ${ids.length} VLAN(s) (object format): ${ids.slice(0,10).join(',')}`);
          return ids;
        }
      }
    } catch(e) {
      if (!e.response || e.response.status === 401) throw e;
      if ([400, 404].includes(e.response.status)) continue;
      appLog('warn', 'mac', `${dev.label}: VLAN list HTTP ${e.response.status}`);
    }
  }

  appLog('warn', 'mac', `${dev.label}: could not fetch VLAN list — defaulting to VLAN 1`);
  return ['1'];
}

// Fetch MACs from a single VLAN: GET /system/vlans/{id}/macs
// AOS-CX 10.15 response structure:
//   depth=0/1: { "dynamic,mac": "/rest/.../macs/dynamic,mac" }  — URI refs only
//   depth=2:   { "dynamic,mac": { from, mac_addr, attributes, desired_port... } }
//   depth=4:   { "dynamic,mac": { ..., port: { name:"1/1/1" } } }  — port resolved
// The port field only appears when the entry is fully resolved at higher depth.
// We try depth=4 first, falling back, and finally fetch individual entries.
async function arubaFetchVlanMacs(dev, cookie, vlanId) {
  const paramVariants = [
    { depth: 4 },
    { depth: 3 },
    { depth: 2 },
    { depth: 1 },
    {},
  ];

  for (const params of paramVariants) {
    try {
      const res = await axiosDevice.get(
        `${apiBase(dev)}/system/vlans/${vlanId}/macs`,
        { headers: { Cookie: cookie }, params, timeout: 10000 }
      );
      if (!res.data || typeof res.data !== 'object') continue;
      const entries = Object.entries(res.data);
      if (!entries.length) return {};

      const firstVal = entries[0][1];
      // Skip if still returning URI strings
      if (typeof firstVal === 'string' && firstVal.startsWith('/rest/')) {
        appLog('debug', 'mac', `${dev.label}: VLAN ${vlanId} depth=${params.depth||0} still shallow, trying deeper`);
        continue;
      }

      // Check if any entry has a usable port field
      const hasPort = entries.some(([, e]) =>
        e && typeof e === 'object' && (
          e.port || e.interface || e.egress_port ||
          (e.desired_port && typeof e.desired_port === 'object' && Object.keys(e.desired_port).length)
        )
      );

      if (hasPort) {
        appLog('debug', 'mac', `${dev.label}: VLAN ${vlanId} depth=${params.depth} has port fields (${entries.length} entries)`);
        return res.data;
      }

      // Has entries but no port — log and try deeper
      appLog('debug', 'mac', `${dev.label}: VLAN ${vlanId} depth=${params.depth||0} entries have no port field yet`);
      // Keep this as fallback if nothing better found
      if (params.depth === undefined || params.depth === 0) return res.data;
    } catch(e) {
      if (!e.response || e.response.status === 401) throw e;
      if (e.response.status === 404) return {};
      if (e.response.status === 400) continue;
      return {};
    }
  }

  // Fetch each MAC entry individually — the individual entry endpoint
  // at /system/vlans/{id}/macs/{from},{mac} gives the fully resolved object
  appLog('info', 'mac', `${dev.label}: VLAN ${vlanId} — fetching ${Object.keys((await axiosDevice.get(`${apiBase(dev)}/system/vlans/${vlanId}/macs`,{headers:{Cookie:cookie},params:{},timeout:8000}).catch(()=>({data:{}})))).data || 0} entries individually`);
  try {
    const shallowRes = await axiosDevice.get(
      `${apiBase(dev)}/system/vlans/${vlanId}/macs`,
      { headers: { Cookie: cookie }, params: {}, timeout: 8000 }
    );
    if (!shallowRes.data) return {};
    const keys   = Object.keys(shallowRes.data);
    const result = {};
    const BATCH  = 8;

    for (let i = 0; i < keys.length; i += BATCH) {
      const batch = keys.slice(i, i + BATCH);
      const fetched = await Promise.allSettled(batch.map(key => {
        // key is "dynamic,00:11:22:aa:bb:cc" — encode colons for the URL
        const encoded = key.split(',').map(encodeURIComponent).join(',');
        return axiosDevice.get(
          `${apiBase(dev)}/system/vlans/${vlanId}/macs/${encoded}`,
          { headers: { Cookie: cookie }, params: { depth: 4 }, timeout: 6000 }
        ).then(r => ({ key, data: r.data }));
      }));
      for (const r of fetched) {
        if (r.status === 'fulfilled' && r.value.data) {
          result[r.value.key] = r.value.data;
        }
      }
    }
    if (keys.length > 0) {
      // Log one sample entry so we can see all fields
      const sample = result[keys[0]];
      appLog('debug', 'mac', `${dev.label}: VLAN ${vlanId} individual entry fields: ${Object.keys(sample||{}).join(',')}`);
      appLog('debug', 'mac', `${dev.label}: VLAN ${vlanId} individual sample: ${JSON.stringify(sample).slice(0,400)}`);
    }
    appLog('info', 'mac', `${dev.label}: VLAN ${vlanId} fetched ${Object.keys(result).length} entries individually`);
    return result;
  } catch(e) {
    appLog('warn', 'mac', `${dev.label}: VLAN ${vlanId} individual fetch failed: ${e.message}`);
    return {};
  }
}

async function arubaFetchMacTable(dev, cookie) {
  // AOS-CX stores MACs per-VLAN: GET /system/vlans/{id}/macs
  // First fetch the list of configured VLANs, then fetch MACs from each one in parallel.
  try {
    const vlanIds = await arubaFetchVlans(dev, cookie);
    appLog('info', 'mac', `${dev.label}: fetching MACs from ${vlanIds.length} VLAN(s)`);

    const combined = {};
    const BATCH = 10;
    for (let i = 0; i < vlanIds.length; i += BATCH) {
      const batch   = vlanIds.slice(i, i + BATCH);
      const results = await Promise.allSettled(
        batch.map(vid => arubaFetchVlanMacs(dev, cookie, vid).then(data => ({ vid, data })))
      );
      for (const r of results) {
        if (r.status === 'fulfilled' && r.value.data) {
          for (const [key, entry] of Object.entries(r.value.data)) {
            if (entry && typeof entry === 'object') {
              entry.vlan_id = entry.vlan_id || r.value.vid;
              combined[`${r.value.vid},${key}`] = entry;
            }
          }
        }
      }
    }

    appLog('info', 'mac', `${dev.label}: ${Object.keys(combined).length} MAC entries across ${vlanIds.length} VLAN(s)`);
    return combined;
  } catch(e) {
    if (e.response && e.response.status === 401) throw e;
    appLog('warn', 'mac', `${dev.label}: MAC table fetch failed: ${e.message}`);
    return {};
  }
}

// GET /api/mac-table/probe?switch=id — probe MAC table availability
app.get('/api/mac-table/probe', async (req, res) => {
  const dev = req.query.switch ? getDeviceById(req.query.switch) : null;
  if (!dev) return res.status(400).json({ error: 'switch param required' });
  if (dev.type !== 'aruba') return res.status(400).json({ error: 'Aruba CX only' });
  let cookie;
  try { cookie = await getDeviceCookie(dev); }
  catch(e) { return res.status(503).json({ error: e.message }); }

  const report = { device: dev.label, host: dev.host, apiVersion: deviceApiVersion[dev.host], tests: [] };

  // Test global paths
  for (const p of ['/system/mac-table', '/system/mac_table', '/system/l2_mac_table']) {
    const url = `${apiBase(dev)}${p}`;
    const t = { url, status: null, entries: null, error: null };
    try {
      const r = await axiosDevice.get(url, { headers:{ Cookie:cookie }, params:{}, timeout:6000 });
      t.status  = r.status;
      t.entries = typeof r.data === 'object' ? Object.keys(r.data).length : null;
      t.sample  = JSON.stringify(r.data).slice(0, 150);
    } catch(e) { t.status = e.response ? e.response.status : null; t.error = e.message; }
    report.tests.push(t);
  }

  // Test per-VLAN path with VLAN 1
  const vlanUrl = `${apiBase(dev)}/system/vlans/1/macs`;  // tested with depth=2 below
  const vt = { url: vlanUrl, status: null, entries: null, error: null };
  try {
    const r = await axiosDevice.get(vlanUrl, { headers:{ Cookie:cookie }, params:{ depth:2 }, timeout:6000 });
    vt.status  = r.status;
    vt.entries = typeof r.data === 'object' ? Object.keys(r.data).length : null;
    vt.sample  = JSON.stringify(r.data).slice(0, 150);
  } catch(e) { vt.status = e.response ? e.response.status : null; vt.error = e.message; }
  report.tests.push(vt);

  // Also test VLAN list
  const vlistUrl = `${apiBase(dev)}/system/vlans`;
  const lt = { url: vlistUrl, status: null, entries: null, error: null };
  try {
    const r = await axiosDevice.get(vlistUrl, { headers:{ Cookie:cookie }, params:{}, timeout:6000 });
    lt.status  = r.status;
    lt.entries = typeof r.data === 'object' ? Object.keys(r.data).length : null;
    lt.sample  = JSON.stringify(Object.keys(r.data || {}).slice(0,10));
  } catch(e) { lt.status = e.response ? e.response.status : null; lt.error = e.message; }
  report.tests.push(lt);

  res.json(report);
});

async function arubaFetchArpTable(dev, cookie) {
  // ARP neighbours live under each VRF.
  // AOS-CX 10.15 key format for /system/vrfs/default/neighbors:
  //   "ip_address,vrf_name" e.g. "192.168.1.10,default"
  // At depth=0 values are URI strings; depth=2 gives full objects with mac field.
  const combined = {};
  // Try VRF-based neighbors first, then fallback URL patterns
  const urlPatterns = [
    `${apiBase(dev)}/system/vrfs/default/neighbors`,
    `${apiBase(dev)}/system/vrfs/mgmt/neighbors`,
    `${apiBase(dev)}/system/arp`,
    `${apiBase(dev)}/system/arp_table`,
    `${apiBase(dev)}/system/arps`,
  ];
  const paramVariants = [{ depth: 2 }, { depth: 1 }, {}];

  for (const url of urlPatterns) {
    for (const params of paramVariants) {
      try {
        const res = await axiosDevice.get(url, {
          headers: { Cookie: cookie }, params, timeout: 8000,
        });
        if (!res.data || typeof res.data !== 'object') continue;

        const entries = Object.entries(res.data);
        if (!entries.length) continue;  // empty result for this depth — try next depth

        // Skip shallow URI-only responses — need actual objects
        const firstVal = entries[0][1];
        if (typeof firstVal === 'string' && firstVal.startsWith('/rest/')) {
          appLog('debug', 'mac', `${dev.label}: ARP ${url} depth=${params.depth||0} shallow — trying deeper`);
          continue;
        }

        appLog('info', 'mac', `${dev.label}: ARP ${url} depth=${params.depth||0} — ${entries.length} entries, fields: ${Object.keys(firstVal||{}).slice(0,8).join(',')}`);
        Object.assign(combined, res.data);
        break;  // found real data — stop trying params for this URL
      } catch(e) {
        if (!e.response) { appLog('debug','mac',`${dev.label}: ARP ${url} network error`); break; }
        if (e.response.status === 401) throw e;
        if (e.response.status === 400) continue;  // wrong params — try next variant
        // 404/405/410 = URL doesn't exist
        appLog('debug', 'mac', `${dev.label}: ARP ${url} HTTP ${e.response.status}`);
        break;
      }
    }
    if (Object.keys(combined).length > 0) break;  // found data — stop trying URLs
  }

  appLog('debug', 'mac', `${dev.label}: ARP table has ${Object.keys(combined).length} entries`);
  return combined;
}

// Build a mac -> { ip, ip6 } lookup from the ARP/neighbour table.
// AOS-CX 10.15 key: "ip_address,vrf_name" e.g. "192.168.1.10,default"
// Entry fields: ip_address, mac, physical_address, l2_mac, port (URI or object)
function buildArpLookup(arpRaw) {
  const lookup = {};
  for (const [key, entry] of Object.entries(arpRaw)) {
    if (!entry || typeof entry !== 'object') continue;

    // MAC field — try all known field names
    const mac = normaliseMac(
      entry.mac           ||
      entry.l2_mac        ||
      entry.physical_address ||
      entry.mac_addr      ||
      entry.hw_address    ||
      ''
    );
    if (!mac) continue;

    // IP address — prefer entry fields, fall back to extracting from key
    // Key format: "192.168.1.10,default" or just "192.168.1.10"
    const ipFromKey = key.includes(',') ? key.split(',')[0] : key;
    const ip = entry.ip_address || entry.ip || entry.address || ipFromKey || '';

    if (!lookup[mac]) lookup[mac] = { ip: '', ip6: '' };
    if (ip.includes(':') && ip.includes('%') === false && (ip.match(/:/g)||[]).length > 3) {
      // IPv6 (has multiple colons, not a MAC)
      if (!lookup[mac].ip6) lookup[mac].ip6 = ip;
    } else if (ip && !ip.includes(':')) {
      // IPv4
      if (!lookup[mac].ip) lookup[mac].ip = ip;
    }
  }
  appLog('debug', 'mac', `ARP lookup built: ${Object.keys(lookup).length} MAC->IP mappings`);
  return lookup;
}

// Normalise a MAC address to lowercase colon-separated form
// e.g. "001122AABBCC" -> "00:11:22:aa:bb:cc"
//      "00-11-22-aa-bb-cc" -> "00:11:22:aa:bb:cc"
function normaliseMac(raw) {
  if (!raw) return '';
  const clean = String(raw).toLowerCase().replace(/[^0-9a-f]/g, '');
  if (clean.length !== 12) return String(raw).toLowerCase();
  return clean.match(/.{2}/g).join(':');
}

// Extract the interface name from a full REST URI or plain string.
// e.g. "/rest/v10.10/system/interfaces/1%2F1%2F1"  -> "1/1/1"
//      "/rest/v10.15/system/interfaces/1%2F1%2F12" -> "1/1/12"
//      "1%2F1%2F1"                                 -> "1/1/1"
//      "1/1/1"                                     -> "1/1/1"
//      "1/1/12"                                    -> "1/1/12"
function extractIfaceName(raw) {
  if (!raw) return '';
  try {
    const str = String(raw);

    // Full REST URI — the interface name is the last path segment, URL-encoded
    // e.g. .../interfaces/1%2F1%2F12  -> decode just that segment -> "1/1/12"
    const ifaceMatch = str.match(/\/interfaces\/([^?#]+)/);
    if (ifaceMatch) {
      return decodeURIComponent(ifaceMatch[1]);
    }

    // Standalone URI-encoded interface name e.g. "1%2F1%2F12"
    if (str.includes('%2F') || str.includes('%2f')) {
      return decodeURIComponent(str);
    }

    // Already a plain interface name — return as-is
    return str;
  } catch (e) {
    return String(raw);
  }
}



// ── Log endpoint cache ────────────────────────────────────────────────────────
// Remember the working log URL per device so we skip the discovery loop
const deviceLogUrl    = {};   // host -> { url, params }  (working URL+params)
const logResultCache  = {};   // devId -> { entries, fetchedAt }
const LOG_RESULT_TTL  = 30000; // 30 seconds

// ── MAC table server-side cache ───────────────────────────────────────────────
// Caches the full MAC+ARP result per device for MAC_CACHE_TTL_MS milliseconds.
// This prevents session exhaustion when the UI polls frequently or multiple
// users have MAC panels open simultaneously.
const MAC_CACHE_TTL_MS  = 60000;   // 60 seconds for MAC table
const ARP_CACHE_TTL_MS  = 30000;   // 30 seconds for ARP (IPs change more often)
const macTableCache = {};  // devId -> { macRaw, arpRaw, fetchedAt }

async function getCachedMacTable(dev, cookie) {
  const cached = macTableCache[dev.id];
  const now     = Date.now();
  if (cached) {
    const macFresh = (now - cached.fetchedAt)    < MAC_CACHE_TTL_MS;
    const arpFresh = (now - cached.arpFetchedAt) < ARP_CACHE_TTL_MS;
    if (macFresh && arpFresh) {
      appLog('debug', 'mac', `${dev.label}: MAC+ARP from cache (MAC ${Math.round((now-cached.fetchedAt)/1000)}s, ARP ${Math.round((now-cached.arpFetchedAt)/1000)}s)`);
      return { macRaw: cached.macRaw, arpRaw: cached.arpRaw };
    }
    if (macFresh && !arpFresh) {
      // MAC still fresh but ARP needs refresh — only re-fetch ARP
      appLog('debug', 'mac', `${dev.label}: refreshing ARP only (MAC still fresh)`);
      const arpRaw = await arubaFetchArpTable(dev, cookie);
      cached.arpRaw      = arpRaw;
      cached.arpFetchedAt = now;
      appLog('debug', 'mac', `${dev.label}: ARP refreshed — ${Object.keys(arpRaw).length} entries`);
      return { macRaw: cached.macRaw, arpRaw };
    }
  }
  // Fetch both fresh
  const [macRaw, arpRaw] = await Promise.all([
    arubaFetchMacTable(dev, cookie),
    arubaFetchArpTable(dev, cookie),
  ]);
  const fetchedNow = Date.now();
  macTableCache[dev.id] = { macRaw, arpRaw, fetchedAt: fetchedNow, arpFetchedAt: fetchedNow };
  appLog('debug', 'mac', `${dev.label}: MAC table cache refreshed (${Object.keys(macRaw).length} MAC entries, ${Object.keys(arpRaw).length} ARP entries)`);
  return { macRaw, arpRaw };
}

// Invalidate cache for a device (e.g. after topology changes)
function invalidateMacCache(devId) {
  delete macTableCache[devId];
}

app.get('/api/mac-table', async (req, res) => {
  try {
    const dev = req.query.switch ? getDeviceById(req.query.switch) : devices[0];
    if (!dev)            return res.status(400).json({ error: 'No device specified' });
    if (dev.type !== 'aruba') return res.status(400).json({ error: 'MAC table only available for Aruba CX devices' });

    try { await getDeviceCookie(dev); }
    catch(e) { return res.status(503).json({ error: 'Could not log in: ' + e.message }); }
    const cookie = getState(dev.id).cookie;

    // Use cached MAC table if available (60s TTL) to avoid session exhaustion
    const { macRaw, arpRaw } = await getCachedMacTable(dev, cookie);

    const arpLookup = buildArpLookup(arpRaw);
    const filterIface = req.query.interface || null;

    // Per-VLAN MAC entry key format: "dynamic,00:11:22:aa:bb:cc"
    // Entry object fields vary by firmware — log first entry for diagnostics
    const macEntries = Object.entries(macRaw).filter(([,v]) => v && typeof v === 'object');
    if (macEntries.length > 0) {
      const [sampleKey, sampleEntry] = macEntries[0];
      appLog('debug', 'mac', `${dev.label}: sample key="${sampleKey}" fields=${Object.keys(sampleEntry).join(',')}`);
      appLog('debug', 'mac', `${dev.label}: sample entry=${JSON.stringify(sampleEntry).slice(0,300)}`);
    }

    const results = [];
    // Log total entry count and first 3 keys for diagnostics
    appLog('info', 'mac', `${dev.label}: normalising ${macEntries.length} MAC entries`);
    if (macEntries.length > 0) {
      appLog('debug', 'mac', `${dev.label}: first 3 keys: ${macEntries.slice(0,3).map(([k])=>k).join(' | ')}`);
      // Log the port field of the first entry specifically
      const firstEntry = macEntries[0][1];
      const portKeys = Object.keys(firstEntry);
      const portRelated = portKeys.filter(k => k.includes('port') || k.includes('interface') || k.includes('egress'));
      appLog('debug', 'mac', `${dev.label}: port-related fields in first entry: ${portRelated.join(', ')}`);
      for (const pk of portRelated) {
        appLog('debug', 'mac', `${dev.label}: ${pk} = ${JSON.stringify(firstEntry[pk]).slice(0,100)}`);
      }
    }

    for (const [key, entry] of macEntries) {
      // Key format on AOS-CX 10.15 per-VLAN: "vlan,from,mac_addr"
      // e.g. "1,dynamic,00:0c:29:75:70:3f"
      // MAC address contains colons so we can't just split on comma naively.
      // The MAC is always the last 5-colon segment — match it with a regex.
      const keyStr  = String(key);
      const macMatch = keyStr.match(/([0-9a-f]{2}(?::[0-9a-f]{2}){5})$/i);
      const macFromKey  = macMatch ? macMatch[1] : '';
      // Type is the second segment (between first and second comma before the MAC)
      const keyParts    = keyStr.split(',');
      // vlan,type,mac — type is index 1 when there are 3+ parts
      const typeFromKey = keyParts.length >= 3 ? keyParts[1] : keyParts[0];

      const rawMac    = entry.mac_addr || entry.mac || macFromKey || '';
      const vlan      = entry.vlan_id  || entry.vlan || keyParts[0] || '';
      const entryType = entry.entry_type || entry.type || entry.from || typeFromKey || 'dynamic';

      // Extract interface — try every field that could contain port info
      let iface = '';

      // Check all fields for the port — the field name varies by firmware/depth
      const portCandidates = [
        entry.port, entry.interface, entry.from_port,
        entry.egress_port, entry.desired_port, entry.l2_destination,
      ];

      for (const candidate of portCandidates) {
        if (!candidate) continue;

        if (typeof candidate === 'string') {
          // Plain string — could be "1/1/1" or a URI "/rest/.../1%2F1%2F1"
          iface = extractIfaceName(candidate);
          if (iface) break;
        } else if (typeof candidate === 'object') {
          // Object keyed by interface name: { "1/1/1": {...} }
          // OR object with name/uri fields: { name: "1/1/1" }
          // OR URI reference: { uri: "/rest/.../1%2F1%2F1" }
          const keys = Object.keys(candidate);
          if (!keys.length) continue;

          // Check if it looks like a name/uri object
          if (candidate.name) { iface = extractIfaceName(candidate.name); break; }
          if (candidate.uri)  { iface = extractIfaceName(candidate.uri);  break; }
          if (candidate.ifname) { iface = candidate.ifname; break; }

          // Otherwise the first key IS the interface name
          iface = extractIfaceName(keys[0]);
          if (iface) break;
        }
      }

      const mac = normaliseMac(rawMac);

      if (!iface && mac) {
        // Log just the port-related fields to keep log short
        const portInfo = {};
        ['port','interface','from_port','egress_port','desired_port'].forEach(k => {
          if (entry[k] !== undefined) portInfo[k] = typeof entry[k] === 'object'
            ? Object.keys(entry[k]).slice(0,3)
            : entry[k];
        });
        appLog('debug', 'mac', `${dev.label}: no iface for ${mac} portInfo=${JSON.stringify(portInfo)}`);
      }

      if (!mac) continue;

      // Skip CPU/management entries
      if (entryType === 'self' || entryType === 'management' || entryType === 'cpu') continue;

      // Filter by interface if requested — include entries with unknown interface if not filtering
      if (filterIface && iface !== filterIface) continue;
      if (!filterIface && !iface) continue;  // hide unknown-port entries from global list

      const arp = arpLookup[mac] || {};
      results.push({
        interface: iface,
        mac,
        vlan:  String(vlan),
        ip:    arp.ip  || '',
        ip6:   arp.ip6 || '',
        type:  entryType,
      });
    }

    // Sort by interface then MAC
    results.sort((a, b) => a.interface.localeCompare(b.interface) || a.mac.localeCompare(b.mac));
    res.json(results);
  } catch (err) {
    console.error('[mac-table] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});


// ═══════════════════════════════════════════════════════════════════════════════
// SWITCH LOG VIEWER — fetch logs from Aruba CX REST API
// ═══════════════════════════════════════════════════════════════════════════════
//
// AOS-CX log endpoints vary significantly across firmware versions:
//
//  AOS-CX 10.09+  GET /rest/v10.09/logs/event-log
//  AOS-CX 10.10+  GET /rest/v10.10/logs/event-log
//  AOS-CX 10.11+  GET /rest/v10.11/logs/event-log
//  Older builds    GET /rest/v1/logs  or  /rest/v1/system/logs
//
// Some builds return a JSON array, others wrap it in { result: [] } or
// { entries: [] }.  We try all known variants in order and normalise
// whatever we find into a common shape.

// ── Log endpoint discovery ───────────────────────────────────────────────────
//
// AOS-CX log URL structure by firmware generation:
//
//  10.06 – 10.09   /rest/v10.08/logs/event-log               (array)
//  10.10 – 10.12   /rest/v10.10/logs/event-log               (array or {result:[]})
//  10.13 – 10.14   /rest/v10.13/system/event-log             (object map or array)
//  10.15+          /rest/v10.15/system/event-log             (object map or array)
//                  /rest/v10.15/logs/event-log               (some builds, array)
//  All versions    /rest/v1/system/syslog                    (array, always try)
//  All versions    /rest/v1/logs                             (legacy fallback)
//
// The object-map shape (10.13+) is:
//   { "0": {timestamp,severity,...}, "1": {...}, ... }
// We detect this and convert to an array.

// All candidate URLs to probe, ordered from newest to oldest.
// Each entry: { url, params }
// We stop at the first URL that returns a non-empty response.
// The AOS-CX 6000/8xxx on 10.13+ uses /system/event-log with specific params.
// The 400 error means the endpoint exists but rejects our query parameters.
// AOS-CX REST API for event-log accepts these params depending on version:
//   limit / count / num_of_logs / offset / since / until / priority / subsystem
// We try multiple param combinations to find what this firmware accepts.
// Known AOS-CX log endpoint paths by firmware:
//   <= 10.12   /rest/vX/logs/event-log      (depth + count params)
//   10.13-10.14 /rest/vX/system/event-log   (limit or count params)
//   10.15+     /rest/vX/logs/event          (NO params needed — returns all)
//              /rest/vX/system/event-log    (limit param)
function buildLogCandidates(host, port, limit, severity) {
  const base = `https://${host}:${port}/rest`;
  const candidates = [];
  const versions      = ['v10.16','v10.15','v10.14','v10.13','v10.12','v10.11','v10.10','v10.09','v10.08'];
  const newVersions   = ['v10.16','v10.15','v10.14','v10.13'];
  const oldVersions   = ['v10.12','v10.11','v10.10','v10.09','v10.08'];
  const sevP          = severity ? { priority:severity } : {};
  const sevA          = severity ? { severity }          : {};
  const sevF          = severity ? { facility:severity } : {};

  // ── /logs/event  (10.15+ confirmed working, no params needed) ──────────────
  for (const v of versions) {
    candidates.push({ url:`${base}/${v}/logs/event`,       params:{} });
    candidates.push({ url:`${base}/${v}/logs/event`,       params:{ limit, ...sevA } });
    candidates.push({ url:`${base}/${v}/logs/event`,       params:{ count:limit, ...sevA } });
  }

  // ── /system/event-log  (10.13+, various param names) ──────────────────────
  for (const v of newVersions) {
    candidates.push({ url:`${base}/${v}/system/event-log`, params:{ limit, ...sevP } });
    candidates.push({ url:`${base}/${v}/system/event-log`, params:{ limit, ...sevA } });
    candidates.push({ url:`${base}/${v}/system/event-log`, params:{ count:limit } });
    candidates.push({ url:`${base}/${v}/system/event-log`, params:{ num_of_logs:limit } });
    candidates.push({ url:`${base}/${v}/system/event-log`, params:{} });
  }

  // ── /logs/event-log  (10.08-10.12) ─────────────────────────────────────────
  for (const v of oldVersions) {
    candidates.push({ url:`${base}/${v}/logs/event-log`,   params:{ depth:1, count:limit, ...sevA } });
    candidates.push({ url:`${base}/${v}/logs/event-log`,   params:{ depth:1, limit, ...sevA } });
    candidates.push({ url:`${base}/${v}/logs/event-log`,   params:{ depth:1 } });
  }

  return candidates;
}

// Unwrap whatever response shape AOS-CX returns into a plain array
// unwrapLogResponse returns:
//   Array  — valid log entries (may be empty if no recent events)
//   null   — unrecognised response shape, keep trying other URLs
//
// AOS-CX 10.15 /logs/event returns a pagination envelope when called without
// an offset: {"total":483,"filtered":483}
// The actual entries come back when fetched with offset/cursor params.
// We detect this envelope and signal the caller to use pagination.
const LOG_PAGINATION_SENTINEL = Symbol('pagination');

function unwrapLogResponse(raw) {
  if (raw === null || raw === undefined) return null;
  // Plain array — most common
  if (Array.isArray(raw)) return raw;
  // Wrapped arrays — various field names across firmware versions
  if (Array.isArray(raw.result))   return raw.result;
  if (Array.isArray(raw.entries))  return raw.entries;
  if (Array.isArray(raw.logs))     return raw.logs;
  if (Array.isArray(raw.events))   return raw.events;
  // AOS-CX 10.15 /logs/event format: {"entityCounts":{"total":N,"filtered":N},"entities":[...]}
  if (Array.isArray(raw.entities)) return raw.entities;
  // Old pagination envelope: {"total":N,"filtered":N} without entities — needs params (skip)
  if (typeof raw === 'object' && raw !== null) {
    if (typeof raw.total === 'number' && typeof raw.filtered === 'number' &&
        !raw.entities && !raw.result && !raw.entries) {
      return LOG_PAGINATION_SENTINEL;
    }
    // Object map shape: {"0":{...},"1":{...}}
    const vals = Object.values(raw);
    if (vals.length && typeof vals[0] === 'object' && vals[0] !== null) {
      const first = vals[0];
      if (first.message || first.description || first.msg ||
          first.severity || first.level || first.timestamp || first.time) {
        return vals;
      }
    }
    // Empty object {} — valid empty response
    if (vals.length === 0) return [];
  }
  return null;
}

// Fetch audit or accounting logs — these live at fixed paths with no version discovery needed.
// AOS-CX exposes them at /rest/vX/logs/audit and /rest/vX/logs/accounting
async function fetchArubaSimpleLog(dev, cookie, logType, limit) {
  const versions = ['v10.16','v10.15','v10.14','v10.13','v10.12','v10.11','v10.10','v10.09','v10.08'];
  const paramVariants = [
    {},
    { limit },
    { count: limit },
    { num_of_logs: limit },
    { depth: 1 },
    { depth: 1, count: limit },
  ];

  for (const ver of versions) {
    const url = `https://${dev.host}:${dev.port}/rest/${ver}/logs/${logType}`;
    for (const params of paramVariants) {
      try {
        appLog('debug', 'switch-logs', `Trying ${logType}: ${url} params:${JSON.stringify(params)}`);
        const resp = await axiosDevice.get(url, {
          headers: { Cookie: cookie },
          params,
          timeout: 10000,
        });
        const entries = unwrapLogResponse(resp.data);
        if (entries !== null) {
          appLog('info', 'switch-logs', `${dev.label}: ${logType} log found at ${url} (${entries.length} entries)`);
          return { url, entries: entries || [] };
        }
        // 200 but unrecognised shape — return empty rather than fail
        if (resp.data !== null && resp.data !== undefined) {
          return { url, entries: [] };
        }
      } catch(e) {
        if (!e.response) throw e;
        const status = e.response.status;
        if (status === 401) throw e;
        if ([400, 404, 405, 410].includes(status)) break; // wrong params or missing — try next version
        appLog('debug', 'switch-logs', `${url} HTTP ${status}`);
      }
    }
  }
  return null;
}

// Fetch a single log URL, handling pagination envelope
async function fetchLogUrl(dev, cookie, url, params, limit) {
  const resp = await axiosDevice.get(url, {
    headers: { Cookie: cookie }, params, timeout: 10000,
  });
  const entries = unwrapLogResponse(resp.data);

  if (entries === LOG_PAGINATION_SENTINEL) {
    appLog('info', 'switch-logs', `${dev.label}: paginated endpoint (${resp.data.total} total entries available)`);
    for (const limitKey of ['limit', 'count']) {
      const r = await axiosDevice.get(url, {
        headers: { Cookie: cookie },
        params:  { offset: 0, [limitKey]: limit },
        timeout: 10000,
      });
      const e = unwrapLogResponse(r.data);
      if (e && e !== LOG_PAGINATION_SENTINEL) return { entries: e, limitKey };
    }
    return null;
  }
  return entries !== null ? { entries } : null;
}

async function fetchArubaLogs(dev, cookie, limit, severity) {
  // If we already know the working URL for this switch, go straight to it
  const known = deviceLogUrl[dev.host];
  if (known) {
    try {
      const sevParam = severity ? { severity } : {};
      const result = await fetchLogUrl(dev, cookie, known.url,
        { ...known.params, ...sevParam }, limit);
      if (result) {
        appLog('info', 'switch-logs', `${dev.label}: ${result.entries.length} entries from cached URL`);
        return { url: known.url, entries: result.entries };
      }
      appLog('warn', 'switch-logs', `${dev.label}: cached log URL no longer works, rediscovering`);
      delete deviceLogUrl[dev.host];
    } catch(e) {
      if (e.response && e.response.status === 401) throw e;
      delete deviceLogUrl[dev.host];
    }
  }

  // Discovery: try each candidate until one works
  const candidates = buildLogCandidates(dev.host, dev.port, limit, severity);
  for (const { url, params } of candidates) {
    try {
      const result = await fetchLogUrl(dev, cookie, url, params, limit);
      if (result) {
        // Cache working URL (without severity so it works for all filter combos)
        deviceLogUrl[dev.host] = { url, params: result.limitKey ? { [result.limitKey]: limit } : {} };
        appLog('info', 'switch-logs', `${dev.label}: discovered log URL ${url} (${result.entries.length} entries)`);
        return { url, entries: result.entries };
      }
    } catch(e) {
      if (!e.response) continue;
      if (e.response.status === 401) throw e;
      if ([400, 404, 405, 410, 403].includes(e.response.status)) continue;
    }
  }
  return null;
}


// Normalise a raw log entry into a consistent shape regardless of firmware
// Syslog PRIORITY values (RFC 5424)
const SYSLOG_PRIORITY = { '0':'emergency','1':'alert','2':'critical','3':'error',
                           '4':'warning','5':'notice','6':'info','7':'debug' };

function normaliseLogEntry(e) {
  // AOS-CX 10.15 /logs/event returns systemd journal entries with these fields:
  //   __REALTIME_TIMESTAMP  — microseconds since epoch (string)
  //   MESSAGE               — log message text
  //   PRIORITY              — syslog priority 0-7 (string)
  //   SYSLOG_IDENTIFIER     — process/daemon name
  //   _HOSTNAME             — switch hostname
  //   SYSLOG_FACILITY       — facility number
  //   _SYSTEMD_UNIT         — systemd unit name

  // Timestamp — __REALTIME_TIMESTAMP is microseconds, divide by 1000 for ms
  let ts = '';
  const rts = e.__REALTIME_TIMESTAMP || e._SOURCE_REALTIME_TIMESTAMP;
  if (rts) {
    const ms = Math.floor(Number(rts) / 1000);
    ts = new Date(ms).toISOString();
  } else {
    const rawTs = e.timestamp || e.time || e.date || e.event_time || e.created_at || '';
    if (typeof rawTs === 'number') {
      ts = new Date(rawTs > 1e10 ? rawTs : rawTs * 1000).toISOString();
    } else if (rawTs && !isNaN(Number(rawTs))) {
      const n = Number(rawTs);
      ts = new Date(n > 1e10 ? n : n * 1000).toISOString();
    } else {
      ts = rawTs;
    }
  }

  // Severity — PRIORITY is a string "0"-"7" in journal format
  const priRaw  = e.PRIORITY || e.severity || e.level || e.priority || '6';
  const sevRaw  = SYSLOG_PRIORITY[String(priRaw)] || String(priRaw).toLowerCase();
  const sevMap  = { err:'error', crit:'critical', emerg:'emergency', warn:'warning' };
  const severity = sevMap[sevRaw] || sevRaw;

  // Category — SYSLOG_IDENTIFIER is the daemon/process name
  const category = e.SYSLOG_IDENTIFIER || e.subsystem || e.daemon || e.process ||
                   e.category || e.facility || e._SYSTEMD_UNIT || '';

  // Message
  const message = e.MESSAGE || e.message || e.description || e.msg || e.text || '';

  // Source / host
  const source = e._HOSTNAME || e.source || e.origin || e.host || '';

  return { timestamp: ts, severity, category: String(category), message: String(message), source: String(source), event_id: '' };
}


// GET /api/switch-logs/probe?switch=id
// Tries every known log URL and reports exactly what each one returns.
// Confirmed working on AOS-CX 10.15: GET /rest/v10.15/logs/event (no params)
// Use this to diagnose why log fetching is failing on a particular switch.
app.get('/api/switch-logs/probe', async (req, res) => {
  const dev = req.query.switch ? getDeviceById(req.query.switch) : null;
  if (!dev)              return res.status(400).json({ error: 'switch param required' });
  if (dev.type !== 'aruba') return res.status(400).json({ error: 'Aruba CX only' });

  let cookie;
  try { cookie = await getDeviceCookie(dev); }
  catch(e) { return res.status(503).json({ error: 'Login failed: ' + e.message }); }

  const candidates = buildLogCandidates(dev.host, dev.port, 5, '');
  const report = [];

  for (const { url, params } of candidates) {
    const entry = { url, params, status: null, shape: null, sample: null, error: null };
    try {
      const resp = await axiosDevice.get(url, {
        headers: { Cookie: cookie },
        params,
        timeout: 6000,
      });
      entry.status = resp.status;
      const raw = resp.data;
      // Describe the shape of what came back
      if (Array.isArray(raw)) {
        entry.shape  = `array[${raw.length}]`;
        entry.sample = raw[0] ? JSON.stringify(raw[0]).slice(0, 300) : '(empty array)';
      } else if (raw && typeof raw === 'object') {
        const keys = Object.keys(raw);
        entry.shape  = `object{${keys.slice(0,5).join(',')}}`;
        const firstVal = Object.values(raw)[0];
        entry.sample = firstVal ? JSON.stringify(firstVal).slice(0, 300) : '(empty object)';
      } else {
        entry.shape  = typeof raw;
        entry.sample = String(raw).slice(0, 200);
      }
      // Report whether our unwrapper would succeed
      const unwrapped = unwrapLogResponse(raw);
      entry.wouldParse = unwrapped ? `yes — ${unwrapped.length} entries` : 'no — unrecognised shape';
    } catch(e) {
      entry.status = e.response ? e.response.status : null;
      entry.error  = e.message;
      // Capture 400 response body — it often says exactly which param is wrong
      if (e.response && e.response.status === 400 && e.response.data) {
        entry.errorBody = JSON.stringify(e.response.data).slice(0, 500);
      }
    }
    report.push(entry);
    // Stop after first successful parse so the useful one is visible at the top
    // (but continue to gather all results for diagnostics)
  }

  // Also fetch the system resource to confirm firmware version
  let firmwareInfo = null;
  try {
    const sysResp = await axiosDevice.get(
      `${apiBase(dev)}/system`,
      { headers: { Cookie: cookie }, params: { attributes: 'software_version,hostname,platform_name' }, timeout: 5000 }
    );
    firmwareInfo = sysResp.data;
  } catch(e) {
    // Try newer path
    try {
      const sysResp = await axiosDevice.get(
        `${apiBase(dev)}/system`,
        { headers: { Cookie: cookie }, params: { attributes: 'software_version,hostname,platform_name' }, timeout: 5000 }
      );
      firmwareInfo = sysResp.data;
    } catch(e2) {}
  }

  res.json({
    device:   dev.label,
    host:     dev.host,
    firmware: firmwareInfo,
    probed:   report.length,
    results:  report,
  });
});

// GET /api/switch-logs?switch=id&type=event|audit|accounting&severity=&search=&limit=200
app.get('/api/switch-logs', async (req, res) => {
  const dev = req.query.switch ? getDeviceById(req.query.switch) : null;
  if (!dev)              return res.status(400).json({ error: 'switch param required' });
  if (dev.type !== 'aruba') return res.status(400).json({ error: 'Switch logs only available for Aruba CX devices' });

  const limit    = Math.min(parseInt(req.query.limit    || 500),  5000);
  const severity = (req.query.severity || '').toLowerCase();
  const category = (req.query.category || '').toLowerCase();
  const search   = (req.query.search   || '').toLowerCase();
  const since    = req.query.since ? new Date(req.query.since) : null;

  if (!db) return res.status(503).json({ error: 'DB not ready' });

  try {
    // Build query with filters
    let where = ['device_id = ?'];
    const params = [dev.id];

    if (severity) { where.push('severity = ?'); params.push(severity); }
    if (since)    { where.push('log_timestamp >= ?'); params.push(since); }
    if (category) { where.push('category LIKE ?'); params.push('%' + category + '%'); }
    if (search)   {
      where.push('(message LIKE ? OR category LIKE ? OR source LIKE ?)');
      params.push('%'+search+'%', '%'+search+'%', '%'+search+'%');
    }

    const [rows] = await db.execute(
      `SELECT log_timestamp AS timestamp, severity, category, message, source
       FROM switch_logs
       WHERE ${where.join(' AND ')}
       ORDER BY log_timestamp DESC
       LIMIT ${limit}`,
      params
    );

    // Return in same shape as before
    const entries = rows.map(r => ({
      timestamp: r.timestamp instanceof Date ? r.timestamp.toISOString() : r.timestamp,
      severity:  r.severity,
      category:  r.category,
      message:   r.message,
      source:    r.source,
    }));

    res.json(entries);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});


// ═══════════════════════════════════════════════════════════════════════════════
// APPLICATION LOG VIEWER
// ═══════════════════════════════════════════════════════════════════════════════

// GET /api/app-logs?level=&category=&search=&limit=500&since=ISO_DATE
app.get('/api/app-logs', (req, res) => {
  const limit    = Math.min(parseInt(req.query.limit||500), MAX_LOG_LINES);
  const level    = (req.query.level    || '').toLowerCase();
  const category = (req.query.category || '').toLowerCase();
  const search   = (req.query.search   || '').toLowerCase();
  const since    = req.query.since ? new Date(req.query.since) : null;

  let entries = [...appLogBuffer];

  if (level)    entries = entries.filter(e => e.level === level);
  if (category) entries = entries.filter(e => e.category.toLowerCase().includes(category));
  if (search)   entries = entries.filter(e => e.message.toLowerCase().includes(search));
  if (since)    entries = entries.filter(e => new Date(e.ts) >= since);

  // Return most recent first
  entries = entries.slice().reverse().slice(0, limit);
  res.json(entries);
});

// GET /api/app-logs/categories — list distinct log categories seen
app.get('/api/app-logs/categories', (req, res) => {
  const cats = [...new Set(appLogBuffer.map(e => e.category))].sort();
  res.json(cats);
});


// ═══════════════════════════════════════════════════════════════════════════════
// DEVICE SEARCH — find which switch port a MAC or IP is connected to
// ═══════════════════════════════════════════════════════════════════════════════
//
// GET /api/search?q=<mac or ip>
//
// Searches ALL configured Aruba CX switches in parallel.
// For each switch it fetches:
//   - MAC table  (/system/mac-table)
//   - ARP table  (/system/vrfs/*/neighbors)
// Then matches the query against every entry and returns every hit with
// the switch name, host, port, VLAN, IP, and MAC.

// Normalise an IP address string for comparison (strip leading zeros etc.)
function normaliseIP(raw) {
  if (!raw) return '';
  return String(raw).trim().toLowerCase();
}

// Return true if query matches this MAC/IP entry
function entryMatchesQuery(entry, queryMac, queryIP) {
  if (queryMac && entry.mac === queryMac) return true;
  if (queryIP  && normaliseIP(entry.ip)  === queryIP) return true;
  if (queryIP  && normaliseIP(entry.ip6) === queryIP) return true;
  return false;
}

// Search one Aruba switch — returns array of match objects
async function searchOneSwitch(dev, queryMac, queryIP) {
  // Reuse existing poller session
  let cookie;
  try { cookie = await getDeviceCookie(dev); }
  catch(e) { appLog('warn', 'search', `${dev.label}: login failed: ${e.message}`); return []; }

  let macRaw, arpRaw;
  try {
    ({ macRaw, arpRaw } = await getCachedMacTable(dev, cookie));
  } catch(e) {
    if (e.response && e.response.status === 401) {
      try {
        cookie = await reloginDevice(dev);
        ({ macRaw, arpRaw } = await getCachedMacTable(dev, cookie));
      } catch(e2) {
        appLog('warn', 'search', `${dev.label}: re-login failed: ${e2.message}`);
        return [];
      }
    } else {
      appLog('warn', 'search', `${dev.label}: fetch failed: ${e.message}`);
      return [];
    }
  }

  const arpLookup = buildArpLookup(arpRaw);
  const hits      = [];

  for (const [, entry] of Object.entries(macRaw || {})) {
    if (!entry || typeof entry !== 'object') continue;

    const rawMac    = entry.mac_addr   || entry.mac        || '';
    const rawPort   = entry.port       || entry.interface  || entry.from_port || '';
    const vlan      = entry.vlan_id    || entry.vlan       || '';
    const entryType = entry.entry_type || entry.type || entry.from || 'dynamic';

    if (entryType === 'self' || entryType === 'management') continue;

    const mac   = normaliseMac(rawMac);
    const iface = extractIfaceName(
      typeof rawPort === 'object'
        ? (rawPort.uri || JSON.stringify(rawPort))
        : rawPort
    );

    if (!mac || !iface) continue;

    const arp = arpLookup[mac] || {};
    const candidate = { mac, iface, vlan: String(vlan), ip: arp.ip || '', ip6: arp.ip6 || '', type: entryType };

    if (entryMatchesQuery(candidate, queryMac, queryIP)) {
      hits.push({
        switchId:    dev.id,
        switchLabel: dev.label,
        switchHost:  dev.host,
        interface:   iface,
        mac,
        vlan:        String(vlan),
        ip:          arp.ip  || '',
        ip6:         arp.ip6 || '',
        entryType,
      });
    }
  }

  // Also search ARP table directly in case the MAC table entry is missing
  // (e.g. device is on a routed VLAN and the L2 entry has aged out)
  if (queryIP) {
    for (const [, entry] of Object.entries(arpRaw || {})) {
      if (!entry || typeof entry !== 'object') continue;
      const ip  = normaliseIP(entry.ip_address || entry.ip || '');
      const mac = normaliseMac(entry.mac || entry.l2_mac || '');
      if (ip !== queryIP && normaliseIP(entry.ipv6_address || '') !== queryIP) continue;
      // Found IP in ARP — now look up the port from MAC table
      const macEntry = Object.values(macRaw || {}).find(m =>
        normaliseMac(m.mac_addr || m.mac || '') === mac
      );
      const rawPort  = macEntry
        ? (macEntry.port || macEntry.interface || macEntry.from_port || '')
        : (entry.port || entry.interface || '');
      const iface    = extractIfaceName(
        typeof rawPort === 'object' ? (rawPort.uri || '') : rawPort
      );
      const vlan     = macEntry ? (macEntry.vlan_id || macEntry.vlan || '') : '';
      // Avoid duplicating a hit already found via MAC table
      const already  = hits.find(h => h.mac === mac && h.switchHost === dev.host);
      if (!already && mac) {
        hits.push({
          switchId:    dev.id,
          switchLabel: dev.label,
          switchHost:  dev.host,
          interface:   iface || '(ARP only — port unknown)',
          mac,
          vlan:        String(vlan),
          ip:          normaliseIP(entry.ip_address || entry.ip || ''),
          ip6:         normaliseIP(entry.ipv6_address || ''),
          entryType:   'arp',
        });
      }
    }
  }

  return hits;
}

// GET /api/search?q=<mac or ip address>
// Search a single MikroTik router via SNMP ARP + neighbor tables
async function searchOneMikrotik(dev, queryMac, queryIP) {
  const cached = mtClientCache[dev.id];
  let clients, lldp;
  if (cached && (Date.now() - cached.fetchedAt) < MT_CLIENT_TTL) {
    clients = cached.clients || [];
    lldp    = cached.lldp    || [];
  } else {
    const session = makeSnmpSession(dev);
    try {
      const [arpMacMap, arpIpMap, ifDescrMap, ifAliasMap,
             mtNbrIpMap, mtNbrMacMap, mtNbrNameMap, mtNbrIfIdxMap] =
        await Promise.allSettled([
          snmpWalk(session, OID.ipNetToMediaPhysAddr),
          snmpWalk(session, OID.ipNetToMediaNetAddr),
          snmpWalk(session, OID.ifDescr),
          snmpWalk(session, OID.ifAlias),
          snmpWalk(session, OID.mtNbrIp),
          snmpWalk(session, OID.mtNbrMac),
          snmpWalk(session, OID.mtNbrName),
          snmpWalk(session, OID.mtNbrIfIdx),
        ]).then(r => r.map(x => x.status === 'fulfilled' ? x.value : {}));
      session.close();

      const ifNameMap = {};
      for (const [idx, name] of Object.entries(ifDescrMap)) {
        const n = Buffer.isBuffer(name) ? name.toString('utf8').replace(/ /g,'').trim() : String(name||idx);
        const a = ifAliasMap[idx];
        const al = Buffer.isBuffer(a) ? a.toString('utf8').replace(/ /g,'').trim() : String(a||'');
        ifNameMap[String(idx)] = al || n || String(idx);
      }

      clients = [];
      const seen = new Set();
      for (const [key, macBuf] of Object.entries(arpMacMap)) {
        const mac = normaliseMac(bufToMac(macBuf) || '');
        if (!mac || seen.has(mac)) continue;
        if (parseInt(mac.split(':')[0],16) & 0x01) continue;
        seen.add(mac);
        const ifIdx = String(key).split('.')[0];
        const ip    = arpIpMap[key] ? String(arpIpMap[key]) : '';
        clients.push({ interface: ifNameMap[ifIdx]||ifIdx, mac, ip, source:'arp' });
      }
      lldp = [];
      for (const [idx, ip] of Object.entries(mtNbrIpMap)) {
        const macBuf  = mtNbrMacMap[idx];
        const mac     = normaliseMac(bufToMac(macBuf)||'');
        const sysName = Buffer.isBuffer(mtNbrNameMap[idx]) ? mtNbrNameMap[idx].toString('utf8').trim() : String(mtNbrNameMap[idx]||'');
        const ifIdx   = String(mtNbrIfIdxMap[idx]||'');
        lldp.push({ interface: ifNameMap[ifIdx]||ifIdx, sysName, mac, ip: String(ip||'') });
        if (mac && !seen.has(mac)) { seen.add(mac); clients.push({ interface: ifNameMap[ifIdx]||ifIdx, mac, ip: String(ip||''), source:'neighbor' }); }
      }
      mtClientCache[dev.id] = { clients, lldp, fetchedAt: Date.now() };
    } catch(e) {
      try { session.close(); } catch(_) {}
      return [];
    }
  }

  const results = [];
  for (const c of clients) {
    const macMatch = queryMac && normaliseMac(c.mac) === queryMac;
    const ipMatch  = queryIP  && c.ip === queryIP;
    if (!macMatch && !ipMatch) continue;
    results.push({
      switchId:    dev.id,
      switchLabel: dev.label,
      switchHost:  dev.host,
      deviceType:  'mikrotik',
      interface:   c.interface,
      mac:         c.mac,
      ip:          c.ip,
      vlan:        '',
      entryType:   c.source,
    });
  }
  return results;
}

app.get('/api/search', async (req, res) => {
  const raw = (req.query.q || '').trim();
  if (!raw) return res.status(400).json({ error: 'q param required (MAC or IP address)' });

  const isMac = /^([0-9a-f]{2}[:\-.]){5}[0-9a-f]{2}$/i.test(raw) ||
                /^[0-9a-f]{12}$/i.test(raw);
  const isIP  = /^(\d{1,3}\.){3}\d{1,3}$/.test(raw);

  if (!isMac && !isIP) {
    return res.status(400).json({
      error: 'Query must be a MAC address (e.g. 00:11:22:aa:bb:cc) or IP address (e.g. 192.168.1.10)',
    });
  }

  const queryMac = isMac ? normaliseMac(raw) : null;
  const queryIP  = isIP  ? raw.trim()        : null;

  appLog('info', 'search', `Searching for ${isMac ? 'MAC' : 'IP'}: ${raw}`);

  const arubaDevs    = devices.filter(d => d.type === 'aruba'    && d.enabled);
  const mikrotikDevs = devices.filter(d => d.type === 'mikrotik' && d.enabled);

  const [arubaResults, mikrotikResults] = await Promise.all([
    Promise.all(arubaDevs.map(dev => searchOneSwitch(dev, queryMac, queryIP))),
    Promise.all(mikrotikDevs.map(dev => searchOneMikrotik(dev, queryMac, queryIP))),
  ]);

  const flat = [...arubaResults.flat(), ...mikrotikResults.flat()];
  appLog('info', 'search', `Found ${flat.length} result(s) for ${raw} across ${arubaDevs.length+mikrotikDevs.length} device(s)`);

  res.json({
    query:     raw,
    queryType: isMac ? 'mac' : 'ip',
    searched:  arubaDevs.length + mikrotikDevs.length,
    results:   flat,
  });
});




// GET /api/arp-probe?switch=id — find which ARP endpoint works
app.get('/api/arp-probe', async (req, res) => {
  try {
    const dev = req.query.switch ? getDeviceById(req.query.switch) : null;
    if (!dev) return res.status(400).json({ error: 'switch param required' });

    let cookie;
    try { cookie = await getDeviceCookie(dev); }
    catch(e) { return res.status(503).json({ error: 'Login failed: ' + e.message }); }

    // Build URLs using both the discovered version and common fallbacks
    const ver  = deviceApiVersion[dev.host] || 'v10.15';
    const base = `https://${dev.host}:${dev.port}/rest/${ver}`;

    const urlsToTry = [
      `${base}/system/vrfs/default/neighbors`,
      `${base}/system/vrfs/mgmt/neighbors`,
      `${base}/system/arp`,
      `${base}/system/arp_table`,
      `${base}/system/arps`,
      `${base}/system/vlans/1/arp`,
      `${base}/system/vlans/1/arp_entries`,
    ];

    const results = [];
    for (const url of urlsToTry) {
      // Only test one param variant to keep it fast — just no params
      const entry = { url, status: null, entries: null, sample: null, error: null };
      try {
        const r = await axiosDevice.get(url, {
          headers: { Cookie: cookie },
          params:  { depth: 2 },
          timeout: 6000,
        });
        entry.status  = r.status;
        if (r.data && typeof r.data === 'object') {
          entry.entries = Object.keys(r.data).length;
          // Show first entry sample so we can see the field names
          const firstKey   = Object.keys(r.data)[0];
          const firstEntry = r.data[firstKey];
          entry.firstKey   = firstKey;
          entry.fields     = typeof firstEntry === 'object' ? Object.keys(firstEntry) : typeof firstEntry;
          entry.sample     = JSON.stringify(firstEntry).slice(0, 300);
        } else {
          entry.sample = String(r.data).slice(0, 100);
        }
      } catch(e) {
        entry.status = e.response ? e.response.status : null;
        entry.error  = e.message;
        if (e.response && e.response.data) {
          entry.errorBody = JSON.stringify(e.response.data).slice(0, 100);
        }
      }
      results.push(entry);
      // Stop after first successful result with data
      if (entry.entries > 0) break;
    }

    res.json({
      device:     dev.label,
      host:       dev.host,
      apiVersion: ver,
      results,
    });
  } catch(e) {
    res.status(500).json({ error: e.message, stack: e.stack });
  }
});


// ═══════════════════════════════════════════════════════════════════════════════
// SYSTEM INFO — fetch switch hardware and software details
// ═══════════════════════════════════════════════════════════════════════════════
//
// GET /api/sysinfo?switch=id
// Returns hardware details: model, serial, firmware, base MAC, uptime, etc.

// Shared helper — fetch, parse and save sysinfo for one Aruba device.
// Used by both the /api/sysinfo endpoint and the CSV export.
async function fetchAndSaveDeviceSysinfo(dev) {
  const cookie = await getDeviceCookie(dev);
    // Fetch system-level info — try no params first (AOS-CX 10.13+ rejects attributes list),
    // then fall back to depth-based fetch
    let sys = {};
    const sysParamVariants = [
      {},                    // no params — returns full system object on 10.13+
      { depth: 1 },
      { depth: 2 },
      { attributes: 'hostname,software_version,base_mac_address,platform_name' },
    ];
    for (const params of sysParamVariants) {
      try {
        const sysRes = await axiosDevice.get(`${apiBase(dev)}/system`, {
          headers: { Cookie: cookie }, params, timeout: 8000,
        });
        if (sysRes.data && typeof sysRes.data === 'object' &&
            Object.keys(sysRes.data).length > 0) {
          sys = sysRes.data;
          appLog('debug', 'sysinfo', `${dev.label}: system info fetched with params ${JSON.stringify(params)}`);
          break;
        }
      } catch(e) {
        if (!e.response || e.response.status === 401) throw e;
        if (e.response.status === 400) continue;
        throw e;
      }
    }

    // Fetch subsystems for detailed hardware info (chassis, cards, PSUs, fans)
    let subsystems = {};
    const subParamVariants = [{}, { depth: 1 }, { depth: 2 }];
    for (const params of subParamVariants) {
      try {
        const subRes = await axiosDevice.get(`${apiBase(dev)}/system/subsystems`, {
          headers: { Cookie: cookie }, params, timeout: 8000,
        });
        if (subRes.data && typeof subRes.data === 'object') {
          // Check values are full objects not URI strings
          const vals = Object.values(subRes.data);
          if (vals.length && typeof vals[0] === 'string' && vals[0].startsWith('/rest/')) continue;
          subsystems = subRes.data;
          break;
        }
      } catch(e) {
        if (!e.response || e.response.status === 401) throw e;
        if ([400, 404].includes(e.response.status)) continue;
      }
    }

    // Fetch interfaces count
    let ifaceCount = 0;
    try {
      const ifRes = await axiosDevice.get(`${apiBase(dev)}/system/interfaces`, {
        headers: { Cookie: cookie },
        params:  { depth: 1 },
        timeout: 8000,
      });
      ifaceCount = typeof ifRes.data === 'object' ? Object.keys(ifRes.data).length : 0;
    } catch(e) {}

    // Parse subsystem details — chassis, management module, line cards
    const chassis = {};
    const psus    = [];
    const fans    = [];
    const modules = [];

    // Log subsystem keys and first entry to diagnose field names
    const subKeys = Object.keys(subsystems);
    appLog('debug', 'sysinfo', `${dev.label}: subsystem keys: ${subKeys.join(', ')}`);
    if (subKeys.length > 0) {
      const firstSub = subsystems[subKeys[0]];
      appLog('debug', 'sysinfo', `${dev.label}: first subsystem "${subKeys[0]}" fields: ${typeof firstSub === 'object' ? Object.keys(firstSub).join(',') : typeof firstSub}`);
      if (typeof firstSub === 'object') {
        appLog('debug', 'sysinfo', `${dev.label}: first subsystem sample: ${JSON.stringify(firstSub).slice(0,400)}`);
      }
    }

    // If subsystems values are URI strings (shallow), fetch chassis directly
    const firstSubVal = subKeys.length ? subsystems[subKeys[0]] : null;
    if (typeof firstSubVal === 'string' && firstSubVal.startsWith('/rest/')) {
      appLog('debug', 'sysinfo', `${dev.label}: subsystems are shallow URIs — fetching chassis directly`);
      // Try fetching each known chassis key directly
      for (const key of subKeys) {
        try {
          const subRes = await axiosDevice.get(
            `${apiBase(dev)}/system/subsystems/${encodeURIComponent(key)}`,
            { headers: { Cookie: cookie }, params: { depth: 4 }, timeout: 8000 }
          );
          if (subRes.data && typeof subRes.data === 'object') {
            subsystems[key] = subRes.data;
            appLog('debug', 'sysinfo', `${dev.label}: fetched subsystem "${key}" fields: ${Object.keys(subRes.data).join(',')}`);
          }
        } catch(e) {
          appLog('debug', 'sysinfo', `${dev.label}: could not fetch subsystem "${key}": ${e.message}`);
        }
      }
    }

    for (const [key, sub] of Object.entries(subsystems)) {
      if (!sub || typeof sub !== 'object') continue;
      const type = sub.type || sub.subsystem_type || '';

      if (type === 'chassis' || key.toLowerCase().includes('chassis')) {
        // AOS-CX 6000: all hardware details are in the product_info sub-object
        const pi = sub.product_info || {};
        chassis.serialNumber     = pi.serial_number       || sub.serial_number     || sub.serial || '';
        chassis.partNumber       = pi.part_number         || sub.part_number       || sub.part   || '';
        chassis.productName      = pi.product_description || pi.product_name       || sub.product_name || '';
        chassis.productShort     = pi.product_name        || sub.product_name      || '';
        chassis.baseMac          = pi.base_mac_address    || sub.base_mac_address  || '';
        chassis.manufacturer     = pi.vendor              || pi.manufacturer       || sub.manufacturer || '';
        chassis.hardwareRevision = pi.hardware_rev        || sub.hardware_revision || sub.hw_rev || '';
        chassis.numberOfMacs     = pi.number_of_macs      || '';
        appLog('debug', 'sysinfo', `${dev.label}: chassis S/N="${chassis.serialNumber}" part="${chassis.partNumber}" MAC="${chassis.baseMac}"`);
      } else if (type === 'power_supply' || key.toLowerCase().includes('psu') || key.toLowerCase().includes('power')) {
        psus.push({
          name:   sub.name  || key,
          status: sub.status || sub.state || '',
          model:  sub.product_name || sub.product_info?.product_name || sub.model || '',
        });
      } else if (type === 'fan_tray' || key.toLowerCase().includes('fan')) {
        fans.push({
          name:   sub.name || key,
          status: sub.status || sub.state || '',
          speed:  sub.fan_speed || '',
        });
      } else if (type === 'line_card' || type === 'management_module') {
        modules.push({
          name:    sub.name || key,
          type,
          serial:  sub.serial_number || sub.product_info?.serial_number || '',
          product: sub.product_name  || sub.product_info?.product_name  || '',
        });
      }
    }

    // Also try base MAC from system object with more field names
    const rawMacSys = sys.base_mac_address || sys.base_mac || sys.baseMacAddress ||
                      sys.switch_mac || sys.mac_address || '';

    // Parse uptime into human-readable form
    const uptimeSec = typeof sys.uptime === 'number' ? sys.uptime
                    : typeof sys.boot_time === 'number' ? Math.round((Date.now()/1000) - sys.boot_time)
                    : null;
    let uptimeStr = '';
    if (uptimeSec !== null) {
      const d = Math.floor(uptimeSec / 86400);
      const h = Math.floor((uptimeSec % 86400) / 3600);
      const m = Math.floor((uptimeSec % 3600)  / 60);
      uptimeStr = [d && `${d}d`, h && `${h}h`, m && `${m}m`].filter(Boolean).join(' ') || '<1m';
    }

    // Software images — current and backup
    const images = sys.software_images || {};

    // SNMP system info — stored under other_info or directly on system object
    const oi = sys.other_info || {};
    const snmpName     = oi.system_name     || sys.snmp_sysname     || sys.system_name     || sys.hostname || '';
    const snmpLocation = oi.system_location || sys.snmp_syslocation || sys.system_location || sys.location || '';
    const snmpContact  = oi.system_contact  || sys.snmp_syscontact  || sys.system_contact  || sys.contact  || '';

    // Serial number — may be on the system object directly or in chassis subsystem
    const serialNumber = chassis.serialNumber || sys.serial_number || sys.serial || '';

    // Base MAC — prefer chassis product_info which has the accurate switch MAC
    const rawMacSource = chassis.baseMac || rawMacSys || '';
    const baseMacNorm = rawMacSource
      ? rawMacSource.toLowerCase().replace(/[^0-9a-f]/g, '').match(/.{2}/g)?.join(':') || rawMacSource
      : '';

    const infoPayload = {
      hostname:         sys.hostname            || dev.label,
      platform:         sys.platform_name       || chassis.productShort || chassis.productName || '',
      productName:      [chassis.partNumber, chassis.productName].filter(Boolean).join(' ') || sys.platform_name || '',
      productShort:     chassis.productShort   || sys.platform_name   || '',
      softwareVersion:  sys.software_version    || '',
      primaryImage:     images.primary_image    || images.primary   || '',
      secondaryImage:   images.secondary_image  || images.secondary || '',
      baseMac:          baseMacNorm,
      vendor:           chassis.manufacturer || '',
      serialNumber,
      snmpName,
      snmpLocation,
      snmpContact,
      uptime:           uptimeStr,
      uptimeSeconds:    uptimeSec,
      interfaceCount:   ifaceCount,
      chassis,
      psus,
      fans,
      modules,
      managementIp:     sys.mgmt_ip             || '',
      managementIpv6:   sys.mgmt_ipv6           || '',
    };
    // Persist to DB so it's available instantly next time
    saveDeviceInfoToDB(dev.id, dev.label, dev.host, infoPayload).catch(() => {});
  return infoPayload;
}

app.get('/api/sysinfo', async (req, res) => {
  const dev = req.query.switch ? getDeviceById(req.query.switch) : null;
  if (!dev)              return res.status(400).json({ error: 'switch param required' });
  if (dev.type !== 'aruba') return res.status(400).json({ error: 'System info only available for Aruba CX devices' });

  let cookie;
  try { cookie = await getDeviceCookie(dev); }
  catch(e) { return res.status(503).json({ error: 'Login failed: ' + e.message }); }

  try {
    // Fetch system-level info — try no params first (AOS-CX 10.13+ rejects attributes list),
    // then fall back to depth-based fetch
    let sys = {};
    const sysParamVariants = [
      {},                    // no params — returns full system object on 10.13+
      { depth: 1 },
      { depth: 2 },
      { attributes: 'hostname,software_version,base_mac_address,platform_name' },
    ];
    for (const params of sysParamVariants) {
      try {
        const sysRes = await axiosDevice.get(`${apiBase(dev)}/system`, {
          headers: { Cookie: cookie }, params, timeout: 8000,
        });
        if (sysRes.data && typeof sysRes.data === 'object' &&
            Object.keys(sysRes.data).length > 0) {
          sys = sysRes.data;
          appLog('debug', 'sysinfo', `${dev.label}: system info fetched with params ${JSON.stringify(params)}`);
          break;
        }
      } catch(e) {
        if (!e.response || e.response.status === 401) throw e;
        if (e.response.status === 400) continue;
        throw e;
      }
    }

    // Fetch subsystems for detailed hardware info (chassis, cards, PSUs, fans)
    let subsystems = {};
    const subParamVariants = [{}, { depth: 1 }, { depth: 2 }];
    for (const params of subParamVariants) {
      try {
        const subRes = await axiosDevice.get(`${apiBase(dev)}/system/subsystems`, {
          headers: { Cookie: cookie }, params, timeout: 8000,
        });
        if (subRes.data && typeof subRes.data === 'object') {
          // Check values are full objects not URI strings
          const vals = Object.values(subRes.data);
          if (vals.length && typeof vals[0] === 'string' && vals[0].startsWith('/rest/')) continue;
          subsystems = subRes.data;
          break;
        }
      } catch(e) {
        if (!e.response || e.response.status === 401) throw e;
        if ([400, 404].includes(e.response.status)) continue;
      }
    }

    // Fetch interfaces count
    let ifaceCount = 0;
    try {
      const ifRes = await axiosDevice.get(`${apiBase(dev)}/system/interfaces`, {
        headers: { Cookie: cookie },
        params:  { depth: 1 },
        timeout: 8000,
      });
      ifaceCount = typeof ifRes.data === 'object' ? Object.keys(ifRes.data).length : 0;
    } catch(e) {}

    // Parse subsystem details — chassis, management module, line cards
    const chassis = {};
    const psus    = [];
    const fans    = [];
    const modules = [];

    // Log subsystem keys and first entry to diagnose field names
    const subKeys = Object.keys(subsystems);
    appLog('debug', 'sysinfo', `${dev.label}: subsystem keys: ${subKeys.join(', ')}`);
    if (subKeys.length > 0) {
      const firstSub = subsystems[subKeys[0]];
      appLog('debug', 'sysinfo', `${dev.label}: first subsystem "${subKeys[0]}" fields: ${typeof firstSub === 'object' ? Object.keys(firstSub).join(',') : typeof firstSub}`);
      if (typeof firstSub === 'object') {
        appLog('debug', 'sysinfo', `${dev.label}: first subsystem sample: ${JSON.stringify(firstSub).slice(0,400)}`);
      }
    }

    // If subsystems values are URI strings (shallow), fetch chassis directly
    const firstSubVal = subKeys.length ? subsystems[subKeys[0]] : null;
    if (typeof firstSubVal === 'string' && firstSubVal.startsWith('/rest/')) {
      appLog('debug', 'sysinfo', `${dev.label}: subsystems are shallow URIs — fetching chassis directly`);
      // Try fetching each known chassis key directly
      for (const key of subKeys) {
        try {
          const subRes = await axiosDevice.get(
            `${apiBase(dev)}/system/subsystems/${encodeURIComponent(key)}`,
            { headers: { Cookie: cookie }, params: { depth: 4 }, timeout: 8000 }
          );
          if (subRes.data && typeof subRes.data === 'object') {
            subsystems[key] = subRes.data;
            appLog('debug', 'sysinfo', `${dev.label}: fetched subsystem "${key}" fields: ${Object.keys(subRes.data).join(',')}`);
          }
        } catch(e) {
          appLog('debug', 'sysinfo', `${dev.label}: could not fetch subsystem "${key}": ${e.message}`);
        }
      }
    }

    for (const [key, sub] of Object.entries(subsystems)) {
      if (!sub || typeof sub !== 'object') continue;
      const type = sub.type || sub.subsystem_type || '';

      if (type === 'chassis' || key.toLowerCase().includes('chassis')) {
        // AOS-CX 6000: all hardware details are in the product_info sub-object
        const pi = sub.product_info || {};
        chassis.serialNumber     = pi.serial_number       || sub.serial_number     || sub.serial || '';
        chassis.partNumber       = pi.part_number         || sub.part_number       || sub.part   || '';
        chassis.productName      = pi.product_description || pi.product_name       || sub.product_name || '';
        chassis.productShort     = pi.product_name        || sub.product_name      || '';
        chassis.baseMac          = pi.base_mac_address    || sub.base_mac_address  || '';
        chassis.manufacturer     = pi.vendor              || pi.manufacturer       || sub.manufacturer || '';
        chassis.hardwareRevision = pi.hardware_rev        || sub.hardware_revision || sub.hw_rev || '';
        chassis.numberOfMacs     = pi.number_of_macs      || '';
        appLog('debug', 'sysinfo', `${dev.label}: chassis S/N="${chassis.serialNumber}" part="${chassis.partNumber}" MAC="${chassis.baseMac}"`);
      } else if (type === 'power_supply' || key.toLowerCase().includes('psu') || key.toLowerCase().includes('power')) {
        psus.push({
          name:   sub.name  || key,
          status: sub.status || sub.state || '',
          model:  sub.product_name || sub.product_info?.product_name || sub.model || '',
        });
      } else if (type === 'fan_tray' || key.toLowerCase().includes('fan')) {
        fans.push({
          name:   sub.name || key,
          status: sub.status || sub.state || '',
          speed:  sub.fan_speed || '',
        });
      } else if (type === 'line_card' || type === 'management_module') {
        modules.push({
          name:    sub.name || key,
          type,
          serial:  sub.serial_number || sub.product_info?.serial_number || '',
          product: sub.product_name  || sub.product_info?.product_name  || '',
        });
      }
    }

    // Also try base MAC from system object with more field names
    const rawMacSys = sys.base_mac_address || sys.base_mac || sys.baseMacAddress ||
                      sys.switch_mac || sys.mac_address || '';

    // Parse uptime into human-readable form
    const uptimeSec = typeof sys.uptime === 'number' ? sys.uptime
                    : typeof sys.boot_time === 'number' ? Math.round((Date.now()/1000) - sys.boot_time)
                    : null;
    let uptimeStr = '';
    if (uptimeSec !== null) {
      const d = Math.floor(uptimeSec / 86400);
      const h = Math.floor((uptimeSec % 86400) / 3600);
      const m = Math.floor((uptimeSec % 3600)  / 60);
      uptimeStr = [d && `${d}d`, h && `${h}h`, m && `${m}m`].filter(Boolean).join(' ') || '<1m';
    }

    // Software images — current and backup
    const images = sys.software_images || {};

    // SNMP system info — stored under other_info or directly on system object
    const oi = sys.other_info || {};
    const snmpName     = oi.system_name     || sys.snmp_sysname     || sys.system_name     || sys.hostname || '';
    const snmpLocation = oi.system_location || sys.snmp_syslocation || sys.system_location || sys.location || '';
    const snmpContact  = oi.system_contact  || sys.snmp_syscontact  || sys.system_contact  || sys.contact  || '';

    // Serial number — may be on the system object directly or in chassis subsystem
    const serialNumber = chassis.serialNumber || sys.serial_number || sys.serial || '';

    // Base MAC — prefer chassis product_info which has the accurate switch MAC
    const rawMacSource = chassis.baseMac || rawMacSys || '';
    const baseMacNorm = rawMacSource
      ? rawMacSource.toLowerCase().replace(/[^0-9a-f]/g, '').match(/.{2}/g)?.join(':') || rawMacSource
      : '';

    const infoPayload = {
      hostname:         sys.hostname            || dev.label,
      platform:         sys.platform_name       || chassis.productShort || chassis.productName || '',
      productName:      [chassis.partNumber, chassis.productName].filter(Boolean).join(' ') || sys.platform_name || '',
      productShort:     chassis.productShort   || sys.platform_name   || '',
      softwareVersion:  sys.software_version    || '',
      primaryImage:     images.primary_image    || images.primary   || '',
      secondaryImage:   images.secondary_image  || images.secondary || '',
      baseMac:          baseMacNorm,
      vendor:           chassis.manufacturer || '',
      serialNumber,
      snmpName,
      snmpLocation,
      snmpContact,
      uptime:           uptimeStr,
      uptimeSeconds:    uptimeSec,
      interfaceCount:   ifaceCount,
      chassis,
      psus,
      fans,
      modules,
      managementIp:     sys.mgmt_ip             || '',
      managementIpv6:   sys.mgmt_ipv6           || '',
    };
    // Persist to DB so it's available instantly next time
    saveDeviceInfoToDB(dev.id, dev.label, dev.host, infoPayload).catch(() => {});
    res.json(infoPayload);
  } catch(e) {
    appLog('error', 'sysinfo', `${dev.label}: ${e.message}`);
    res.status(500).json({ error: e.message });
  }
});


// GET /api/device-info — return stored device info for all devices (from DB)
// Returns a map of deviceId -> info object
app.get('/api/device-info', async (req, res) => {
  if (!db) return res.status(503).json({ error: 'DB not ready' });
  try {
    const [rows] = await db.execute('SELECT * FROM device_info');
    const result = {};
    for (const row of rows) {
      result[row.device_id] = {
        hostname:        row.hostname,
        platform:        row.platform,
        softwareVersion: row.software_version,
        serialNumber:    row.serial_number,
        baseMac:         row.base_mac,
        snmpName:        row.snmp_name,
        snmpLocation:    row.snmp_location,
        snmpContact:     row.snmp_contact,
        managementIp:    row.management_ip,
        interfaceCount:  row.interface_count,
        primaryImage:    row.primary_image,
        uptimeSeconds:   row.uptime_seconds,
        fetchedAt:       row.fetched_at,
      };
    }
    res.json(result);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});



// ─── MikroTik clients (MAC table + ARP + LLDP) ──────────────────────────────
// GET /api/mikrotik-clients?switch=id&interface=optional
// Returns MAC addresses, IPs and LLDP neighbours per interface

// Convert OID-encoded MAC (6 decimal octets as OID suffix) to colon notation
function oidToMac(oidSuffix) {
  const parts = String(oidSuffix).split('.');
  if (parts.length < 6) return null;
  const hex = parts.slice(-6).map(n => parseInt(n).toString(16).padStart(2,'0'));
  return hex.join(':');
}

// Convert buffer or OID-encoded bytes to MAC string
function bufToMac(buf) {
  if (!buf) return null;
  // Real Buffer (e.g. from direct SNMP get)
  if (Buffer.isBuffer(buf)) {
    if (buf.length < 6) return null;
    return Array.from(buf.slice(0,6)).map(b => b.toString(16).padStart(2,'0')).join(':');
  }
  // String fallback — shouldn't happen with the fixed snmpWalk, but handle anyway
  if (typeof buf === 'string' && buf.length >= 6) {
    // Try parsing as hex pairs
    const clean = buf.replace(/[^0-9a-fA-F]/g, '');
    if (clean.length >= 12) return clean.match(/.{2}/g).slice(0,6).join(':').toLowerCase();
  }
  return null;
}

const mtClientCache = {};  // devId -> { data, fetchedAt }
const MT_CLIENT_TTL = 60000;

app.get('/api/mikrotik-clients', async (req, res) => {
  const dev = req.query.switch ? getDeviceById(req.query.switch) : null;
  if (!dev)                    return res.status(400).json({ error: 'switch param required' });
  if (dev.type !== 'mikrotik') return res.status(400).json({ error: 'MikroTik only' });

  const filterIface = req.query.interface || null;

  // Serve from cache if fresh
  const cached = mtClientCache[dev.id];
  if (cached && (Date.now() - cached.fetchedAt) < MT_CLIENT_TTL) {
    const clients = filterIface ? cached.clients.filter(r => r.interface === filterIface) : cached.clients;
    const lldp    = filterIface ? cached.lldp.filter(r => r.interface === filterIface)    : cached.lldp;
    return res.json({ clients, lldp });
  }

  const session = makeSnmpSession(dev);
  try {
    // Walk tables in parallel — ARP key format: ifIndex.a.b.c.d
    const [
      ifDescrMap, ifAliasMap,
      arpMacMap, arpIpMap,          // ipNetToMediaPhysAddr/NetAddr keyed by ifIdx.ip
      lldpNameMap, lldpPortMap, lldpSysDescMap,
      mtNbrIpMap, mtNbrMacMap, mtNbrNameMap, mtNbrIfIdxMap,
    ] = await Promise.allSettled([
      snmpWalk(session, OID.ifDescr),
      snmpWalk(session, OID.ifAlias),
      snmpWalk(session, OID.ipNetToMediaPhysAddr),
      snmpWalk(session, OID.ipNetToMediaNetAddr),
      snmpWalk(session, OID.lldpRemSysName),
      snmpWalk(session, OID.lldpRemPortDesc),
      snmpWalk(session, OID.lldpRemSysDesc),
      snmpWalk(session, OID.mtNbrIp),
      snmpWalk(session, OID.mtNbrMac),
      snmpWalk(session, OID.mtNbrName),
      snmpWalk(session, OID.mtNbrIfIdx),
    ]).then(results => results.map(r => r.status === 'fulfilled' ? r.value : {}));

    session.close();

    appLog('debug', 'mikrotik', `${dev.label}: arp=${Object.keys(arpMacMap).length} lldp=${Object.keys(lldpNameMap).length} mtNbr=${Object.keys(mtNbrIpMap).length}`);

    // ifIndex -> name — values are now raw Buffers, convert to string
    const ifNameMap = {};
    for (const [idx, name] of Object.entries(ifDescrMap)) {
      const nameStr  = Buffer.isBuffer(name) ? name.toString('utf8').replace(/ /g,'').trim() : String(name || idx);
      const aliasRaw = ifAliasMap[idx];
      const aliasStr = Buffer.isBuffer(aliasRaw) ? aliasRaw.toString('utf8').replace(/ /g,'').trim() : String(aliasRaw || '');
      ifNameMap[String(idx)] = aliasStr || nameStr || String(idx);
    }

    // Log the ifNameMap and first few ARP keys so we can diagnose key format


    // ARP table — key format from snmpWalk suffix of 1.3.6.1.2.1.4.22.1.2:
    // The OID is .ifIndex.a.b.c.d so the suffix key is "ifIndex.a.b.c.d"
    const clients = [];
    const seen    = new Set();

    for (const [key, macBuf] of Object.entries(arpMacMap)) {
      const mac = normaliseMac(bufToMac(macBuf) || '');
      if (!mac || seen.has(mac)) continue;
      if (parseInt(mac.split(':')[0], 16) & 0x01) continue;  // skip multicast
      if (mac === 'ff:ff:ff:ff:ff:ff') continue;

      seen.add(mac);

      // Key is "ifIndex.a.b.c.d" — first dot-separated segment is ifIndex
      const parts = String(key).split('.');
      const ifIdx = parts[0];
      const iface = ifNameMap[ifIdx] || ifIdx;
      const ipRaw = arpIpMap[key];
      // IP may be returned as a string "192.168.1.1" or as an OID-encoded value
      let ip = '';
      if (ipRaw) {
        ip = String(ipRaw);
        // If it looks like an OID (all digits and dots) but not an IP, extract last 4 octets
        if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
          // Already looks like an IP address
        } else if (typeof ipRaw === 'object' && Buffer.isBuffer(ipRaw)) {
          // Buffer — convert to dotted IP
          ip = Array.from(ipRaw.slice(0,4)).join('.');
        }
      }

      clients.push({ interface: iface, mac, ip, source: 'arp' });
    }

    // MikroTik neighbor table — key is a simple index
    // mtNbrIfIdx gives the ifIndex of the local interface
    const lldpRows = [];
    for (const [idx, ip] of Object.entries(mtNbrIpMap)) {
      const macBuf  = mtNbrMacMap[idx];
      const mac     = normaliseMac(bufToMac(macBuf) || '');
      const sysName = Buffer.isBuffer(mtNbrNameMap[idx]) ? mtNbrNameMap[idx].toString('utf8').replace(/ /g,'').trim() : String(mtNbrNameMap[idx] || '');
      const ifIdx   = String(mtNbrIfIdxMap[idx] || '');
      const iface   = ifNameMap[ifIdx] || ifIdx;
      const ipStr   = ip ? String(ip) : '';

      // Add to LLDP neighbours list
      lldpRows.push({ interface: iface, sysName, portDesc: '', sysDesc: '', ip: ipStr, mac });

      // Also add to clients if we have a MAC and it's not already from ARP
      if (mac && !seen.has(mac)) {
        seen.add(mac);
        clients.push({ interface: iface, mac, ip: ipStr, source: 'neighbor' });
      }
    }

    // Standard LLDP neighbours (if available)
    const lldpByPort = {};
    for (const [key, sysName] of Object.entries(lldpNameMap)) {
      const localPort = key.split('.')[0];
      if (!lldpByPort[localPort]) lldpByPort[localPort] = {};
      lldpByPort[localPort].sysName  = Buffer.isBuffer(sysName) ? sysName.toString('utf8').replace(/ /g,'').trim() : String(sysName || '');
      lldpByPort[localPort].portDesc = Buffer.isBuffer(lldpPortMap[key]) ? lldpPortMap[key].toString('utf8').trim() : String(lldpPortMap[key] || '');
      lldpByPort[localPort].sysDesc  = Buffer.isBuffer(lldpSysDescMap[key]) ? lldpSysDescMap[key].toString('utf8').trim() : String(lldpSysDescMap[key] || '');
    }
    for (const [localPort, info] of Object.entries(lldpByPort)) {
      const iface = ifNameMap[localPort] || localPort;
      // Merge with existing MikroTik neighbor entries where possible
      const existing = lldpRows.find(r => r.interface === iface && r.sysName === info.sysName);
      if (!existing) {
        lldpRows.push({ interface: iface, ...info, ip: '', mac: '' });
      } else {
        existing.portDesc = existing.portDesc || info.portDesc;
        existing.sysDesc  = existing.sysDesc  || info.sysDesc;
      }
    }

    appLog('info', 'mikrotik', `${dev.label}: ${clients.length} clients, ${lldpRows.length} neighbours`);
    mtClientCache[dev.id] = { clients, lldp: lldpRows, fetchedAt: Date.now() };

    const outClients = filterIface ? clients.filter(r => r.interface === filterIface) : clients;
    const outLldp    = filterIface ? lldpRows.filter(r => r.interface === filterIface) : lldpRows;
    res.json({ clients: outClients, lldp: outLldp });
  } catch(e) {
    try { session.close(); } catch(_) {}
    appLog('warn', 'mikrotik', `${dev.label}: client table error: ${e.message}`);
    res.status(500).json({ error: e.message });
  }
});

// ─── MikroTik SNMP scanner ────────────────────────────────────────────────────

async function probeMikrotik(ip, community, port) {
  return new Promise(resolve => {
    const session = snmp.createSession(ip, community || 'public', {
      version: snmp.Version2c, port: port || 161, retries: 1, timeout: 3000,
    });
    session.get([
      '1.3.6.1.2.1.1.5.0',   // sysName
      '1.3.6.1.2.1.1.1.0',   // sysDescr
    ], (err, varbinds) => {
      session.close();
      if (err) return resolve({ ok: false });
      const get = i => {
        try {
          const v = varbinds[i];
          if (!v || snmp.isVarbindError(v)) return '';
          return Buffer.isBuffer(v.value) ? v.value.toString('utf8') : String(v.value);
        } catch(e) { return ''; }
      };
      const sysName  = get(0);
      const sysDescr = get(1);
      resolve({ ok: true, sysName: sysName || ip, sysDescr });
    });
  });
}

function loadMtScanConfig() {
  try { return JSON.parse(fs.readFileSync('mt-scan-config.json','utf8')); } catch(e) { return {}; }
}
function saveMtScanConfig(cfg) {
  fs.writeFileSync('mt-scan-config.json', JSON.stringify(cfg, null, 2));
}

async function runMikrotikSubnetScan(subnetEntry, community, snmpPort, pollInterval) {
  const hosts = subnetHosts(subnetEntry.subnet, parseInt(subnetEntry.prefixLen) || 24);
  appLog('info','scan',`MikroTik scan: ${hosts.length} hosts on ${subnetEntry.subnet}/${subnetEntry.prefixLen}`);
  let found = 0, added = 0;
  const BATCH = 30;
  for (let i = 0; i < hosts.length; i += BATCH) {
    const batch = hosts.slice(i, i + BATCH);
    const results = await Promise.all(batch.map(ip => probeMikrotik(ip, community, snmpPort)));
    results.forEach((r, idx) => {
      if (!r.ok) return;
      found++;
      const ip = batch[idx];
      if (devices.find(d => d.host === ip)) return;
      const dev = {
        id:            'dev_' + Date.now() + '_' + Math.random().toString(36).slice(2,6),
        type:          'mikrotik',
        label:         r.sysName || ip,
        host:          ip,
        snmpCommunity: community || 'public',
        snmpPort:      parseInt(snmpPort) || 161,
        interval:      parseInt(pollInterval) || 30,
        enabled:       true,
        discoveredBy:  'scan',
      };
      devices.push(dev);
      saveDevices();
      startDevicePoller(dev);
      added++;
      appLog('info','scan',`MikroTik discovered: ${ip} (${dev.label})`);
    });
  }
  return { subnet: subnetEntry.subnet, prefixLen: subnetEntry.prefixLen, scanned: hosts.length, found, added };
}

app.get('/api/scan/mikrotik-config', (req, res) => res.json(loadMtScanConfig()));

app.put('/api/scan/mikrotik-config', (req, res) => {
  const cfg = loadMtScanConfig();
  Object.assign(cfg, req.body);
  saveMtScanConfig(cfg);
  scheduleMikrotikScan();
  scheduleExport();
  scheduleLogSync();
  scheduleLogPurge();
  scheduleCveCheck();
  // Run CVE check 60s after startup if results file doesn't exist
  if (!fs.existsSync(CVE_RESULTS_FILE)) setTimeout(runCveCheck, 60000);
  res.json({ ok: true });
});

app.post('/api/scan/mikrotik-subnets', (req, res) => {
  const cfg = loadMtScanConfig();
  if (!cfg.subnets) cfg.subnets = [];
  const { subnet, prefixLen = 24, label = '' } = req.body;
  if (!subnet) return res.status(400).json({ error: 'subnet required' });
  const entry = { id: 'mtsn_' + Date.now(), subnet, prefixLen: parseInt(prefixLen), label, enabled: true };
  cfg.subnets.push(entry);
  saveMtScanConfig(cfg);
  res.status(201).json(entry);
});

app.delete('/api/scan/mikrotik-subnets/:id', (req, res) => {
  const cfg = loadMtScanConfig();
  cfg.subnets = (cfg.subnets || []).filter(s => s.id !== req.params.id);
  saveMtScanConfig(cfg);
  res.json({ ok: true });
});

app.post('/api/scan/mikrotik-run', async (req, res) => {
  const cfg     = { ...loadMtScanConfig(), ...req.body };
  const subnets = (cfg.subnets || []).filter(s => s.enabled !== false && s.subnet);
  if (!subnets.length) return res.json({ results:[], scanned:0, found:0, added:0 });
  let total = { scanned:0, found:0, added:0 };
  const results = [];
  for (const entry of subnets) {
    const r = await runMikrotikSubnetScan(entry, cfg.community||'public', cfg.snmpPort||161, cfg.interval||30);
    results.push(r);
    total.scanned += r.scanned; total.found += r.found; total.added += r.added;
  }
  cfg.lastScan = new Date().toISOString();
  saveMtScanConfig(cfg);
  res.json({ ...total, results });
});

let mtScanTimer = null;
function scheduleMikrotikScan() {
  if (mtScanTimer) { clearInterval(mtScanTimer); mtScanTimer = null; }
  const cfg = loadMtScanConfig();
  if (!cfg.enabled || !cfg.scanHours) return;
  const ms = (parseInt(cfg.scanHours) || 6) * 3600 * 1000;
  mtScanTimer = setInterval(async () => {
    const c = loadMtScanConfig();
    for (const entry of (c.subnets||[]).filter(s=>s.enabled!==false)) {
      await runMikrotikSubnetScan(entry, c.community||'public', c.snmpPort||161, c.interval||30);
    }
    c.lastScan = new Date().toISOString();
    saveMtScanConfig(c);
  }, ms);
  appLog('info','scan',`MikroTik auto-scan every ${cfg.scanHours}h`);
}


// ─── MikroTik tools endpoint ─────────────────────────────────────────────────
// GET /api/mikrotik-tools?switch=id
// Returns: sysinfo, routes, arp, neighbours, dhcp leases

const mtToolsCache = {};  // devId -> { data, fetchedAt }
const MT_TOOLS_TTL = 30000;

function bufToStr(v) {
  if (!v) return '';
  if (Buffer.isBuffer(v)) return v.toString('utf8').replace(/ /g,'').trim();
  return String(v);
}

function bufToIp(v) {
  if (!v) return '';
  if (Buffer.isBuffer(v) && v.length >= 4) return Array.from(v.slice(0,4)).join('.');
  if (typeof v === 'string') return v;
  return String(v);
}

function oidSuffixToIp(suffix) {
  // OID suffix like "192.168.1.0" is already dotted decimal
  const parts = String(suffix).split('.');
  if (parts.length >= 4) return parts.slice(-4).join('.');
  return suffix;
}

const ROUTE_TYPE  = { '1':'other','2':'invalid','3':'direct','4':'indirect' };
const ROUTE_PROTO = { '1':'other','2':'local','3':'static','4':'icmp','8':'ospf','9':'bgp','13':'rip','14':'isis' };

app.get('/api/mikrotik-tools', async (req, res) => {
  const dev = req.query.switch ? getDeviceById(req.query.switch) : null;
  if (!dev)                    return res.status(400).json({ error: 'switch param required' });
  if (dev.type !== 'mikrotik') return res.status(400).json({ error: 'MikroTik only' });

  const cached = mtToolsCache[dev.id];
  if (cached && (Date.now() - cached.fetchedAt) < MT_TOOLS_TTL) {
    return res.json(cached.data);
  }

  const session = makeSnmpSession(dev);
  try {
    const [
      ifDescrMap, ifAliasMap,
      routeDestMap, routeIfIdxMap, routeNextHopMap, routeMaskMap, routeTypeMap, routeProtoMap, routeMetricMap,
      arpMacMap, arpIpMap,
      nbrIpMap, nbrMacMap, nbrNameMap, nbrIfIdxMap,
      dhcpAddrMap, dhcpHostMap, dhcpMacMap, dhcpServerMap, dhcpStatusMap,
      sysDescrVal, sysUpTimeVal, sysContactVal, sysLocationVal,
    ] = await Promise.allSettled([
      snmpWalk(session, OID.ifDescr),
      snmpWalk(session, OID.ifAlias),
      snmpWalk(session, OID.ipRouteDest),
      snmpWalk(session, OID.ipRouteIfIndex),
      snmpWalk(session, OID.ipRouteNextHop),
      snmpWalk(session, OID.ipRouteMask),
      snmpWalk(session, OID.ipRouteType),
      snmpWalk(session, OID.ipRouteProto),
      snmpWalk(session, OID.ipRouteMetric),
      snmpWalk(session, OID.ipNetToMediaPhysAddr),
      snmpWalk(session, OID.ipNetToMediaNetAddr),
      snmpWalk(session, OID.mtNbrIp),
      snmpWalk(session, OID.mtNbrMac),
      snmpWalk(session, OID.mtNbrName),
      snmpWalk(session, OID.mtNbrIfIdx),
      snmpWalk(session, OID.mtDhcpServerLeaseAddr),
      snmpWalk(session, OID.mtDhcpServerLeaseHostname),
      snmpWalk(session, OID.mtDhcpServerLeaseMac),
      snmpWalk(session, OID.mtDhcpServerLeaseServer),
      snmpWalk(session, OID.mtDhcpServerLeaseStatus),
      snmpGetSingle(session, OID.sysDescr),
      snmpGetSingle(session, OID.sysUpTime),
      snmpGetSingle(session, OID.sysContact),
      snmpGetSingle(session, OID.sysLocation),
    ]).then(r => r.map(x => x.status === 'fulfilled' ? x.value : (x.reason?.message?.includes('No Such') ? null : null)));

    session.close();

    // Build ifIndex -> interface name map from the walked tables
    const ifNameMap = {};
    for (const [idx, name] of Object.entries(ifDescrMap||{})) {
      const n = Buffer.isBuffer(name) ? name.toString('utf8').replace(/ /g,'').trim() : String(name||idx);
      const a = (ifAliasMap||{})[idx];
      const al = a ? (Buffer.isBuffer(a) ? a.toString('utf8').replace(/ /g,'').trim() : String(a)) : '';
      ifNameMap[String(idx)] = al || n || String(idx);
    }

    // Use shared fetchMikrotikSysinfo for system info (handles firmware, board, etc.)
    const sysinfo = await fetchMikrotikSysinfo(dev);

    // ── Route table ──────────────────────────────────────────────────────────
    const routes = [];
    for (const [key, destRaw] of Object.entries(routeDestMap||{})) {
      const dest    = bufToIp(destRaw) || oidSuffixToIp(key);
      const mask    = bufToIp(routeMaskMap[key]);
      const nextHop = bufToIp(routeNextHopMap[key]);
      const ifIdx   = String(routeIfIdxMap[key] || '');
      const iface   = ifNameMap[ifIdx] || ifIdx;
      const type    = ROUTE_TYPE[String(routeTypeMap[key]||'')] || '';
      const proto   = ROUTE_PROTO[String(routeProtoMap[key]||'')] || '';
      const metric  = routeMetricMap[key] !== undefined ? Number(routeMetricMap[key]) : null;
      if (type === 'invalid') continue;
      routes.push({ dest, mask, nextHop, interface: iface, type, proto, metric });
    }
    routes.sort((a,b) => (a.dest||'').localeCompare(b.dest));

    // ── ARP table ────────────────────────────────────────────────────────────
    const arp = [];
    for (const [key, macBuf] of Object.entries(arpMacMap||{})) {
      const mac   = normaliseMac(bufToMac(macBuf)||'');
      if (!mac) continue;
      const ip    = arpIpMap[key] ? String(arpIpMap[key]) : '';
      const ifIdx = String(key).split('.')[0];
      const iface = ifNameMap[ifIdx] || ifIdx;
      arp.push({ ip, mac, interface: iface });
    }
    arp.sort((a,b) => (a.ip||'').localeCompare(b.ip));

    // ── Neighbours ───────────────────────────────────────────────────────────
    const neighbours = [];
    for (const [idx, ipRaw] of Object.entries(nbrIpMap||{})) {
      const mac     = normaliseMac(bufToMac(nbrMacMap[idx])||'');
      const name    = bufToStr(nbrNameMap[idx]);
      const ifIdx   = String(nbrIfIdxMap[idx]||'');
      const iface   = ifNameMap[ifIdx] || ifIdx;
      neighbours.push({ interface: iface, ip: String(ipRaw||''), mac, name });
    }

    // ── DHCP leases ──────────────────────────────────────────────────────────
    const dhcp = [];
    for (const [key, addrRaw] of Object.entries(dhcpAddrMap||{})) {
      const ip       = bufToIp(addrRaw) || String(addrRaw||'');
      const hostname = bufToStr(dhcpHostMap[key]);
      const mac      = normaliseMac(bufToMac(dhcpMacMap[key])||'');
      const server   = bufToStr(dhcpServerMap[key]);
      const status   = bufToStr(dhcpStatusMap[key]);
      if (!ip) continue;
      dhcp.push({ ip, hostname, mac, server, status });
    }
    dhcp.sort((a,b) => (a.ip||'').localeCompare(b.ip));

    appLog('info','mikrotik',`${dev.label}: tools — ${routes.length} routes, ${arp.length} ARP, ${neighbours.length} neighbours, ${dhcp.length} DHCP leases`);

    const data = { sysinfo, routes, arp, neighbours, dhcp };
    mtToolsCache[dev.id] = { data, fetchedAt: Date.now() };
    res.json(data);
  } catch(e) {
    try { session.close(); } catch(_) {}
    appLog('warn','mikrotik',`${dev.label}: tools error: ${e.message}`);
    res.status(500).json({ error: e.message });
  }
});


// ─── Server status endpoint ───────────────────────────────────────────────────
// GET /api/status — system resources, DB stats, app uptime
app.get('/api/status', async (req, res) => {
  try {
    // ── Node.js / OS resources ───────────────────────────────────────────────
    const memTotal  = os.totalmem();
    const memFree   = os.freemem();
    const memUsed   = memTotal - memFree;
    const memPct    = Math.round(memUsed / memTotal * 100);

    const cpuAvg = os.loadavg();  // [1min, 5min, 15min]
    const cpuCount = os.cpus().length;

    const procMem = process.memoryUsage();
    const uptime  = process.uptime();  // seconds

    // ── Disk space (where the app lives) ─────────────────────────────────────
    let disk = null;
    try {
      const { execSync } = require('child_process');
      const dfOut = execSync(`df -k "${__dirname}"`, { timeout: 3000 }).toString();
      const lines = dfOut.trim().split('\n');
      if (lines.length >= 2) {
        const parts = lines[1].trim().split(/\s+/);
        // df columns: Filesystem 1K-blocks Used Available Use% Mounted
        disk = {
          totalKb: parseInt(parts[1]) || 0,
          usedKb:  parseInt(parts[2]) || 0,
          freeKb:  parseInt(parts[3]) || 0,
          pct:     parseInt(parts[4])  || 0,
          mount:   parts[5] || '/',
        };
      }
    } catch(e) { /* df may not be available */ }

    // ── Database stats ───────────────────────────────────────────────────────
    let dbStats = null;
    if (db) {
      try {
        const dbName = process.env.DB_NAME || 'aruba_monitor';
        // Table row counts and sizes
        const [tables] = await db.execute(`
          SELECT
            table_name,
            table_rows,
            ROUND(data_length / 1024 / 1024, 2)  AS data_mb,
            ROUND(index_length / 1024 / 1024, 2) AS index_mb,
            ROUND((data_length + index_length) / 1024 / 1024, 2) AS total_mb
          FROM information_schema.tables
          WHERE table_schema = ?
          ORDER BY (data_length + index_length) DESC
        `, [dbName]);

        // Total DB size
        const [[totRow]] = await db.execute(`
          SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS total_mb
          FROM information_schema.tables
          WHERE table_schema = ?
        `, [dbName]);

        // Oldest and newest sample
        const [[sampleRange]] = await db.execute(`
          SELECT MIN(sampled_at) AS oldest, MAX(sampled_at) AS newest,
                 COUNT(*) AS total_rows
          FROM bandwidth_samples
        `);

        dbStats = {
          totalMb:   parseFloat(totRow?.total_mb || 0),
          tables:    tables.map(t => ({
            name:    t.table_name,
            rows:    parseInt(t.table_rows) || 0,
            dataMb:  parseFloat(t.data_mb)  || 0,
            indexMb: parseFloat(t.index_mb) || 0,
            totalMb: parseFloat(t.total_mb) || 0,
          })),
          samples: {
            total:   parseInt(sampleRange?.total_rows) || 0,
            oldest:  sampleRange?.oldest || null,
            newest:  sampleRange?.newest || null,
          },
        };
      } catch(e) {
        dbStats = { error: e.message };
      }
    }

    // ── App log stats ─────────────────────────────────────────────────────────
    let logFileSizeKb = 0;
    try {
      const stat = fs.statSync(APP_LOG_FILE);
      logFileSizeKb = Math.round(stat.size / 1024);
    } catch(e) {}

    // Format uptime
    const uptimeSec = Math.floor(uptime);
    const upD = Math.floor(uptimeSec / 86400);
    const upH = Math.floor((uptimeSec % 86400) / 3600);
    const upM = Math.floor((uptimeSec % 3600) / 60);
    const uptimeStr = [upD&&`${upD}d`, upH&&`${upH}h`, upM&&`${upM}m`].filter(Boolean).join(' ') || '<1m';

    res.json({
      app: {
        uptime:    uptimeStr,
        uptimeSec,
        nodeVersion: process.version,
        pid:       process.pid,
        logLines:  appLogBuffer.length,
        logFileSizeKb,
      },
      system: {
        hostname:  os.hostname(),
        platform:  os.platform(),
        arch:      os.arch(),
        cpuModel:  os.cpus()[0]?.model || '',
        cpuCount,
        loadAvg1:  Math.round(cpuAvg[0] * 100) / 100,
        loadAvg5:  Math.round(cpuAvg[1] * 100) / 100,
        loadAvg15: Math.round(cpuAvg[2] * 100) / 100,
        memTotalMb:  Math.round(memTotal  / 1024 / 1024),
        memUsedMb:   Math.round(memUsed   / 1024 / 1024),
        memFreeMb:   Math.round(memFree   / 1024 / 1024),
        memPct,
        procHeapMb:  Math.round(procMem.heapUsed / 1024 / 1024),
        procRssMb:   Math.round(procMem.rss      / 1024 / 1024),
        disk,
      },
      db: dbStats,
      devices: {
        total:   devices.length,
        enabled: devices.filter(d => d.enabled).length,
        aruba:   devices.filter(d => d.type === 'aruba').length,
        mikrotik:devices.filter(d => d.type === 'mikrotik').length,
      },
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});


// ─── CSV Export ───────────────────────────────────────────────────────────────

function loadExportSchedule() {
  try { return JSON.parse(fs.readFileSync(EXPORT_SCHEDULE_FILE, 'utf8')); }
  catch(e) { return { enabled: false, intervalHours: 24, outputDir: EXPORT_DIR, lastExport: null }; }
}
function saveExportSchedule(cfg) {
  fs.writeFileSync(EXPORT_SCHEDULE_FILE, JSON.stringify(cfg, null, 2));
}

// Build CSV for Aruba CX switches — fetches fresh sysinfo from each switch
async function buildArubaCSV() {
  const arubaDevs = devices.filter(d => d.type === 'aruba' && d.enabled);
  appLog('info', 'export', `Fetching sysinfo for ${arubaDevs.length} Aruba device(s) for CSV export`);

  // Fetch fresh sysinfo for all devices in parallel
  const results = await Promise.allSettled(arubaDevs.map(async dev => {
    try {
      const info = await fetchAndSaveDeviceSysinfo(dev);
      return { dev, info };
    } catch(e) {
      appLog('warn', 'export', `${dev.label}: sysinfo failed: ${e.message}`);
      return { dev, info: null };
    }
  }));

  const headers = ['Label','Hostname','Management IP','Product','Firmware Version',
                   'Serial Number','Base MAC','SNMP Name','Location','Contact',
                   'Interface Count','Last Updated'];

  const csvRows = results.map(r => {
    if (r.status !== 'fulfilled') return [];
    const { dev, info } = r.value;
    const i = info || {};
    const ch = i.chassis || {};
    return [
      dev.label,
      i.hostname         || '',
      i.managementIp     || '',
      i.productName      || i.platform || '',
      i.softwareVersion  || '',
      i.serialNumber     || ch.serialNumber || '',
      i.baseMac          || '',
      i.snmpName         || '',
      i.snmpLocation     || '',
      i.snmpContact      || '',
      i.interfaceCount   != null ? i.interfaceCount : '',
      new Date().toISOString(),
    ];
  }).filter(r => r.length);

  return buildCSV(headers, csvRows);
}

// Build CSV for MikroTik routers// Fetch sysinfo for a single MikroTik device via SNMP
// Note: net-snmp sessions are not safe for concurrent requests — fetch sequentially
async function fetchMikrotikSysinfo(dev) {
  // Fetch each OID individually — multi-OID GET fails silently on some MikroTik firmware
  // when proprietary OIDs are mixed with standard MIB-2 OIDs
  const getOne = (oid) => new Promise((resolve) => {
    const sess = makeSnmpSession(dev);
    sess.get([oid], (err, varbinds) => {
      sess.close();
      if (err || !varbinds || !varbinds[0]) return resolve(null);
      if (snmp.isVarbindError(varbinds[0])) return resolve(null);
      resolve(varbinds[0].value ?? null);
    });
  });

  // Fetch standard MIB-2 OIDs first (always work), then proprietary
  const sysNameVal     = await getOne(OID.sysName);
  const sysDescrVal    = await getOne(OID.sysDescr);
  const sysUpTimeVal   = await getOne(OID.sysUpTime);
  const sysContactVal  = await getOne(OID.sysContact);
  const sysLocationVal = await getOne(OID.sysLocation);
  const mtFirmwareVal  = await getOne(OID.mtFirmware);
  const mtSoftIdVal    = await getOne(OID.mtSoftId);

  appLog('info', 'mikrotik', `${dev.label}: sysinfo — name=${bufToStr(sysNameVal)} fw=${bufToStr(mtFirmwareVal)} contact=${bufToStr(sysContactVal)} descr=${bufToStr(sysDescrVal)}`);

  try {
    const session = null; // unused

    const upTimeTicks = sysUpTimeVal ? Number(sysUpTimeVal) : 0;
    const upTimeSec   = Math.floor(upTimeTicks / 100);
    const upD = Math.floor(upTimeSec / 86400);
    const upH = Math.floor((upTimeSec % 86400) / 3600);
    const upM = Math.floor((upTimeSec % 3600) / 60);
    const uptime = upTimeSec > 0
      ? [upD&&`${upD}d`, upH&&`${upH}h`, upM&&`${upM}m`].filter(Boolean).join(' ') || '<1m'
      : '';

    const sysDescr = bufToStr(sysDescrVal);
    // Firmware from confirmed OID 1.3.6.1.4.1.14988.1.1.4.4.0
    let firmware  = bufToStr(mtFirmwareVal);
    let boardName = "";  // extracted from sysDescr below
    let softId    = bufToStr(mtSoftIdVal);

    // Try to extract version from sysDescr (older firmware includes it)
    if (!firmware && sysDescr) {
      const vMatch = sysDescr.match(/\b(\d+\.\d+(?:\.\d+)*)(?:\s|\(|$)/);
      if (vMatch) firmware = vMatch[1];
    }
    // Extract board name from sysDescr
    // "RouterOS RB4011iGS+" -> "RB4011iGS+"
    // "MikroTik RouterOS 6.49.10 on RB951Ui" -> "RB951Ui"
    if (!boardName && sysDescr) {
      const onMatch = sysDescr.match(/\bon\s+(\S+)/i);
      const cleaned = sysDescr
        .replace(/^(MikroTik\s+)?RouterOS\s*/i, '')
        .replace(/\s+\d+\.\d+.*$/, '')
        .trim();
      boardName = (onMatch && onMatch[1]) ||
                  (cleaned && !/^(stable|testing)/i.test(cleaned) ? cleaned : '');
    }

    return {
      hostname:  bufToStr(sysNameVal) || dev.label,
      sysDescr,
      uptime,
      contact:   bufToStr(sysContactVal),
      location:  bufToStr(sysLocationVal),
      firmware,
      buildTime: '',
      softId,
      boardName,
    };
  } catch(e) {
    throw e;
  }
}

// Build CSV for MikroTik routers — reads from mikrotik_info DB table
async function buildMikrotikCSV() {
  const mtDevs = devices.filter(d => d.type === 'mikrotik');
  appLog('info', 'export', `Building MikroTik CSV from DB for ${mtDevs.length} device(s)`);

  const headers = ['Label','Host','SNMP Community','Port',
                   'Hostname','Board/Model','Firmware','Software ID',
                   'Uptime','Contact','Location','Description','Last Updated'];

  let dbRows = [];
  if (db) {
    try {
      const [rows] = await db.execute('SELECT * FROM mikrotik_info ORDER BY label');
      dbRows = rows;
    } catch(e) {
      appLog('warn', 'export', `mikrotik_info DB read failed: ${e.message}`);
    }
  }

  // Build lookup map by device_id
  const dbMap = {};
  for (const r of dbRows) dbMap[r.device_id] = r;

  const csvRows = mtDevs.map(dev => {
    const r = dbMap[dev.id] || {};
    return [
      dev.label              || '',
      dev.host               || '',
      dev.snmpCommunity      || 'public',
      dev.snmpPort           || 161,
      r.hostname             || '',
      r.board_name           || '',
      r.firmware             || '',
      r.soft_id              || '',
      r.uptime               || '',
      r.contact              || '',
      r.location             || '',
      r.sys_descr            || '',
      r.fetched_at ? new Date(r.fetched_at).toISOString() : '',
    ];
  });

  return buildCSV(headers, csvRows);
}

function buildCSV(headers, rows) {
  const escape = v => {
    const str = String(v ?? '');
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
      return '"' + str.replace(/"/g, '""') + '"';
    }
    return str;
  };
  const lines = [
    headers.map(escape).join(','),
    ...rows.map(r => r.map(escape).join(',')),
  ];
  return lines.join('\r\n');
}

function exportFilename(type) {
  const ts = new Date().toISOString().replace(/[:.]/g,'-').slice(0,19);
  return `netmon-${type}-${ts}.csv`;
}

async function runExport(outputDir, types) {
  const dir = outputDir || EXPORT_DIR;
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const results = [];

  if (!types || types.includes('aruba')) {
    const csv  = await buildArubaCSV();
    const name = exportFilename('aruba');
    fs.writeFileSync(path.join(dir, name), csv, 'utf8');
    appLog('info', 'export', `Aruba export: ${name} (${csv.split('\n').length - 1} rows)`);
    results.push({ type: 'aruba', filename: name, rows: csv.split('\n').length - 1, path: path.join(dir, name) });
  }
  if (!types || types.includes('mikrotik')) {
    const csv  = await buildMikrotikCSV();
    const name = exportFilename('mikrotik');
    fs.writeFileSync(path.join(dir, name), csv, 'utf8');
    appLog('info', 'export', `MikroTik export: ${name} (${csv.split('\n').length - 1} rows)`);
    results.push({ type: 'mikrotik', filename: name, rows: csv.split('\n').length - 1, path: path.join(dir, name) });
  }

  const cfg = loadExportSchedule();
  cfg.lastExport = new Date().toISOString();
  saveExportSchedule(cfg);
  return results;
}

// GET /api/export/schedule
app.get('/api/export/schedule', (req, res) => res.json(loadExportSchedule()));

// PUT /api/export/schedule
app.put('/api/export/schedule', (req, res) => {
  const cfg = { ...loadExportSchedule(), ...req.body };
  saveExportSchedule(cfg);
  scheduleExport();
  res.json({ ok: true });
});

// POST /api/export/run — manual export, returns CSV inline or saves to disk
app.post('/api/export/run', async (req, res) => {
  const { type, outputDir, inline } = req.body || {};
  const types = type ? [type] : ['aruba', 'mikrotik'];

  try {
    if (inline) {
      // Return CSV directly for browser download
      const csv = type === 'mikrotik' ? await buildMikrotikCSV() : await buildArubaCSV();
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${exportFilename(type||'devices')}"`);
      return res.send(csv);
    }
    const results = await runExport(outputDir, types);
    res.json({ ok: true, results });
  } catch(e) {
    appLog('error','export', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /api/export/list — list saved export files
app.get('/api/export/list', (req, res) => {
  const dir = req.query.dir || EXPORT_DIR;
  try {
    if (!fs.existsSync(dir)) return res.json([]);
    const files = fs.readdirSync(dir)
      .filter(f => f.endsWith('.csv'))
      .map(f => {
        const stat = fs.statSync(path.join(dir, f));
        return { name: f, sizeKb: Math.round(stat.size/1024), mtime: stat.mtime };
      })
      .sort((a,b) => new Date(b.mtime) - new Date(a.mtime));
    res.json(files);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /api/export/download?file=name&dir=optional
app.get('/api/export/download', (req, res) => {
  const dir  = req.query.dir  || EXPORT_DIR;
  const file = req.query.file || '';
  if (!file || file.includes('..') || file.includes('/')) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  const full = path.join(dir, file);
  if (!fs.existsSync(full)) return res.status(404).json({ error: 'File not found' });
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${file}"`);
  res.sendFile(full);
});

let exportTimer = null;
function scheduleExport() {
  if (exportTimer) { clearInterval(exportTimer); exportTimer = null; }
  const cfg = loadExportSchedule();
  if (!cfg.enabled || !cfg.intervalHours) return;
  const ms = (cfg.intervalHours || 24) * 3600 * 1000;
  exportTimer = setInterval(() => runExport(cfg.outputDir, null).catch(e => appLog('error','export',e.message)), ms);
  appLog('info', 'export', `CSV export scheduled every ${cfg.intervalHours}h to ${cfg.outputDir || EXPORT_DIR}`);
}


// GET /api/mikrotik-info — return stored MikroTik info for all devices
app.get('/api/mikrotik-info', async (req, res) => {
  if (!db) return res.status(503).json({ error: 'DB not ready' });
  try {
    const [rows] = await db.execute('SELECT * FROM mikrotik_info');
    const result = {};
    for (const row of rows) {
      result[row.device_id] = {
        hostname:  row.hostname,
        boardName: row.board_name,
        firmware:  row.firmware,
        softId:    row.soft_id,
        sysDescr:  row.sys_descr,
        uptime:    row.uptime,
        contact:   row.contact,
        location:  row.location,
        fetchedAt: row.fetched_at,
      };
    }
    res.json(result);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});


// GET /api/mikrotik-sysinfo-test?switch=id — direct test of fetchMikrotikSysinfo
app.get('/api/mikrotik-sysinfo-test', async (req, res) => {
  const dev = req.query.switch ? getDeviceById(req.query.switch) : null;
  if (!dev) return res.status(400).json({ error: 'switch param required' });
  try {
    const info = await fetchMikrotikSysinfo(dev);
    await saveMikrotikInfoToDB(dev, info);
    res.json({ ok: true, info });
  } catch(e) {
    res.status(500).json({ error: e.message, stack: e.stack });
  }
});


// ─── Switch log DB storage ────────────────────────────────────────────────────

const SWITCH_LOG_RETENTION_DAYS_DEFAULT = 90;

function loadLogRetentionDays() {
  try {
    const cfg = JSON.parse(fs.readFileSync('log-retention.json', 'utf8'));
    return parseInt(cfg.retentionDays) || SWITCH_LOG_RETENTION_DAYS_DEFAULT;
  } catch(e) { return SWITCH_LOG_RETENTION_DAYS_DEFAULT; }
}
function saveLogRetention(days) {
  fs.writeFileSync('log-retention.json', JSON.stringify({ retentionDays: days }, null, 2));
}

// Store normalised log entries into DB, deduplicating by hash of device+ts+message
async function storeSwitchLogs(dev, entries) {
  if (!db || !entries.length) return { inserted: 0, duplicates: 0 };

  let inserted = 0, duplicates = 0;
  for (const e of entries) {
    // Dedup hash: device + timestamp + first 200 chars of message
    const hashInput = `${dev.id}|${e.timestamp}|${String(e.message).slice(0, 200)}`;
    const dedup = crypto.createHash('sha1').update(hashInput).digest('hex');

    const ts = e.timestamp ? new Date(e.timestamp) : new Date();
    try {
      await db.execute(`
        INSERT IGNORE INTO switch_logs
          (device_id, switch_host, switch_label, log_timestamp, severity,
           category, message, source, dedup_hash)
        VALUES (?,?,?,?,?,?,?,?,?)
      `, [
        dev.id, dev.host, dev.label,
        ts,
        e.severity   || 'info',
        e.category   || '',
        e.message    || '',
        e.source     || '',
        dedup,
      ]);
      // INSERT IGNORE returns 0 affectedRows for duplicates
      inserted++;
    } catch(e2) {
      if (!e2.message?.includes('Duplicate')) {
        appLog('warn', 'switch-logs', `${dev.label}: DB insert error: ${e2.message}`);
      }
      duplicates++;
    }
  }
  return { inserted, duplicates };
}

// Purge logs older than retention period
async function purgeSwitchLogs() {
  if (!db) return;
  const days = loadLogRetentionDays();
  try {
    const [result] = await db.execute(
      `DELETE FROM switch_logs WHERE log_timestamp < DATE_SUB(NOW(), INTERVAL ? DAY)`,
      [days]
    );
    if (result.affectedRows > 0) {
      appLog('info', 'switch-logs', `Purged ${result.affectedRows} log entries older than ${days} days`);
    }
  } catch(e) {
    appLog('warn', 'switch-logs', `Purge failed: ${e.message}`);
  }
}

// Schedule daily purge at startup + every 24h
let logPurgeTimer = null;
function scheduleLogPurge() {
  if (logPurgeTimer) clearInterval(logPurgeTimer);
  purgeSwitchLogs();  // run immediately
  logPurgeTimer = setInterval(purgeSwitchLogs, 24 * 3600 * 1000);
}

// Background log sync — fetch new logs from each Aruba switch and store in DB
// Uses the cached working URL so it doesn't hammer the switch
async function syncSwitchLogs(dev) {
  if (dev.type !== 'aruba' || !dev.enabled) return;
  try {
    const result = await fetchWithReloginForDev(dev, cookie =>
      fetchArubaLogs(dev, cookie, 1000, '')
    );
    if (!result || !result.entries.length) return;
    const entries = result.entries.map(normaliseLogEntry);
    const { inserted, duplicates } = await storeSwitchLogs(dev, entries);
    if (inserted > 0) {
      appLog('debug', 'switch-logs', `${dev.label}: synced ${inserted} new log entries (${duplicates} duplicates skipped)`);
    }
  } catch(e) {
    appLog('debug', 'switch-logs', `${dev.label}: log sync failed: ${e.message}`);
  }
}

async function syncAllSwitchLogs() {
  const arubaDevs = devices.filter(d => d.type === 'aruba' && d.enabled);
  for (const dev of arubaDevs) {
    await syncSwitchLogs(dev);
  }
}

// Schedule log sync every 5 minutes
let logSyncTimer = null;
function scheduleLogSync() {
  if (logSyncTimer) clearInterval(logSyncTimer);
  // Initial sync 20s after startup (give pollers time to establish sessions)
  setTimeout(syncAllSwitchLogs, 20000);
  logSyncTimer = setInterval(syncAllSwitchLogs, 5 * 60 * 1000);
  appLog('info', 'switch-logs', `Log sync scheduled every 5 minutes`);
}

// Helper — relogin wrapper for a specific dev without the request context
async function fetchWithReloginForDev(dev, fetchFn) {
  await getDeviceCookie(dev);
  try {
    return await fetchFn(getState(dev.id).cookie);
  } catch(e) {
    if (e.response && e.response.status === 401) {
      await reloginDevice(dev);
      return await fetchFn(getState(dev.id).cookie);
    }
    throw e;
  }
}

// GET /api/switch-logs/retention
app.get('/api/switch-logs/retention', (req, res) => {
  res.json({ retentionDays: loadLogRetentionDays() });
});

// PUT /api/switch-logs/retention
app.put('/api/switch-logs/retention', (req, res) => {
  const days = parseInt(req.body.retentionDays) || SWITCH_LOG_RETENTION_DAYS_DEFAULT;
  saveLogRetention(days);
  res.json({ ok: true, retentionDays: days });
});

// GET /api/switch-logs/stats — log counts per device
app.get('/api/switch-logs/stats', async (req, res) => {
  if (!db) return res.status(503).json({ error: 'DB not ready' });
  try {
    const [rows] = await db.execute(`
      SELECT device_id, switch_label, COUNT(*) AS total,
             MIN(log_timestamp) AS oldest, MAX(log_timestamp) AS newest
      FROM switch_logs GROUP BY device_id, switch_label
    `);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/switch-logs/sync — manual sync trigger
app.post('/api/switch-logs/sync', async (req, res) => {
  const devId = req.body?.switch;
  const devs  = devId
    ? devices.filter(d => d.id === devId && d.type === 'aruba')
    : devices.filter(d => d.type === 'aruba' && d.enabled);
  for (const dev of devs) await syncSwitchLogs(dev);
  res.json({ ok: true, synced: devs.length });
});


// ─── CVE / Vulnerability checking ────────────────────────────────────────────
// Queries NIST NVD API for known CVEs matching device firmware versions.
// NVD API v2: https://nvd.nist.gov/developers/vulnerabilities
// Free, no auth required (rate limit: 5 req/30s without API key, 50/30s with key)

const CVE_CACHE_FILE  = 'cve-cache.json';
const CVE_RESULTS_FILE= 'cve-results.json';
const CVE_CHECK_INTERVAL_HRS = 24;

function loadCveConfig() {
  try { return JSON.parse(fs.readFileSync('cve-config.json', 'utf8')); }
  catch(e) { return { enabled: true, intervalHours: 24, nvdApiKey: '', lastCheck: null }; }
}
function saveCveConfig(cfg) {
  fs.writeFileSync('cve-config.json', JSON.stringify(cfg, null, 2));
}
function loadCveResults() {
  try { return JSON.parse(fs.readFileSync(CVE_RESULTS_FILE, 'utf8')); }
  catch(e) { return {}; }
}
function saveCveResults(results) {
  fs.writeFileSync(CVE_RESULTS_FILE, JSON.stringify(results, null, 2));
}

// Query NVD for CVEs matching a keyword (vendor + product + version)
async function queryNvd(keyword, apiKey) {
  const params = new URLSearchParams({
    keywordSearch: keyword,
    resultsPerPage: 20,
  });
  const headers = { 'User-Agent': 'netmon-cve-checker/1.0' };
  if (apiKey) headers['apiKey'] = apiKey;

  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?${params}`;
  const res  = await axios.get(url, { headers, timeout: 15000 });
  return res.data?.vulnerabilities || [];
}

// Parse CVE entry into summary object
function parseCve(vuln) {
  const cve  = vuln.cve;
  const id   = cve.id;
  const desc = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
  const pub  = cve.published;
  const mod  = cve.lastModified;

  // CVSS score — prefer v3.1, fall back to v3.0 then v2
  let score = null, severity = '', vector = '';
  const metrics = cve.metrics || {};
  const cv31 = metrics.cvssMetricV31?.[0];
  const cv30 = metrics.cvssMetricV30?.[0];
  const cv2  = metrics.cvssMetricV2?.[0];
  if (cv31) {
    score = cv31.cvssData.baseScore;
    severity = cv31.cvssData.baseSeverity;
    vector   = cv31.cvssData.vectorString;
  } else if (cv30) {
    score = cv30.cvssData.baseScore;
    severity = cv30.cvssData.baseSeverity;
    vector   = cv30.cvssData.vectorString;
  } else if (cv2) {
    score = cv2.cvssData.baseScore;
    severity = cv2.baseSeverity || '';
    vector   = cv2.cvssData.vectorString;
  }

  const refs = (cve.references || []).slice(0, 5).map(r => r.url);
  return { id, score, severity, vector, description: desc, published: pub, lastModified: mod, references: refs };
}

// Check one device for CVEs
async function checkDeviceCves(dev, apiKey) {
  let keywords = [];

  if (dev.type === 'aruba') {
    // Get firmware from DB
    if (!db) return [];
    const [[row]] = await db.execute(
      'SELECT platform, software_version FROM device_info WHERE device_id = ?', [dev.id]
    );
    if (!row || !row.software_version) return [];
    // Search for HPE Aruba with firmware version
    const fw = row.software_version.replace(/^PL\./, ''); // strip PL. prefix
    keywords = [
      `HPE Aruba CX ${fw}`,
      `Aruba Networks AOS-CX ${fw}`,
    ];
  } else if (dev.type === 'mikrotik') {
    // Get firmware from mikrotik_info DB
    if (!db) return [];
    const [[row]] = await db.execute(
      'SELECT firmware, board_name FROM mikrotik_info WHERE device_id = ?', [dev.id]
    );
    if (!row || !row.firmware) return [];
    keywords = [
      `MikroTik RouterOS ${row.firmware}`,
      `Mikrotik ${row.firmware}`,
    ];
  }

  const allCves = [];
  const seen    = new Set();
  for (const kw of keywords) {
    try {
      appLog('debug', 'cve', `${dev.label}: querying NVD for "${kw}"`);
      const vulns = await queryNvd(kw, apiKey);
      for (const v of vulns) {
        const parsed = parseCve(v);
        if (!seen.has(parsed.id)) {
          seen.add(parsed.id);
          allCves.push(parsed);
        }
      }
      // Rate limit: 5 req/30s without key, 50/30s with key
      await new Promise(r => setTimeout(r, apiKey ? 700 : 6500));
    } catch(e) {
      appLog('warn', 'cve', `${dev.label}: NVD query failed: ${e.message}`);
    }
  }

  // Sort by score descending
  allCves.sort((a, b) => (b.score || 0) - (a.score || 0));
  return allCves;
}

async function runCveCheck() {
  const cfg = loadCveConfig();
  const allDevices = devices.filter(d => d.enabled);
  const results = loadCveResults();

  appLog('info', 'cve', `Starting CVE check for ${allDevices.length} device(s)`);

  for (const dev of allDevices) {
    try {
      const cves = await checkDeviceCves(dev, cfg.nvdApiKey);
      results[dev.id] = {
        deviceId:    dev.id,
        label:       dev.label,
        host:        dev.host,
        type:        dev.type,
        checkedAt:   new Date().toISOString(),
        cveCount:    cves.length,
        criticalCount: cves.filter(c => c.severity === 'CRITICAL').length,
        highCount:     cves.filter(c => c.severity === 'HIGH').length,
        cves,
      };
      appLog('info', 'cve', `${dev.label}: ${cves.length} CVE(s) found`);
    } catch(e) {
      appLog('warn', 'cve', `${dev.label}: CVE check failed: ${e.message}`);
    }
  }

  saveCveResults(results);
  cfg.lastCheck = new Date().toISOString();
  saveCveConfig(cfg);
  appLog('info', 'cve', `CVE check complete`);
  return results;
}

// GET /api/cve/results
app.get('/api/cve/results', (req, res) => {
  res.json(loadCveResults());
});

// GET /api/cve/config
app.get('/api/cve/config', (req, res) => {
  const cfg = loadCveConfig();
  res.json({ enabled: cfg.enabled, intervalHours: cfg.intervalHours,
             hasApiKey: !!cfg.nvdApiKey, lastCheck: cfg.lastCheck });
});

// PUT /api/cve/config
app.put('/api/cve/config', (req, res) => {
  const cfg = loadCveConfig();
  const { enabled, intervalHours, nvdApiKey } = req.body;
  if (enabled      !== undefined) cfg.enabled      = !!enabled;
  if (intervalHours!== undefined) cfg.intervalHours= parseInt(intervalHours)||24;
  if (nvdApiKey    !== undefined) cfg.nvdApiKey    = nvdApiKey;
  saveCveConfig(cfg);
  scheduleCveCheck();
  res.json({ ok: true });
});

// POST /api/cve/run — manual trigger
app.post('/api/cve/run', async (req, res) => {
  res.json({ ok: true, message: 'CVE check started' });
  runCveCheck().catch(e => appLog('error', 'cve', e.message));
});

let cveCheckTimer = null;
function scheduleCveCheck() {
  if (cveCheckTimer) { clearInterval(cveCheckTimer); cveCheckTimer = null; }
  const cfg = loadCveConfig();
  if (!cfg.enabled) return;
  const ms = (cfg.intervalHours || 24) * 3600 * 1000;
  cveCheckTimer = setInterval(runCveCheck, ms);
  appLog('info', 'cve', `CVE check scheduled every ${cfg.intervalHours}h`);
}


// GET /api/debug/session — shows session and cookie state (remove after debugging)
app.get('/api/debug/session', (req, res) => {
  res.json({
    sessionId:    req.session?.id || null,
    userId:       req.session?.userId || null,
    username:     req.session?.username || null,
    nodeEnv:      process.env.NODE_ENV,
    secureCookies:SECURE_COOKIES,
    cookieHeader: req.headers['cookie'] || '(none)',
    protocol:     req.protocol,
    secure:       req.secure,
    xfproto:      req.headers['x-forwarded-proto'] || '(none)',
    xffor:        req.headers['x-forwarded-for'] || '(none)',
  });
});

// ── Topology ──────────────────────────────────────────────────────────────────

// GET /api/topology — full node+link graph with live traffic per link
app.get('/api/topology', async (req, res) => {
  try {
    const topo  = loadTopo();
    const nodes = devices.map(dev => {
      const st  = getState(dev.id);
      const pos = topo.nodes[dev.id] || null;
      return {
        id: dev.id, label: dev.label, host: dev.host,
        type:      dev.type || 'aruba',
        enabled:   dev.enabled,
        status:    st.status,
        lastError: st.lastError,
        x: pos?.x ?? null,
        y: pos?.y ?? null,
      };
    });

    // Enrich each link with its latest traffic reading from the DB
    const enrichedLinks = await Promise.all((topo.links || []).map(async link => {
      let rxMbps = 0, txMbps = 0, linkStatus = 'unknown';
      if (db && link.sourceId && link.sourcePort) {
        const src = getDeviceById(link.sourceId);
        if (src) {
          try {
            const [rows] = await db.execute(
              `SELECT rx_mbps, tx_mbps, link_status FROM bandwidth_samples
               WHERE switch_host = ? AND interface = ?
               ORDER BY sampled_at DESC LIMIT 1`,
              [src.host, link.sourcePort]
            );
            if (rows.length) {
              rxMbps     = parseFloat(rows[0].rx_mbps);
              txMbps     = parseFloat(rows[0].tx_mbps);
              linkStatus = rows[0].link_status;
            }
          } catch (e) {}
        }
      }
      return { ...link, rxMbps, txMbps, linkStatus };
    }));

    res.json({ nodes, links: enrichedLinks });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT /api/topology/nodes — save canvas node positions { deviceId: {x, y} }
app.put('/api/topology/nodes', (req, res) => {
  const topo   = loadTopo();
  topo.nodes   = { ...topo.nodes, ...req.body };
  saveTopo(topo);
  res.json({ ok: true });
});

// GET /api/topology/links
app.get('/api/topology/links', (req, res) => {
  res.json(loadTopo().links || []);
});

// POST /api/topology/links — add a link
app.post('/api/topology/links', (req, res) => {
  const { sourceId, targetId, sourcePort, targetPort, label } = req.body;
  if (!sourceId || !targetId)
    return res.status(400).json({ error: 'sourceId and targetId are required' });
  const topo = loadTopo();
  const link = {
    id:         'lnk_' + Date.now(),
    sourceId,   targetId,
    sourcePort: sourcePort || '',
    targetPort: targetPort || '',
    label:      label || '',
  };
  topo.links.push(link);
  saveTopo(topo);
  res.status(201).json(link);
});

// PUT /api/topology/links/:id — update a link
app.put('/api/topology/links/:id', (req, res) => {
  const topo = loadTopo();
  const lnk  = topo.links.find(l => l.id === req.params.id);
  if (!lnk) return res.status(404).json({ error: 'Not found' });
  Object.assign(lnk, req.body);
  saveTopo(topo);
  res.json({ ok: true });
});

// DELETE /api/topology/links/:id — remove a link
app.delete('/api/topology/links/:id', (req, res) => {
  const topo = loadTopo();
  topo.links = topo.links.filter(l => l.id !== req.params.id);
  saveTopo(topo);
  res.json({ ok: true });
});


// ═══════════════════════════════════════════════════════════════════════════════
// SUBNET SCANNER — auto-discover Aruba CX switches on a subnet
// ═══════════════════════════════════════════════════════════════════════════════

// scan-config.json now stores:
// { subnets: [{id, subnet, prefixLen, label, enabled}], port, username, password,
//   interval, scanIntervalHours, enabled, lastScan }
const SCAN_DEFAULTS = {
  subnets: [],          // array of subnet entries
  port: '443', username: 'admin', password: '',
  interval: 30, scanIntervalHours: 6,
  enabled: false, lastScan: null,
};

function loadScanConfig() {
  if (fs.existsSync(SCAN_FILE)) {
    try { return { ...SCAN_DEFAULTS, ...JSON.parse(fs.readFileSync(SCAN_FILE,'utf8')) }; }
    catch(e) {}
  }
  return { ...SCAN_DEFAULTS };
}
function saveScanConfig(cfg) { fs.writeFileSync(SCAN_FILE, JSON.stringify(cfg,null,2)); }

// Expand a CIDR subnet into an array of host IPs (skip network/broadcast, max 254 for /24)
function subnetHosts(subnet, prefixLen) {
  const parts = subnet.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return [];
  const hosts = [];
  const hostBits = 32 - prefixLen;
  const hostCount = Math.min(Math.pow(2, hostBits) - 2, 1022); // cap at /22
  const networkInt = (parts[0]<<24)|(parts[1]<<16)|(parts[2]<<8)|parts[3];
  const mask = hostCount === 0 ? 0 : (~0 << hostBits) >>> 0;
  const net  = networkInt & mask;
  for (let i = 1; i <= hostCount; i++) {
    const ip = net + i;
    hosts.push([(ip>>>24)&255,((ip>>>16)&255),((ip>>>8)&255),ip&255].join('.'));
  }
  return hosts;
}

// Try to log in to a candidate IP — returns { ok, sysName } or { ok:false }
async function probeAruba(ip, port, username, password) {
  try {
    const cookie = await Promise.race([
      arubaLogin({ host:ip, port, username, password }),
      new Promise((_,r) => setTimeout(() => r(new Error('timeout')), 4000))
    ]);
    // Fetch system info to get the hostname
    let sysName = ip;
    try {
      // Use discovered version if available, else try v10.10 as default probe
      const probeVer = deviceApiVersion[ip] || 'v10.10';
      const res = await axiosDevice.get(`https://${ip}:${port}/rest/${probeVer}/system`, {
        headers:{ Cookie: cookie }, params:{ attributes:'hostname' }, timeout:3000
      });
      sysName = res.data.hostname || ip;
    } catch(e) {}
    // Logout politely
    await arubaLogout({ host:ip, port }, cookie).catch(()=>{});
    return { ok:true, sysName };
  } catch(e) {
    return { ok:false };
  }
}

// Scan one subnet entry and return results
async function scanOneSubnet(subnetEntry, cfg) {
  const { subnet, prefixLen } = subnetEntry;
  const hosts = subnetHosts(subnet, parseInt(prefixLen)||24);
  appLog('info','scan',`Scanning ${hosts.length} hosts on ${subnet}/${prefixLen}`);
  let found=0, added=0;
  const BATCH=20;
  for (let i=0; i<hosts.length; i+=BATCH) {
    const batch = hosts.slice(i, i+BATCH);
    const results = await Promise.all(batch.map(ip => probeAruba(ip, cfg.port, cfg.username, cfg.password)));
    results.forEach((result, idx) => {
      const ip = batch[idx];
      if (!result.ok) return;
      found++;
      if (devices.find(d => d.host === ip)) {
        appLog('info','scan',`Already known: ${ip}`);
        return;
      }
      const dev = {
        id:       'dev_' + Date.now() + '_' + Math.random().toString(36).slice(2,6),
        type:     'aruba',
        label:    result.sysName || ip,
        host:     ip,
        port:     String(cfg.port || '443'),
        username: cfg.username,
        password: cfg.password,
        interval: parseInt(cfg.interval)||30,
        enabled:  true,
        discoveredBy: 'scan',
      };
      devices.push(dev);
      saveDevices();
      startDevicePoller(dev);
      added++;
      appLog('info','scan',`Discovered and added: ${ip} (${dev.label})`);
    });
  }
  return { subnet, prefixLen, scanned:hosts.length, found, added };
}

// Scan all configured subnets
async function runSubnetScan(cfg, calledBy='auto') {
  const subnets = (cfg.subnets||[]).filter(s => s.enabled !== false && s.subnet);
  if (!subnets.length || !cfg.username || !cfg.password) {
    appLog('warn','scan','Skipped — no subnets or credentials not configured');
    return { results:[], scanned:0, found:0, added:0 };
  }
  appLog('info','scan',`${calledBy}: scanning ${subnets.length} subnet(s)`);
  const results = [];
  let totalScanned=0, totalFound=0, totalAdded=0;
  for (const entry of subnets) {
    const r = await scanOneSubnet(entry, cfg);
    results.push(r);
    totalScanned += r.scanned; totalFound += r.found; totalAdded += r.added;
  }
  cfg.lastScan = new Date().toISOString();
  saveScanConfig(cfg);
  appLog('info','scan',`Done — scanned ${totalScanned}, found ${totalFound}, added ${totalAdded}`);
  return { results, scanned:totalScanned, found:totalFound, added:totalAdded };
}

let scanTimer = null;
function scheduleScan() {
  if (scanTimer) { clearInterval(scanTimer); scanTimer=null; }
  const cfg = loadScanConfig();
  if (!cfg.enabled || !cfg.scanIntervalHours) return;
  const ms = cfg.scanIntervalHours * 3600 * 1000;
  scanTimer = setInterval(() => runSubnetScan(loadScanConfig(), 'scheduled'), ms);
  console.log(`[scan] Scheduled every ${cfg.scanIntervalHours}h`);
}

// GET /api/scan/config
app.get('/api/scan/config', (req, res) => res.json(loadScanConfig()));

// PUT /api/scan/config — save global scan settings
app.put('/api/scan/config', (req, res) => {
  const cfg = { ...loadScanConfig(), ...req.body };
  saveScanConfig(cfg);
  scheduleScan();
  res.json({ ok:true });
});

// POST /api/scan/subnets — add a subnet entry
app.post('/api/scan/subnets', (req, res) => {
  const cfg = loadScanConfig();
  const { subnet, prefixLen=24, label='' } = req.body;
  if (!subnet) return res.status(400).json({ error:'subnet required' });
  if (!cfg.subnets) cfg.subnets = [];
  const entry = { id:'sn_'+Date.now(), subnet, prefixLen:parseInt(prefixLen), label, enabled:true };
  cfg.subnets.push(entry);
  saveScanConfig(cfg);
  res.status(201).json(entry);
});

// PUT /api/scan/subnets/:id — update a subnet entry
app.put('/api/scan/subnets/:id', (req, res) => {
  const cfg = loadScanConfig();
  const entry = (cfg.subnets||[]).find(s => s.id === req.params.id);
  if (!entry) return res.status(404).json({ error:'Not found' });
  Object.assign(entry, req.body);
  saveScanConfig(cfg);
  res.json({ ok:true });
});

// DELETE /api/scan/subnets/:id — remove a subnet entry
app.delete('/api/scan/subnets/:id', (req, res) => {
  const cfg = loadScanConfig();
  cfg.subnets = (cfg.subnets||[]).filter(s => s.id !== req.params.id);
  saveScanConfig(cfg);
  res.json({ ok:true });
});

// POST /api/scan/run — trigger an immediate scan
app.post('/api/scan/run', async (req, res) => {
  const cfg    = loadScanConfig();
  const merged = { ...cfg, ...req.body };
  res.json(await runSubnetScan(merged, 'manual'));
});

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIG BACKUPS — scheduled + on-demand, 30-day retention
// ═══════════════════════════════════════════════════════════════════════════════

const BACKUP_SCHEDULE_FILE = path.join(DATA_DIR, 'backup-schedule.json');
const BACKUP_DEFAULTS = { enabled:false, intervalHours:24, lastBackup:null };

function loadBackupSchedule() {
  if (fs.existsSync(BACKUP_SCHEDULE_FILE)) {
    try { return { ...BACKUP_DEFAULTS, ...JSON.parse(fs.readFileSync(BACKUP_SCHEDULE_FILE,'utf8')) }; }
    catch(e) {}
  }
  return { ...BACKUP_DEFAULTS };
}
function saveBackupSchedule(s) { fs.writeFileSync(BACKUP_SCHEDULE_FILE, JSON.stringify(s,null,2)); }

function ensureBackupsDir() {
  if (!fs.existsSync(BACKUPS_DIR)) fs.mkdirSync(BACKUPS_DIR, { recursive:true });
}

// Fetch the running config from an Aruba CX switch
async function fetchArubaConfig(dev) {
  let cookie;
  try { cookie = await getDeviceCookie(dev); }
  catch(e) { appLog('warn', 'search', `${dev.label}: login failed: ${e.message}`); return []; }
  try {
    // Try /system/config/running-config first (AOS-CX 10.x)
    const res = await axiosDevice.get(
      `${apiBase(dev)}/configs/running-config`,
      { headers:{ Cookie:cookie }, responseType:'text', timeout:15000 }
    );
    return typeof res.data === 'object' ? JSON.stringify(res.data, null, 2) : String(res.data);
  } catch(e) {
    // Fallback to checkpoint endpoint
    const res = await axiosDevice.get(
      `${apiBase(dev)}/system`,
      { headers:{ Cookie:cookie }, params:{ depth:3, selector:'writable' }, timeout:15000 }
    );
    return JSON.stringify(res.data, null, 2);
  }
}

// Back up a single device — saves to backups/<deviceId>/<timestamp>.txt
async function backupDevice(dev) {
  if (dev.type !== 'aruba') return { ok:false, reason:'Backup only supported for Aruba CX devices' };
  ensureBackupsDir();
  const devDir = path.join(BACKUPS_DIR, dev.id);
  if (!fs.existsSync(devDir)) fs.mkdirSync(devDir, { recursive:true });
  try {
    const config = await fetchArubaConfig(dev);
    const ts     = new Date().toISOString().replace(/[:.]/g,'-');
    const fname  = `${ts}.txt`;
    fs.writeFileSync(path.join(devDir, fname), config, 'utf8');
    console.log(`[backup] ${dev.label} -> ${fname} (${config.length} bytes)`);
    pruneOldBackups(devDir);
    return { ok:true, filename:fname, size:config.length };
  } catch(e) {
    console.error(`[backup] ${dev.label} failed:`, e.message);
    return { ok:false, reason:e.message };
  }
}

// Remove backups older than 30 days
function pruneOldBackups(devDir) {
  const cutoff = Date.now() - (30 * 24 * 3600 * 1000);
  try {
    fs.readdirSync(devDir).forEach(file => {
      const full = path.join(devDir, file);
      if (fs.statSync(full).mtimeMs < cutoff) { fs.unlinkSync(full); console.log(`[backup] Pruned ${file}`); }
    });
  } catch(e) {}
}

// Run a full backup of all enabled Aruba devices
async function runBackupAll() {
  const arubaDevs = devices.filter(d => d.type==='aruba' && d.enabled);
  const results   = await Promise.allSettled(arubaDevs.map(backupDevice));
  const sched     = loadBackupSchedule();
  sched.lastBackup = new Date().toISOString();
  saveBackupSchedule(sched);
  return arubaDevs.map((d,i) => ({
    device: d.label, host: d.host,
    ...(results[i].status==='fulfilled' ? results[i].value : { ok:false, reason:results[i].reason?.message })
  }));
}

let backupTimer = null;
function scheduleBackups() {
  if (backupTimer) { clearInterval(backupTimer); backupTimer=null; }
  const sched = loadBackupSchedule();
  if (!sched.enabled || !sched.intervalHours) return;
  const ms = sched.intervalHours * 3600 * 1000;
  backupTimer = setInterval(runBackupAll, ms);
  console.log(`[backup] Scheduled every ${sched.intervalHours}h`);
}

// GET /api/backups/schedule
app.get('/api/backups/schedule', (req, res) => res.json(loadBackupSchedule()));

// PUT /api/backups/schedule
app.put('/api/backups/schedule', (req, res) => {
  const sched = { ...loadBackupSchedule(), ...req.body };
  saveBackupSchedule(sched);
  scheduleBackups();
  res.json({ ok:true });
});

// POST /api/backups/run — immediate backup of all devices (or one)
app.post('/api/backups/run', async (req, res) => {
  if (req.body.switchId) {
    const dev = getDeviceById(req.body.switchId);
    if (!dev) return res.status(404).json({ error:'Not found' });
    res.json(await backupDevice(dev));
  } else {
    res.json(await runBackupAll());
  }
});

// GET /api/backups/list?switch=id — list backups for a device
app.get('/api/backups/list', (req, res) => {
  const dev = req.query.switch ? getDeviceById(req.query.switch) : null;
  if (!dev) return res.status(400).json({ error:'switch param required' });
  ensureBackupsDir();
  const devDir = path.join(BACKUPS_DIR, dev.id);
  if (!fs.existsSync(devDir)) return res.json([]);
  const files = fs.readdirSync(devDir)
    .filter(f => f.endsWith('.txt'))
    .map(f => {
      const stat = fs.statSync(path.join(devDir,f));
      return { filename:f, size:stat.size, date:stat.mtime.toISOString() };
    })
    .sort((a,b) => b.date.localeCompare(a.date));
  res.json(files);
});

// GET /api/backups/download?switch=id&file=fname — download a backup file
app.get('/api/backups/download', (req, res) => {
  const dev = req.query.switch ? getDeviceById(req.query.switch) : null;
  if (!dev || !req.query.file) return res.status(400).json({ error:'switch and file params required' });
  const safe = path.basename(req.query.file); // prevent path traversal
  const full = path.join(BACKUPS_DIR, dev.id, safe);
  if (!fs.existsSync(full)) return res.status(404).json({ error:'File not found' });
  res.setHeader('Content-Disposition', `attachment; filename="${dev.label}-${safe}"`);
  res.setHeader('Content-Type','text/plain');
  res.sendFile(full);
});

// GET /api/backups/diff?switch=id&file1=a.txt&file2=b.txt — line-by-line diff between two backups
app.get('/api/backups/diff', (req, res) => {
  const dev = req.query.switch ? getDeviceById(req.query.switch) : null;
  if (!dev || !req.query.file1 || !req.query.file2) return res.status(400).json({ error:'switch, file1, file2 required' });
  try {
    const devDir = path.join(BACKUPS_DIR, dev.id);
    const a = fs.readFileSync(path.join(devDir, path.basename(req.query.file1)),'utf8').split('\n');
    const b = fs.readFileSync(path.join(devDir, path.basename(req.query.file2)),'utf8').split('\n');
    const diff = [];
    const maxLen = Math.max(a.length, b.length);
    for (let i=0; i<maxLen; i++) {
      if (a[i] !== b[i]) diff.push({ line:i+1, old:a[i]??null, new:b[i]??null });
    }
    res.json({ file1:req.query.file1, file2:req.query.file2, changes:diff.length, diff });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// HIDDEN INTERFACES — per-device list of interfaces to hide from the live view
// ═══════════════════════════════════════════════════════════════════════════════
// Stored as { "deviceId": ["1/1/1", "1/1/2", ...] }

function loadHidden() {
  if (fs.existsSync(HIDDEN_FILE)) {
    try { return JSON.parse(fs.readFileSync(HIDDEN_FILE,'utf8')); }
    catch(e) {}
  }
  return {};
}
function saveHidden(h) { fs.writeFileSync(HIDDEN_FILE, JSON.stringify(h,null,2)); }

// GET /api/hidden?switch=id
app.get('/api/hidden', (req, res) => {
  const hidden = loadHidden();
  const key    = req.query.switch;
  res.json(key ? (hidden[key] || []) : hidden);
});

// PUT /api/hidden — replace the full hidden list for a device
// Body: { switchId, interfaces: ["1/1/1", ...] }
app.put('/api/hidden', (req, res) => {
  const { switchId, interfaces } = req.body;
  if (!switchId) return res.status(400).json({ error:'switchId required' });
  const hidden = loadHidden();
  hidden[switchId] = Array.isArray(interfaces) ? interfaces : [];
  saveHidden(hidden);
  res.json({ ok:true });
});

// POST /api/hidden/toggle — toggle a single interface hidden state
// Body: { switchId, interface }
app.post('/api/hidden/toggle', (req, res) => {
  const { switchId, interface: iface } = req.body;
  if (!switchId || !iface) return res.status(400).json({ error:'switchId and interface required' });
  const hidden = loadHidden();
  if (!hidden[switchId]) hidden[switchId] = [];
  const idx = hidden[switchId].indexOf(iface);
  if (idx === -1) hidden[switchId].push(iface);
  else hidden[switchId].splice(idx,1);
  saveHidden(hidden);
  res.json({ ok:true, hidden: hidden[switchId] });
});


// ─── Device info background refresh ──────────────────────────────────────────
// Refreshes system info for all enabled Aruba devices and stores in DB.
// Runs once at startup (after a short delay) and then every SYSINFO_INTERVAL_HRS hours.

const SYSINFO_INTERVAL_HRS = 6;

async function refreshAllDeviceInfo() {
  const arubaDevs = devices.filter(d => d.type === 'aruba' && d.enabled);
  if (!arubaDevs.length) return;
  appLog('info', 'sysinfo', `Refreshing device info for ${arubaDevs.length} switch(es)`);

  for (const dev of arubaDevs) {
    try {
      // Use the same complete fetch+parse+save logic as the /api/sysinfo endpoint
      // This correctly reads product_info.serial_number, base_mac_address, etc.
      const info = await fetchAndSaveDeviceSysinfo(dev);
      appLog('info', 'sysinfo', `${dev.label}: updated — fw=${info.softwareVersion} serial=${info.serialNumber} mac=${info.baseMac}`);
    } catch(e) {
      appLog('warn', 'sysinfo', `${dev.label}: refresh failed: ${e.message}`);
    }
  }
}


function scheduleSysInfoRefresh() {
  // Run every SYSINFO_INTERVAL_HRS hours
  setInterval(refreshAllDeviceInfo, SYSINFO_INTERVAL_HRS * 3600 * 1000);
  appLog('info', 'sysinfo', `Device info refresh scheduled every ${SYSINFO_INTERVAL_HRS}h`);
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
(async () => {
  await initDB();
  ensureBackupsDir();
  loadDevices();
  devices.filter(d => d.enabled).forEach(startDevicePoller);
  scheduleScan();
  scheduleBackups();
  scheduleSysInfoRefresh();
  scheduleMikrotikScan();
  scheduleExport();
  scheduleLogSync();
  scheduleLogPurge();
  scheduleCveCheck();
  // Run CVE check 60s after startup if results file doesn't exist
  if (!fs.existsSync(CVE_RESULTS_FILE)) setTimeout(runCveCheck, 60000);
  // Run an immediate scan on startup if enabled
  const scanCfg = loadScanConfig();
  if (scanCfg.enabled && scanCfg.subnet) {
    setTimeout(() => runSubnetScan(scanCfg, 'startup'), 5000);
  }
  // Refresh device info shortly after startup (give pollers time to establish sessions)
  setTimeout(refreshAllDeviceInfo, 15000);
  // Reset master admin password if env var is set (for credential recovery)
  if (process.env.RESET_ADMIN_PASSWORD) {
    const newHash = await bcrypt.hash(process.env.RESET_ADMIN_PASSWORD, 12);
    await db.execute('UPDATE users SET password_hash = ?, enabled = 1 WHERE is_master = 1', [newHash]);
    console.log('[auth] Master admin password has been reset via RESET_ADMIN_PASSWORD env var');
    console.log('[auth] IMPORTANT: Remove RESET_ADMIN_PASSWORD from your environment now!');
  }

  app.listen(PORT, () => console.log(`[server] Listening on http://localhost:${PORT}`));
  process.on('SIGTERM', () => { devices.forEach(d => stopDevicePoller(d.id)); process.exit(0); });
  process.on('SIGINT',  () => { devices.forEach(d => stopDevicePoller(d.id)); process.exit(0); });
})();
