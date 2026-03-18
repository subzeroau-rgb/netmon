#!/usr/bin/env node
// ─── Master admin password reset utility ─────────────────────────────────────
// Run this when you've lost access to the admin account:
//   cd ~/aruba-cx-monitor/backend
//   node reset-admin.js
// Or with a specific password:
//   node reset-admin.js mynewpassword

require('dotenv').config();
const mysql   = require('mysql2/promise');
const bcrypt  = require('bcryptjs');
const readline = require('readline');

const newPassword = process.argv[2];

async function reset() {
  const db = await mysql.createPool({
    host:     process.env.DB_HOST  || 'localhost',
    port:     parseInt(process.env.DB_PORT || '3306'),
    user:     process.env.DB_USER  || 'root',
    password: process.env.DB_PASS  || '',
    database: process.env.DB_NAME  || 'aruba_monitor',
  });

  const [[row]] = await db.execute('SELECT id, username FROM users WHERE is_master = 1');
  if (!row) { console.error('No master admin account found.'); process.exit(1); }

  const setPassword = async (pwd) => {
    if (pwd.length < 8) { console.error('Password must be at least 8 characters.'); process.exit(1); }
    const hash = await bcrypt.hash(pwd, 12);
    await db.execute('UPDATE users SET password_hash = ?, enabled = 1 WHERE is_master = 1', [hash]);
    console.log(`\n✓ Password reset for master admin "${row.username}"`);
    console.log('  You can now log in with the new password.');
    process.exit(0);
  };

  if (newPassword) {
    await setPassword(newPassword);
  } else {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(`Enter new password for master admin "${row.username}": `, async (pwd) => {
      rl.close();
      await setPassword(pwd.trim());
    });
  }
}

reset().catch(e => { console.error('Error:', e.message); process.exit(1); });
