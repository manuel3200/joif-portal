'use strict';

const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const sqlite3 = require('sqlite3').verbose();

function createDatabase(options = {}) {
  const dbPath = options.dbPath || process.env.DATA_PATH || process.env.DB_PATH || path.resolve(__dirname, 'portal.sqlite');
  const dbDir = path.dirname(dbPath);
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }
  const isFirstRun = !fs.existsSync(dbPath);

  const db = new sqlite3.Database(dbPath);
  db.run('PRAGMA journal_mode = WAL;');
  db.run('PRAGMA synchronous = NORMAL;');

  const query = (sql, params = []) => {
    return new Promise((resolve, reject) => {
      const trimmed = sql.trim().toUpperCase();
      if (trimmed.startsWith('SELECT') || trimmed.startsWith('PRAGMA')) {
        db.all(sql, params, (err, rows) => {
          if (err) return reject(err);
          resolve({ rows, rowCount: rows.length });
        });
      } else {
        db.run(sql, params, function (err) {
          if (err) return reject(err);
          resolve({ changes: this.changes, lastID: this.lastID, rowCount: this.changes });
        });
      }
    });
  };

  const init = async () => {
    await query(`
      CREATE TABLE IF NOT EXISTS servers (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        country_code TEXT NOT NULL DEFAULT 'US',
        country_name TEXT NOT NULL DEFAULT 'Estados Unidos',
        flag TEXT NOT NULL DEFAULT '🇺🇸',
        domain TEXT NOT NULL,
        ip TEXT NOT NULL,
        ssh_port INTEGER NOT NULL DEFAULT 22,
        proxy_port INTEGER NOT NULL DEFAULT 80,
        ssl_port INTEGER NOT NULL DEFAULT 443,
        udpgw_port INTEGER NOT NULL DEFAULT 7300,
        api_url TEXT NOT NULL,
        api_secret TEXT NOT NULL DEFAULT '',
        payload_template TEXT NOT NULL DEFAULT '',
        daily_limit INTEGER NOT NULL DEFAULT 50,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        created_by_ip TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (server_id) REFERENCES servers(id)
      );
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS admin_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_token TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL DEFAULT 'Token Principal Reseller',
        role TEXT NOT NULL DEFAULT 'reseller',
        is_active INTEGER NOT NULL DEFAULT 1,
        daily_limit INTEGER NOT NULL DEFAULT 500,
        total_created INTEGER NOT NULL DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_used_at DATETIME
      );
    `);

    // Sembrar API Key por defecto si no existe
    const keysCount = await query("SELECT COUNT(*) as count FROM api_keys");
    if (!keysCount.rows[0]?.count) {
      const initialKey = 'bc_live_' + crypto.randomBytes(24).toString('hex');
      await query("INSERT INTO api_keys (key_token, name) VALUES (?, 'Token Principal Reseller')", [initialKey]);
    }

    // Sembrar configuraciones por defecto
    const defaultConfigs = [
      { key: 'admin_password', value: 'Admin12345!' },
      { key: 'reseller_api_enabled', value: 'true' },
      { key: 'reseller_limit_gb', value: 'true' },
      { key: 'default_account_duration_days', value: '2' },
      { key: 'site_title', value: 'JOIF Cloud' }
    ];

    for (const item of defaultConfigs) {
      const existing = await query("SELECT value FROM admin_config WHERE key = ?", [item.key]);
      if (existing.rowCount === 0) {
        await query("INSERT INTO admin_config (key, value) VALUES (?, ?)", [item.key, item.value]);
      }
    }
  };

  const ready = init();

  return {
    db,
    query: async (sql, params) => {
      await ready;
      return query(sql, params);
    },
    ready,
    close: () => new Promise((resolve) => db.close(resolve))
  };
}

module.exports = { createDatabase };
