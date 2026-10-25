'use strict';

const path = require('node:path');
const fs = require('node:fs');
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

    // Sembrar servidor de prueba por defecto si la base es nueva
    const existingServers = await query('SELECT COUNT(*) as count FROM servers');
    if (existingServers.rows[0].count === 0) {
      await query(`
        INSERT INTO servers (
          id, name, country_code, country_name, flag, domain, ip,
          ssh_port, proxy_port, ssl_port, udpgw_port, api_url, api_secret,
          payload_template, daily_limit, is_active
        ) VALUES (
          'usa-01',
          'USA Premium #1',
          'US',
          'Estados Unidos',
          '🇺🇸',
          'usa.joif.net',
          '193.122.239.14',
          22,
          80,
          443,
          7300,
          'http://193.122.239.14:3000',
          '',
          'GET / HTTP/1.3[crlf]Host: rexo.personal.com.ar[crlf][crlf][crlf][split][crlf][split]GETT / HTTP/1.1[crlf]Host: usa.joif.net[crlf]Connection: Keep-Alive[crlf]Upgrade: websocket[crlf][crlf]',
          50,
          1
        );
      `);
    }

    // Sembrar contraseña de administrador por defecto si no existe
    const adminPass = await query("SELECT value FROM admin_config WHERE key = 'admin_password'");
    if (adminPass.rowCount === 0) {
      await query("INSERT INTO admin_config (key, value) VALUES ('admin_password', 'Admin12345!')");
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
