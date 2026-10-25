'use strict';

const express = require('express');
const path = require('node:path');
const crypto = require('node:crypto');
const { createDatabase } = require('./db');
const { checkEdgeHealth, createEdgeAccount, deleteEdgeAccount } = require('./server-client');

require('dotenv').config();

const PORT = Number(process.env.PORT) || 3000;
const CAPTCHA_SECRET = process.env.CAPTCHA_SECRET || crypto.randomBytes(16).toString('hex');
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

class AntibotChallengeCache {
  constructor() {
    this.challenges = new Map();
    this.failedAttempts = new Map();
    this.cleanupTimer = setInterval(() => {
      const now = Date.now();
      for (const [id, item] of this.challenges.entries()) {
        if (item.expiresAt < now) this.challenges.delete(id);
      }
      for (const [ip, item] of this.failedAttempts.entries()) {
        if (item.lockedUntil < now) this.failedAttempts.delete(ip);
      }
    }, 60000);
    if (this.cleanupTimer.unref) this.cleanupTimer.unref();
  }

  createChallenge(secret) {
    const isAddition = Math.random() > 0.35;
    let a, b, answer, question;

    if (isAddition) {
      a = Math.floor(Math.random() * 25) + 5;
      b = Math.floor(Math.random() * 15) + 1;
      answer = a + b;
      question = `¿Cuánto es ${a} + ${b}?`;
    } else {
      a = Math.floor(Math.random() * 30) + 15;
      b = Math.floor(Math.random() * 12) + 1;
      answer = a - b;
      question = `¿Cuánto es ${a} - ${b}?`;
    }

    const challengeId = crypto.randomBytes(16).toString('hex');
    const expiresAt = Date.now() + 180000; // 3 minutos
    const signature = crypto
      .createHmac('sha256', secret)
      .update(`${challengeId}:${expiresAt}:${answer}`)
      .digest('hex');

    this.challenges.set(challengeId, {
      answer,
      expiresAt,
      used: false
    });

    return {
      question,
      challengeId,
      expiresAt,
      signature,
      token: signature
    };
  }

  isIpLocked(ip) {
    const record = this.failedAttempts.get(ip);
    return Boolean(record && record.lockedUntil > Date.now());
  }

  recordFailure(ip) {
    const now = Date.now();
    const item = this.failedAttempts.get(ip) || { count: 0, lockedUntil: 0 };
    item.count += 1;
    if (item.count >= 5) {
      item.lockedUntil = now + 600000; // 10 minutos de bloqueo
    }
    this.failedAttempts.set(ip, item);
  }

  clearFailures(ip) {
    this.failedAttempts.delete(ip);
  }

  verify(challengeId, answer, signature, expiresAt, secret) {
    // 1. Verificación basada en caché (One-Time-Use con ChallengeId)
    if (challengeId && this.challenges.has(challengeId)) {
      const record = this.challenges.get(challengeId);
      if (record.used) {
        return { valid: false, reason: 'Este desafío anti-bot ya fue utilizado. Recarga la pregunta.' };
      }
      if (Date.now() > record.expiresAt) {
        this.challenges.delete(challengeId);
        return { valid: false, reason: 'El desafío anti-bot ha caducado. Genera uno nuevo.' };
      }
      if (Number(answer) !== record.answer) {
        return { valid: false, reason: 'Respuesta de verificación matemática incorrecta.' };
      }

      // Validar firma HMAC
      const expectedSig = crypto
        .createHmac('sha256', secret)
        .update(`${challengeId}:${record.expiresAt}:${record.answer}`)
        .digest('hex');

      if (signature !== expectedSig) {
        return { valid: false, reason: 'Firma de verificación anti-bot inválida.' };
      }

      // Marcar de inmediato como usado en memoria para evitar repeticiones (Zero-Replay)
      record.used = true;
      return { valid: true };
    }

    // 2. Modo fallback (para tests o solicitudes de firma directa)
    if (signature) {
      const expectedToken = crypto
        .createHmac('sha256', secret)
        .update(String(answer).trim())
        .digest('hex');
      if (signature === expectedToken) {
        return { valid: true };
      }
    }

    return { valid: false, reason: 'Respuesta de verificación incorrecta o desafío expirado.' };
  }

  close() {
    clearInterval(this.cleanupTimer);
    this.challenges.clear();
    this.failedAttempts.clear();
  }
}

function createApp(options = {}) {
  const database = options.database || createDatabase(options);
  const antibot = options.antibot || new AntibotChallengeCache();
  const app = express();

  app.disable('x-powered-by');
  app.set('trust proxy', true);
  app.use(express.json());

  // CloudFront / Static Assets Caching (1 hora para HTML con stale-while-revalidate, 7 días para estáticos)
  app.use(
    express.static(path.resolve(__dirname, 'public'), {
      maxAge: '1d',
      setHeaders: (res, filePath) => {
        if (filePath.endsWith('.html')) {
          res.setHeader('Cache-Control', 'public, max-age=3600, stale-while-revalidate=86400');
        } else {
          res.setHeader('Cache-Control', 'public, max-age=604800, immutable');
        }
      }
    })
  );

  // Healthcheck para Portainer y Docker
  app.get('/health', (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.status(200).json({
      status: 'ok',
      uptime: Math.round(process.uptime()),
      timestamp: new Date().toISOString()
    });
  });

  // No-Cache estricto para APIs dinámicas
  app.use('/api', (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
  });

  // Función para obtener la IP del cliente real (detecta AWS CloudFront, Cloudflare y Proxies)
  const getClientIp = (req) => {
    const cfViewer = req.headers['cloudfront-viewer-address'];
    if (cfViewer) {
      const raw = cfViewer.split(':')[0].replace(/[[\]]/g, '').trim();
      if (raw) return raw;
    }
    const xForwarded = req.headers['x-forwarded-for'];
    if (xForwarded) {
      const first = xForwarded.split(',')[0].trim();
      if (first) return first;
    }
    return (
      req.headers['cf-connecting-ip'] ||
      req.headers['true-client-ip'] ||
      req.ip ||
      req.socket?.remoteAddress ||
      '127.0.0.1'
    );
  };

  // Middleware de Admin
  const requireAdmin = async (req, res, next) => {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    const adminPassHeader = req.headers['x-admin-password'];

    const storedPassRow = await database.query("SELECT value FROM admin_config WHERE key = 'admin_password'");
    const expectedPass = storedPassRow.rows[0]?.value || 'Admin12345!';

    if (adminPassHeader && adminPassHeader === expectedPass) {
      return next();
    }

    if (token) {
      try {
        const decoded = JSON.parse(Buffer.from(token, 'base64url').toString('utf8'));
        if (decoded && decoded.role === 'admin' && decoded.exp > Date.now()) {
          return next();
        }
      } catch {}
    }

    return res.status(401).json({ error: 'Acceso no autorizado como administrador.' });
  };

  // Middleware para autenticar llamadas de Reseller con Token B2B (bc_live_...)
  const requireResellerAuth = async (req, res, next) => {
    const enabledRes = await database.query("SELECT value FROM admin_config WHERE key = 'reseller_api_enabled'");
    const isEnabled = enabledRes.rows[0]?.value !== 'false';
    if (!isEnabled) {
      return res.status(403).json({ error: 'La API Reseller está desactivada actualmente.' });
    }

    const authHeader = req.headers['authorization'] || '';
    let token = '';
    if (authHeader.startsWith('Bearer ')) {
      token = authHeader.slice(7).trim();
    } else if (req.headers['x-api-key']) {
      token = String(req.headers['x-api-key']).trim();
    }

    if (!token) {
      return res.status(401).json({ error: 'Token de autorización requerido en header Authorization: Bearer ${b2bApiToken}' });
    }

    const keyRes = await database.query("SELECT * FROM api_keys WHERE key_token = ? AND is_active = 1", [token]);
    if (keyRes.rowCount === 0) {
      return res.status(401).json({ error: 'Token de API inválido, revocado o inactivo.' });
    }

    req.resellerKey = keyRes.rows[0];
    next();
  };

  // ==========================================
  // RUTAS PÚBLICAS
  // ==========================================

  // 1. Listado de servidores disponibles con cupos en vivo
  app.get('/api/public/servers', async (req, res) => {
    try {
      const serversResult = await database.query(`
        SELECT 
          s.id, s.name, s.country_code, s.country_name, s.flag,
          s.domain, s.ip, s.ssh_port, s.proxy_port, s.ssl_port, s.udpgw_port,
          s.payload_template, s.daily_limit,
          COUNT(CASE WHEN date(a.created_at) = date('now') THEN 1 END) as accounts_today
        FROM servers s
        LEFT JOIN accounts a ON s.id = a.server_id
        WHERE s.is_active = 1
        GROUP BY s.id
        ORDER BY s.country_name ASC, s.name ASC
      `);

      const servers = serversResult.rows.map((srv) => ({
        id: srv.id,
        name: srv.name,
        country_code: srv.country_code,
        country_name: srv.country_name,
        flag: srv.flag,
        domain: srv.domain,
        ip: srv.ip,
        ports: {
          ssh: srv.ssh_port,
          proxy: srv.proxy_port,
          ssl: srv.ssl_port,
          udpgw: srv.udpgw_port
        },
        payload_template: srv.payload_template,
        daily_limit: srv.daily_limit,
        accounts_today: Number(srv.accounts_today) || 0,
        slots_remaining: Math.max(0, srv.daily_limit - (Number(srv.accounts_today) || 0)),
        status: 'online'
      }));

      res.json({ success: true, servers });
    } catch (err) {
      res.status(500).json({ error: 'Error obteniendo lista de servidores: ' + err.message });
    }
  });

  // 2. Generador de Captcha matemático con caché anti-replay
  app.get('/api/public/captcha', (req, res) => {
    const challenge = antibot.createChallenge(CAPTCHA_SECRET);
    res.json(challenge);
  });

  // 3. Creación de cuenta pública (2 días de vigencia)
  app.post('/api/public/create-account', async (req, res) => {
    const { serverId, username, password, captchaAnswer, captchaToken, challengeId, expiresAt, signature } = req.body;
    const clientIp = getClientIp(req);

    // a. Verificar si la IP está bloqueada por exceso de intentos erróneos
    if (antibot.isIpLocked(clientIp)) {
      return res.status(429).json({ error: 'Demasiados intentos fallidos de verificación. Tu IP está temporalmente en espera (10 min).' });
    }

    // b. Validar respuesta del captcha anti-bot
    const sig = signature || captchaToken;
    if (captchaAnswer === undefined || captchaAnswer === null || captchaAnswer === '' || !sig) {
      return res.status(400).json({ error: 'Por favor responde la pregunta de verificación (anti-bot).' });
    }

    const verification = antibot.verify(challengeId, captchaAnswer, sig, expiresAt, CAPTCHA_SECRET);
    if (!verification.valid) {
      antibot.recordFailure(clientIp);
      return res.status(400).json({ error: verification.reason || 'Respuesta de verificación incorrecta. Inténtalo de nuevo.' });
    }

    // Limpiar contador de fallos de captcha al responder correctamente
    antibot.clearFailures(clientIp);

    // b. Validar formato de usuario y contraseña
    if (!username || !/^[a-zA-Z0-9]{3,12}$/.test(username)) {
      return res.status(400).json({ error: 'El usuario debe ser alfanumérico (3 a 12 caracteres, sin espacios).' });
    }
    if (!password || !/^[a-zA-Z0-9_.-]{4,20}$/.test(password)) {
      return res.status(400).json({ error: 'La contraseña debe tener entre 4 y 20 caracteres.' });
    }

    // c. Anti-Abuso: Límite por IP (máximo 2 cuentas por IP cada 24 horas)
    const ipCheck = await database.query(`
      SELECT COUNT(*) as count 
      FROM accounts 
      WHERE created_by_ip = ? AND created_at > datetime('now', '-24 hours')
    `, [clientIp]);

    if (ipCheck.rows[0]?.count >= 2) {
      return res.status(429).json({ error: 'Has alcanzado el límite máximo de 2 cuentas por día desde tu IP. Vuelve mañana.' });
    }

    // d. Buscar servidor y verificar cupo diario
    const srvResult = await database.query('SELECT * FROM servers WHERE id = ? AND is_active = 1', [serverId]);
    if (srvResult.rowCount === 0) {
      return res.status(404).json({ error: 'Servidor no encontrado o temporalmente fuera de servicio.' });
    }
    const server = srvResult.rows[0];

    const todayCountRes = await database.query(`
      SELECT COUNT(*) as count 
      FROM accounts 
      WHERE server_id = ? AND date(created_at) = date('now')
    `, [serverId]);

    if (todayCountRes.rows[0]?.count >= server.daily_limit) {
      return res.status(400).json({ error: 'Este servidor ya alcanzó su cupo máximo de cuentas diarias. Elige otro servidor disponible.' });
    }

    // e. Calcular vigencia exacta: 2 días (48 horas)
    const DURATION_DAYS = 2;
    const expiresDate = new Date(Date.now() + DURATION_DAYS * 24 * 60 * 60 * 1000);
    const expiresIso = expiresDate.toISOString();

    // f. Ordenar creación en el nodo Edge VPS
    try {
      await createEdgeAccount({
        apiUrl: server.api_url,
        apiSecret: server.api_secret,
        username,
        password,
        expirationDate: expiresIso,
        maxConnections: 1
      });
    } catch (edgeErr) {
      console.error(`[HUB] Error al crear cuenta en nodo edge ${server.name}:`, edgeErr.message);
      return res.status(502).json({
        error: `Error al crear cuenta en ${server.name}: ${edgeErr.message}. Verifica que el servicio esté activo y la clave API coincida.`
      });
    }

    // g. Guardar registro en la base de datos central
    await database.query(`
      INSERT INTO accounts (server_id, username, password, created_by_ip, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `, [serverId, username, password, clientIp, expiresIso]);

    // h. Armar payload listo para usar
    let payload = server.payload_template;
    if (!payload) {
      payload = `GET / HTTP/1.3[crlf]Host: rexo.personal.com.ar[crlf][crlf][crlf][split][crlf][split]GETT / HTTP/1.1[crlf]Host: ${server.domain}[crlf]Connection: Keep-Alive[crlf]Upgrade: websocket[crlf][crlf]`;
    }

    return res.status(201).json({
      success: true,
      server: {
        id: server.id,
        name: server.name,
        country: server.country_name,
        flag: server.flag,
        domain: server.domain,
        ip: server.ip
      },
      account: {
        username,
        password,
        duration_days: DURATION_DAYS,
        expires_at: expiresIso
      },
      ports: {
        ssh: server.ssh_port,
        proxy: server.proxy_port,
        ssl: server.ssl_port,
        udpgw: server.udpgw_port
      },
      payload
    });
  });

  // ==========================================
  // RUTAS DE ADMINISTRACIÓN
  // ==========================================

  // Login de Admin
  app.post('/api/admin/login', async (req, res) => {
    const { password } = req.body;
    const passRow = await database.query("SELECT value FROM admin_config WHERE key = 'admin_password'");
    const expected = passRow.rows[0]?.value || 'Admin12345!';

    if (password === expected) {
      const token = Buffer.from(
        JSON.stringify({ role: 'admin', exp: Date.now() + 24 * 60 * 60 * 1000 })
      ).toString('base64url');
      return res.json({ success: true, token });
    }
    return res.status(401).json({ error: 'Contraseña de administrador incorrecta.' });
  });

  // Listar todos los servidores (Admin)
  app.get('/api/admin/servers', requireAdmin, async (req, res) => {
    try {
      const result = await database.query(`
        SELECT s.*, COUNT(a.id) as total_accounts,
               COUNT(CASE WHEN date(a.created_at) = date('now') THEN 1 END) as today_accounts
        FROM servers s
        LEFT JOIN accounts a ON s.id = a.server_id
        GROUP BY s.id
        ORDER BY s.created_at DESC
      `);
      res.json({ success: true, servers: result.rows });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Agregar servidor (Admin)
  app.post('/api/admin/servers', requireAdmin, async (req, res) => {
    const {
      id, name, country_code, country_name, flag, domain, ip,
      ssh_port, proxy_port, ssl_port, udpgw_port, api_url, api_secret,
      payload_template, daily_limit, is_active
    } = req.body;

    if (!id || !name || !domain || !ip || !api_url) {
      return res.status(400).json({ error: 'Faltan campos obligatorios (id, name, domain, ip, api_url).' });
    }

    try {
      await database.query(`
        INSERT INTO servers (
          id, name, country_code, country_name, flag, domain, ip,
          ssh_port, proxy_port, ssl_port, udpgw_port, api_url, api_secret,
          payload_template, daily_limit, is_active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        id.trim().toLowerCase(),
        name.trim(),
        country_code || 'US',
        country_name || 'Estados Unidos',
        flag || '🌐',
        domain.trim(),
        ip.trim(),
        Number(ssh_port) || 22,
        Number(proxy_port) || 80,
        Number(ssl_port) || 443,
        Number(udpgw_port) || 7300,
        api_url.trim(),
        api_secret || '',
        payload_template || '',
        Number(daily_limit) || 50,
        is_active !== undefined ? (is_active ? 1 : 0) : 1
      ]);

      res.status(201).json({ success: true, message: 'Servidor agregado con éxito.' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Editar servidor (Admin)
  app.put('/api/admin/servers/:id', requireAdmin, async (req, res) => {
    const srvId = req.params.id;
    const {
      name, country_code, country_name, flag, domain, ip,
      ssh_port, proxy_port, ssl_port, udpgw_port, api_url, api_secret,
      payload_template, daily_limit, is_active
    } = req.body;

    try {
      await database.query(`
        UPDATE servers SET
          name = COALESCE(?, name),
          country_code = COALESCE(?, country_code),
          country_name = COALESCE(?, country_name),
          flag = COALESCE(?, flag),
          domain = COALESCE(?, domain),
          ip = COALESCE(?, ip),
          ssh_port = COALESCE(?, ssh_port),
          proxy_port = COALESCE(?, proxy_port),
          ssl_port = COALESCE(?, ssl_port),
          udpgw_port = COALESCE(?, udpgw_port),
          api_url = COALESCE(?, api_url),
          api_secret = COALESCE(?, api_secret),
          payload_template = COALESCE(?, payload_template),
          daily_limit = COALESCE(?, daily_limit),
          is_active = COALESCE(?, is_active)
        WHERE id = ?
      `, [
        name, country_code, country_name, flag, domain, ip,
        ssh_port, proxy_port, ssl_port, udpgw_port, api_url, api_secret,
        payload_template, daily_limit, is_active,
        srvId
      ]);

      res.json({ success: true, message: 'Servidor actualizado.' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Eliminar servidor (Admin)
  app.delete('/api/admin/servers/:id', requireAdmin, async (req, res) => {
    try {
      await database.query('DELETE FROM accounts WHERE server_id = ?', [req.params.id]);
      await database.query('DELETE FROM servers WHERE id = ?', [req.params.id]);
      res.json({ success: true, message: 'Servidor eliminado.' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Probar conectividad con un servidor (Ping / Health)
  app.post('/api/admin/servers/:id/ping', requireAdmin, async (req, res) => {
    const srv = await database.query('SELECT api_url, api_secret FROM servers WHERE id = ?', [req.params.id]);
    if (srv.rowCount === 0) return res.status(404).json({ error: 'Servidor no encontrado' });

    const startTime = Date.now();
    const health = await checkEdgeHealth(srv.rows[0].api_url, srv.rows[0].api_secret);
    const latency = Date.now() - startTime;

    res.json({ ...health, latency_ms: latency });
  });

  // Listar todas las cuentas creadas (Admin)
  app.get('/api/admin/accounts', requireAdmin, async (req, res) => {
    try {
      const accountsRes = await database.query(`
        SELECT a.id, a.server_id, s.name as server_name, s.flag,
               a.username, a.created_by_ip, a.expires_at, a.created_at
        FROM accounts a
        JOIN servers s ON a.server_id = s.id
        ORDER BY a.created_at DESC
        LIMIT 100
      `);
      res.json({ success: true, accounts: accountsRes.rows });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Revocar / eliminar cuenta remotamente (Admin)
  app.delete('/api/admin/accounts/:id', requireAdmin, async (req, res) => {
    try {
      const accRes = await database.query(`
        SELECT a.username, a.server_id, s.api_url, s.api_secret 
        FROM accounts a 
        JOIN servers s ON a.server_id = s.id 
        WHERE a.id = ?
      `, [req.params.id]);

      if (accRes.rowCount === 0) return res.status(404).json({ error: 'Cuenta no encontrada' });
      const acc = accRes.rows[0];

      // Eliminar en el VPS
      await deleteEdgeAccount({
        apiUrl: acc.api_url,
        apiSecret: acc.api_secret,
        username: acc.username
      }).catch((e) => console.warn('[HUB] Advertencia eliminando en VPS:', e.message));

      // Eliminar en la base central
      await database.query('DELETE FROM accounts WHERE id = ?', [req.params.id]);

      res.json({ success: true, message: 'Cuenta eliminada exitosamente.' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ==========================================
  // CONFIGURACIÓN Y GESTIÓN DE API KEYS (ADMIN)
  // ==========================================

  // Obtener configuraciones generales y estadísticas
  app.get('/api/admin/settings', requireAdmin, async (req, res) => {
    try {
      const configRes = await database.query('SELECT key, value FROM admin_config');
      const configs = {};
      configRes.rows.forEach(r => { configs[r.key] = r.value; });

      const srvCount = await database.query('SELECT COUNT(*) as count FROM servers');
      const accCount = await database.query('SELECT COUNT(*) as count FROM accounts');
      const todayCount = await database.query("SELECT COUNT(*) as count FROM accounts WHERE date(created_at) = date('now')");
      const keysCount = await database.query('SELECT COUNT(*) as count FROM api_keys WHERE is_active = 1');

      res.json({
        success: true,
        configs,
        stats: {
          total_servers: srvCount.rows[0]?.count || 0,
          total_accounts: accCount.rows[0]?.count || 0,
          today_accounts: todayCount.rows[0]?.count || 0,
          active_api_keys: keysCount.rows[0]?.count || 0
        }
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Actualizar configuraciones
  app.post('/api/admin/settings', requireAdmin, async (req, res) => {
    try {
      const { settings } = req.body;
      if (!settings || typeof settings !== 'object') {
        return res.status(400).json({ error: 'Configuración inválida' });
      }

      for (const [key, value] of Object.entries(settings)) {
        if (key === 'admin_password') continue;
        await database.query(`
          INSERT INTO admin_config (key, value) VALUES (?, ?)
          ON CONFLICT(key) DO UPDATE SET value = excluded.value
        `, [key, String(value)]);
      }

      res.json({ success: true, message: 'Configuraciones actualizadas exitosamente.' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Cambiar contraseña de administrador
  app.post('/api/admin/change-password', requireAdmin, async (req, res) => {
    try {
      const { new_password } = req.body;
      if (!new_password || typeof new_password !== 'string' || new_password.length < 6) {
        return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 6 caracteres.' });
      }

      await database.query(`
        INSERT INTO admin_config (key, value) VALUES ('admin_password', ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
      `, [new_password]);

      res.json({ success: true, message: 'Contraseña de administrador actualizada.' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Listar todas las API Keys
  app.get('/api/admin/api-keys', requireAdmin, async (req, res) => {
    try {
      const result = await database.query(`
        SELECT id, key_token, name, role, is_active, daily_limit, total_created, created_at, last_used_at
        FROM api_keys
        ORDER BY created_at DESC
      `);
      res.json({ success: true, keys: result.rows });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Generar nueva API Key (estilo bc_live_...)
  app.post('/api/admin/api-keys', requireAdmin, async (req, res) => {
    try {
      const { name, daily_limit } = req.body;
      const keyToken = 'bc_live_' + crypto.randomBytes(24).toString('hex');
      const keyName = name && name.trim() ? name.trim() : 'Token Reseller ' + new Date().toISOString().slice(0, 10);
      const limit = Number(daily_limit) > 0 ? Number(daily_limit) : 500;

      const result = await database.query(`
        INSERT INTO api_keys (key_token, name, daily_limit)
        VALUES (?, ?, ?)
      `, [keyToken, keyName, limit]);

      res.status(201).json({
        success: true,
        message: 'API Key generada exitosamente.',
        key: {
          id: result.lastID,
          key_token: keyToken,
          name: keyName,
          daily_limit: limit,
          is_active: 1
        }
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Alternar estado activo de API Key
  app.post('/api/admin/api-keys/:id/toggle', requireAdmin, async (req, res) => {
    try {
      const curr = await database.query('SELECT is_active FROM api_keys WHERE id = ?', [req.params.id]);
      if (curr.rowCount === 0) return res.status(404).json({ error: 'Key no encontrada' });
      const newStatus = curr.rows[0].is_active ? 0 : 1;
      await database.query('UPDATE api_keys SET is_active = ? WHERE id = ?', [newStatus, req.params.id]);
      res.json({ success: true, is_active: newStatus });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Eliminar API Key
  app.delete('/api/admin/api-keys/:id', requireAdmin, async (req, res) => {
    try {
      await database.query('DELETE FROM api_keys WHERE id = ?', [req.params.id]);
      res.json({ success: true, message: 'API Key eliminada.' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ==========================================
  // API RESELLER B2B (INTEGRACIÓN EXTERNA)
  // ==========================================

  // 1. Crear cuenta SSH en un VPS asignado (POST /api/v1/reseller/ssh/create)
  app.post('/api/v1/reseller/ssh/create', requireResellerAuth, async (req, res) => {
    const { username, password, connection_limit, expiration_days, vps_id, gb_limity } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Faltan campos obligatorios: username y password.' });
    }

    if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) {
      return res.status(400).json({ error: 'El nombre de usuario debe contener entre 3 y 24 caracteres alfanuméricos.' });
    }

    // Buscar servidor
    let server = null;
    if (vps_id !== undefined && vps_id !== null && vps_id !== '') {
      const srvRes = await database.query('SELECT * FROM servers WHERE (id = ? OR rowid = ?) AND is_active = 1', [String(vps_id), String(vps_id)]);
      server = srvRes.rows[0];
    }
    if (!server) {
      const fallback = await database.query('SELECT * FROM servers WHERE is_active = 1 ORDER BY created_at ASC LIMIT 1');
      server = fallback.rows[0];
    }
    if (!server) {
      return res.status(503).json({ error: 'No hay servidores VPS disponibles o activos en el clúster.' });
    }

    const durationDays = Number(expiration_days) > 0 ? Number(expiration_days) : 30;
    const expiresDate = new Date(Date.now() + durationDays * 24 * 60 * 60 * 1000);
    const expiresIso = expiresDate.toISOString();

    try {
      await createEdgeAccount({
        apiUrl: server.api_url,
        apiSecret: server.api_secret,
        username,
        password,
        expirationDate: expiresIso,
        maxConnections: Number(connection_limit) || 1
      });
    } catch (edgeErr) {
      console.error(`[RESELLER API] Error creando cuenta en VPS ${server.name}:`, edgeErr.message);
      return res.status(502).json({ error: `Error al crear cuenta en ${server.name}: ${edgeErr.message}` });
    }

    // Registrar en BD
    await database.query(`
      INSERT INTO accounts (server_id, username, password, created_by_ip, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `, [server.id, username, password, 'API_B2B', expiresIso]);

    // Incrementar contador en api_keys
    await database.query(`
      UPDATE api_keys
      SET total_created = total_created + 1, last_used_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `, [req.resellerKey.id]);

    let payload = server.payload_template;
    if (!payload) {
      payload = `GET / HTTP/1.3[crlf]Host: rexo.personal.com.ar[crlf][crlf][crlf][split][crlf][split]GETT / HTTP/1.1[crlf]Host: ${server.domain}[crlf]Connection: Keep-Alive[crlf]Upgrade: websocket[crlf][crlf]`;
    }

    return res.status(201).json({
      success: true,
      message: 'Cuenta creada con éxito en el clúster',
      data: {
        username,
        password,
        connection_limit: Number(connection_limit) || 1,
        gb_limit: Number(gb_limity) || 0,
        expiration_days: durationDays,
        expires_at: expiresIso,
        vps_id: server.id,
        server: {
          id: server.id,
          name: server.name,
          country: server.country_name,
          flag: server.flag,
          domain: server.domain,
          ip: server.ip,
          ssh_port: server.ssh_port,
          proxy_port: server.proxy_port,
          ssl_port: server.ssl_port,
          udpgw_port: server.udpgw_port
        },
        payload
      }
    });
  });

  // 2. Info de cuenta específica (GET /api/v1/reseller/ssh/info/:username)
  app.get('/api/v1/reseller/ssh/info/:username', requireResellerAuth, async (req, res) => {
    const { username } = req.params;
    const accRes = await database.query(`
      SELECT a.*, s.name as server_name, s.domain, s.ip, s.ssh_port, s.proxy_port, s.udpgw_port, s.api_url, s.api_secret
      FROM accounts a
      JOIN servers s ON a.server_id = s.id
      WHERE a.username = ?
      ORDER BY a.created_at DESC LIMIT 1
    `, [username]);

    if (accRes.rowCount === 0) {
      return res.status(404).json({ error: `Usuario ${username} no encontrado` });
    }

    const acc = accRes.rows[0];
    const expDate = new Date(acc.expires_at);
    const now = new Date();
    const daysRemaining = Math.max(0, Math.ceil((expDate - now) / (1000 * 60 * 60 * 24)));

    return res.json({
      success: true,
      username: acc.username,
      server_id: acc.server_id,
      server_name: acc.server_name,
      domain: acc.domain,
      ip: acc.ip,
      ports: {
        ssh: acc.ssh_port,
        proxy: acc.proxy_port,
        udpgw: acc.udpgw_port
      },
      expires_at: acc.expires_at,
      days_remaining: daysRemaining,
      created_at: acc.created_at,
      is_active: expDate > now
    });
  });

  // 3. Listar cuentas creadas (GET /api/v1/reseller/ssh/list)
  app.get('/api/v1/reseller/ssh/list', requireResellerAuth, async (req, res) => {
    const result = await database.query(`
      SELECT a.id, a.server_id, s.name as server_name, s.domain, s.ip,
             a.username, a.expires_at, a.created_at,
             CASE WHEN datetime(a.expires_at) > datetime('now') THEN 1 ELSE 0 END as is_active
      FROM accounts a
      JOIN servers s ON a.server_id = s.id
      ORDER BY a.created_at DESC
      LIMIT 200
    `);

    return res.json({
      success: true,
      total: result.rowCount,
      accounts: result.rows
    });
  });

  // 4. Eliminar cuenta permanentemente (DELETE /api/v1/reseller/ssh/delete/:username)
  app.delete('/api/v1/reseller/ssh/delete/:username', requireResellerAuth, async (req, res) => {
    const { username } = req.params;
    const accRes = await database.query(`
      SELECT a.id, a.username, a.server_id, s.api_url, s.api_secret
      FROM accounts a
      JOIN servers s ON a.server_id = s.id
      WHERE a.username = ?
      LIMIT 1
    `, [username]);

    if (accRes.rowCount === 0) {
      return res.status(404).json({ error: `Usuario ${username} no encontrado` });
    }

    const acc = accRes.rows[0];

    try {
      await deleteEdgeAccount({
        apiUrl: acc.api_url,
        apiSecret: acc.api_secret,
        username: acc.username
      });
    } catch (e) {
      console.warn('[RESELLER API] Aviso eliminando en VPS:', e.message);
    }

    await database.query('DELETE FROM accounts WHERE id = ?', [acc.id]);

    return res.json({
      success: true,
      message: `Cuenta ${username} eliminada permanentemente del clúster.`
    });
  });

  return { app, database, antibot };
}

if (require.main === module) {
  const { app } = createApp();
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🌐 [PORTAL-HUB] Servidor Central activo en http://0.0.0.0:${PORT}`);
  });
}

module.exports = { createApp, AntibotChallengeCache };
