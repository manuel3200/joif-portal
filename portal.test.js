'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');
const http = require('node:http');

const { createApp } = require('./server');
const { createDatabase } = require('./db');

function makeTestServer(app) {
  return new Promise((resolve) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        server,
        url: `http://127.0.0.1:${port}`,
        close: () => new Promise((res) => server.close(res))
      });
    });
  });
}

test('Central Portal - Public API & Account Creation Flow', async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-test-'));
  const dbPath = path.join(tmpDir, 'test-portal.sqlite');
  const database = createDatabase({ dbPath });
  await database.ready;

  await database.query(`
    INSERT INTO servers (
      id, name, country_code, country_name, flag, domain, ip,
      ssh_port, proxy_port, ssl_port, udpgw_port, api_url, api_secret,
      payload_template, daily_limit, is_active
    ) VALUES (
      'usa-01', 'USA Premium #1', 'US', 'Estados Unidos', '🇺🇸',
      'usa.joif.net', '193.122.239.14', 22, 80, 443, 7300,
      'http://193.122.239.14:3000', 'joif2026', '', 50, 1
    )
  `);

  // Interceptar fetch para simular el nodo Edge VPS
  const originalFetch = global.fetch;
  let mockEdgeCreatedAccounts = [];

  global.fetch = async (url, options = {}) => {
    if (typeof url === 'string' && (url.includes('193.122.239.14') || url.includes('161.153.217.69') || url.includes('/api/users') || url.endsWith('/check'))) {
      if (url.includes('/api/users')) {
        const body = JSON.parse(options.body || '{}');
        mockEdgeCreatedAccounts.push(body);
        return {
          ok: true,
          status: 201,
          json: async () => ({ message: 'Usuario creado con éxito', id: 99 })
        };
      }
      if (url.includes('/check')) {
        return {
          ok: true,
          status: 200,
          json: async () => ['user1', 'user2']
        };
      }
    }
    return originalFetch(url, options);
  };

  const { app, antibot, telegramService } = createApp({ database, autoStartTelegram: false });
  const serverHandle = await makeTestServer(app);

  t.after(async () => {
    global.fetch = originalFetch;
    if (antibot) antibot.close();
    if (telegramService) telegramService.stopPolling();
    await serverHandle.close();
    await database.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  await t.test('1. GET /health retorna status ok para Portainer y CloudFront', async () => {
    const res = await fetch(`${serverHandle.url}/health`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, 'ok');
    assert.ok(typeof data.uptime === 'number');
  });

  await t.test('2. GET /api/public/servers retorna lista de servidores y headers No-Cache para CloudFront', async () => {
    const res = await fetch(`${serverHandle.url}/api/public/servers`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('cache-control') || '', /no-store/);
    const data = await res.json();
    assert.equal(data.success, true);
    assert.ok(Array.isArray(data.servers));
    assert.ok(data.servers.length >= 1);
    const usa = data.servers.find((s) => s.id === 'usa-01');
    assert.ok(usa);
    assert.equal(usa.domain, 'usa.joif.net');
    assert.equal(usa.ports.ssh, 22);
    assert.equal(usa.ports.proxy, 80);
    assert.equal(usa.slots_remaining, 50);
  });

  await t.test('3. GET /api/public/captcha entrega pregunta matemática, challengeId y firma HMAC', async () => {
    const res = await fetch(`${serverHandle.url}/api/public/captcha`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(data.question.includes('¿Cuánto es'));
    assert.ok(typeof data.challengeId === 'string' && data.challengeId.length === 32);
    assert.ok(typeof data.signature === 'string' && data.signature.length === 64);
  });

  await t.test('4. POST /api/public/create-account rechaza captcha erróneo', async () => {
    const res = await fetch(`${serverHandle.url}/api/public/create-account`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        serverId: 'usa-01',
        username: 'juan123',
        password: 'password123',
        captchaAnswer: '999',
        captchaToken: 'invalid_token'
      })
    });
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.match(data.error, /Respuesta de verificación incorrecta/);
  });

  await t.test('5. POST /api/public/create-account crea cuenta por 2 días y bloquea replay en caché', async () => {
    // Obtener captcha real
    const capRes = await fetch(`${serverHandle.url}/api/public/captcha`);
    const capData = await capRes.json();
    const addMatch = capData.question.match(/(\d+)\s*\+\s*(\d+)/);
    const subMatch = capData.question.match(/(\d+)\s*-\s*(\d+)/);
    const answer = addMatch
      ? Number(addMatch[1]) + Number(addMatch[2])
      : Number(subMatch[1]) - Number(subMatch[2]);

    const res = await fetch(`${serverHandle.url}/api/public/create-account`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '200.50.10.1'
      },
      body: JSON.stringify({
        serverId: 'usa-01',
        username: 'testuser1',
        password: 'mypassword123',
        captchaAnswer: answer,
        challengeId: capData.challengeId,
        expiresAt: capData.expiresAt,
        signature: capData.signature
      })
    });

    assert.equal(res.status, 201);
    const data = await res.json();
    assert.equal(data.success, true);
    assert.equal(data.account.username, 'testuser1');
    assert.equal(data.account.duration_days, 2);
    assert.equal(mockEdgeCreatedAccounts.length, 1);
    assert.equal(mockEdgeCreatedAccounts[0].username, 'testuser1');

    // Verificar que expiración es ~48h en el futuro
    const expTime = new Date(data.account.expires_at).getTime();
    const diffHours = (expTime - Date.now()) / (1000 * 60 * 60);
    assert.ok(diffHours > 47 && diffHours <= 49);

    // ANTI-BOT CACHE REPLAY TEST: Intentar reutilizar el mismo desafío ya resuelto debe ser rechazado
    const replayRes = await fetch(`${serverHandle.url}/api/public/create-account`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '200.50.10.2'
      },
      body: JSON.stringify({
        serverId: 'usa-01',
        username: 'testreplay',
        password: 'password123',
        captchaAnswer: answer,
        challengeId: capData.challengeId,
        expiresAt: capData.expiresAt,
        signature: capData.signature
      })
    });
    assert.equal(replayRes.status, 400);
    const replayData = await replayRes.json();
  });

  await t.test('6. Rate Limiting bloquea más de 2 cuentas por IP al día', async () => {
    const createWithIp = async (ip, user) => {
      const capRes = await fetch(`${serverHandle.url}/api/public/captcha`);
      const capData = await capRes.json();
      const addMatch = capData.question.match(/(\d+)\s*\+\s*(\d+)/);
      const subMatch = capData.question.match(/(\d+)\s*-\s*(\d+)/);
      const answer = addMatch
        ? Number(addMatch[1]) + Number(addMatch[2])
        : Number(subMatch[1]) - Number(subMatch[2]);

      return fetch(`${serverHandle.url}/api/public/create-account`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Forwarded-For': ip
        },
        body: JSON.stringify({
          serverId: 'usa-01',
          username: user,
          password: 'password123',
          captchaAnswer: answer,
          challengeId: capData.challengeId,
          expiresAt: capData.expiresAt,
          signature: capData.signature
        })
      });
    };

    // La IP 200.50.10.1 ya creó 1 cuenta en el test 4.
    // Creamos la 2da cuenta:
    const res2 = await createWithIp('200.50.10.1', 'testuser2');
    assert.equal(res2.status, 201);

    // Intentamos la 3ra cuenta desde la misma IP (debe rechazar con 429):
    const res3 = await createWithIp('200.50.10.1', 'testuser3');
    assert.equal(res3.status, 429);
    const data3 = await res3.json();
    assert.match(data3.error, /límite máximo de 2 cuentas/);
  });

  await t.test('6. Panel Admin: login y gestión de servidores', async () => {
    // Login con clave por defecto
    const loginRes = await fetch(`${serverHandle.url}/api/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'Admin12345!' })
    });
    assert.equal(loginRes.status, 200);
    const loginData = await loginRes.json();
    assert.ok(loginData.token);

    // Agregar nuevo servidor
    const addRes = await fetch(`${serverHandle.url}/api/admin/servers`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${loginData.token}`
      },
      body: JSON.stringify({
        id: 'cl-01',
        name: 'Chile Santiago 01',
        country_code: 'CL',
        country_name: 'Chile',
        flag: '🇨🇱',
        domain: 'chile.juanconnect.online',
        ip: '161.153.217.69',
        ssh_port: 22,
        proxy_port: 80,
        api_url: 'http://161.153.217.69:3000',
        daily_limit: 30
      })
    });
    assert.equal(addRes.status, 201);

    // Listar servidores desde Admin
    const listRes = await fetch(`${serverHandle.url}/api/admin/servers`, {
      headers: { Authorization: `Bearer ${loginData.token}` }
    });
    const listData = await listRes.json();
    assert.equal(listData.servers.length, 2);
    const cl = listData.servers.find((s) => s.id === 'cl-01');
    assert.ok(cl);
    assert.equal(cl.flag, '🇨🇱');

    // Test de Seguridad: Intentar falsificar token sin firma criptográfica HMAC
    const fakeToken = Buffer.from(JSON.stringify({ role: 'admin', exp: Date.now() + 86400000 })).toString('base64url');
    const fakeRes = await fetch(`${serverHandle.url}/api/admin/servers`, {
      headers: { Authorization: `Bearer ${fakeToken}` }
    });
    assert.equal(fakeRes.status, 401, 'Token falsificado sin firma debe ser rechazado con 401');

    // Test de Seguridad: Token con firma alterada
    const tamperedToken = `${loginData.token.split('.')[0]}.firmainvalida123`;
    const tamperedRes = await fetch(`${serverHandle.url}/api/admin/servers`, {
      headers: { Authorization: `Bearer ${tamperedToken}` }
    });
    assert.equal(tamperedRes.status, 401, 'Token con firma alterada debe ser rechazado con 401');
  });

  await t.test('7. API JOIF Reseller & Generación de Token joif_live_...', async () => {
    // 1. Obtener API Keys como Admin
    const keysRes = await fetch(`${serverHandle.url}/api/admin/api-keys`, {
      headers: { 'x-admin-password': 'Admin12345!' }
    });
    assert.equal(keysRes.status, 200);
    const keysData = await keysRes.json();
    assert.ok(keysData.keys.length >= 1);
    const defaultKey = keysData.keys[0].key_token;
    assert.ok(defaultKey.startsWith('joif_live_'), 'El token debe comenzar con joif_live_');
    assert.equal(defaultKey.length, 58, 'El token debe tener 58 caracteres (joif_live_ + 48 hex)');

    // 2. Generar una nueva API Key desde el Admin
    const genRes = await fetch(`${serverHandle.url}/api/admin/api-keys`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-admin-password': 'Admin12345!'
      },
      body: JSON.stringify({ name: 'Token Bot Telegram', daily_limit: 1000 })
    });
    assert.equal(genRes.status, 201);
    const genData = await genRes.json();
    assert.ok(genData.key.key_token.startsWith('joif_live_'));
    const testApiToken = genData.key.key_token;

    // 3. Crear cuenta vía POST /api/v1/reseller/ssh/create con Bearer Token
    const createRes = await fetch(`${serverHandle.url}/api/v1/reseller/ssh/create`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${testApiToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username: 'botuser99',
        password: 'password123',
        connection_limit: 2,
        expiration_days: 30,
        vps_id: 'usa-01'
      })
    });
    assert.equal(createRes.status, 201);
    const createData = await createRes.json();
    assert.equal(createData.success, true);
    assert.equal(createData.data.username, 'botuser99');
    assert.equal(createData.data.server.id, 'usa-01');
    assert.ok(createData.data.server.ssh_port === 22);

    // 4. Consultar info de la cuenta: GET /api/v1/reseller/ssh/info/:username
    const infoRes = await fetch(`${serverHandle.url}/api/v1/reseller/ssh/info/botuser99`, {
      headers: { Authorization: `Bearer ${testApiToken}` }
    });
    assert.equal(infoRes.status, 200);
    const infoData = await infoRes.json();
    assert.equal(infoData.username, 'botuser99');
    assert.equal(infoData.is_active, true);
    assert.ok(infoData.days_remaining >= 29);

    // 5. Listar cuentas: GET /api/v1/reseller/ssh/list
    const listRes = await fetch(`${serverHandle.url}/api/v1/reseller/ssh/list`, {
      headers: { Authorization: `Bearer ${testApiToken}` }
    });
    assert.equal(listRes.status, 200);
    const listData = await listRes.json();
    assert.ok(listData.accounts.some((a) => a.username === 'botuser99'));

    // 6. Eliminar cuenta: DELETE /api/v1/reseller/ssh/delete/:username
    const delRes = await fetch(`${serverHandle.url}/api/v1/reseller/ssh/delete/botuser99`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${testApiToken}` }
    });
    assert.equal(delRes.status, 200);
    const delData = await delRes.json();
    assert.equal(delData.success, true);
  });

  await t.test('8. Verificación por Bot de Telegram y Grupo Oficial', async () => {
    // 1. GET /api/public/config retorna estado inicial
    const cfgRes = await fetch(`${serverHandle.url}/api/public/config`);
    assert.equal(cfgRes.status, 200);
    const cfgData = await cfgRes.json();
    assert.equal(cfgData.success, true);
    assert.equal(cfgData.telegram_verification_enabled, false);

    // 2. Activar verificación por Telegram desde Admin
    const setRes = await fetch(`${serverHandle.url}/api/admin/settings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-admin-password': 'Admin12345!'
      },
      body: JSON.stringify({
        settings: {
          telegram_verification_enabled: 'true',
          telegram_bot_token: '123456:FAKE_TOKEN_FOR_TEST',
          telegram_group_id: '@comunidad_prueba',
          telegram_group_link: 'https://t.me/comunidad_prueba',
          telegram_bot_username: 'PruebaVpnBot'
        }
      })
    });
    assert.equal(setRes.status, 200);

    // 3. Crear cuenta pública sin código de telegram debe fallar con 400
    const failRes = await fetch(`${serverHandle.url}/api/public/create-account`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '190.10.20.1'
      },
      body: JSON.stringify({
        serverId: 'usa-01',
        username: 'tguser01',
        password: 'password123'
      })
    });
    assert.equal(failRes.status, 400);
    const failData = await failRes.json();
    assert.match(failData.error, /código de verificación/);

    // 4. Generar un token válido en la base de datos a través de telegramService
    const code = await telegramService.generateCode('998877', 'tg_test_user');
    assert.equal(typeof code, 'string');
    assert.equal(code.length, 6);

    // 5. Crear cuenta pública con el código de Telegram correcto
    const okRes = await fetch(`${serverHandle.url}/api/public/create-account`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '190.10.20.1'
      },
      body: JSON.stringify({
        serverId: 'usa-01',
        username: 'tguser01',
        password: 'password123',
        telegramCode: code
      })
    });
    assert.equal(okRes.status, 201);
    const okData = await okRes.json();
    assert.equal(okData.success, true);
    assert.equal(okData.account.username, 'tguser01');

    // 6. Intentar reutilizar el mismo código de Telegram debe ser rechazado (Zero-Replay)
    const reuseRes = await fetch(`${serverHandle.url}/api/public/create-account`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '190.10.20.2'
      },
      body: JSON.stringify({
        serverId: 'usa-01',
        username: 'tguser02',
        password: 'password123',
        telegramCode: code
      })
    });
    assert.equal(reuseRes.status, 400);
    const reuseData = await reuseRes.json();
    assert.match(reuseData.error, /inválido|utilizado|expirado/);
  });
});
