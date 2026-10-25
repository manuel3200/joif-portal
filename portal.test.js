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

  const { app, antibot } = createApp({ database });
  const serverHandle = await makeTestServer(app);

  t.after(async () => {
    global.fetch = originalFetch;
    if (antibot) antibot.close();
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
  });
});
