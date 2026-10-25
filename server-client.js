'use strict';

/**
 * Cliente de comunicación con los nodos Edge VPS de MiVPN / JOIF Cloud
 */

async function checkEdgeHealth(apiUrl, apiSecret = '', timeoutMs = 3000) {
  try {
    const cleanUrl = apiUrl.replace(/\/+$/, '');
    const headers = {};
    if (apiSecret) headers['x-api-key'] = apiSecret;

    const res = await fetch(`${cleanUrl}/check`, {
      method: 'GET',
      headers,
      signal: AbortSignal.timeout(timeoutMs)
    });

    return {
      online: res.ok,
      status: res.status
    };
  } catch (err) {
    return {
      online: false,
      error: err.message
    };
  }
}

async function createEdgeAccount({ apiUrl, apiSecret = '', username, password, expirationDate, maxConnections = 1, timeoutMs = 6000 }) {
  const cleanUrl = apiUrl.replace(/\/+$/, '');
  const headers = {
    'Content-Type': 'application/json'
  };
  if (apiSecret) headers['x-api-key'] = apiSecret;

  const body = JSON.stringify({
    username,
    password,
    expiration_date: expirationDate,
    max_connections: maxConnections
  });

  const res = await fetch(`${cleanUrl}/api/users`, {
    method: 'POST',
    headers,
    body,
    signal: AbortSignal.timeout(timeoutMs)
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new Error(data.error || `El servidor edge respondió con estado HTTP ${res.status}`);
  }

  return data;
}

async function deleteEdgeAccount({ apiUrl, apiSecret = '', username, timeoutMs = 5000 }) {
  const cleanUrl = apiUrl.replace(/\/+$/, '');
  const headers = {};
  if (apiSecret) headers['x-api-key'] = apiSecret;

  const res = await fetch(`${cleanUrl}/api/users/${encodeURIComponent(username)}`, {
    method: 'DELETE',
    headers,
    signal: AbortSignal.timeout(timeoutMs)
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok && res.status !== 404) {
    throw new Error(data.error || `Error eliminando cuenta: HTTP ${res.status}`);
  }

  return data;
}

module.exports = {
  checkEdgeHealth,
  createEdgeAccount,
  deleteEdgeAccount
};
