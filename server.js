import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';

const PORT = Number(process.env.PORT || 3000);
const USERNAME = 'admin';
const PASSWORD = 'admin@123';
const SESSION_COOKIE = 'session';
const sessions = new Map();
const defaultAllowedOrigins = [
  'http://localhost',
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://frontend.greensand-a82f7b12.southindia.azurecontainerapps.io',
  'https://frontend.greensand-a82f7b12.southindia.azurecontainerapps.io'
].join(',');
const allowedOrigins = new Set(
  (process.env.FRONTEND_ORIGINS || process.env.FRONTEND_ORIGIN || defaultAllowedOrigins)
    .split(',')
    .map(origin => origin.trim().replace(/\/$/, ''))
    .filter(Boolean)
);

function equalSecret(value, expected) {
  const provided = Buffer.from(String(value ?? ''));
  const target = Buffer.from(expected);
  return provided.length === target.length && timingSafeEqual(provided, target);
}

function sendJson(res, status, body, headers = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers
  });
  res.end(JSON.stringify(body));
}

function readCookies(header = '') {
  return Object.fromEntries(header.split(';').map(part => {
    const index = part.indexOf('=');
    if (index < 0) return ['', ''];
    return [part.slice(0, index).trim(), decodeURIComponent(part.slice(index + 1).trim())];
  }).filter(([key]) => key));
}

const production = process.env.NODE_ENV === 'production';
const cookieFlags = `Path=/; HttpOnly; SameSite=${production ? 'None; Secure' : 'Lax'}`;

createServer(async (req, res) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.has(origin.replace(/\/$/, ''))) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  if (req.method === 'GET' && url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('OK');
  }

  const cookies = readCookies(req.headers.cookie);
  const activeUser = sessions.get(cookies[SESSION_COOKIE]);

  if (req.method === 'POST' && url.pathname === '/api/login') {
    let body;
    try {
      let raw = '';
      for await (const chunk of req) {
        raw += chunk;
        if (raw.length > 10_000) throw new Error('Request too large');
      }
      body = JSON.parse(raw);
    } catch {
      return sendJson(res, 400, { error: 'Send a valid JSON request.' });
    }

    if (!equalSecret(body?.username, USERNAME) || !equalSecret(body?.password, PASSWORD)) {
      return sendJson(res, 401, { error: 'Incorrect username or password.' });
    }

    const token = randomBytes(32).toString('hex');
    sessions.set(token, USERNAME);
    return sendJson(res, 200, { username: USERNAME }, {
      'Set-Cookie': `${SESSION_COOKIE}=${token}; ${cookieFlags}`
    });
  }

  if (req.method === 'GET' && url.pathname === '/api/me') {
    if (!activeUser) return sendJson(res, 401, { error: 'Not signed in.' });
    return sendJson(res, 200, { username: activeUser });
  }

  if (req.method === 'POST' && url.pathname === '/api/logout') {
    if (cookies[SESSION_COOKIE]) sessions.delete(cookies[SESSION_COOKIE]);
    return sendJson(res, 200, { ok: true }, {
      'Set-Cookie': `${SESSION_COOKIE}=; ${cookieFlags}; Max-Age=0`
    });
  }

  return sendJson(res, 404, { error: 'Route not found.' });
}).listen(PORT, '0.0.0.0', () => {
  console.log(`Backend listening on port ${PORT}`);
});
