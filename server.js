/* ============================================================
   KUBO · Servidor (Node.js 22+, sem dependências externas)
   - Banco de dados: SQLite (módulo nativo node:sqlite)
   - Login: senha com scrypt + sessão em cookie HttpOnly
   ============================================================ */
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'kubo.db');
const PUBLIC_DIR = path.join(__dirname, 'public');
const COOKIE_NAME = 'kubo_session';
const SESSION_DAYS_REMEMBER = 30;
const SESSION_HOURS_SHORT = 12;
const MAX_BODY = 5 * 1024 * 1024;
const MAX_ROWS = 5000;

/* ---------------------------- BANCO DE DADOS ---------------------------- */
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

  CREATE TABLE IF NOT EXISTS settings (
    user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    theme      TEXT NOT NULL DEFAULT 'light',
    updated_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS projects (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id      TEXT NOT NULL,
    data    TEXT NOT NULL,
    PRIMARY KEY (user_id, id)
  );

  CREATE TABLE IF NOT EXISTS clients (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id      TEXT NOT NULL,
    data    TEXT NOT NULL,
    PRIMARY KEY (user_id, id)
  );

  CREATE TABLE IF NOT EXISTS sales (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id      TEXT NOT NULL,
    data    TEXT NOT NULL,
    PRIMARY KEY (user_id, id)
  );

  CREATE TABLE IF NOT EXISTS transactions (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id      TEXT NOT NULL,
    data    TEXT NOT NULL,
    PRIMARY KEY (user_id, id)
  );
`);

const q = {
  userByEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
  userById: db.prepare('SELECT id, name, email FROM users WHERE id = ?'),
  insertUser: db.prepare('INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)'),
  insertSession: db.prepare('INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)'),
  sessionByHash: db.prepare('SELECT user_id, expires_at FROM sessions WHERE token_hash = ?'),
  deleteSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
  purgeSessions: db.prepare('DELETE FROM sessions WHERE expires_at < ?'),
  firstUser: db.prepare('SELECT MIN(id) AS id FROM users'),
  getMeta: db.prepare('SELECT value FROM meta WHERE key = ?'),
  setMeta: db.prepare('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'),
  getSettings: db.prepare('SELECT theme FROM settings WHERE user_id = ?'),
  upsertSettings: db.prepare(`INSERT INTO settings (user_id, theme, updated_at) VALUES (?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET theme = excluded.theme, updated_at = excluded.updated_at`)
};
const TABLES = ['projects', 'clients', 'transactions', 'sales'];
const tableSql = {};
for (const t of TABLES) {
  tableSql[t] = {
    list: db.prepare(`SELECT data FROM ${t} WHERE user_id = ?`),
    clear: db.prepare(`DELETE FROM ${t} WHERE user_id = ?`),
    insert: db.prepare(`INSERT OR REPLACE INTO ${t} (user_id, id, data) VALUES (?, ?, ?)`)
  };
}

function inTransaction(fn) {
  db.exec('BEGIN IMMEDIATE');
  try { const out = fn(); db.exec('COMMIT'); return out; }
  catch (err) { try { db.exec('ROLLBACK'); } catch (e) { /* ignore */ } throw err; }
}

/* ---------------------------- SENHAS & SESSÕES ---------------------------- */
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString('hex')}$${hash.toString('hex')}`;
}
function verifyPassword(password, stored) {
  try {
    const [scheme, saltHex, hashHex] = String(stored).split('$');
    if (scheme !== 'scrypt') return false;
    const expected = Buffer.from(hashHex, 'hex');
    const actual = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length, { N: 16384, r: 8, p: 1 });
    return crypto.timingSafeEqual(actual, expected);
  } catch (err) { return false; }
}
const DUMMY_HASH = hashPassword('senha-falsa-para-igualar-o-tempo');
const sha256 = (v) => crypto.createHash('sha256').update(v).digest('hex');

function createSession(userId, remember) {
  const token = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();
  const ttl = remember ? SESSION_DAYS_REMEMBER * 86400000 : SESSION_HOURS_SHORT * 3600000;
  q.insertSession.run(sha256(token), userId, now, now + ttl);
  return { token, maxAgeSec: Math.floor(ttl / 1000) };
}
function parseCookies(header) {
  const out = {};
  String(header || '').split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i > 0) {
      const raw = part.slice(i + 1).trim();
      let val = raw;
      try { val = decodeURIComponent(raw); } catch (err) { /* cookie malformado: usa como veio */ }
      out[part.slice(0, i).trim()] = val;
    }
  });
  return out;
}
function getSessionUser(req) {
  const token = parseCookies(req.headers.cookie)[COOKIE_NAME];
  if (!token) return null;
  const row = q.sessionByHash.get(sha256(token));
  if (!row || row.expires_at < Date.now()) return null;
  return q.userById.get(row.user_id) || null;
}
function isSecure(req) {
  return req.socket.encrypted || String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
}
function cookieHeader(req, value, maxAgeSec, persistent) {
  const parts = [`${COOKIE_NAME}=${value}`, 'Path=/', 'HttpOnly', 'SameSite=Lax'];
  if (persistent) parts.push(`Max-Age=${maxAgeSec}`);
  if (isSecure(req)) parts.push('Secure');
  return parts.join('; ');
}

/* ---------------------------- LIMITE DE TENTATIVAS ---------------------------- */
const attempts = new Map(); // chave -> { count, until }
const MAX_FAILS = 6;
const LOCK_MS = 5 * 60 * 1000;
// Atrás de proxy/HTTPS (TRUST_PROXY=1) usa o IP real; senão todo mundo cairia no mesmo bloqueio.
function clientIp(req) {
  if (process.env.TRUST_PROXY === '1') {
    const fwd = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (fwd) return fwd;
  }
  return req.socket.remoteAddress;
}
function attemptKey(req, email) { return `${clientIp(req)}|${String(email).toLowerCase()}`; }
function lockedFor(key) {
  const a = attempts.get(key);
  if (!a) return 0;
  if (a.until && a.until > Date.now()) return a.until - Date.now();
  if (a.until && a.until <= Date.now()) attempts.delete(key);
  return 0;
}
function registerFail(key) {
  const a = attempts.get(key) || { count: 0, until: 0 };
  a.count += 1;
  if (a.count >= MAX_FAILS) { a.until = Date.now() + LOCK_MS; a.count = 0; }
  attempts.set(key, a);
}
setInterval(() => {
  const now = Date.now();
  for (const [k, a] of attempts) if (a.until && a.until < now) attempts.delete(k);
  q.purgeSessions.run(now);
}, 10 * 60 * 1000).unref();

/* ---------------------------- HELPERS HTTP ---------------------------- */
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'same-origin'
};
function send(res, status, body, headers = {}) {
  res.writeHead(status, { ...SECURITY_HEADERS, ...headers });
  res.end(body);
}
function sendJSON(res, status, obj, headers = {}) {
  send(res, status, JSON.stringify(obj), { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(Object.assign(new Error('Corpo muito grande'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
      catch (err) { reject(Object.assign(new Error('JSON inválido'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try { return new URL(origin).host === req.headers.host; } catch (err) { return false; }
}

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon', '.webp': 'image/webp', '.txt': 'text/plain; charset=utf-8'
};

/* ---------------------------- VALIDAÇÃO ---------------------------- */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
function cleanName(v) { return String(v || '').replace(/\s+/g, ' ').trim(); }

function validateCollection(list, label) {
  if (!Array.isArray(list)) throw Object.assign(new Error(`"${label}" deve ser uma lista.`), { status: 400 });
  if (list.length > MAX_ROWS) throw Object.assign(new Error(`Limite de ${MAX_ROWS} itens em "${label}".`), { status: 413 });
  for (const item of list) {
    if (!item || typeof item !== 'object' || Array.isArray(item) || typeof item.id !== 'string' || !item.id || item.id.length > 100) {
      throw Object.assign(new Error(`Item inválido em "${label}".`), { status: 400 });
    }
  }
  return list;
}

/* ------------- ÁREA DE DADOS COMPARTILHADA -------------
   Todas as contas leem e gravam os mesmos projetos, clientes e lançamentos.
   Eles ficam guardados em nome da primeira conta criada (a "dona" da área).
   O tema (claro/escuro) continua sendo de cada pessoa.                      */
const REGISTER_OPEN = process.env.ALLOW_REGISTER !== '0';
// Mesmo com cadastros fechados, a primeira conta sempre pode ser criada.
const registerAllowed = () => REGISTER_OPEN || workspaceOwnerId() === null;

function workspaceOwnerId() {
  const row = q.firstUser.get();
  return row ? row.id : null;
}
function getRev() {
  const row = q.getMeta.get('rev');
  return row ? Number(row.value) || 0 : 0;
}
function countRows(userId) {
  return TABLES.reduce((n, t) => n + tableSql[t].list.all(userId).length, 0);
}
// Se já existiam dados salvos em outra conta (versão anterior, com dados separados),
// passa tudo para a dona da área compartilhada.
function adoptExistingData() {
  const owner = workspaceOwnerId();
  if (owner === null) return;
  if (!q.getMeta.get('rev')) q.setMeta.run('rev', '0');
  if (countRows(owner) > 0) return;
  let best = null;
  for (const u of db.prepare('SELECT id FROM users WHERE id != ?').all(owner)) {
    const n = countRows(u.id);
    if (n > 0 && (!best || n > best.n)) best = { id: u.id, n };
  }
  if (!best) return;
  inTransaction(() => {
    for (const t of TABLES) db.prepare(`UPDATE OR REPLACE ${t} SET user_id = ? WHERE user_id = ?`).run(owner, best.id);
  });
  console.log(`  Dados da conta #${best.id} movidos para a área compartilhada.`);
}
adoptExistingData();

function loadWorkspace(user) {
  const owner = workspaceOwnerId();
  const out = {};
  for (const t of TABLES) out[t] = tableSql[t].list.all(owner).map((r) => JSON.parse(r.data));
  const s = q.getSettings.get(user.id);
  out.theme = s ? s.theme : null;
  out.empty = TABLES.every((t) => out[t].length === 0);
  out.rev = getRev();
  return out;
}
function saveWorkspace(user, body) {
  const owner = workspaceOwnerId();
  const lists = {};
  for (const t of TABLES) lists[t] = validateCollection(body[t] === undefined ? [] : body[t], t);
  const theme = body.theme === 'dark' ? 'dark' : 'light';
  return inTransaction(() => {
    const current = getRev();
    // Alguém salvou depois que esta pessoa carregou a tela: não sobrescreve.
    if (body.rev !== undefined && Number(body.rev) !== current) return { conflict: true, rev: current };
    // Registro de vendas: quem registrou e quando é carimbado AQUI, pelo servidor.
    // Vendas novas recebem o usuário da sessão; as que já existiam mantêm o carimbo original.
    const existingSales = new Map(tableSql.sales.list.all(owner).map((r) => { const o = JSON.parse(r.data); return [o.id, o]; }));
    const nowIso = new Date().toISOString();
    lists.sales = lists.sales.map((sale) => {
      const old = existingSales.get(sale.id);
      return {
        ...sale,
        createdAt: old ? old.createdAt : nowIso,
        createdBy: old ? old.createdBy : user.name,
        createdByEmail: old ? old.createdByEmail : user.email
      };
    });
    for (const t of TABLES) {
      tableSql[t].clear.run(owner);
      for (const item of lists[t]) tableSql[t].insert.run(owner, item.id, JSON.stringify(item));
    }
    q.upsertSettings.run(user.id, theme, Date.now());
    q.setMeta.run('rev', String(current + 1));
    return { conflict: false, rev: current + 1 };
  });
}

/* ---------------------------- ROTAS DA API ---------------------------- */
async function handleApi(req, res, pathname) {
  const method = req.method;

  if (method !== 'GET' && method !== 'HEAD' && !sameOrigin(req)) {
    return sendJSON(res, 403, { error: 'Origem não permitida.' });
  }

  if (pathname === '/api/config' && method === 'GET') return sendJSON(res, 200, { registerOpen: registerAllowed() });

  if (pathname === '/api/register' && method === 'POST') {
    if (!registerAllowed()) return sendJSON(res, 403, { error: 'Novos cadastros estão desativados.' });
    const body = await readBody(req);
    const name = cleanName(body.name);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    if (name.length < 2 || name.length > 80) return sendJSON(res, 400, { error: 'Informe seu nome (2 a 80 caracteres).', field: 'name' });
    if (!EMAIL_RE.test(email) || email.length > 160) return sendJSON(res, 400, { error: 'Informe um e-mail válido.', field: 'email' });
    if (password.length < 8) return sendJSON(res, 400, { error: 'A senha precisa ter pelo menos 8 caracteres.', field: 'password' });
    if (password.length > 200) return sendJSON(res, 400, { error: 'Senha muito longa.', field: 'password' });
    if (q.userByEmail.get(email)) return sendJSON(res, 409, { error: 'Já existe uma conta com este e-mail.', field: 'email' });

    let info;
    try { info = q.insertUser.run(name, email, hashPassword(password), Date.now()); }
    catch (err) { return sendJSON(res, 409, { error: 'Já existe uma conta com este e-mail.', field: 'email' }); }
    const userId = Number(info.lastInsertRowid);
    const session = createSession(userId, true);
    return sendJSON(res, 201, { user: { id: userId, name, email } }, {
      'Set-Cookie': cookieHeader(req, session.token, session.maxAgeSec, true)
    });
  }

  if (pathname === '/api/login' && method === 'POST') {
    const body = await readBody(req);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const remember = body.remember !== false;
    const key = attemptKey(req, email);
    const wait = lockedFor(key);
    if (wait > 0) {
      return sendJSON(res, 429, { error: `Muitas tentativas. Tente de novo em ${Math.ceil(wait / 60000)} min.` });
    }
    if (!email || !password || password.length > 200) return sendJSON(res, 400, { error: 'Informe e-mail e senha.' });

    const user = q.userByEmail.get(email);
    const ok = verifyPassword(password, user ? user.password_hash : DUMMY_HASH) && Boolean(user);
    if (!ok) {
      registerFail(key);
      return sendJSON(res, 401, { error: 'E-mail ou senha incorretos.' });
    }
    attempts.delete(key);
    const session = createSession(user.id, remember);
    return sendJSON(res, 200, { user: { id: user.id, name: user.name, email: user.email } }, {
      'Set-Cookie': cookieHeader(req, session.token, session.maxAgeSec, remember)
    });
  }

  if (pathname === '/api/logout' && method === 'POST') {
    const token = parseCookies(req.headers.cookie)[COOKIE_NAME];
    if (token) q.deleteSession.run(sha256(token));
    return sendJSON(res, 200, { ok: true }, {
      'Set-Cookie': `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
    });
  }

  const user = getSessionUser(req);
  if (!user) return sendJSON(res, 401, { error: 'Não autenticado.' });

  if (pathname === '/api/me' && method === 'GET') return sendJSON(res, 200, { user });

  if (pathname === '/api/data' && method === 'GET') return sendJSON(res, 200, loadWorkspace(user));

  if (pathname === '/api/rev' && method === 'GET') return sendJSON(res, 200, { rev: getRev() });

  if (pathname === '/api/data' && (method === 'PUT' || method === 'POST')) {
    const body = await readBody(req);
    const result = saveWorkspace(user, body);
    if (result.conflict) return sendJSON(res, 409, { error: 'Os dados foram alterados por outra pessoa.', conflict: true, rev: result.rev });
    return sendJSON(res, 200, { ok: true, rev: result.rev });
  }

  return sendJSON(res, 404, { error: 'Rota não encontrada.' });
}

/* ---------------------------- ARQUIVOS ESTÁTICOS ---------------------------- */
function serveStatic(req, res, pathname) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Método não permitido');

  let rel;
  try { rel = decodeURIComponent(pathname); } catch (err) { return send(res, 400, 'Requisição inválida'); }
  if (rel.includes('\0')) return send(res, 400, 'Requisição inválida');
  if (rel === '/' || rel === '/index.html') rel = '/index.html';
  if (rel === '/login') rel = '/login.html';

  const user = getSessionUser(req);

  // O painel só abre com login; a tela de login redireciona quem já está logado.
  if (rel === '/index.html' && !user) return send(res, 302, '', { Location: '/login.html' });
  if (rel === '/login.html' && user) return send(res, 302, '', { Location: '/' });

  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) return send(res, 403, 'Acesso negado');

  fs.readFile(file, (err, data) => {
    if (err) return send(res, 404, 'Página não encontrada', { 'Content-Type': 'text/plain; charset=utf-8' });
    const type = MIME[path.extname(file).toLowerCase()] || 'application/octet-stream';
    const noCache = rel.endsWith('.html');
    send(res, 200, req.method === 'HEAD' ? '' : data, {
      'Content-Type': type,
      'Cache-Control': noCache ? 'no-store' : 'public, max-age=3600'
    });
  });
}

/* ---------------------------- SERVIDOR ---------------------------- */
const server = http.createServer(async (req, res) => {
  try {
    const { pathname } = new URL(req.url, 'http://localhost');
    if (pathname.startsWith('/api/')) return await handleApi(req, res, pathname);
    return serveStatic(req, res, pathname);
  } catch (err) {
    const status = err.status || 500;
    if (status === 500) console.error(err);
    if (!res.headersSent) sendJSON(res, status, { error: status === 500 ? 'Erro interno do servidor.' : err.message });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`\n  Kubo rodando em  http://localhost:${PORT}`);
  console.log(`  Banco de dados:  ${DB_PATH}\n`);
});

function shutdown() { server.close(() => { try { db.close(); } catch (e) { /* ignore */ } process.exit(0); }); }
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
