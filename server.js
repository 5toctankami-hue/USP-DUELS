'use strict';
// USP Duels server: accounts (scrypt), progress saves, leaderboard and 1v1 WebSocket rooms.
// No npm packages needed. Run: node server.js
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = +process.env.PORT || 3000;
const DATA = process.env.DATA_FILE || path.join(__dirname, 'data', 'db.json');
const PUB = path.join(__dirname, 'public');
fs.mkdirSync(path.dirname(DATA), { recursive: true });

// ---------- storage (JSON file, written atomically)
let db = { secret: '', users: {} };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DATA, 'utf8'))); } catch (e) {}
if (!db.secret) db.secret = crypto.randomBytes(32).toString('hex');
const SECRET = process.env.SECRET || db.secret;
let timer = null;
function persist() {
  if (timer) return;
  timer = setTimeout(() => {
    timer = null;
    const tmp = DATA + '.tmp';
    fs.writeFile(tmp, JSON.stringify(db), err => { if (!err) fs.rename(tmp, DATA, () => {}); });
  }, 400);
}
persist();

// ---------- tokens and passwords
const b64 = b => Buffer.from(b).toString('base64url');
function sign(key) {
  const p = b64(JSON.stringify({ u: key, exp: Date.now() + 30 * 864e5 }));
  return p + '.' + crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
}
function verify(t) {
  if (typeof t !== 'string') return null;
  const [p, s] = t.split('.');
  if (!p || !s) return null;
  const e = crypto.createHmac('sha256', SECRET).update(p).digest(), g = Buffer.from(s, 'base64url');
  if (g.length !== e.length || !crypto.timingSafeEqual(g, e)) return null;
  try { const d = JSON.parse(Buffer.from(p, 'base64url').toString()); return d.exp > Date.now() && db.users[d.u] ? d.u : null; } catch (e) { return null; }
}
const scrypt = (p, s) => new Promise((res, rej) => crypto.scrypt(p, s, 64, (e, k) => e ? rej(e) : res(k)));

// ---------- save validation (the server never trusts the shape of a client save)
// skin id -> weapon, same order as the SK list in public/index.html
const SKW = [...Array(6).fill('usp'), ...Array(6).fill('awp'), ...Array(15).fill('knife')];
const int = (v, lo, hi, d = 0) => { v = Math.floor(Number(v)); return Number.isFinite(v) ? Math.min(hi, Math.max(lo, v)) : d; };
const flt = (v, lo, hi, d) => { v = Number(v); return Number.isFinite(v) ? Math.min(hi, Math.max(lo, v)) : d; };
function clean(s, user) {
  s = s && typeof s === 'object' ? s : {};
  const own = [...new Set((Array.isArray(s.owned) ? s.owned : []).filter(x => Number.isInteger(x) && x >= 0 && x < SKW.length))];
  for (const d of [0, 6, 12]) if (!own.includes(d)) own.push(d);
  const eq = s.eq && typeof s.eq === 'object' ? s.eq : {}, st = s.st && typeof s.st === 'object' ? s.st : {};
  const pick = (w, d) => { const v = Math.floor(Number(eq[w])); return SKW[v] === w && own.includes(v) ? v : d; };
  const E = { usp: pick('usp', 0), awp: pick('awp', 6), knife: pick('knife', 12) };
  return { coins: int(s.coins, 0, 1e9), cases: int(s.cases, 0, 1e5, 1), owned: own, eq: E,
    sn: flt(s.sn, .2, 3, 1), ss: flt(s.ss, .2, 3, 1), fov: int(s.fov, 60, 110, 75), q: int(s.q, 0, 2, 2), nick: user,
    st: { w: int(st.w, 0, 1e7), l: int(st.l, 0, 1e7), h: int(st.h, 0, 1e7) }, ts: Date.now() };
}

// ---------- http
const hits = new Map();
setInterval(() => hits.clear(), 10 * 60 * 1000).unref();
const ipOf = req => (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '';
const limited = ip => { const n = (hits.get(ip) || 0) + 1; hits.set(ip, n); return n > 30; };
function body(req, max = 20000) {
  return new Promise((res, rej) => {
    let b = '';
    req.on('data', c => { b += c; if (b.length > max) { rej(new Error('big')); req.destroy(); } });
    req.on('end', () => { try { res(b ? JSON.parse(b) : {}); } catch (e) { rej(e); } });
    req.on('error', rej);
  });
}
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
const HDR = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin' };

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const send = (code, obj) => { res.writeHead(code, Object.assign({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, HDR)); res.end(JSON.stringify(obj)); };
  try {
    if (url.pathname === '/healthz') return send(200, { ok: true });
    if (url.pathname.startsWith('/api/')) {
      const authKey = () => verify((req.headers.authorization || '').replace(/^Bearer /, ''));
      if (url.pathname === '/api/top' && req.method === 'GET') {
        return send(200, Object.values(db.users).map(u => ({ u: u.user, w: u.save.st.w, h: u.save.st.h })).sort((a, b) => b.w - a.w || b.h - a.h).slice(0, 20));
      }
      if (url.pathname === '/api/me' && req.method === 'GET') {
        const k = authKey(); if (!k) return send(401, { error: 'Нужно войти' });
        return send(200, { user: db.users[k].user, save: db.users[k].save });
      }
      if (url.pathname === '/api/save' && req.method === 'PUT') {
        const k = authKey(); if (!k) return send(401, { error: 'Нужно войти' });
        db.users[k].save = clean(await body(req), db.users[k].user); persist();
        return send(200, { ok: true });
      }
      if ((url.pathname === '/api/register' || url.pathname === '/api/login') && req.method === 'POST') {
        if (limited(ipOf(req))) return send(429, { error: 'Слишком много попыток. Подождите несколько минут.' });
        const b = await body(req), user = String(b.user || ''), pass = String(b.pass || ''), key = user.toLowerCase();
        if (!/^[A-Za-z0-9_]{3,16}$/.test(user)) return send(400, { error: 'Логин: 3–16 символов, латиница, цифры и _' });
        if (pass.length < 6 || pass.length > 64) return send(400, { error: 'Пароль: от 6 до 64 символов' });
        if (url.pathname === '/api/register') {
          if (db.users[key]) return send(409, { error: 'Такой логин уже занят' });
          if (Object.keys(db.users).length >= 20000) return send(503, { error: 'Регистрация временно закрыта' });
          const salt = crypto.randomBytes(16).toString('hex'), hash = (await scrypt(pass, salt)).toString('hex');
          db.users[key] = { user, salt, hash, created: Date.now(), save: clean({}, user) }; persist();
          return send(200, { token: sign(key), user, save: db.users[key].save });
        }
        const u = db.users[key];
        const ok = u && crypto.timingSafeEqual(Buffer.from(u.hash, 'hex'), await scrypt(pass, u.salt));
        if (!ok) return send(401, { error: 'Неверный логин или пароль' });
        return send(200, { token: sign(key), user: u.user, save: u.save });
      }
      return send(404, { error: 'Не найдено' });
    }
    // static files
    let rel = decodeURIComponent(url.pathname); if (rel === '/') rel = '/index.html';
    const file = path.join(PUB, rel);
    if (!file.startsWith(PUB + path.sep)) { res.writeHead(403); return res.end(); }
    fs.readFile(file, (e, data) => {
      if (e) { res.writeHead(404, HDR); return res.end('Not found'); }
      res.writeHead(200, Object.assign({ 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' }, HDR));
      res.end(data);
    });
  } catch (e) { send(400, { error: 'Некорректный запрос' }); }
});

// ---------- WebSocket (minimal RFC 6455 server) and 1v1 rooms
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
function frame(op, data) {
  const p = Buffer.from(data), l = p.length; let h;
  if (l < 126) h = Buffer.from([0x80 | op, l]);
  else if (l < 65536) { h = Buffer.alloc(4); h[0] = 0x80 | op; h[1] = 126; h.writeUInt16BE(l, 2); }
  else { h = Buffer.alloc(10); h[0] = 0x80 | op; h[1] = 127; h.writeBigUInt64BE(BigInt(l), 2); }
  return Buffer.concat([h, p]);
}
const rooms = new Map(), TOPICS = new Set(['cfg', 'shot', 'hit', 'dead']);
let clients = 0;
class Client {
  constructor(socket, user) {
    this.s = socket; this.user = user; this.id = crypto.randomBytes(4).toString('hex'); this.room = null; this.code = ''; this.p = { n: user };
    this.buf = Buffer.alloc(0); this.tok = 150; this.t0 = Date.now(); this.seen = Date.now(); clients++;
    socket.on('data', d => this.data(d)); socket.on('close', () => this.close()); socket.on('error', () => this.close());
  }
  raw(op, d) { if (this.s.writable) this.s.write(frame(op, d)); }
  send(o) { this.raw(1, JSON.stringify(o)); }
  data(d) {
    this.seen = Date.now(); this.buf = Buffer.concat([this.buf, d]);
    for (;;) {
      const b = this.buf; if (b.length < 2) return;
      const op = b[0] & 15, fin = b[0] & 0x80, masked = b[1] & 0x80; let len = b[1] & 0x7f, off = 2;
      if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (b.length < 10) return; len = Number(b.readBigUInt64BE(2)); off = 10; }
      if (!masked || len > 8192 || !fin) return this.kill();
      if (b.length < off + 4 + len) return;
      const mk = b.subarray(off, off + 4), pl = Buffer.from(b.subarray(off + 4, off + 4 + len));
      for (let i = 0; i < len; i++) pl[i] ^= mk[i & 3];
      this.buf = b.subarray(off + 4 + len);
      if (op === 8) return this.kill();
      if (op === 9) this.raw(10, pl);
      else if (op === 1) this.msg(pl.toString());
    }
  }
  msg(t) {
    const now = Date.now(); this.tok = Math.min(150, this.tok + (now - this.t0) * .1); this.t0 = now;
    if (--this.tok < 0) { if (this.tok < -300) this.kill(); return; }
    let m; try { m = JSON.parse(t); } catch (e) { return; }
    if (!m || typeof m !== 'object') return;
    if (m.t === 'join') {
      const code = String(m.code || '');
      if (!/^[a-z0-9]{1,12}$/.test(code)) return;
      this.leave();
      let r = rooms.get(code); if (!r) rooms.set(code, r = new Map());
      if (r.size >= 2) return this.send({ t: 'full' });
      this.room = r; this.code = code;
      this.send({ t: 'hello', id: this.id, peers: [...r.values()].map(c => ({ id: c.id, p: c.p })) });
      r.forEach(c => c.send({ t: 'join', id: this.id, p: this.p }));
      r.set(this.id, this);
    } else if (!this.room) return;
    else if (m.t === 'pres' && m.p && typeof m.p === 'object') {
      const ks = Object.keys(m.p); if (ks.length > 12) return;
      for (const k of ks) {
        const v = m.p[k];
        if (!/^[a-z]{1,6}$/.test(k) || k === 'n') continue;
        if (v === null) delete this.p[k];
        else if (typeof v === 'number' && Number.isFinite(v)) this.p[k] = v;
        else if (typeof v === 'string' && v.length <= 24) this.p[k] = v;
      }
      this.p.n = this.user; this.others({ t: 'pres', id: this.id, p: this.p });
    } else if (m.t === 'ev' && TOPICS.has(m.topic)) {
      if (JSON.stringify(m.data || null).length > 2000) return;
      this.others({ t: 'ev', id: this.id, topic: m.topic, data: m.data });
    }
  }
  others(o) { if (this.room) this.room.forEach(c => { if (c !== this) c.send(o); }); }
  leave() {
    if (!this.room) return;
    this.room.delete(this.id); this.others({ t: 'left', id: this.id });
    if (!this.room.size) rooms.delete(this.code);
    this.room = null;
  }
  kill() { this.leave(); try { this.raw(8, Buffer.alloc(0)); this.s.end(); } catch (e) {} this.s.destroy(); }
  close() { if (this.dead) return; this.dead = true; clients--; this.leave(); }
}
server.on('upgrade', (req, socket) => {
  const url = new URL(req.url, 'http://x'), key = req.headers['sec-websocket-key'], origin = req.headers.origin;
  let sameOrigin = true; try { sameOrigin = !origin || new URL(origin).host === req.headers.host; } catch (e) { sameOrigin = false; }
  const k = verify(url.searchParams.get('token'));
  if (url.pathname !== '/ws' || !key || !k || !sameOrigin || clients > 1000) { socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return socket.destroy(); }
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' +
    crypto.createHash('sha1').update(key + GUID).digest('base64') + '\r\n\r\n');
  socket.setNoDelay(true);
  const c = new Client(socket, db.users[k].user);
  c.hb = setInterval(() => { if (Date.now() - c.seen > 70000) c.kill(); else c.raw(9, Buffer.alloc(0)); }, 25000);
  socket.on('close', () => clearInterval(c.hb));
});

server.listen(PORT, () => console.log('USP Duels: http://localhost:' + PORT));
process.on('SIGTERM', () => { try { fs.writeFileSync(DATA, JSON.stringify(db)); } catch (e) {} process.exit(0); });
