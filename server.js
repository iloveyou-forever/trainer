"use strict";
const express = require("express"), crypto = require("crypto"), path = require("path"), fs = require("fs");
const { promisify } = require("util");
const { DatabaseSync } = require("node:sqlite");
const scrypt = promisify(crypto.scrypt);
let nodemailer = null; try { nodemailer = require("nodemailer"); } catch (e) {}

const E = process.env;
const PORT = +E.PORT || 3000;
const DATA = E.DATA_DIR || path.join(__dirname, "data");
const BASE = (E.BASE_URL || "").replace(/\/$/, "");
const ADMIN_CODE = E.ADMIN_CODE || "";
const AI_KEY = E.ANTHROPIC_API_KEY || "";
const AI_MODEL = E.ANTHROPIC_MODEL || "claude-haiku-5-5";
const AI_LIMIT = +E.AI_DAILY_LIMIT || 5;
const DAY = 864e5, SESSION_DAYS = 30;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const PW = /^(?=.*[A-Za-zА-Яа-яЁё])(?=.*\d).{8,128}$/;

fs.mkdirSync(DATA, { recursive: true });
const db = new DatabaseSync(path.join(DATA, "app.db"));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, pw TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user', blocked INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, last INTEGER);
CREATE TABLE IF NOT EXISTS sessions(h TEXT PRIMARY KEY, uid TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, exp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS resets(h TEXT PRIMARY KEY, uid TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, exp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS states(uid TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, json TEXT NOT NULL, upd INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS usage(uid TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, day TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY(uid, day));`);

/* ---------- утилиты ---------- */
const now = () => Date.now();
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const rnd = n => crypto.randomBytes(n).toString("hex");
const str = (v, n) => (typeof v === "string" ? v.trim().slice(0, n) : "");
const pub = u => ({ id: u.id, name: u.name, email: u.email, role: u.role });
async function hashPw(pw) { const s = crypto.randomBytes(16); const h = await scrypt(pw, s, 64); return s.toString("hex") + ":" + h.toString("hex"); }
async function checkPw(pw, st) { const [s, h] = st.split(":"); const x = await scrypt(pw, Buffer.from(s, "hex"), 64); return crypto.timingSafeEqual(x, Buffer.from(h, "hex")); }
let DUMMY = ""; hashPw("dummy-password-1").then(h => { DUMMY = h; });

const hits = new Map();
function limited(key, max, win) { const t = now(); const a = (hits.get(key) || []).filter(x => t - x < win); a.push(t); hits.set(key, a); return a.length > max; }
setInterval(() => {
  const t = now();
  for (const [k, a] of hits) if (!a.some(x => t - x < 36e5)) hits.delete(k);
  db.prepare("DELETE FROM sessions WHERE exp<?").run(t);
  db.prepare("DELETE FROM resets WHERE exp<?").run(t);
}, 6e5).unref();

function cookie(req, name) {
  const m = (req.headers.cookie || "").split(";").map(s => s.trim()).find(s => s.startsWith(name + "="));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : "";
}
function setSess(req, res, uid) {
  const tok = rnd(32);
  db.prepare("INSERT INTO sessions(h,uid,exp) VALUES(?,?,?)").run(sha(tok), uid, now() + SESSION_DAYS * DAY);
  res.setHeader("Set-Cookie", `sid=${tok}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 86400}${req.secure ? "; Secure" : ""}`);
}
function clearSess(res) { res.setHeader("Set-Cookie", "sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"); }
function userFrom(req) {
  const t = cookie(req, "sid"); if (!t) return null;
  const s = db.prepare("SELECT uid, exp FROM sessions WHERE h=?").get(sha(t));
  if (!s || s.exp < now()) return null;
  const u = db.prepare("SELECT id,name,email,role,blocked FROM users WHERE id=?").get(s.uid);
  return u && !u.blocked ? u : null;
}
async function sendMail(to, subject, text) {
  if (nodemailer && E.SMTP_HOST) {
    const t = nodemailer.createTransport({ host: E.SMTP_HOST, port: +E.SMTP_PORT || 587, secure: +E.SMTP_PORT === 465,
      auth: E.SMTP_USER ? { user: E.SMTP_USER, pass: E.SMTP_PASS } : undefined });
    await t.sendMail({ from: E.SMTP_FROM || E.SMTP_USER, to, subject, text });
  } else console.log("[MAIL не настроена] кому:", to, "|", subject, "|", text);
}
const adminCount = () => db.prepare("SELECT COUNT(*) c FROM users WHERE role='admin' AND blocked=0").get().c;

/* ---------- приложение ---------- */
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  if (req.secure) res.setHeader("Strict-Transport-Security", "max-age=31536000");
  next();
});
app.use("/api/analyze", express.json({ limit: "2mb" }));
app.use(express.json({ limit: "300kb" }));
// защита от CSRF: изменяющие запросы только со своего origin
app.use("/api", (req, res, next) => {
  if (req.method !== "GET" && req.headers.origin) {
    try { if (new URL(req.headers.origin).host !== req.headers.host) return res.status(403).json({ error: "origin" }); }
    catch (e) { return res.status(403).json({ error: "origin" }); }
  }
  res.setHeader("Cache-Control", "no-store");
  next();
});
const auth = (req, res, next) => { const u = userFrom(req); if (!u) return res.status(401).json({ error: "auth" }); req.user = u; next(); };
const admin = (req, res, next) => (req.user.role === "admin" ? next() : res.status(403).json({ error: "forbidden" }));

// Само приложение отдаётся только после входа
app.get("/", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(path.join(__dirname, "public", userFrom(req) ? "app.html" : "login.html"));
});
app.get("/healthz", (req, res) => res.json({ ok: true }));

/* ---------- аккаунты ---------- */
app.post("/api/register", async (req, res) => {
  const b = req.body || {};
  if (limited("reg:" + req.ip, 10, 36e5)) return res.status(429).json({ error: "too_many" });
  const name = str(b.name, 60), email = str(b.email, 120).toLowerCase(), pw = typeof b.password === "string" ? b.password : "";
  if (name.length < 2 || !EMAIL.test(email) || !PW.test(pw) || b.adult !== true || b.consent !== true) return res.status(400).json({ error: "invalid" });
  let role = "user";
  if (b.adminCode) {
    const a = Buffer.from(String(b.adminCode)), c = Buffer.from(ADMIN_CODE);
    if (!ADMIN_CODE || a.length !== c.length || !crypto.timingSafeEqual(a, c)) return res.status(403).json({ error: "bad_code" });
    role = "admin";
  }
  if (db.prepare("SELECT 1 FROM users WHERE email=?").get(email)) return res.status(409).json({ error: "email_taken" });
  const id = rnd(12), hash = await hashPw(pw);
  try { db.prepare("INSERT INTO users(id,name,email,pw,role,created,last) VALUES(?,?,?,?,?,?,?)").run(id, name, email, hash, role, now(), now()); }
  catch (e) { return res.status(409).json({ error: "email_taken" }); }
  setSess(req, res, id);
  res.json({ id, name, email, role });
});

app.post("/api/login", async (req, res) => {
  const b = req.body || {}, email = str(b.email, 120).toLowerCase(), pw = typeof b.password === "string" ? b.password.slice(0, 128) : "";
  if (limited("l:" + req.ip + ":" + email, 8, 9e5) || limited("li:" + req.ip, 40, 9e5)) return res.status(429).json({ error: "too_many" });
  const u = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  const ok = await checkPw(pw, u ? u.pw : DUMMY);
  if (!u || !ok) return res.status(401).json({ error: "bad_credentials" });
  if (u.blocked) return res.status(403).json({ error: "blocked" });
  db.prepare("UPDATE users SET last=? WHERE id=?").run(now(), u.id);
  setSess(req, res, u.id);
  res.json(pub(u));
});

app.post("/api/logout", (req, res) => {
  const t = cookie(req, "sid");
  if (t) db.prepare("DELETE FROM sessions WHERE h=?").run(sha(t));
  clearSess(res); res.json({ ok: true });
});
app.get("/api/me", auth, (req, res) => res.json(pub(req.user)));

app.delete("/api/me", auth, async (req, res) => {
  const pw = typeof (req.body || {}).password === "string" ? req.body.password.slice(0, 128) : "";
  const u = db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id);
  if (!(await checkPw(pw, u.pw))) return res.status(403).json({ error: "bad_password" });
  if (u.role === "admin" && adminCount() < 2) return res.status(400).json({ error: "last_admin" });
  db.prepare("DELETE FROM users WHERE id=?").run(u.id);
  clearSess(res); res.json({ ok: true });
});

app.post("/api/forgot", async (req, res) => {
  const email = str((req.body || {}).email, 120).toLowerCase();
  if (limited("f:" + req.ip, 5, 36e5)) return res.status(429).json({ error: "too_many" });
  const u = EMAIL.test(email) ? db.prepare("SELECT id,email FROM users WHERE email=? AND blocked=0").get(email) : null;
  if (u) {
    const tok = rnd(32);
    db.prepare("INSERT INTO resets(h,uid,exp) VALUES(?,?,?)").run(sha(tok), u.id, now() + 18e5);
    const link = (BASE || `${req.protocol}://${req.headers.host}`) + "/#reset=" + tok;
    sendMail(u.email, "Сброс пароля / Password reset", `Ссылка действует 30 минут / The link is valid for 30 minutes:\n${link}`).catch(e => console.error("mail error:", e.message));
  }
  res.json({ ok: true });
});

app.post("/api/reset", async (req, res) => {
  const b = req.body || {}, tok = str(b.token, 64), pw = typeof b.password === "string" ? b.password : "";
  if (limited("r:" + req.ip, 20, 36e5)) return res.status(429).json({ error: "too_many" });
  if (!/^[a-f0-9]{64}$/.test(tok) || !PW.test(pw)) return res.status(400).json({ error: "invalid" });
  const r = db.prepare("SELECT uid, exp FROM resets WHERE h=?").get(sha(tok));
  if (!r || r.exp < now()) return res.status(400).json({ error: "invalid" });
  const hash = await hashPw(pw);
  db.prepare("UPDATE users SET pw=? WHERE id=?").run(hash, r.uid);
  db.prepare("DELETE FROM resets WHERE uid=?").run(r.uid);
  db.prepare("DELETE FROM sessions WHERE uid=?").run(r.uid);
  res.json({ ok: true });
});

/* ---------- прогресс пользователя (синхронизация) ---------- */
app.get("/api/state", auth, (req, res) => {
  const r = db.prepare("SELECT json, upd FROM states WHERE uid=?").get(req.user.id);
  res.json({ state: r ? JSON.parse(r.json) : null, upd: r ? r.upd : 0 });
});
app.put("/api/state", auth, (req, res) => {
  const s = (req.body || {}).state;
  if (!s || typeof s !== "object" || Array.isArray(s)) return res.status(400).json({ error: "invalid" });
  const j = JSON.stringify(s);
  if (j.length > 200000) return res.status(413).json({ error: "too_large" });
  db.prepare("INSERT INTO states(uid,json,upd) VALUES(?,?,?) ON CONFLICT(uid) DO UPDATE SET json=excluded.json, upd=excluded.upd").run(req.user.id, j, now());
  res.json({ ok: true });
});

/* ---------- ИИ-анализ (фото не сохраняются нигде) ---------- */
const LANGN = { ru: "Russian", en: "English", es: "Spanish" };
const PROMPT = lang => 'You are a supportive strength and conditioning coach. The attached photos (1-3) show an adult who wants a calisthenics plan (pull-up bar, bodyweight, resistance bands). A photo may show the whole body or any single body part (arms, forearms, calves, legs, back, chest, shoulders, abs): use all photos together. Assess ONLY visible muscular development and proportions for training purposes; you may mention other visible muscles (shoulders, abs, quads, glutes) in pros and cons. Be honest but kind and constructive. Never comment on attractiveness, never diagnose, never estimate body-fat percentage, no medical claims. If no body part is clearly visible return {"error":"noperson"}. If the person appears to be under 18 return {"error":"minor"}. If any photo is sexual, explicit or otherwise inappropriate, return {"error":"explicit"} and do not describe it. Rate a muscle ONLY if it is clearly visible in the photos and you can justify the rating from what you actually see; never guess and never infer one muscle from another. Otherwise use null for both the rating and its reason. Do not score or discuss body parts that are not in the photos. Write all text in ' + (LANGN[lang] || "English") + '. Return ONLY JSON: {"score": number 1-10 (overall development for training), "summary": one sentence, "pros": [3 short strings], "cons": [3 short strings, weak points phrased constructively], "why": string (3 short sentences: what is visible, what limits it, what would raise it), "reasons": {"c": short or null, "t": ..., "b": ..., "bi": ..., "k": ..., "f": ...} (max 12 words per rated muscle), "muscles": {"c":1-5 or null,"t":1-5 or null,"b":1-5 or null,"bi":1-5 or null,"k":1-5 or null,"f":1-5 or null}} where c=chest, t=triceps, b=back, bi=biceps, k=calves, f=forearms, 1=weakest and 5=best developed.';
const busy = new Set();
app.post("/api/analyze", auth, async (req, res) => {
  if (!AI_KEY) return res.status(503).json({ error: "ai_off" });
  const b = req.body || {}, imgs = b.images;
  if (!Array.isArray(imgs) || imgs.length < 1 || imgs.length > 3) return res.status(400).json({ error: "invalid" });
  for (const d of imgs) {
    if (typeof d !== "string" || d.length > 600000 || !/^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(d)) return res.status(400).json({ error: "invalid" });
    const m = Buffer.from(d.slice(23, 43), "base64");
    if (m[0] !== 0xff || m[1] !== 0xd8 || m[2] !== 0xff) return res.status(400).json({ error: "invalid" });
  }
  const uid = req.user.id, day = new Date().toISOString().slice(0, 10);
  if (busy.has(uid)) return res.status(429).json({ error: "busy" });
  const used = db.prepare("SELECT n FROM usage WHERE uid=? AND day=?").get(uid, day);
  if (used && used.n >= AI_LIMIT) return res.status(429).json({ error: "limit" });
  db.prepare("INSERT INTO usage(uid,day,n) VALUES(?,?,1) ON CONFLICT(uid,day) DO UPDATE SET n=n+1").run(uid, day);
  busy.add(uid);
  try {
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": AI_KEY, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: AI_MODEL, max_tokens: 800, messages: [{ role: "user", content: [
        ...imgs.map(d => ({ type: "image", source: { type: "base64", media_type: "image/jpeg", data: d.slice(23) } })),
        { type: "text", text: PROMPT(b.lang) }] }] }),
      signal: AbortSignal.timeout(60000)
    });
    if (!r.ok) { console.error("AI HTTP", r.status); return res.status(502).json({ error: "ai_failed" }); }
    const data = await r.json();
    const text = ((data.content || []).find(c => c.type === "text") || {}).text || "";
    const i = text.indexOf("{"), j = text.lastIndexOf("}");
    if (i < 0 || j < i) return res.status(502).json({ error: "ai_failed" });
    res.json(JSON.parse(text.slice(i, j + 1)));
  } catch (e) {
    console.error("AI error:", e.message);
    res.status(502).json({ error: "ai_failed" });
  } finally { busy.delete(uid); }
});

/* ---------- панель администратора ---------- */
app.get("/api/admin/users", auth, admin, (req, res) =>
  res.json(db.prepare("SELECT id,name,email,role,blocked,created,last FROM users ORDER BY created DESC LIMIT 1000").all()));

app.patch("/api/admin/users/:id", auth, admin, (req, res) => {
  const u = db.prepare("SELECT * FROM users WHERE id=?").get(req.params.id);
  if (!u) return res.status(404).json({ error: "not_found" });
  const b = req.body || {};
  const name = b.name === undefined ? u.name : str(b.name, 60);
  const email = b.email === undefined ? u.email : str(b.email, 120).toLowerCase();
  const role = b.role === undefined ? u.role : b.role;
  const blocked = b.blocked === undefined ? u.blocked : (b.blocked ? 1 : 0);
  if (name.length < 2 || !EMAIL.test(email) || (role !== "admin" && role !== "user")) return res.status(400).json({ error: "invalid" });
  if (u.id === req.user.id && blocked) return res.status(400).json({ error: "self" });
  if (u.role === "admin" && !u.blocked && (role !== "admin" || blocked) && adminCount() < 2) return res.status(400).json({ error: "last_admin" });
  try { db.prepare("UPDATE users SET name=?,email=?,role=?,blocked=? WHERE id=?").run(name, email, role, blocked, u.id); }
  catch (e) { return res.status(409).json({ error: "email_taken" }); }
  if (blocked) db.prepare("DELETE FROM sessions WHERE uid=?").run(u.id);
  res.json({ ok: true });
});

app.delete("/api/admin/users/:id", auth, admin, (req, res) => {
  const u = db.prepare("SELECT * FROM users WHERE id=?").get(req.params.id);
  if (!u) return res.status(404).json({ error: "not_found" });
  if (u.id === req.user.id) return res.status(400).json({ error: "self" });
  if (u.role === "admin" && !u.blocked && adminCount() < 2) return res.status(400).json({ error: "last_admin" });
  db.prepare("DELETE FROM users WHERE id=?").run(u.id);
  res.json({ ok: true });
});

app.use((req, res) => res.status(404).json({ error: "not_found" }));
app.use((err, req, res, next) => res.status(err.status || 500).json({ error: err.type === "entity.too.large" ? "too_large" : "bad_request" }));

app.listen(PORT, () => {
  console.log(`Перекладина запущена на порту ${PORT}`);
  if (!adminCount()) console.log(ADMIN_CODE ? "Админа ещё нет: зарегистрируйтесь с кодом администратора (ADMIN_CODE)." : "Админа нет, а ADMIN_CODE не задан: задайте его, чтобы создать администратора.");
  if (!AI_KEY) console.log("ANTHROPIC_API_KEY не задан: ИИ-анализ по фото отключён.");
});
