const express = require('express');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'db.json');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '5879';

app.use(express.json({ limit: '5mb' }));
app.use(express.static('public'));

// ============ DB ============
function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], sessions: {}, bannedLinks: [] }, null, 2));
    return { users: [], sessions: {}, bannedLinks: [] };
  }
  try {
    const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (!db.bannedLinks) db.bannedLinks = [];
    if (!db.sessions) db.sessions = {};
    return db;
  } catch (e) { return { users: [], sessions: {}, bannedLinks: [] }; }
}

function saveDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
function genToken() { return crypto.randomBytes(16).toString('hex'); }

function normalizeUrl(url) {
  try {
    const u = new URL(url);
    return (u.hostname + u.pathname).toLowerCase().replace(/\/+$/, '');
  } catch (e) { return String(url).toLowerCase().trim(); }
}

function getUser(req) {
  const token = req.headers['x-token'] || req.query.token;
  if (!token) return null;
  const db = loadDB();
  const username = db.sessions[token];
  if (!username) return null;
  return db.users.find(u => u.username === username) || null;
}

function checkAdmin(req, res, next) {
  const password = req.headers['x-admin-password'] || req.query.password;
  if (password === ADMIN_PASSWORD) return next();
  res.status(401).json({ error: 'رمز اشتباه' });
}

// ============ ثبت‌نام ============
app.post('/api/signup', async (req, res) => {
  const { username, password, name } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'نام کاربری و رمز لازمه' });
  if (!/^[a-z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({ error: 'نام کاربری: ۳-۲۰ کاراکتر، حروف کوچک انگلیسی، عدد و _' });
  }
  if (password.length < 4) return res.status(400).json({ error: 'رمز حداقل ۴ کاراکتر' });

  const db = loadDB();
  if (db.users.find(u => u.username === username)) {
    return res.status(400).json({ error: 'این نام کاربری گرفته شده' });
  }

  const hashed = await bcrypt.hash(password, 10);
  const user = {
    username,
    password: hashed,
    name: (name || username).trim().slice(0, 50),
    title: '',
    bio: '',
    about: '',
    avatarStyle: 'gradient1',
    links: [],
    views: 0,
    banned: false,
    createdAt: new Date().toISOString()
  };

  db.users.push(user);
  const token = genToken();
  db.sessions[token] = username;
  saveDB(db);

  res.json({ message: 'ثبت‌نام موفق', token, username });
});

// ============ ورود ============
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'نام کاربری و رمز لازمه' });

  const db = loadDB();
  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'کاربر پیدا نشد' });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'رمز اشتباهه' });

  if (user.banned) {
    return res.status(403).json({ error: '⛔ حساب شما مسدود شده است' });
  }

  const token = genToken();
  db.sessions[token] = username;
  saveDB(db);

  res.json({ message: 'ورود موفق', token, username });
});

// ============ پروفایل خودم ============
app.get('/api/me', (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'وارد نشدی' });
  const { password, ...safe } = user;
  res.json(safe);
});

app.post('/api/me', (req, res) => {
  const me = getUser(req);
  if (!me) return res.status(401).json({ error: 'وارد نشدی' });
  if (me.banned) return res.status(403).json({ error: '⛔ حساب مسدود' });

  const { name, title, bio, about, avatarStyle } = req.body || {};
  const db = loadDB();
  const user = db.users.find(u => u.username === me.username);

  if (name !== undefined) user.name = String(name).trim().slice(0, 50);
  if (title !== undefined) user.title = String(title).trim().slice(0, 100);
  if (bio !== undefined) user.bio = String(bio).trim().slice(0, 300);
  if (about !== undefined) user.about = String(about).trim().slice(0, 5000);
  if (avatarStyle !== undefined) user.avatarStyle = String(avatarStyle).slice(0, 20);

  saveDB(db);
  res.json({ message: 'ذخیره شد' });
});

// ============ لینک‌ها ============
app.post('/api/me/links', (req, res) => {
  const me = getUser(req);
  if (!me) return res.status(401).json({ error: 'وارد نشدی' });
  if (me.banned) return res.status(403).json({ error: '⛔ حساب مسدود' });

  const { title, url, icon, description } = req.body || {};
  if (!title || !url) return res.status(400).json({ error: 'عنوان و لینک لازمه' });

  const db = loadDB();
  if (db.bannedLinks.includes(normalizeUrl(url))) {
    return res.status(403).json({ error: '⛔ این لینک مسدوده' });
  }

  const user = db.users.find(u => u.username === me.username);
  user.links.push({
    id: Date.now().toString(),
    title: String(title).trim().slice(0, 60),
    url: String(url).trim(),
    icon: String(icon || 'link').slice(0, 20),
    description: String(description || '').trim().slice(0, 100),
    clicks: 0
  });
  saveDB(db);
  res.json({ message: 'اضافه شد' });
});

app.delete('/api/me/links/:id', (req, res) => {
  const me = getUser(req);
  if (!me) return res.status(401).json({ error: 'وارد نشدی' });

  const db = loadDB();
  const user = db.users.find(u => u.username === me.username);
  user.links = user.links.filter(l => l.id !== req.params.id);
  saveDB(db);
  res.json({ message: 'حذف شد' });
});

// ============ پروفایل عمومی ============
app.get('/api/user/:username', (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.username === req.params.username);
  if (!user) return res.status(404).json({ error: 'کاربر پیدا نشد' });
  if (user.banned) return res.status(403).json({ error: '⛔ این وبلاگ مسدود شده است' });

  user.views = (user.views || 0) + 1;
  saveDB(db);

  const { password, ...safe } = user;
  // فیلتر لینک‌های بن‌شده
  safe.links = safe.links.filter(l => !db.bannedLinks.includes(normalizeUrl(l.url)));
  res.json(safe);
});

app.post('/api/user/:username/link/:id/click', (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.username === req.params.username);
  if (!user) return res.status(404).json({ error: 'یافت نشد' });
  const link = user.links.find(l => l.id === req.params.id);
  if (!link) return res.status(404).json({ error: 'لینک پیدا نشد' });
  link.clicks = (link.clicks || 0) + 1;
  saveDB(db);
  res.json({ clicks: link.clicks });
});

// ============ لیست کاربرا ============
app.get('/api/users', (req, res) => {
  const db = loadDB();
  const list = db.users
    .filter(u => !u.banned)
    .map(u => ({
      username: u.username,
      name: u.name,
      title: u.title,
      bio: u.bio,
      avatarStyle: u.avatarStyle,
      linksCount: u.links.filter(l => !db.bannedLinks.includes(normalizeUrl(l.url))).length,
      views: u.views || 0
    }))
    .sort((a, b) => b.views - a.views)
    .slice(0, 50);
  res.json(list);
});

// ============ خروج ============
app.post('/api/logout', (req, res) => {
  const token = req.headers['x-token'];
  if (token) {
    const db = loadDB();
    delete db.sessions[token];
    saveDB(db);
  }
  res.json({ message: 'خارج شدی' });
});

// ============ ADMIN ============

// لیست همه کاربرا (برای ادمین)
app.get('/api/admin/users', checkAdmin, (req, res) => {
  const db = loadDB();
  const list = db.users.map(u => ({
    username: u.username,
    name: u.name,
    title: u.title,
    bio: u.bio,
    avatarStyle: u.avatarStyle,
    linksCount: u.links.length,
    views: u.views || 0,
    banned: u.banned,
    createdAt: u.createdAt
  })).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json(list);
});

// بن کاربر
app.post('/api/admin/ban-user', checkAdmin, (req, res) => {
  const { username } = req.body || {};
  const db = loadDB();
  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(404).json({ error: 'پیدا نشد' });
  user.banned = true;
  saveDB(db);
  res.json({ message: 'کاربر بن شد' });
});

app.post('/api/admin/unban-user', checkAdmin, (req, res) => {
  const { username } = req.body || {};
  const db = loadDB();
  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(404).json({ error: 'پیدا نشد' });
  user.banned = false;
  saveDB(db);
  res.json({ message: 'کاربر آنبن شد' });
});

// حذف کاربر
app.post('/api/admin/delete-user', checkAdmin, (req, res) => {
  const { username } = req.body || {};
  const db = loadDB();
  db.users = db.users.filter(u => u.username !== username);
  saveDB(db);
  res.json({ message: 'کاربر حذف شد' });
});

// لیست همه لینک‌ها
app.get('/api/admin/links', checkAdmin, (req, res) => {
  const db = loadDB();
  const all = [];
  db.users.forEach(u => {
    u.links.forEach(l => {
      all.push({
        username: u.username,
        userName: u.name,
        linkId: l.id,
        title: l.title,
        url: l.url,
        icon: l.icon,
        clicks: l.clicks || 0,
        banned: db.bannedLinks.includes(normalizeUrl(l.url)),
        userBanned: u.banned
      });
    });
  });
  res.json(all);
});

// بن لینک
app.post('/api/admin/ban-link', checkAdmin, (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'لینک لازمه' });
  const normalized = normalizeUrl(url);
  const db = loadDB();
  if (!db.bannedLinks.includes(normalized)) {
    db.bannedLinks.push(normalized);
    saveDB(db);
  }
  res.json({ message: 'لینک بن شد', url: normalized });
});

app.post('/api/admin/unban-link', checkAdmin, (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'لینک لازمه' });
  const normalized = normalizeUrl(url);
  const db = loadDB();
  db.bannedLinks = db.bannedLinks.filter(u => u !== normalized);
  saveDB(db);
  res.json({ message: 'لینک آنبن شد' });
});

app.get('/api/admin/banned-links', checkAdmin, (req, res) => {
  const db = loadDB();
  res.json(db.bannedLinks);
});

// حذف یک لینک خاص
app.post('/api/admin/delete-link', checkAdmin, (req, res) => {
  const { username, linkId } = req.body || {};
  const db = loadDB();
  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(404).json({ error: 'کاربر پیدا نشد' });
  user.links = user.links.filter(l => l.id !== linkId);
  saveDB(db);
  res.json({ message: 'لینک حذف شد' });
});

// ============ مسیر /u/:username ============
app.get('/u/:username', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'user.html'));
});

app.listen(PORT, () => console.log(`✍️ بیوکده ۲.۰ روی پورت ${PORT}`));
