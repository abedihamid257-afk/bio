const express = require('express');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'db.json');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '5879';
const MAX_BLOGS_PER_USER = 5;

const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const GITHUB_REPO = process.env.GITHUB_REPO || '';
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || 'data';

app.use(express.json({ limit: '5mb' }));
app.use(express.static('public'));

// ============ DB ============
let db = { users: [], sessions: {}, blogs: [], bannedLinks: [] };

function ensureDBFile() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
  }
}

async function pushDBToGitHub() {
  if (!GITHUB_TOKEN || !GITHUB_REPO) return false;
  const apiUrl = `https://api.github.com/repos/${GITHUB_REPO}/contents/db.json`;
  const headers = {
    'Authorization': `token ${GITHUB_TOKEN}`,
    'Content-Type': 'application/json',
    'User-Agent': 'biokade'
  };
  try {
    let sha = null;
    const getRes = await fetch(`${apiUrl}?ref=${GITHUB_BRANCH}`, { headers });
    if (getRes.ok) {
      const data = await getRes.json();
      sha = data.sha;
    }
    const content = Buffer.from(JSON.stringify(db, null, 2)).toString('base64');
    const body = {
      message: `🔄 آپدیت دیتابیس - ${new Date().toLocaleString('fa-IR')}`,
      content, branch: GITHUB_BRANCH
    };
    if (sha) body.sha = sha;
    const putRes = await fetch(apiUrl, { method: 'PUT', headers, body: JSON.stringify(body) });
    return putRes.ok;
  } catch (e) { return false; }
}

async function loadDBFromGitHub() {
  if (!GITHUB_TOKEN || !GITHUB_REPO) return null;
  const apiUrl = `https://api.github.com/repos/${GITHUB_REPO}/contents/db.json?ref=${GITHUB_BRANCH}`;
  try {
    const res = await fetch(apiUrl, {
      headers: { 'Authorization': `token ${GITHUB_TOKEN}`, 'User-Agent': 'biokade' }
    });
    if (!res.ok) return null;
    const data = await res.json();
    return JSON.parse(Buffer.from(data.content, 'base64').toString('utf8'));
  } catch (e) { return null; }
}

function saveDB() {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); } catch (e) {}
  pushDBToGitHub().then(ok => { if (ok) console.log('✅ DB ذخیره شد'); });
}

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
    return res.status(400).json({ error: 'نام کاربری: ۳-۲۰ کاراکتر، حروف کوچک، عدد، _' });
  }
  if (password.length < 4) return res.status(400).json({ error: 'رمز حداقل ۴ کاراکتر' });

  if (db.users.find(u => u.username === username)) {
    return res.status(400).json({ error: 'این نام کاربری گرفته شده' });
  }

  const hashed = await bcrypt.hash(password, 10);
  const user = {
    username,
    password: hashed,
    name: (name || username).trim().slice(0, 50),
    banned: false,
    createdAt: new Date().toISOString()
  };

  db.users.push(user);
  const token = genToken();
  db.sessions[token] = username;
  saveDB();

  res.json({ message: 'ثبت‌نام موفق', token, username });
});

// ============ ورود ============
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'نام کاربری و رمز لازمه' });

  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'کاربر پیدا نشد' });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'رمز اشتباهه' });
  if (user.banned) return res.status(403).json({ error: '⛔ حساب شما مسدود شده است' });

  const token = genToken();
  db.sessions[token] = username;
  saveDB();

  res.json({ message: 'ورود موفق', token, username });
});

// ============ خروج ============
app.post('/api/logout', (req, res) => {
  const token = req.headers['x-token'];
  if (token) { delete db.sessions[token]; saveDB(); }
  res.json({ message: 'خارج شدی' });
});

// ============ پروفایل کاربر ============
app.get('/api/me', (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'وارد نشدی' });
  const { password, ...safe } = user;
  // وبلاگ‌های کاربر
  safe.blogs = db.blogs.filter(b => b.owner === user.username);
  res.json(safe);
});

// ============ وبلاگ‌ها ============

// ساخت وبلاگ جدید
app.post('/api/blogs', (req, res) => {
  const me = getUser(req);
  if (!me) return res.status(401).json({ error: 'وارد نشدی' });
  if (me.banned) return res.status(403).json({ error: '⛔ حساب مسدود' });

  const userBlogs = db.blogs.filter(b => b.owner === me.username);
  if (userBlogs.length >= MAX_BLOGS_PER_USER) {
    return res.status(403).json({ error: `حداکثر ${MAX_BLOGS_PER_USER} وبلاگ می‌تونی بسازی` });
  }

  const { username, name, title, bio, about, avatarStyle } = req.body || {};
  if (!username) return res.status(400).json({ error: 'نام کاربری وبلاگ لازمه' });
  if (!/^[a-z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({ error: 'نام کاربری وبلاگ: ۳-۲۰ کاراکتر، حروف کوچک، عدد، _' });
  }
  if (db.blogs.find(b => b.username === username)) {
    return res.status(400).json({ error: 'این آدرس قبلاً گرفته شده' });
  }

  const blog = {
    id: genToken(),
    owner: me.username,
    username,
    name: (name || username).trim().slice(0, 50),
    title: (title || '').trim().slice(0, 100),
    bio: (bio || '').trim().slice(0, 300),
    about: (about || '').trim().slice(0, 5000),
    avatarStyle: (avatarStyle || 'gradient1').slice(0, 20),
    links: [],
    views: 0,
    banned: false,
    createdAt: new Date().toISOString()
  };

  db.blogs.push(blog);
  saveDB();
  res.json({ message: 'وبلاگ ساخته شد', blog });
});

// ویرایش وبلاگ
app.post('/api/blogs/:id/update', (req, res) => {
  const me = getUser(req);
  if (!me) return res.status(401).json({ error: 'وارد نشدی' });

  const blog = db.blogs.find(b => b.id === req.params.id && b.owner === me.username);
  if (!blog) return res.status(404).json({ error: 'وبلاگ پیدا نشد' });
  if (blog.banned) return res.status(403).json({ error: '⛔ وبلاگ مسدود' });

  const { name, title, bio, about, avatarStyle } = req.body || {};
  if (name !== undefined) blog.name = String(name).trim().slice(0, 50);
  if (title !== undefined) blog.title = String(title).trim().slice(0, 100);
  if (bio !== undefined) blog.bio = String(bio).trim().slice(0, 300);
  if (about !== undefined) blog.about = String(about).trim().slice(0, 5000);
  if (avatarStyle !== undefined) blog.avatarStyle = String(avatarStyle).slice(0, 20);

  saveDB();
  res.json({ message: 'ذخیره شد' });
});

// حذف وبلاگ
app.delete('/api/blogs/:id', (req, res) => {
  const me = getUser(req);
  if (!me) return res.status(401).json({ error: 'وارد نشدی' });

  db.blogs = db.blogs.filter(b => !(b.id === req.params.id && b.owner === me.username));
  saveDB();
  res.json({ message: 'حذف شد' });
});

// لینک‌ها
app.post('/api/blogs/:id/links', (req, res) => {
  const me = getUser(req);
  if (!me) return res.status(401).json({ error: 'وارد نشدی' });

  const blog = db.blogs.find(b => b.id === req.params.id && b.owner === me.username);
  if (!blog) return res.status(404).json({ error: 'وبلاگ پیدا نشد' });
  if (blog.banned) return res.status(403).json({ error: '⛔ وبلاگ مسدود' });

  const { title, url, icon, description } = req.body || {};
  if (!title || !url) return res.status(400).json({ error: 'عنوان و لینک لازمه' });

  if (db.bannedLinks.includes(normalizeUrl(url))) {
    return res.status(403).json({ error: '⛔ این لینک مسدوده' });
  }

  blog.links.push({
    id: Date.now().toString(),
    title: String(title).trim().slice(0, 60),
    url: String(url).trim(),
    icon: String(icon || 'link').slice(0, 20),
    description: String(description || '').trim().slice(0, 100),
    clicks: 0
  });
  saveDB();
  res.json({ message: 'اضافه شد' });
});

app.delete('/api/blogs/:id/links/:linkId', (req, res) => {
  const me = getUser(req);
  if (!me) return res.status(401).json({ error: 'وارد نشدی' });

  const blog = db.blogs.find(b => b.id === req.params.id && b.owner === me.username);
  if (!blog) return res.status(404).json({ error: 'وبلاگ پیدا نشد' });

  blog.links = blog.links.filter(l => l.id !== req.params.linkId);
  saveDB();
  res.json({ message: 'حذف شد' });
});

// ============ پروفایل عمومی وبلاگ ============
app.get('/api/blog/:username', (req, res) => {
  const blog = db.blogs.find(b => b.username === req.params.username);
  if (!blog) return res.status(404).json({ error: 'وبلاگ پیدا نشد' });
  if (blog.banned) return res.status(403).json({ error: '⛔ این وبلاگ مسدود شده است' });

  blog.views = (blog.views || 0) + 1;
  saveDB();

  // فیلتر لینک‌های بن‌شده
  const safe = { ...blog };
  safe.links = safe.links.filter(l => !db.bannedLinks.includes(normalizeUrl(l.url)));
  res.json(safe);
});

app.post('/api/blog/:username/link/:id/click', (req, res) => {
  const blog = db.blogs.find(b => b.username === req.params.username);
  if (!blog) return res.status(404).json({ error: 'یافت نشد' });
  const link = blog.links.find(l => l.id === req.params.id);
  if (!link) return res.status(404).json({ error: 'لینک پیدا نشد' });
  link.clicks = (link.clicks || 0) + 1;
  saveDB();
  res.json({ clicks: link.clicks });
});

// ============ لیست وبلاگ‌ها (صفحه اصلی) ============
app.get('/api/blogs', (req, res) => {
  const list = db.blogs
    .filter(b => !b.banned)
    .map(b => ({
      username: b.username,
      name: b.name,
      title: b.title,
      bio: b.bio,
      avatarStyle: b.avatarStyle,
      linksCount: b.links.filter(l => !db.bannedLinks.includes(normalizeUrl(l.url))).length,
      views: b.views || 0,
      owner: b.owner
    }))
    .sort((a, b) => b.views - a.views)
    .slice(0, 100);
  res.json(list);
});

// ============ ADMIN ============

// لیست همه کاربرا
app.get('/api/admin/users', checkAdmin, (req, res) => {
  const list = db.users.map(u => {
    const userBlogs = db.blogs.filter(b => b.owner === u.username);
    return {
      username: u.username,
      name: u.name,
      blogsCount: userBlogs.length,
      banned: u.banned,
      createdAt: u.createdAt
    };
  }).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json(list);
});

// لیست همه وبلاگ‌ها
app.get('/api/admin/blogs', checkAdmin, (req, res) => {
  const list = db.blogs.map(b => ({
    id: b.id,
    username: b.username,
    name: b.name,
    title: b.title,
    owner: b.owner,
    linksCount: b.links.length,
    views: b.views || 0,
    banned: b.banned,
    createdAt: b.createdAt
  })).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json(list);
});

// لیست همه لینک‌ها
app.get('/api/admin/links', checkAdmin, (req, res) => {
  const all = [];
  db.blogs.forEach(blog => {
    blog.links.forEach(l => {
      all.push({
        blogUsername: blog.username,
        blogId: blog.id,
        owner: blog.owner,
        linkId: l.id,
        title: l.title,
        url: l.url,
        icon: l.icon,
        clicks: l.clicks || 0,
        banned: db.bannedLinks.includes(normalizeUrl(l.url)),
        blogBanned: blog.banned
      });
    });
  });
  res.json(all);
});

// لیست لینک‌های بن‌شده
app.get('/api/admin/banned-links', checkAdmin, (req, res) => {
  res.json(db.bannedLinks);
});

// بن کاربر
app.post('/api/admin/ban-user', checkAdmin, (req, res) => {
  const { username } = req.body || {};
  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(404).json({ error: 'پیدا نشد' });
  user.banned = true;
  saveDB();
  res.json({ message: 'کاربر بن شد' });
});

app.post('/api/admin/unban-user', checkAdmin, (req, res) => {
  const { username } = req.body || {};
  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(404).json({ error: 'پیدا نشد' });
  user.banned = false;
  saveDB();
  res.json({ message: 'کاربر آنبن شد' });
});

app.post('/api/admin/delete-user', checkAdmin, (req, res) => {
  const { username } = req.body || {};
  db.users = db.users.filter(u => u.username !== username);
  db.blogs = db.blogs.filter(b => b.owner !== username);
  saveDB();
  res.json({ message: 'کاربر و وبلاگ‌هاش حذف شد' });
});

// بن وبلاگ
app.post('/api/admin/ban-blog', checkAdmin, (req, res) => {
  const { id } = req.body || {};
  const blog = db.blogs.find(b => b.id === id);
  if (!blog) return res.status(404).json({ error: 'پیدا نشد' });
  blog.banned = true;
  saveDB();
  res.json({ message: 'وبلاگ بن شد' });
});

app.post('/api/admin/unban-blog', checkAdmin, (req, res) => {
  const { id } = req.body || {};
  const blog = db.blogs.find(b => b.id === id);
  if (!blog) return res.status(404).json({ error: 'پیدا نشد' });
  blog.banned = false;
  saveDB();
  res.json({ message: 'وبلاگ آنبن شد' });
});

app.post('/api/admin/delete-blog', checkAdmin, (req, res) => {
  const { id } = req.body || {};
  db.blogs = db.blogs.filter(b => b.id !== id);
  saveDB();
  res.json({ message: 'وبلاگ حذف شد' });
});

// بن لینک
app.post('/api/admin/ban-link', checkAdmin, (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'لینک لازمه' });
  const normalized = normalizeUrl(url);
  if (!db.bannedLinks.includes(normalized)) {
    db.bannedLinks.push(normalized);
    saveDB();
  }
  res.json({ message: 'لینک بن شد', url: normalized });
});

app.post('/api/admin/unban-link', checkAdmin, (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'لینک لازمه' });
  const normalized = normalizeUrl(url);
  db.bannedLinks = db.bannedLinks.filter(u => u !== normalized);
  saveDB();
  res.json({ message: 'لینک آنبن شد' });
});

app.post('/api/admin/delete-link', checkAdmin, (req, res) => {
  const { blogId, linkId } = req.body || {};
  const blog = db.blogs.find(b => b.id === blogId);
  if (!blog) return res.status(404).json({ error: 'وبلاگ پیدا نشد' });
  blog.links = blog.links.filter(l => l.id !== linkId);
  saveDB();
  res.json({ message: 'لینک حذف شد' });
});

// ============ مسیرها ============
app.get('/u/:username', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'user.html'));
});

// ============ شروع ============
async function start() {
  console.log('🚀 در حال راه‌اندازی...');
  ensureDBFile();

  const remoteDB = await loadDBFromGitHub();
  if (remoteDB && remoteDB.users) {
    db = remoteDB;
    if (!db.sessions) db.sessions = {};
    if (!db.bannedLinks) db.bannedLinks = [];
    if (!db.blogs) db.blogs = [];
    // مهاجرت: اگه کاربرای قبلی وبلاگ تو خودشون داشتن، به blogs منتقل کن
    db.users.forEach(u => {
      if (u.links && u.links.length && !db.blogs.find(b => b.owner === u.username)) {
        db.blogs.push({
          id: genToken(),
          owner: u.username,
          username: u.username,
          name: u.name || u.username,
          title: u.title || '',
          bio: u.bio || '',
          about: u.about || '',
          avatarStyle: u.avatarStyle || 'gradient1',
          links: u.links,
          views: u.views || 0,
          banned: false,
          createdAt: u.createdAt || new Date().toISOString()
        });
      }
    });
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
    console.log(`✅ DB از GitHub - ${db.users.length} کاربر، ${db.blogs.length} وبلاگ`);
  } else {
    try {
      const raw = fs.readFileSync(DB_FILE, 'utf8');
      db = JSON.parse(raw);
      if (!db.users) db.users = [];
      if (!db.sessions) db.sessions = {};
      if (!db.bannedLinks) db.bannedLinks = [];
      if (!db.blogs) db.blogs = [];
      console.log(`✅ DB محلی - ${db.users.length} کاربر، ${db.blogs.length} وبلاگ`);
    } catch (e) {
      console.log('⚠️ DB خالی');
    }
  }

  app.listen(PORT, () => console.log(`✍️ بیوکده روی پورت ${PORT}`));
}

start();
