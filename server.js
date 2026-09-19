const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'db.json');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '5879';

app.use(express.json({ limit: '5mb' }));
app.use(express.static('public'));

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ blogs: [], bannedLinks: [] }, null, 2));
    return { blogs: [], bannedLinks: [] };
  }
  try {
    const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (!db.bannedLinks) db.bannedLinks = [];
    return db;
  } catch (e) { return { blogs: [], bannedLinks: [] }; }
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function genKey() {
  return crypto.randomBytes(8).toString('hex');
}

function checkAdmin(req, res, next) {
  const password = req.headers['x-admin-password'] || req.query.password;
  if (password === ADMIN_PASSWORD) return next();
  res.status(401).json({ error: 'رمز اشتباه است' });
}

// نرمال‌سازی URL برای مقایسه
function normalizeUrl(url) {
  try {
    const u = new URL(url);
    return (u.hostname + u.pathname).toLowerCase().replace(/\/+$/, '');
  } catch (e) {
    return String(url).toLowerCase().trim();
  }
}

// ============ ساخت وبلاگ ============
app.post('/api/create', (req, res) => {
  const { username, name, title, bio, about, avatarStyle } = req.body || {};

  if (!username) return res.status(400).json({ error: 'نام کاربری لازمه' });
  if (!/^[a-z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({ error: 'نام کاربری: ۳-۲۰ کاراکتر، حروف کوچک، عدد، _' });
  }

  const db = loadDB();
  if (db.blogs.find(b => b.username === username)) {
    return res.status(400).json({ error: 'این نام کاربری قبلاً گرفته شده' });
  }

  const editKey = genKey();
  const blog = {
    username,
    editKey,
    name: (name || username).trim().slice(0, 50),
    title: (title || '').trim().slice(0, 100),
    bio: (bio || '').trim().slice(0, 300),
    about: (about || '').trim().slice(0, 5000),
    avatarStyle: (avatarStyle || 'gradient1').slice(0, 20),
    links: [],
    views: 0,
    createdAt: new Date().toISOString()
  };

  db.blogs.push(blog);
  saveDB(db);

  res.json({ message: 'ساخته شد', username, editKey });
});

// ============ دریافت وبلاگ ============
app.get('/api/blog/:username', (req, res) => {
  const db = loadDB();
  const blog = db.blogs.find(b => b.username === req.params.username);
  if (!blog) return res.status(404).json({ error: 'پیدا نشد' });

  const key = req.query.key;
  const isOwner = key && key === blog.editKey;

  if (isOwner) return res.json(blog);

  // عمومی - لینک‌های بن‌شده فیلتر می‌شن
  const { editKey, ...safe } = blog;
  safe.links = safe.links.filter(l => !db.bannedLinks.includes(normalizeUrl(l.url)));
  res.json(safe);
});

// ============ ویرایش ============
app.post('/api/blog/:username/update', (req, res) => {
  const { key, name, title, bio, about, avatarStyle } = req.body || {};
  const db = loadDB();
  const blog = db.blogs.find(b => b.username === req.params.username);
  if (!blog) return res.status(404).json({ error: 'پیدا نشد' });
  if (key !== blog.editKey) return res.status(401).json({ error: 'کلید اشتباه' });

  if (name !== undefined) blog.name = String(name).trim().slice(0, 50);
  if (title !== undefined) blog.title = String(title).trim().slice(0, 100);
  if (bio !== undefined) blog.bio = String(bio).trim().slice(0, 300);
  if (about !== undefined) blog.about = String(about).trim().slice(0, 5000);
  if (avatarStyle !== undefined) blog.avatarStyle = String(avatarStyle).slice(0, 20);

  saveDB(db);
  res.json({ message: 'ذخیره شد' });
});

// ============ لینک‌ها ============
app.post('/api/blog/:username/links', (req, res) => {
  const { key, title, url, icon, description } = req.body || {};
  const db = loadDB();
  const blog = db.blogs.find(b => b.username === req.params.username);
  if (!blog) return res.status(404).json({ error: 'پیدا نشد' });
  if (key !== blog.editKey) return res.status(401).json({ error: 'کلید اشتباه' });
  if (!title || !url) return res.status(400).json({ error: 'عنوان و لینک لازمه' });

  // چک بن
  if (db.bannedLinks.includes(normalizeUrl(url))) {
    return res.status(403).json({ error: '⛔ این لینک مسدود شده است' });
  }

  blog.links.push({
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

app.delete('/api/blog/:username/links/:id', (req, res) => {
  const key = req.query.key;
  const db = loadDB();
  const blog = db.blogs.find(b => b.username === req.params.username);
  if (!blog) return res.status(404).json({ error: 'پیدا نشد' });
  if (key !== blog.editKey) return res.status(401).json({ error: 'کلید اشتباه' });

  blog.links = blog.links.filter(l => l.id !== req.params.id);
  saveDB(db);
  res.json({ message: 'حذف شد' });
});

// ============ بازدید ============
app.post('/api/blog/:username/view', (req, res) => {
  const db = loadDB();
  const blog = db.blogs.find(b => b.username === req.params.username);
  if (!blog) return res.status(404).json({ error: 'پیدا نشد' });
  blog.views = (blog.views || 0) + 1;
  saveDB(db);
  res.json({ views: blog.views });
});

// ============ لیست وبلاگ‌ها ============
app.get('/api/blogs', (req, res) => {
  const db = loadDB();
  const list = db.blogs.map(b => ({
    username: b.username,
    name: b.name,
    title: b.title,
    bio: b.bio,
    avatarStyle: b.avatarStyle,
    linksCount: b.links.filter(l => !db.bannedLinks.includes(normalizeUrl(l.url))).length,
    views: b.views || 0,
    createdAt: b.createdAt
  })).sort((a, b) => b.views - a.views).slice(0, 50);
  res.json(list);
});

// ============ ADMIN ============

// لیست همه لینک‌ها (برای بن کردن)
app.get('/api/admin/all-links', checkAdmin, (req, res) => {
  const db = loadDB();
  const allLinks = [];
  db.blogs.forEach(blog => {
    blog.links.forEach(link => {
      allLinks.push({
        blogUsername: blog.username,
        blogName: blog.name,
        linkId: link.id,
        title: link.title,
        url: link.url,
        banned: db.bannedLinks.includes(normalizeUrl(link.url))
      });
    });
  });
  res.json(allLinks);
});

// لیست لینک‌های بن‌شده
app.get('/api/admin/banned-links', checkAdmin, (req, res) => {
  const db = loadDB();
  res.json(db.bannedLinks);
});

// بن کردن لینک
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

// آنبن کردن لینک
app.post('/api/admin/unban-link', checkAdmin, (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'لینک لازمه' });
  const normalized = normalizeUrl(url);
  const db = loadDB();
  db.bannedLinks = db.bannedLinks.filter(u => u !== normalized);
  saveDB(db);
  res.json({ message: 'لینک آنبن شد', url: normalized });
});

// لیست وبلاگ‌ها (برای ادمین)
app.get('/api/admin/blogs', checkAdmin, (req, res) => {
  const db = loadDB();
  const list = db.blogs.map(b => ({
    username: b.username,
    name: b.name,
    linksCount: b.links.length,
    views: b.views || 0,
    createdAt: b.createdAt
  })).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json(list);
});

// ============ مسیرها ============
app.get('/u/:username', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'user.html'));
});

app.listen(PORT, () => console.log(`✍️ بیوکده روی پورت ${PORT}`));
