require('dotenv').config();
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const crypto = require('crypto');
const { exec } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const AVATARS_DIR = path.join(__dirname, 'avatars');
const THUMBS_DIR = path.join(__dirname, 'thumbnails');

[UPLOADS_DIR, AVATARS_DIR, THUMBS_DIR].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d); });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOADS_DIR));
app.use('/avatars', express.static(AVATARS_DIR));
app.use('/thumbnails', express.static(THUMBS_DIR));

// ── DATA HELPERS ──────────────────────────────────────────
const DB = {
  users:         path.join(__dirname, 'users.json'),
  videos:        path.join(__dirname, 'videos.json'),
  sessions:      path.join(__dirname, 'sessions.json'),
  comments:      path.join(__dirname, 'comments.json'),
  notifications: path.join(__dirname, 'notifications.json'),
};

function read(file) {
  if (!fs.existsSync(file)) return [];
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return []; }
}
function write(file, data) { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }

// ── NOTIFICATION HELPER ───────────────────────────────────
function pushNotif(userId, type, data) {
  const notifs = read(DB.notifications);
  notifs.unshift({ id: crypto.randomUUID(), userId, type, data, read: false, createdAt: new Date().toISOString() });
  write(DB.notifications, notifs);
}

// ── AUTH HELPERS ──────────────────────────────────────────
function hashPassword(password, salt) {
  const s = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, s, 100000, 64, 'sha512').toString('hex');
  return { hash, salt: s };
}
function verifyPassword(password, hash, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex') === hash;
}
function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const sessions = read(DB.sessions);
  sessions.push({ token, userId, createdAt: new Date().toISOString() });
  write(DB.sessions, sessions);
  return token;
}
function getSession(token) {
  if (!token) return null;
  const session = read(DB.sessions).find(s => s.token === token);
  if (!session) return null;
  return read(DB.users).find(u => u.id === session.userId) || null;
}
function auth(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  const user = getSession(token);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  req.user = user; next();
}
function optAuth(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  req.user = token ? getSession(token) : null;
  next();
}
function safeUser(u) { const { hash, salt, ...s } = u; return s; }

// ── MULTER ────────────────────────────────────────────────
const videoStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + crypto.randomBytes(6).toString('hex') + path.extname(file.originalname))
});
const avatarStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, AVATARS_DIR),
  filename: (req, file, cb) => cb(null, req.user.id + path.extname(file.originalname))
});
const uploadVideo = multer({ storage: videoStorage, fileFilter: (req, file, cb) => /\.(mp4|webm|mov|mkv|avi)$/i.test(file.originalname) ? cb(null, true) : cb(new Error('Video files only')), limits: { fileSize: 2 * 1024 * 1024 * 1024 } });
const uploadAvatar = multer({ storage: avatarStorage, fileFilter: (req, file, cb) => /\.(jpg|jpeg|png|webp|gif)$/i.test(file.originalname) ? cb(null, true) : cb(new Error('Image only')), limits: { fileSize: 5 * 1024 * 1024 } });

// ── AUTH ROUTES ───────────────────────────────────────────
app.post('/api/auth/register', (req, res) => {
  const { username, email, password, channelName } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password min 6 characters' });
  const users = read(DB.users);
  if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) return res.status(400).json({ error: 'Email already registered' });
  if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) return res.status(400).json({ error: 'Username taken' });
  const { hash, salt } = hashPassword(password);
  const isFirst = users.length === 0; // first user becomes admin
  const user = {
    id: crypto.randomUUID(), username: username.trim(),
    email: email.toLowerCase().trim(),
    channelName: channelName?.trim() || username.trim() + "'s Channel",
    channelDesc: '', avatar: null, hash, salt,
    subscribers: [], verified: false,
    isAdmin: isFirst,
    createdAt: new Date().toISOString()
  };
  users.push(user); write(DB.users, users);
  res.json({ token: createSession(user.id), user: safeUser(user) });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const users = read(DB.users);
  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user || !verifyPassword(password, user.hash, user.salt)) return res.status(401).json({ error: 'Invalid email or password' });
  res.json({ token: createSession(user.id), user: safeUser(user) });
});

app.post('/api/auth/logout', auth, (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  write(DB.sessions, read(DB.sessions).filter(s => s.token !== token));
  res.json({ success: true });
});

app.get('/api/auth/me', auth, (req, res) => res.json(safeUser(req.user)));

// ── ADMIN: VERIFY USER ────────────────────────────────────
app.post('/api/admin/verify/:username', auth, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'Admins only' });
  const users = read(DB.users);
  const idx = users.findIndex(u => u.username.toLowerCase() === req.params.username.toLowerCase());
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  users[idx].verified = !users[idx].verified;
  write(DB.users, users);
  res.json({ verified: users[idx].verified, username: users[idx].username });
});

// ── CHANNEL ROUTES ────────────────────────────────────────
app.get('/api/channel/:username', (req, res) => {
  const user = read(DB.users).find(u => u.username.toLowerCase() === req.params.username.toLowerCase());
  if (!user) return res.status(404).json({ error: 'Channel not found' });
  const videos = read(DB.videos).filter(v => v.userId === user.id).reverse();
  res.json({ user: safeUser(user), videos, videoCount: videos.length });
});

app.put('/api/channel', auth, (req, res) => {
  const { channelName, channelDesc } = req.body;
  const users = read(DB.users);
  const idx = users.findIndex(u => u.id === req.user.id);
  if (channelName) users[idx].channelName = channelName.trim();
  if (channelDesc !== undefined) users[idx].channelDesc = channelDesc.trim();
  write(DB.users, users); res.json(safeUser(users[idx]));
});

app.post('/api/channel/avatar', auth, (req, res) => {
  uploadAvatar.single('avatar')(req, res, err => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const users = read(DB.users);
    const idx = users.findIndex(u => u.id === req.user.id);
    users[idx].avatar = '/avatars/' + req.file.filename;
    write(DB.users, users); res.json({ avatar: users[idx].avatar });
  });
});

app.post('/api/channel/:username/subscribe', auth, (req, res) => {
  const users = read(DB.users);
  const idx = users.findIndex(u => u.username.toLowerCase() === req.params.username.toLowerCase());
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  if (users[idx].id === req.user.id) return res.status(400).json({ error: "Can't subscribe to yourself" });
  if (!users[idx].subscribers) users[idx].subscribers = [];
  const subIdx = users[idx].subscribers.indexOf(req.user.id);
  const subscribed = subIdx === -1;
  subscribed ? users[idx].subscribers.push(req.user.id) : users[idx].subscribers.splice(subIdx, 1);
  write(DB.users, users);
  if (subscribed) pushNotif(users[idx].id, 'subscribe', { fromUsername: req.user.username, fromChannelName: req.user.channelName, fromAvatar: req.user.avatar });
  res.json({ subscribed, count: users[idx].subscribers.length });
});

// ── VIDEO ROUTES ──────────────────────────────────────────
app.get('/api/videos', (req, res) => {
  const videos = read(DB.videos);
  const users = read(DB.users);
  const enriched = videos.map(v => {
    const u = users.find(u => u.id === v.userId);
    return { ...v, channel: u ? { username: u.username, channelName: u.channelName, avatar: u.avatar, verified: u.verified } : null };
  }).reverse();
  res.json(enriched);
});

app.get('/api/videos/mine', auth, (req, res) => {
  res.json(read(DB.videos).filter(v => v.userId === req.user.id).reverse());
});

app.post('/api/videos/upload', auth, (req, res) => {
  uploadVideo.single('video')(req, res, err => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const videos = read(DB.videos);
    const entry = {
      id: crypto.randomUUID(), userId: req.user.id,
      filename: req.file.filename, originalName: req.file.originalname,
      title: req.body.title?.trim() || path.parse(req.file.originalname).name,
      description: req.body.description?.trim() || '',
      size: req.file.size, views: 0, likes: [],
      uploadedAt: new Date().toISOString()
    };
    videos.push(entry); write(DB.videos, videos);
    res.json({ success: true, video: entry });
  });
});

app.get('/api/stream/:filename', (req, res) => {
  const filePath = path.join(UPLOADS_DIR, req.params.filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Not found' });
  const videos = read(DB.videos);
  const vid = videos.find(v => v.filename === req.params.filename);
  if (vid) { vid.views++; write(DB.videos, videos); }
  const stat = fs.statSync(filePath);
  const fileSize = stat.size;
  const range = req.headers.range;
  if (range) {
    const [s, e] = range.replace(/bytes=/, '').split('-');
    const start = parseInt(s, 10), end = e ? parseInt(e, 10) : fileSize - 1;
    res.writeHead(206, { 'Content-Range': `bytes ${start}-${end}/${fileSize}`, 'Accept-Ranges': 'bytes', 'Content-Length': end - start + 1, 'Content-Type': 'video/mp4' });
    fs.createReadStream(filePath, { start, end }).pipe(res);
  } else {
    res.writeHead(200, { 'Content-Length': fileSize, 'Content-Type': 'video/mp4' });
    fs.createReadStream(filePath).pipe(res);
  }
});

app.post('/api/videos/:id/like', auth, (req, res) => {
  const videos = read(DB.videos);
  const idx = videos.findIndex(v => v.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  if (!videos[idx].likes) videos[idx].likes = [];
  const likeIdx = videos[idx].likes.indexOf(req.user.id);
  const liked = likeIdx === -1;
  liked ? videos[idx].likes.push(req.user.id) : videos[idx].likes.splice(likeIdx, 1);
  write(DB.videos, videos);
  res.json({ liked, count: videos[idx].likes.length });
});

app.delete('/api/videos/:id', auth, (req, res) => {
  const videos = read(DB.videos);
  const idx = videos.findIndex(v => v.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  if (videos[idx].userId !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  const [removed] = videos.splice(idx, 1);
  const fp = path.join(UPLOADS_DIR, removed.filename);
  if (fs.existsSync(fp)) fs.unlinkSync(fp);
  // delete comments for this video
  write(DB.comments, read(DB.comments).filter(c => c.videoId !== req.params.id));
  write(DB.videos, videos);
  res.json({ success: true });
});

// ── ANALYTICS ─────────────────────────────────────────────
app.get('/api/analytics', auth, (req, res) => {
  const videos = read(DB.videos).filter(v => v.userId === req.user.id);
  const users = read(DB.users);
  const me = users.find(u => u.id === req.user.id);
  const comments = read(DB.comments).filter(c => videos.some(v => v.id === c.videoId));

  const totalViews = videos.reduce((s, v) => s + (v.views || 0), 0);
  const totalLikes = videos.reduce((s, v) => s + (v.likes?.length || 0), 0);
  const totalSubs = me?.subscribers?.length || 0;
  const totalComments = comments.length;

  const videoStats = videos.map(v => ({
    title: v.title.length > 28 ? v.title.slice(0, 28) + '…' : v.title,
    views: v.views || 0,
    likes: v.likes?.length || 0,
    uploadedAt: v.uploadedAt
  })).sort((a, b) => b.views - a.views).slice(0, 10);

  res.json({ totalViews, totalLikes, totalSubs, totalComments, videoStats });
});

// ── COMMENTS ──────────────────────────────────────────────
app.get('/api/videos/:id/comments', optAuth, (req, res) => {
  const comments = read(DB.comments).filter(c => c.videoId === req.params.id);
  const users = read(DB.users);
  const enriched = comments.map(c => {
    const u = users.find(u => u.id === c.userId);
    return { ...c, user: u ? { username: u.username, channelName: u.channelName, avatar: u.avatar, verified: u.verified } : null };
  });
  res.json(enriched);
});

app.post('/api/videos/:id/comments', auth, (req, res) => {
  const { text } = req.body;
  if (!text?.trim()) return res.status(400).json({ error: 'Comment cannot be empty' });
  const videos = read(DB.videos);
  const video = videos.find(v => v.id === req.params.id);
  if (!video) return res.status(404).json({ error: 'Video not found' });

  const comment = {
    id: crypto.randomUUID(), videoId: req.params.id,
    userId: req.user.id, text: text.trim(),
    createdAt: new Date().toISOString()
  };
  const comments = read(DB.comments);
  comments.push(comment);
  write(DB.comments, comments);

  // notify video owner (not if commenting on own video)
  if (video.userId !== req.user.id) {
    pushNotif(video.userId, 'comment', {
      fromUsername: req.user.username, fromChannelName: req.user.channelName,
      fromAvatar: req.user.avatar, videoId: req.params.id,
      videoTitle: video.title, text: text.trim().slice(0, 80)
    });
  }

  res.json({ ...comment, user: { username: req.user.username, channelName: req.user.channelName, avatar: req.user.avatar, verified: req.user.verified } });
});

app.delete('/api/comments/:id', auth, (req, res) => {
  const comments = read(DB.comments);
  const idx = comments.findIndex(c => c.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  if (comments[idx].userId !== req.user.id && !req.user.isAdmin) return res.status(403).json({ error: 'Forbidden' });
  comments.splice(idx, 1);
  write(DB.comments, comments);
  res.json({ success: true });
});

// ── NOTIFICATIONS ─────────────────────────────────────────
app.get('/api/notifications', auth, (req, res) => {
  const notifs = read(DB.notifications).filter(n => n.userId === req.user.id);
  res.json(notifs);
});

app.get('/api/notifications/unread', auth, (req, res) => {
  const count = read(DB.notifications).filter(n => n.userId === req.user.id && !n.read).length;
  res.json({ count });
});

app.post('/api/notifications/read-all', auth, (req, res) => {
  const notifs = read(DB.notifications).map(n => n.userId === req.user.id ? { ...n, read: true } : n);
  write(DB.notifications, notifs);
  res.json({ success: true });
});

app.delete('/api/notifications/:id', auth, (req, res) => {
  const notifs = read(DB.notifications);
  const idx = notifs.findIndex(n => n.id === req.params.id && n.userId === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  notifs.splice(idx, 1);
  write(DB.notifications, notifs);
  res.json({ success: true });
});

// ── BANNER UPLOAD ─────────────────────────────────────────
const bannerStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, AVATARS_DIR),
  filename: (req, file, cb) => cb(null, 'banner_' + req.user.id + path.extname(file.originalname))
});
const uploadBanner = multer({ storage: bannerStorage, fileFilter: (req, file, cb) => /\.(jpg|jpeg|png|webp|gif)$/i.test(file.originalname) ? cb(null, true) : cb(new Error('Image only')), limits: { fileSize: 10 * 1024 * 1024 } });

app.post('/api/channel/banner', auth, (req, res) => {
  uploadBanner.single('banner')(req, res, err => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const users = read(DB.users);
    const idx = users.findIndex(u => u.id === req.user.id);
    users[idx].banner = '/avatars/' + req.file.filename;
    write(DB.users, users); res.json({ banner: users[idx].banner });
  });
});


// ── THUMBNAIL UPLOAD ──────────────────────────────────────
const thumbStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, THUMBS_DIR),
  filename: (req, file, cb) => cb(null, req.params.id + path.extname(file.originalname))
});
const uploadThumb = multer({ storage: thumbStorage, fileFilter: (req, file, cb) => /\.(jpg|jpeg|png|webp)$/i.test(file.originalname) ? cb(null, true) : cb(new Error('Image only')), limits: { fileSize: 5 * 1024 * 1024 } });

app.post('/api/videos/:id/thumbnail', auth, (req, res) => {
  const videos = read(DB.videos);
  const idx = videos.findIndex(v => v.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  if (videos[idx].userId !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  uploadThumb.single('thumbnail')(req, res, err => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: 'No file' });
    // delete old thumbnail if exists
    if (videos[idx].thumbnail) {
      const old = path.join(__dirname, videos[idx].thumbnail.replace(/^\//, ''));
      if (fs.existsSync(old)) fs.unlinkSync(old);
    }
    videos[idx].thumbnail = '/thumbnails/' + req.file.filename;
    write(DB.videos, videos);
    res.json({ thumbnail: videos[idx].thumbnail });
  });
});


// ── USER PREFS ────────────────────────────────────────────
app.get('/api/prefs', auth, (req, res) => {
  const users = read(DB.users);
  const u = users.find(u => u.id === req.user.id);
  res.json(u?.prefs || {});
});

app.put('/api/prefs', auth, (req, res) => {
  const users = read(DB.users);
  const idx = users.findIndex(u => u.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  users[idx].prefs = { ...(users[idx].prefs || {}), ...req.body };
  write(DB.users, users);
  res.json(users[idx].prefs);
});

// ── SINGLE VIDEO ──────────────────────────────────────────
app.get('/api/videos/:id', (req, res) => {
  const videos = read(DB.videos);
  const v = videos.find(v => v.id === req.params.id);
  if (!v) return res.status(404).json({ error: 'Not found' });
  const users = read(DB.users);
  const u = users.find(u => u.id === v.userId);
  const comments = read(DB.comments).filter(c => c.videoId === v.id).length;
  res.json({ ...v, channel: u ? { username: u.username, channelName: u.channelName, avatar: u.avatar, verified: u.verified, subscribers: u.subscribers?.length || 0 } : null, commentCount: comments });
});

// catch-all: serve index.html for client-side routing
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api') && !req.path.startsWith('/uploads') && !req.path.startsWith('/avatars')) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
});

app.listen(PORT, () => console.log(`\n🎬 VidWave → http://localhost:${PORT}\n`));