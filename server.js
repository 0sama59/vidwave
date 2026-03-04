require('dotenv').config();
const express    = require('express');
const multer     = require('multer');
const path       = require('path');
const cors       = require('cors');
const crypto     = require('crypto');
const mongoose   = require('mongoose');
const cloudinary = require('cloudinary');
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── CLOUDINARY ────────────────────────────────────────────
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key:    process.env.CLOUDINARY_KEY,
  api_secret: process.env.CLOUDINARY_SECRET,
});

// ── MONGODB ───────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(e => { console.error('MongoDB error:', e.message); process.exit(1); });

// ── SCHEMAS ───────────────────────────────────────────────
const UserSchema = new mongoose.Schema({
  username:    { type: String, required: true, unique: true },
  email:       { type: String, required: true, unique: true, lowercase: true },
  channelName: { type: String, default: '' },
  channelDesc: { type: String, default: '' },
  avatar:      { type: String, default: null },
  avatarId:    { type: String, default: null },
  banner:      { type: String, default: null },
  bannerId:    { type: String, default: null },
  hash:        { type: String, required: true },
  salt:        { type: String, required: true },
  subscribers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  verified:    { type: Boolean, default: false },
  isAdmin:     { type: Boolean, default: false },
  prefs:       { type: Object, default: {} },
}, { timestamps: true });

const VideoSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title:       { type: String, required: true },
  description: { type: String, default: '' },
  filename:    { type: String, required: true },
  url:         { type: String, required: true },
  thumbnail:   { type: String, default: null },
  thumbnailId: { type: String, default: null },
  views:       { type: Number, default: 0 },
  likes:       [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  size:        { type: Number, default: 0 },
}, { timestamps: true });

const CommentSchema = new mongoose.Schema({
  videoId: { type: mongoose.Schema.Types.ObjectId, ref: 'Video', required: true },
  userId:  { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text:    { type: String, required: true },
}, { timestamps: true });

const NotifSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type:   { type: String, required: true },
  data:   { type: Object, default: {} },
  read:   { type: Boolean, default: false },
}, { timestamps: true });

const SessionSchema = new mongoose.Schema({
  token:  { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
}, { timestamps: true });

const User    = mongoose.model('User',    UserSchema);
const Video   = mongoose.model('Video',   VideoSchema);
const Comment = mongoose.model('Comment', CommentSchema);
const Notif   = mongoose.model('Notif',   NotifSchema);
const Session = mongoose.model('Session', SessionSchema);

// ── MIDDLEWARE ────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── CLOUDINARY STORAGES ───────────────────────────────────
const videoStorage = new CloudinaryStorage({
  cloudinary,
  params: { folder: 'vidwave/videos', resource_type: 'video', allowed_formats: ['mp4','webm','mov','mkv','avi'] },
});
const makeImageStorage = (folder) => new CloudinaryStorage({
  cloudinary,
  params: { folder: `vidwave/${folder}`, resource_type: 'image', allowed_formats: ['jpg','jpeg','png','webp','gif'] },
});

const uploadVideo  = multer({ storage: videoStorage,                  limits: { fileSize: 2 * 1024 * 1024 * 1024 } });
const uploadAvatar = multer({ storage: makeImageStorage('avatars'),    limits: { fileSize: 5  * 1024 * 1024 } });
const uploadBanner = multer({ storage: makeImageStorage('banners'),    limits: { fileSize: 10 * 1024 * 1024 } });
const uploadThumb  = multer({ storage: makeImageStorage('thumbnails'), limits: { fileSize: 5  * 1024 * 1024 } });

// ── AUTH HELPERS ──────────────────────────────────────────
function hashPassword(password, salt) {
  const s = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, s, 100000, 64, 'sha512').toString('hex');
  return { hash, salt: s };
}
function verifyPassword(password, hash, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex') === hash;
}
async function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  await Session.create({ token, userId });
  return token;
}
async function getSession(token) {
  if (!token) return null;
  const s = await Session.findOne({ token });
  if (!s) return null;
  return User.findById(s.userId);
}
function makeAuth(required = true) {
  return async (req, res, next) => {
    const token = req.headers['authorization']?.replace('Bearer ', '');
    const user  = await getSession(token);
    if (required && !user) return res.status(401).json({ error: 'Unauthorized' });
    req.user = user;
    next();
  };
}
const auth    = makeAuth(true);
const optAuth = makeAuth(false);
function safeUser(u) {
  const o = u.toObject ? u.toObject() : { ...u };
  delete o.hash; delete o.salt;
  return o;
}
async function pushNotif(userId, type, data) {
  await Notif.create({ userId, type, data });
}

// ── AUTH ──────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, channelName } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });
    if (await User.findOne({ email: email.toLowerCase() })) return res.status(400).json({ error: 'Email already registered' });
    if (await User.findOne({ username: new RegExp(`^${username}$`, 'i') })) return res.status(400).json({ error: 'Username taken' });
    const { hash, salt } = hashPassword(password);
    const isFirst = (await User.countDocuments()) === 0;
    const user = await User.create({
      username: username.trim(),
      email: email.toLowerCase().trim(),
      channelName: channelName?.trim() || username.trim() + "'s Channel",
      hash, salt, isAdmin: isFirst, verified: isFirst,
    });
    res.json({ token: await createSession(user._id), user: safeUser(user) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || !verifyPassword(password, user.hash, user.salt))
      return res.status(401).json({ error: 'Invalid email or password' });
    res.json({ token: await createSession(user._id), user: safeUser(user) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/logout', auth, async (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  await Session.deleteOne({ token });
  res.json({ success: true });
});

app.get('/api/auth/me', auth, (req, res) => res.json(safeUser(req.user)));

// ── ADMIN ─────────────────────────────────────────────────
app.post('/api/admin/verify/:username', auth, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admins only' });
    const u = await User.findOne({ username: new RegExp(`^${req.params.username}$`, 'i') });
    if (!u) return res.status(404).json({ error: 'User not found' });
    u.verified = !u.verified;
    await u.save();
    res.json({ verified: u.verified, username: u.username });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── CHANNEL ───────────────────────────────────────────────
app.get('/api/channel/:username', async (req, res) => {
  try {
    const u = await User.findOne({ username: new RegExp(`^${req.params.username}$`, 'i') });
    if (!u) return res.status(404).json({ error: 'Channel not found' });
    const videos = await Video.find({ userId: u._id }).sort({ createdAt: -1 });
    const enriched = videos.map(v => ({
      ...v.toObject(),
      channel: { username: u.username, channelName: u.channelName, avatar: u.avatar, verified: u.verified }
    }));
    res.json({ user: safeUser(u), videos: enriched, videoCount: videos.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/channel', auth, async (req, res) => {
  try {
    const { channelName, channelDesc } = req.body;
    const u = await User.findById(req.user._id);
    if (channelName !== undefined) u.channelName = channelName.trim();
    if (channelDesc !== undefined) u.channelDesc = channelDesc.trim();
    await u.save();
    res.json(safeUser(u));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/channel/avatar', auth, uploadAvatar.single('avatar'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const u = await User.findById(req.user._id);
    if (u.avatarId) await cloudinary.uploader.destroy(u.avatarId).catch(() => {});
    u.avatar = req.file.path; u.avatarId = req.file.filename;
    await u.save();
    res.json({ avatar: u.avatar });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/channel/banner', auth, uploadBanner.single('banner'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const u = await User.findById(req.user._id);
    if (u.bannerId) await cloudinary.uploader.destroy(u.bannerId).catch(() => {});
    u.banner = req.file.path; u.bannerId = req.file.filename;
    await u.save();
    res.json({ banner: u.banner });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/channel/:username/subscribe', auth, async (req, res) => {
  try {
    const u = await User.findOne({ username: new RegExp(`^${req.params.username}$`, 'i') });
    if (!u) return res.status(404).json({ error: 'Not found' });
    if (u._id.equals(req.user._id)) return res.status(400).json({ error: "Can't sub yourself" });
    const idx = u.subscribers.findIndex(s => s.equals(req.user._id));
    const subscribed = idx === -1;
    subscribed ? u.subscribers.push(req.user._id) : u.subscribers.splice(idx, 1);
    await u.save();
    if (subscribed) pushNotif(u._id, 'subscribe', { fromUsername: req.user.username, fromChannelName: req.user.channelName, fromAvatar: req.user.avatar });
    res.json({ subscribed, count: u.subscribers.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── VIDEOS ────────────────────────────────────────────────
app.get('/api/videos', async (req, res) => {
  try {
    const videos = await Video.find().sort({ createdAt: -1 }).populate('userId', 'username channelName avatar verified');
    res.json(videos.map(v => {
      const o = v.toObject();
      o.channel = o.userId ? { username: o.userId.username, channelName: o.userId.channelName, avatar: o.userId.avatar, verified: o.userId.verified } : null;
      o.userId  = o.userId?._id;
      return o;
    }));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/videos/:id', async (req, res) => {
  try {
    const v = await Video.findById(req.params.id).populate('userId', 'username channelName avatar verified subscribers');
    if (!v) return res.status(404).json({ error: 'Not found' });
    const o = v.toObject();
    const u = o.userId;
    o.channel      = u ? { username: u.username, channelName: u.channelName, avatar: u.avatar, verified: u.verified, subscribers: u.subscribers?.length || 0 } : null;
    o.userId       = u?._id;
    o.commentCount = await Comment.countDocuments({ videoId: v._id });
    res.json(o);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/videos/upload', auth, uploadVideo.single('video'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const video = await Video.create({
      userId:      req.user._id,
      title:       req.body.title?.trim() || req.file.originalname,
      description: req.body.description?.trim() || '',
      filename:    req.file.filename,
      url:         req.file.path,
      size:        req.file.size || 0,
    });
    res.json({ success: true, video });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// stream = redirect to cloudinary URL
app.get('/api/stream/:id', async (req, res) => {
  try {
    const v = await Video.findById(req.params.id);
    if (!v) return res.status(404).json({ error: 'Not found' });
    Video.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } }).exec();
    res.redirect(v.url);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/videos/:id/like', auth, async (req, res) => {
  try {
    const v = await Video.findById(req.params.id);
    if (!v) return res.status(404).json({ error: 'Not found' });
    const idx = v.likes.findIndex(id => id.equals(req.user._id));
    const liked = idx === -1;
    liked ? v.likes.push(req.user._id) : v.likes.splice(idx, 1);
    await v.save();
    res.json({ liked, count: v.likes.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/videos/:id/thumbnail', auth, uploadThumb.single('thumbnail'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const v = await Video.findById(req.params.id);
    if (!v) return res.status(404).json({ error: 'Not found' });
    if (!v.userId.equals(req.user._id)) return res.status(403).json({ error: 'Forbidden' });
    if (v.thumbnailId) await cloudinary.uploader.destroy(v.thumbnailId).catch(() => {});
    v.thumbnail = req.file.path; v.thumbnailId = req.file.filename;
    await v.save();
    res.json({ thumbnail: v.thumbnail });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/videos/:id', auth, async (req, res) => {
  try {
    const v = await Video.findById(req.params.id);
    if (!v) return res.status(404).json({ error: 'Not found' });
    if (!v.userId.equals(req.user._id)) return res.status(403).json({ error: 'Forbidden' });
    await cloudinary.uploader.destroy(v.filename, { resource_type: 'video' }).catch(() => {});
    if (v.thumbnailId) await cloudinary.uploader.destroy(v.thumbnailId).catch(() => {});
    await Comment.deleteMany({ videoId: v._id });
    await Video.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── COMMENTS ──────────────────────────────────────────────
app.get('/api/videos/:id/comments', optAuth, async (req, res) => {
  try {
    const comments = await Comment.find({ videoId: req.params.id })
      .populate('userId', 'username channelName avatar verified')
      .sort({ createdAt: 1 });
    res.json(comments.map(c => {
      const o = c.toObject();
      o.user   = o.userId ? { username: o.userId.username, channelName: o.userId.channelName, avatar: o.userId.avatar, verified: o.userId.verified } : null;
      o.userId = o.userId?._id;
      return o;
    }));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/videos/:id/comments', auth, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text?.trim()) return res.status(400).json({ error: 'Empty comment' });
    const video = await Video.findById(req.params.id);
    if (!video) return res.status(404).json({ error: 'Video not found' });
    const comment = await Comment.create({ videoId: req.params.id, userId: req.user._id, text: text.trim() });
    if (!video.userId.equals(req.user._id)) {
      pushNotif(video.userId, 'comment', { fromUsername: req.user.username, fromChannelName: req.user.channelName, fromAvatar: req.user.avatar, videoId: req.params.id, videoTitle: video.title, text: text.trim().slice(0, 80) });
    }
    res.json({ ...comment.toObject(), user: { username: req.user.username, channelName: req.user.channelName, avatar: req.user.avatar, verified: req.user.verified } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/comments/:id', auth, async (req, res) => {
  try {
    const c = await Comment.findById(req.params.id);
    if (!c) return res.status(404).json({ error: 'Not found' });
    if (!c.userId.equals(req.user._id) && !req.user.isAdmin) return res.status(403).json({ error: 'Forbidden' });
    await Comment.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── NOTIFICATIONS ─────────────────────────────────────────
app.get('/api/notifications', auth, async (req, res) => {
  try { res.json(await Notif.find({ userId: req.user._id }).sort({ createdAt: -1 }).limit(50)); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/notifications/unread', auth, async (req, res) => {
  try { res.json({ count: await Notif.countDocuments({ userId: req.user._id, read: false }) }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/notifications/read-all', auth, async (req, res) => {
  try { await Notif.updateMany({ userId: req.user._id }, { read: true }); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/notifications/:id', auth, async (req, res) => {
  try { await Notif.findOneAndDelete({ _id: req.params.id, userId: req.user._id }); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

// ── ANALYTICS ─────────────────────────────────────────────
app.get('/api/analytics', auth, async (req, res) => {
  try {
    const videos        = await Video.find({ userId: req.user._id });
    const me            = await User.findById(req.user._id);
    const totalViews    = videos.reduce((s, v) => s + v.views, 0);
    const totalLikes    = videos.reduce((s, v) => s + v.likes.length, 0);
    const totalSubs     = me.subscribers.length;
    const totalComments = await Comment.countDocuments({ videoId: { $in: videos.map(v => v._id) } });
    const videoStats    = videos.map(v => ({ title: v.title.slice(0, 28), views: v.views, likes: v.likes.length })).sort((a, b) => b.views - a.views).slice(0, 10);
    res.json({ totalViews, totalLikes, totalSubs, totalComments, videoStats });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── PREFS ─────────────────────────────────────────────────
app.get('/api/prefs', auth, async (req, res) => {
  try { const u = await User.findById(req.user._id); res.json(u.prefs || {}); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/prefs', auth, async (req, res) => {
  try {
    const u = await User.findById(req.user._id);
    u.prefs = { ...(u.prefs || {}), ...req.body };
    u.markModified('prefs');
    await u.save();
    res.json(u.prefs);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── PING / KEEP ALIVE ─────────────────────────────────────
app.get('/api/ping', (req, res) => res.json({ ok: true }));
setInterval(() => {
  const port = process.env.PORT || 3000;
  require('http').get(`http://localhost:${port}/api/ping`, r => r.resume())
    .on('error', e => console.warn('ping failed:', e.message));
}, 10 * 60 * 1000);

// ── CATCH ALL ─────────────────────────────────────────────
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api')) res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`\n🎬 VidWave → http://localhost:${PORT}\n`));
