const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const fs      = require('fs');
const path    = require('path');

const app        = express();
const JWT_SECRET = 'tt-soton-2026';
const DB_FILE    = path.join(__dirname, 'db.json');

// ── DB helpers ────────────────────────────────────────────
function readDb() {
  if (!fs.existsSync(DB_FILE)) {
    const init = { users: [], profiles: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(init, null, 2));
    return init;
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function writeDb(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

function nextId(arr) {
  return arr.length === 0 ? 1 : Math.max(...arr.map(x => x.id)) + 1;
}

// ── Middleware ────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Unauthorised' });
  try {
    req.user = jwt.verify(header.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ── Auth ──────────────────────────────────────────────────
app.post('/api/auth/signup', async (req, res) => {
  const { email, password, name } = req.body || {};
  if (!email || !password || !name)
    return res.status(400).json({ error: 'All fields required' });

  const lower = email.toLowerCase().trim();
  if (!lower.endsWith('@soton.ac.uk') && !lower.endsWith('@southampton.ac.uk'))
    return res.status(400).json({ error: 'Use your @soton.ac.uk email' });

  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const db = readDb();
  if (db.users.find(u => u.email === lower))
    return res.status(400).json({ error: 'Email already registered' });

  const hash = await bcrypt.hash(password, 10);
  const user    = { id: nextId(db.users), email: lower, password: hash, name: name.trim() };
  const profile = { id: nextId(db.profiles), userId: user.id, discipline: null, groupSize: null, year: null, onboarded: false };

  db.users.push(user);
  db.profiles.push(profile);
  writeDb(db);

  const token = jwt.sign({ id: user.id, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, name: user.name, onboarded: false });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password required' });

  const db   = readDb();
  const user = db.users.find(u => u.email === email.toLowerCase().trim());
  if (!user) return res.status(400).json({ error: 'Invalid email or password' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid)  return res.status(400).json({ error: 'Invalid email or password' });

  const profile = db.profiles.find(p => p.userId === user.id);
  const token   = jwt.sign({ id: user.id, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, name: user.name, onboarded: profile?.onboarded || false });
});

// ── Profile ───────────────────────────────────────────────
app.get('/api/profile', auth, (req, res) => {
  const db      = readDb();
  const user    = db.users.find(u => u.id === req.user.id);
  const profile = db.profiles.find(p => p.userId === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { password, ...safe } = user;
  res.json({ ...safe, ...profile });
});

app.post('/api/profile/setup', auth, (req, res) => {
  const { discipline, groupSize, year } = req.body || {};
  if (!discipline || !groupSize)
    return res.status(400).json({ error: 'Discipline and group size required' });

  const db      = readDb();
  const profile = db.profiles.find(p => p.userId === req.user.id);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });

  profile.discipline = discipline;
  profile.groupSize  = groupSize;
  profile.year       = year || null;
  profile.onboarded  = true;
  writeDb(db);
  res.json({ success: true });
});

// ── Matches ───────────────────────────────────────────────
app.get('/api/matches', auth, (req, res) => {
  const db        = readDb();
  const myProfile = db.profiles.find(p => p.userId === req.user.id);

  if (!myProfile?.onboarded)
    return res.status(400).json({ error: 'Complete your profile first' });

  const matches = db.profiles
    .filter(p => p.userId !== req.user.id && p.discipline === myProfile.discipline && p.onboarded)
    .sort((a, b) => (a.groupSize === myProfile.groupSize ? -1 : 1))
    .map(p => {
      const u = db.users.find(u => u.id === p.userId);
      return { id: u.id, name: u.name, discipline: p.discipline, groupSize: p.groupSize, year: p.year };
    });

  res.json(matches);
});

// ── Connect (reveal email) ────────────────────────────────
app.get('/api/connect/:id', auth, (req, res) => {
  const db   = readDb();
  const user = db.users.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json({ email: user.email, name: user.name });
});

app.listen(3000, () => console.log('TrainTribe running at http://localhost:3000'));
