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
    const init = { users: [], profiles: [], sessions: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(init, null, 2));
    return init;
  }
  const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  if (!data.sessions) data.sessions = [];
  return data;
}

function writeDb(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

function nextId(arr) {
  return arr.length === 0 ? 1 : Math.max(...arr.map(x => x.id)) + 1;
}

function today() {
  return new Date().toISOString().split('T')[0];
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

  const hash    = await bcrypt.hash(password, 10);
  const user    = { id: nextId(db.users), email: lower, password: hash, name: name.trim() };
  const profile = { id: nextId(db.profiles), userId: user.id, disciplines: [], groupSizes: [], year: null, onboarded: false };

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

  const profile   = db.profiles.find(p => p.userId === user.id);
  const todaySess = (db.sessions || []).find(s => s.userId === user.id && s.date === today());
  const token     = jwt.sign({ id: user.id, name: user.name }, JWT_SECRET, { expiresIn: '30d' });

  res.json({
    token,
    name:       user.name,
    onboarded:  profile?.onboarded || false,
    hasSession: !!todaySess
  });
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
  const { disciplines, groupSizes, year } = req.body || {};

  if (!Array.isArray(disciplines) || disciplines.length === 0)
    return res.status(400).json({ error: 'Choose at least one discipline' });
  if (!Array.isArray(groupSizes) || groupSizes.length === 0)
    return res.status(400).json({ error: 'Choose at least one group size' });

  const db      = readDb();
  const profile = db.profiles.find(p => p.userId === req.user.id);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });

  profile.disciplines = disciplines;
  profile.groupSizes  = groupSizes;
  profile.year        = year || null;
  profile.onboarded   = true;
  writeDb(db);
  res.json({ success: true });
});

// ── Today's session ───────────────────────────────────────
app.get('/api/session/today', auth, (req, res) => {
  const db      = readDb();
  const session = db.sessions.find(s => s.userId === req.user.id && s.date === today());
  res.json(session || null);
});

app.post('/api/session', auth, (req, res) => {
  const { discipline, groupSize } = req.body || {};
  if (!discipline || !groupSize)
    return res.status(400).json({ error: 'Discipline and group size required' });

  const db  = readDb();
  const d   = today();

  // Replace any existing session for today
  db.sessions = db.sessions.filter(s => !(s.userId === req.user.id && s.date === d));
  db.sessions.push({ userId: req.user.id, discipline, groupSize, date: d });
  writeDb(db);
  res.json({ success: true });
});

// ── Matches (based on today's session) ───────────────────
app.get('/api/matches', auth, (req, res) => {
  const db        = readDb();
  const mySession = db.sessions.find(s => s.userId === req.user.id && s.date === today());

  if (!mySession)
    return res.status(400).json({ error: 'Set your session for today first' });

  const matches = db.sessions
    .filter(s =>
      s.date      === today() &&
      s.userId    !== req.user.id &&
      s.discipline === mySession.discipline &&
      s.groupSize  === mySession.groupSize
    )
    .map(s => {
      const u = db.users.find(u => u.id === s.userId);
      const p = db.profiles.find(p => p.userId === s.userId);
      return { id: u.id, name: u.name, discipline: s.discipline, groupSize: s.groupSize, year: p?.year };
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

app.listen(process.env.PORT || 3000, '0.0.0.0', () => console.log('TrainTribe running'));
