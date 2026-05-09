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

// ── Admin ─────────────────────────────────────────────────
const ADMIN_KEY = process.env.ADMIN_KEY || 'tt-admin-2026';

app.get('/admin', (req, res) => {
  if (req.query.key !== ADMIN_KEY) {
    return res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Admin — TrainTribe</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Inter,sans-serif;background:#0D0D1A;color:#E8E8F0;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#181830;border:1px solid rgba(255,255,255,0.08);border-radius:16px;padding:40px 36px;width:100%;max-width:360px}
h1{font-size:20px;font-weight:800;color:#fff;margin-bottom:6px}p{font-size:13px;color:#8888AA;margin-bottom:24px}
form{display:flex;flex-direction:column;gap:12px}
input{background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.08);border-radius:10px;padding:12px 14px;font-size:15px;color:#fff;outline:none;font-family:inherit}
button{padding:13px;border-radius:10px;font-size:14px;font-weight:700;cursor:pointer;border:none;background:#FF4D00;color:#fff;font-family:inherit}
</style></head><body>
<div class="card"><h1>🔐 Admin Panel</h1><p>TrainTribe owner access only.</p>
<form method="GET" action="/admin">
<input type="password" name="key" placeholder="Admin password" autofocus/>
<button type="submit">Enter</button>
</form></div></body></html>`);
  }

  const db  = readDb();
  const tod = today();
  const DISC = { hyrox:'🏋️ HYROX', running:'🏃 Running', lifting:'💪 Weightlifting' };
  const SIZE = { '1':'1 partner', '3':'Up to 3', '3+':'3+' };

  const users = db.users.map(u => {
    const profile  = db.profiles.find(p => p.userId === u.id) || {};
    const sessions = db.sessions.filter(s => s.userId === u.id).sort((a,b) => b.date.localeCompare(a.date));
    const todaySess = sessions.find(s => s.date === tod);
    return { ...u, profile, sessions, todaySess };
  });

  const activeToday  = users.filter(u => u.todaySess).length;
  const onboarded    = users.filter(u => u.profile.onboarded).length;

  const rows = users.map(u => {
    const discs = (u.profile.disciplines || []).map(d => DISC[d] || d).join(', ') || '—';
    const sizes = (u.profile.groupSizes  || []).map(s => SIZE[s] || s).join(', ') || '—';
    const today_info = u.todaySess
      ? `✅ ${DISC[u.todaySess.discipline] || u.todaySess.discipline} · ${SIZE[u.todaySess.groupSize] || u.todaySess.groupSize}`
      : '—';
    const lastSess = u.sessions[0]?.date || '—';
    return `<tr>
      <td>${u.name}</td>
      <td>${u.email}</td>
      <td>${u.profile.year || '—'}</td>
      <td>${discs}</td>
      <td>${sizes}</td>
      <td>${today_info}</td>
      <td>${lastSess}</td>
    </tr>`;
  }).join('');

  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Admin — TrainTribe</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Inter,sans-serif;background:#0D0D1A;color:#E8E8F0;padding:32px 24px}
h1{font-size:22px;font-weight:900;color:#fff;margin-bottom:4px}
.sub{font-size:13px;color:#8888AA;margin-bottom:28px}
.stats{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:28px}
.stat{background:#181830;border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:20px 24px;min-width:140px}
.stat .n{font-size:36px;font-weight:900;color:#fff;line-height:1;margin-bottom:4px}
.stat .l{font-size:12px;font-weight:600;color:#8888AA;text-transform:uppercase;letter-spacing:.06em}
.wrap{background:#181830;border:1px solid rgba(255,255,255,0.08);border-radius:16px;overflow:auto}
table{width:100%;border-collapse:collapse;min-width:700px}
th{text-align:left;padding:10px 16px;font-size:11px;font-weight:700;color:#8888AA;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid rgba(255,255,255,0.08);background:rgba(0,0,0,.2)}
td{padding:12px 16px;font-size:13px;border-bottom:1px solid rgba(255,255,255,0.04)}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.02)}
a{color:#FF4D00;font-size:13px;text-decoration:none}
</style></head><body>
<h1>TrainTribe Admin</h1>
<div class="sub">${tod} · <a href="/admin?key=${ADMIN_KEY}">Refresh</a></div>
<div class="stats">
  <div class="stat"><div class="n">${users.length}</div><div class="l">Total accounts</div></div>
  <div class="stat"><div class="n">${onboarded}</div><div class="l">Onboarded</div></div>
  <div class="stat"><div class="n">${activeToday}</div><div class="l">Active today</div></div>
  <div class="stat"><div class="n">${users.length - onboarded}</div><div class="l">Not set up</div></div>
</div>
<div class="wrap"><table>
<thead><tr><th>Name</th><th>Email</th><th>Year</th><th>Disciplines</th><th>Group pref</th><th>Today</th><th>Last session</th></tr></thead>
<tbody>${rows || '<tr><td colspan="7" style="text-align:center;padding:32px;color:#8888AA">No users yet.</td></tr>'}</tbody>
</table></div></body></html>`);
});

app.listen(process.env.PORT || 3000, '0.0.0.0', () => console.log('TrainTribe running'));
