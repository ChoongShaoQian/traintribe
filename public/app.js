// Auth helpers shared across all app pages

function getToken()  { return localStorage.getItem('tt_token'); }
function getName()   { return localStorage.getItem('tt_name'); }

function setSession(token, name, onboarded) {
  localStorage.setItem('tt_token',     token);
  localStorage.setItem('tt_name',      name);
  localStorage.setItem('tt_onboarded', onboarded ? '1' : '0');
}

function clearSession() {
  localStorage.removeItem('tt_token');
  localStorage.removeItem('tt_name');
  localStorage.removeItem('tt_onboarded');
}

function logout() {
  clearSession();
  window.location.href = '/login.html';
}

function requireAuth() {
  if (!getToken()) { window.location.href = '/login.html'; return false; }
  return true;
}

function requireOnboarded() {
  if (localStorage.getItem('tt_onboarded') !== '1') {
    window.location.href = '/onboarding.html'; return false;
  }
  return true;
}

async function api(method, path, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${getToken()}` }
  };
  if (body) opts.body = JSON.stringify(body);
  const res  = await fetch(`/api${path}`, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Something went wrong');
  return data;
}

// Discipline display helpers
const DISC_LABEL = { hyrox: 'HYROX', running: 'Running', lifting: 'Weightlifting' };
const DISC_ICON  = { hyrox: '🏋️', running: '🏃', lifting: '💪' };
const DISC_CLASS = { hyrox: 'chip-hyrox', running: 'chip-running', lifting: 'chip-lifting' };

const SIZE_LABEL = { '1': '1 partner', '3': 'Up to 3', '3+': '3 or more' };
