/* ToolboxV8 – app.js */

// ── Auth ────────────────────────────────────────────────
// Authentification gérée côté serveur via cookie HttpOnly.
// Le cookie est envoyé automatiquement par le navigateur,
// donc pas besoin de lire/écrire un token en JS.

function requireAuth() { /* no-op : garde côté serveur */ }

function logout() {
  // Soumet un POST /logout pour effacer le cookie côté serveur.
  const form = document.createElement('form');
  form.method = 'POST';
  form.action = '/logout';
  document.body.appendChild(form);
  form.submit();
}

async function loadUserInfo() {
  const data = await apiFetch('/api/auth/me');
  if (!data) return;
  const initials = data.username.slice(0, 2).toUpperCase();
  const el = document.getElementById('user-avatar');
  const nameEl = document.getElementById('user-name');
  const roleEl = document.getElementById('user-role');
  if (el) el.textContent = initials;
  if (nameEl) nameEl.textContent = data.username;
  if (roleEl) roleEl.textContent = data.role;

  // Révèle les éléments de menu réservés à l'admin (section Administration)
  if (data.role === 'admin') {
    document.querySelectorAll('.nav-admin-only').forEach(el => {
      el.style.display = '';
    });
  }

  // Le rôle 'reader' ne voit que Dashboard + Rapports
  // → on masque tous les liens marqués 'nav-not-reader' (Modules, SIEM, etc.)
  if (data.role === 'reader') {
    document.querySelectorAll('.nav-not-reader').forEach(el => {
      el.style.display = 'none';
    });
  }
}

// ── API fetch ────────────────────────────────────────────
async function apiFetch(path, options = {}) {
  try {
    const res = await fetch(path, {
      credentials: 'same-origin',
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
    });

    updateApiStatus(res.ok || res.status < 500);

    if (res.status === 401) {
      window.location.href = '/login';
      return null;
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    if (res.status === 204 || res.headers.get('content-length') === '0') return null;
    return await res.json();
  } catch (e) {
    updateApiStatus(false);
    if (e.name !== 'TypeError') throw e;
    return null;
  }
}

function updateApiStatus(ok) {
  const dot = document.getElementById('api-status');
  if (!dot) return;
  dot.classList.toggle('offline', !ok);
  dot.title = ok ? 'API connectée' : 'API hors ligne';
}

// ── Horloge ──────────────────────────────────────────────
function startClock() {
  function tick() {
    const el = document.getElementById('clock');
    if (el) el.textContent = new Date().toLocaleTimeString('fr-FR');
  }
  tick();
  setInterval(tick, 1000);
}

// ── Utils ────────────────────────────────────────────────
function formatDate(iso) {
  if (!iso) return '–';
  try {
    return new Intl.DateTimeFormat('fr-FR', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    }).format(new Date(iso));
  } catch { return iso; }
}
