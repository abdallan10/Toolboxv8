/* ToolboxV8 – main.js */

const API_BASE = '/api';

/* ---- API fetch (cookie HttpOnly envoyé automatiquement) ---- */
async function apiFetch(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    credentials: 'same-origin',
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
  if (res.status === 401) {
    window.location.href = '/login';
    return null;
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

/* ---- Module launcher ---- */
async function launchModule(module, target, options = {}) {
  const result = await apiFetch('/modules/launch', {
    method: 'POST',
    body: JSON.stringify({ module, target, options }),
  });
  return result;
}

/* ---- Poll job status ---- */
function pollJob(jobId, onUpdate, intervalMs = 3000) {
  const id = setInterval(async () => {
    try {
      const data = await apiFetch(`/modules/jobs/${jobId}`);
      if (!data) { clearInterval(id); return; }
      onUpdate(data);
      if (['done', 'error'].includes(data.job?.status)) {
        clearInterval(id);
      }
    } catch (e) {
      clearInterval(id);
    }
  }, intervalMs);
  return id;
}

/* ---- Toast notifications ---- */
function toast(message, type = 'info') {
  const t = document.createElement('div');
  t.className = `toast toast--${type}`;
  t.textContent = message;
  t.style.cssText = `
    position: fixed; bottom: 24px; right: 24px; z-index: 9999;
    background: var(--bg-surface); border: 1px solid var(--border);
    padding: 12px 20px; border-radius: 8px; color: var(--text);
    font-size: .9rem; box-shadow: 0 4px 12px #00000066;
  `;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

/* ---- Init ---- */
document.addEventListener('DOMContentLoaded', () => {
  const path = window.location.pathname;
  document.querySelectorAll('.nav-link').forEach(link => {
    if (path.startsWith(link.getAttribute('href'))) {
      link.classList.add('active');
    }
  });
});
