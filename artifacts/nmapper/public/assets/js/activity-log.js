// activity-log.js — Journal d'activité NMAPPER v2
// Polling 30s quand la vue est active, filtres type/date, export CSV, effacer.

const ActivityLog = (() => {
  let _pollTimer = null;
  let _allLogs   = [];

  const ICONS = {
    scan_start:   '🎯',
    scan_done:    '✅',
    scan_error:   '❌',
    scan_cancel:  '⏹',
    import_file:  '📥',
    export_pdf:   '📄',
    export_csv:   '📊',
    deploy_start: '🚀',
    deploy_done:  '✅',
    deploy_error: '❌',
    agent_connect:'📡',
    login:        '🔑',
    logout:       '🚪',
  };

  const TYPE_GROUPS = {
    scan:   ['scan_start', 'scan_done', 'scan_error', 'scan_cancel'],
    import: ['import_file'],
    export: ['export_pdf', 'export_csv'],
    deploy: ['deploy_start', 'deploy_done', 'deploy_error'],
    agent:  ['agent_connect'],
    auth:   ['login', 'logout'],
  };

  // ── Fetch ───────────────────────────────────────────────────

  async function _fetchLogs() {
    try {
      const res = await fetch('/scanner-api/activity/logs?limit=500', { credentials: 'same-origin' });
      if (!res.ok) {
        if (res.status === 401) {
          _showUnauthMsg();
          return;
        }
        return;
      }
      const data = await res.json();
      _allLogs = data.logs || [];
      _render();
    } catch (_) {}
  }

  function _showUnauthMsg() {
    const c = document.getElementById('act-log-container');
    if (c) c.innerHTML = `<p style="color:var(--txt-3);text-align:center;padding:40px 0;">
      🔒 Connectez-vous au scanner (clé API) pour accéder au journal.</p>`;
  }

  // ── Filters ─────────────────────────────────────────────────

  function _getFilters() {
    return {
      type: document.getElementById('act-filter-type')?.value  || '',
      date: document.getElementById('act-filter-date')?.value  || '',
      q:    document.getElementById('act-filter-q')?.value.trim().toLowerCase() || '',
    };
  }

  function _filterLogs(logs) {
    const { type, date, q } = _getFilters();
    let out = logs;

    if (type && TYPE_GROUPS[type]) {
      out = out.filter(e => TYPE_GROUPS[type].includes(e.action));
    }

    if (date) {
      const now    = Date.now();
      const cutoff =
        date === 'today' ? new Date().setHours(0, 0, 0, 0) :
        date === '7d'    ? now - 7  * 86400_000 :
                           now - 30 * 86400_000;
      out = out.filter(e => new Date(e.ts).getTime() >= cutoff);
    }

    if (q) {
      out = out.filter(e =>
        (e.action  || '').toLowerCase().includes(q) ||
        (e.target  || '').toLowerCase().includes(q) ||
        (e.detail  || '').toLowerCase().includes(q)
      );
    }

    return out;
  }

  // ── Render ──────────────────────────────────────────────────

  function _relTime(ts) {
    const diff = (Date.now() - new Date(ts).getTime()) / 1000;
    if (diff < 5)    return 'à l\'instant';
    if (diff < 60)   return `il y a ${Math.round(diff)}s`;
    if (diff < 3600) return `il y a ${Math.round(diff / 60)}min`;
    if (diff < 86400) return `il y a ${Math.round(diff / 3600)}h`;
    return new Date(ts).toLocaleDateString('fr-FR', { day:'2-digit', month:'2-digit', year:'2-digit', hour:'2-digit', minute:'2-digit' });
  }

  function _badge(status) {
    const map = {
      success: ['var(--ok)',     'var(--ok-dim)',     '✓ succès'],
      error:   ['var(--danger)', 'var(--danger-dim)', '✗ erreur'],
      warn:    ['var(--warn)',   'var(--warn-dim)',   '! avert.'],
      info:    ['var(--info)',   'var(--info-dim)',   'ℹ info'],
    };
    const [c, bg, label] = map[status] || map.info;
    return `<span style="display:inline-flex;align-items:center;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;background:${bg};color:${c};">${label}</span>`;
  }

  function _esc(s) {
    return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function _render() {
    const container = document.getElementById('act-log-container');
    if (!container) return;

    const logs = _filterLogs(_allLogs);

    if (!logs.length) {
      container.innerHTML = `<p style="color:var(--txt-3);text-align:center;padding:48px 0;font-size:13px;">
        Aucun événement enregistré.</p>`;
      const cnt = document.getElementById('act-count');
      if (cnt) cnt.textContent = '0 événement';
      return;
    }

    const cnt = document.getElementById('act-count');
    if (cnt) cnt.textContent = `${logs.length} événement${logs.length > 1 ? 's' : ''}`;

    const rows = logs.map(e => {
      const icon = ICONS[e.action] || '📌';
      return `<tr style="border-bottom:1px solid var(--stroke-soft);">
        <td style="font-size:15px;text-align:center;width:32px;padding:8px 4px;">${icon}</td>
        <td style="font-family:var(--font-mono);font-size:11px;color:var(--txt-3);white-space:nowrap;padding:8px 10px;">${_relTime(e.ts)}</td>
        <td style="padding:8px 10px;"><code style="font-size:12px;color:var(--accent);">${_esc(e.action)}</code></td>
        <td style="font-size:12px;color:var(--txt-1);padding:8px 10px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${_esc(e.target)}">${_esc(e.target || '—')}</td>
        <td style="padding:8px 10px;">${_badge(e.status)}</td>
        <td style="font-size:11px;color:var(--txt-3);padding:8px 10px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${_esc(e.detail)}">${_esc(e.detail || '')}</td>
      </tr>`;
    }).join('');

    container.innerHTML = `<div style="overflow-x:auto;">
      <table style="width:100%;border-collapse:collapse;">
        <thead>
          <tr style="font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:var(--txt-3);border-bottom:2px solid var(--stroke);">
            <th style="padding:6px 4px;text-align:center;"></th>
            <th style="padding:6px 10px;text-align:left;">Quand</th>
            <th style="padding:6px 10px;text-align:left;">Action</th>
            <th style="padding:6px 10px;text-align:left;">Cible</th>
            <th style="padding:6px 10px;text-align:left;">Statut</th>
            <th style="padding:6px 10px;text-align:left;">Détail</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
  }

  // ── Export CSV ──────────────────────────────────────────────

  async function _exportCSV() {
    const logs = _filterLogs(_allLogs);
    if (!logs.length) { showMessage?.('warning', '⚠️ Aucun événement à exporter.'); return; }
    const header = ['Timestamp ISO','Action','Cible','Statut','Détail'];
    const esc    = v => `"${String(v || '').replace(/"/g,'""')}"`;
    const lines  = [header.map(esc).join(';')];
    logs.forEach(e => lines.push([e.ts, e.action, e.target||'', e.status, e.detail||''].map(esc).join(';')));
    const blob = new Blob(['\uFEFF' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `nmapper-journal-${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    showMessage?.('success', `✅ Journal exporté (${logs.length} entrées)`);
  }

  // ── Clear ───────────────────────────────────────────────────

  async function _clearLogs() {
    if (!confirm('Effacer tout le journal d\'activité ?\nCette action est irréversible.')) return;
    try {
      const res = await fetch('/scanner-api/activity/logs', { method: 'DELETE', credentials: 'same-origin' });
      if (res.ok) {
        _allLogs = [];
        _render();
        showMessage?.('success', '✅ Journal effacé');
      }
    } catch (_) {}
  }

  // ── Event bindings ──────────────────────────────────────────

  function _bind() {
    document.getElementById('act-refresh-btn')?.addEventListener('click', _fetchLogs);
    document.getElementById('act-export-btn')?.addEventListener('click', _exportCSV);
    document.getElementById('act-clear-btn')?.addEventListener('click', _clearLogs);
    ['act-filter-type','act-filter-date','act-filter-q'].forEach(id => {
      document.getElementById(id)?.addEventListener('input', _render);
      document.getElementById(id)?.addEventListener('change', _render);
    });
  }

  // ── Public ──────────────────────────────────────────────────

  function onEnter() {
    _fetchLogs();
    if (!_pollTimer) _pollTimer = setInterval(_fetchLogs, 30_000);
  }

  function onLeave() {
    if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }
  }

  /**
   * Enregistre un événement côté client vers le backend.
   * Silencieux si non authentifié ou hors ligne.
   */
  async function logEvent(action, target = '', status = 'info', detail = '') {
    try {
      await fetch('/scanner-api/activity/log', {
        method:      'POST',
        credentials: 'same-origin',
        headers:     { 'Content-Type': 'application/json' },
        body:        JSON.stringify({ action, target, status, detail }),
      });
    } catch (_) {}
  }

  function init() {
    _bind();
  }

  return { init, onEnter, onLeave, logEvent };
})();

document.addEventListener('DOMContentLoaded', () => ActivityLog.init());
