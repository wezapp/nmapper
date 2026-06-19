// dashboard-live.js — KPIs monitoring temps réel sur le dashboard

const DashboardLive = (() => {
  let _timer = null;

  function _el(id) { return document.getElementById(id); }

  async function refresh() {
    try {
      const r = await fetch('/scanner-api/dashboard/stats', { credentials: 'include' });
      if (!r.ok) { _renderEmpty(); return; }
      const d = await r.json();
      _render(d);
    } catch (_) {
      _renderEmpty();
    }
  }

  function _render(d) {
    const online = d.agents_online ?? 0;
    const total  = d.agents_total  ?? 0;
    const hosts  = d.hosts_total   ?? 0;
    const vuln   = d.hosts_vuln    ?? 0;
    const evts   = d.events_total  ?? 0;

    _set('kpi-agents-online', online);
    _set('kpi-agents-total',  `/ ${total} total`);
    _set('kpi-hosts-total',   hosts);
    _set('kpi-hosts-vuln',    vuln);
    _set('kpi-events',        evts);

    const pct = hosts > 0 ? Math.round((vuln / hosts) * 100) : 0;
    _set('kpi-vuln-pct', `${pct}% du parc`);

    // Couleur KPI agents selon état
    const agentCard = document.querySelector('.dash-kpi-agents .dash-kpi-val');
    if (agentCard) agentCard.style.color = online > 0 ? 'var(--ok)' : 'var(--txt-3)';

    // Couleur KPI vuln
    const vulnCard = document.querySelector('.dash-kpi-vuln .dash-kpi-val');
    if (vulnCard) vulnCard.style.color = vuln > 0 ? 'var(--danger)' : 'var(--ok)';

    // Hôtes vulnérables
    const vulnList = _el('dash-live-vuln-list');
    if (vulnList) {
      if (!d.top_vuln || d.top_vuln.length === 0) {
        vulnList.innerHTML = '<p style="color:var(--ok);font-size:12px;padding:6px 0;">✅ Aucun hôte vulnérable détecté</p>';
      } else {
        vulnList.innerHTML = d.top_vuln.map(h =>
          `<div class="dlv-row">
            <span class="dlv-ip">${h.ip}</span>
            <span class="dlv-host" title="${h.hostname||''}">${h.hostname || 'inconnu'}</span>
            <span class="dlv-ports" title="${h.ports} ports ouverts">${h.ports} ports</span>
          </div>`
        ).join('');
      }
    }

    // Événements récents
    const evtList = _el('dash-live-events-list');
    if (evtList) {
      if (!d.recent_events || d.recent_events.length === 0) {
        evtList.innerHTML = '<p style="color:var(--txt-3);font-size:12px;padding:6px 0;">Aucun événement récent</p>';
      } else {
        evtList.innerHTML = d.recent_events.map(e => {
          const cls = e.level === 'warn' ? 'var(--warn)' : e.level === 'error' ? 'var(--danger)' : 'var(--txt-2)';
          return `<div class="dlv-evt" style="color:${cls};">
            <span class="dlv-ts">${e.ts||''}</span>
            <span>${e.message||''}</span>
          </div>`;
        }).join('');
      }
    }
  }

  function _renderEmpty() {
    ['kpi-agents-online','kpi-hosts-total','kpi-hosts-vuln','kpi-events'].forEach(id => _set(id, '—'));
    _set('kpi-agents-total', '/ — total');
    _set('kpi-vuln-pct', '—% du parc');
  }

  function _set(id, val) {
    const el = _el(id);
    if (el) el.textContent = val;
  }

  // Auto-refresh toutes les 30s lorsqu'on est sur le dashboard
  function startAutoRefresh() {
    stopAutoRefresh();
    refresh();
    _timer = setInterval(refresh, 30_000);
  }

  function stopAutoRefresh() {
    if (_timer) { clearInterval(_timer); _timer = null; }
  }

  return { refresh, startAutoRefresh, stopAutoRefresh };
})();
