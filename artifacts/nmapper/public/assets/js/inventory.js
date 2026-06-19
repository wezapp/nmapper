// inventory.js — Table inventaire unifiée (Nmap + Agents) dans la vue Cartographie

const Inventory = (() => {
  let _all = [];

  // Ports haut-risque pour le scoring
  const _HIGH = new Set([21,23,445,3389,5900,6379,27017,9200,11211,5432,3306,1433,1521]);
  const _MED  = new Set([22,25,80,110,143,443,8080,8443,8888,3000,5000,8000]);

  function _normVlan(v) {
    if (!v) return 'Unknown';
    v = v.trim().replace(/^vlan\s+vlan/i, 'VLAN');
    if (/^\d+$/.test(v)) v = 'VLAN' + v;
    return v;
  }

  function _score(ports) {
    let s = 0;
    (ports || []).filter(p => p.state === 'open').forEach(p => {
      s += _HIGH.has(p.port) ? 20 : _MED.has(p.port) ? 5 : 2;
    });
    return Math.min(100, s);
  }

  function _riskLabel(score, vuln) {
    if (vuln || score >= 80) return { label: 'Critique', cls: 'risk-critical' };
    if (score >= 50)         return { label: 'Élevé',   cls: 'risk-high' };
    if (score >= 20)         return { label: 'Moyen',   cls: 'risk-medium' };
    return                          { label: 'Faible',  cls: 'risk-low' };
  }

  function _critLabel(c) {
    const m = { critical: '🔴 Critique', high: '🟠 Élevée', normal: '🟡 Normale', low: '🟢 Faible' };
    return m[c] || '🟡 Normale';
  }

  async function load() {
    const wrap = document.getElementById('inv-table-wrap');
    if (wrap) wrap.innerHTML = '<p style="text-align:center;color:var(--txt-3);padding:32px;">Chargement…</p>';

    // 1. Hôtes monitoring (agents)
    let monHosts = [];
    try {
      const r = await fetch('/scanner-api/monitor/hosts', { credentials: 'include' });
      if (r.ok) {
        const d = await r.json();
        const agentIPs = new Set((d.agents || []).map(a => a.ip));
        const agentCrit = {};
        (d.agents || []).forEach(a => { agentCrit[a.ip] = a.criticality; });
        monHosts = (d.hosts || []).map(h => ({
          ip:          h.ip,
          hostname:    h.hostname || '',
          os:          h.os || '',
          vlan:        _normVlan(h.vlan),
          ports:       h.ports || [],
          vulnerable:  h.vulnerable,
          criticality: h.criticality || agentCrit[h.ip] || 'normal',
          source:      agentIPs.has(h.ip) ? 'agent' : (h.agent_id ? 'arp' : 'arp'),
          last_seen:   h.last_seen,
          score:       _score(h.ports),
          _canEdit:    true,
        }));
      }
    } catch (_) {}

    // 2. Hôtes Nmap (window.networkData)
    const nmapHosts = [];
    if (window.networkData && Array.isArray(networkData.hosts)) {
      const monIPs = new Set(monHosts.map(h => h.ip));
      networkData.hosts.forEach(h => {
        if (monIPs.has(h.ip)) return; // déjà présent via monitoring
        const ports = [];
        (h.vlans || [{ ports: h.ports }]).forEach(v => {
          (v.ports || []).forEach(p => ports.push(p));
        });
        nmapHosts.push({
          ip:          h.ip,
          hostname:    h.hostname || '',
          os:          h.os || h.osName || '',
          vlan:        _normVlan(h.vlan || (h.vlans && h.vlans[0]?.name) || ''),
          ports,
          vulnerable:  h.vulnerabilityScore >= 70,
          criticality: 'normal',
          source:      'nmap',
          last_seen:   null,
          score:       _score(ports),
          _canEdit:    false,
        });
      });
    }

    _all = [...monHosts, ...nmapHosts];
    _populateVlanFilter();
    _render();
  }

  function _populateVlanFilter() {
    const sel = document.getElementById('inv-filter-vlan');
    if (!sel) return;
    const vlans = [...new Set(_all.map(h => h.vlan))].sort();
    sel.innerHTML = '<option value="">Tous les VLANs</option>' +
      vlans.map(v => `<option value="${v}">${v}</option>`).join('');
  }

  function _getFilters() {
    return {
      q:      (document.getElementById('inv-search')?.value || '').toLowerCase(),
      vlan:   document.getElementById('inv-filter-vlan')?.value   || '',
      source: document.getElementById('inv-filter-source')?.value  || '',
      crit:   document.getElementById('inv-filter-crit')?.value    || '',
    };
  }

  function _render() {
    const f   = _getFilters();
    const wrap = document.getElementById('inv-table-wrap');
    if (!wrap) return;

    const filtered = _all.filter(h => {
      if (f.q && !`${h.ip} ${h.hostname} ${h.os} ${h.vlan}`.toLowerCase().includes(f.q)) return false;
      if (f.vlan   && h.vlan   !== f.vlan)   return false;
      if (f.source && h.source !== f.source)  return false;
      if (f.crit   && h.criticality !== f.crit) return false;
      return true;
    });

    const cnt = document.getElementById('inv-count');
    if (cnt) cnt.textContent = `${filtered.length} hôte${filtered.length !== 1 ? 's' : ''} sur ${_all.length}`;

    if (filtered.length === 0) {
      wrap.innerHTML = '<p style="text-align:center;color:var(--txt-3);padding:48px;">Aucun résultat</p>';
      return;
    }

    const rows = filtered.map(h => {
      const risk   = _riskLabel(h.score, h.vulnerable);
      const open   = (h.ports || []).filter(p => p.state === 'open').length;
      const srcBadge = {
        agent: '<span class="inv-badge inv-badge-agent">Agent</span>',
        nmap:  '<span class="inv-badge inv-badge-nmap">Nmap</span>',
        arp:   '<span class="inv-badge inv-badge-arp">ARP</span>',
      }[h.source] || '';

      const lastSeen = h.last_seen
        ? new Date(h.last_seen * 1000).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })
        : '—';

      const critCell = h._canEdit
        ? `<select class="inv-crit-sel" data-ip="${h.ip}" onchange="Inventory.setCriticality(this)">
            <option value="critical" ${h.criticality==='critical'?'selected':''}>🔴 Critique</option>
            <option value="high"     ${h.criticality==='high'    ?'selected':''}>🟠 Élevée</option>
            <option value="normal"   ${h.criticality==='normal'  ?'selected':''}>🟡 Normale</option>
            <option value="low"      ${h.criticality==='low'     ?'selected':''}>🟢 Faible</option>
           </select>`
        : `<span style="color:var(--txt-3)">${_critLabel(h.criticality)}</span>`;

      return `<tr>
        <td class="inv-td-host">
          <div class="inv-hostname" title="${h.hostname}">${h.hostname || '<span style="color:var(--txt-3);font-style:italic;">INCONNU</span>'}</div>
          <div class="inv-ip">${h.ip}</div>
        </td>
        <td>${h.os ? `<span title="${h.os}">${h.os.length>20?h.os.slice(0,19)+'…':h.os}</span>` : '<span style="color:var(--txt-3)">—</span>'}</td>
        <td><span class="inv-vlan">${h.vlan}</span></td>
        <td>${srcBadge}</td>
        <td>${critCell}</td>
        <td>
          <div class="inv-score-bar">
            <div class="inv-score-fill ${risk.cls}" style="width:${h.score}%"></div>
          </div>
          <span class="inv-score-val ${risk.cls}">${h.score}</span>
        </td>
        <td><span class="risk-badge ${risk.cls}">${risk.label}</span></td>
        <td class="inv-td-ports">${open} port${open!==1?'s':''}</td>
        <td style="color:var(--txt-3);font-size:11px;">${lastSeen}</td>
      </tr>`;
    }).join('');

    wrap.innerHTML = `
      <div class="inv-table-scroll">
        <table class="inv-table">
          <thead><tr>
            <th>Hôte / IP</th><th>OS</th><th>VLAN</th><th>Source</th>
            <th>Criticité</th><th>Score</th><th>Risque</th><th>Ports</th><th>Vu à</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  }

  async function setCriticality(sel) {
    const ip   = sel.dataset.ip;
    const crit = sel.value;
    try {
      const r = await fetch(`/scanner-api/monitor/hosts/${encodeURIComponent(ip)}/criticality`, {
        method:  'PATCH',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ criticality: crit }),
      });
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        alert(`Erreur : ${d.detail || r.status}`);
        return;
      }
      // mise à jour locale
      const h = _all.find(x => x.ip === ip);
      if (h) h.criticality = crit;
    } catch (e) {
      alert(`Erreur réseau : ${e.message}`);
    }
  }

  // Écoute les filtres en live
  document.addEventListener('DOMContentLoaded', () => {
    const textIds   = ['inv-search'];
    const selectIds = ['inv-filter-vlan','inv-filter-source','inv-filter-crit'];
    textIds.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.addEventListener('input', () => _render());
    });
    selectIds.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.addEventListener('change', () => _render());
    });
  });

  return { load, setCriticality };
})();

// Bascule entre les onglets Carte / Inventaire
function switchMapTab(tab) {
  document.getElementById('map-carte-panel').style.display   = tab === 'carte'   ? '' : 'none';
  document.getElementById('map-tableau-panel').style.display = tab === 'tableau' ? '' : 'none';
  document.getElementById('map-tab-carte').classList.toggle('active',   tab === 'carte');
  document.getElementById('map-tab-tableau').classList.toggle('active', tab === 'tableau');
  if (tab === 'tableau') Inventory.load();
}
