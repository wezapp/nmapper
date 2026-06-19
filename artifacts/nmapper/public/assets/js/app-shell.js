// app-shell.js — Navigation par vues pour NMAPPER v2

const NMapperShell = {
  defaultView: 'dashboard',

  views: {
    dashboard:  { title: 'Dashboard — Analyse',     sub: 'Analytique des scans Nmap' },
    map:        { title: 'Cartographie réseau',     sub: 'Topologie interactive & filtres' },
    scoring:    { title: 'Scoring & risques',       sub: 'Méthodologie de calcul du risque' },
    reports:    { title: 'Rapports',               sub: 'Export PDF / CSV' },
    builder:    { title: 'Générateur Nmap',        sub: 'Commandes & multi-étapes' },
    scanner:    { title: 'Scanner actif',          sub: 'Lancement de scans & résultats en temps réel' },
    agentdash:  { title: 'Dashboard — Agents',      sub: 'Supervision temps réel du parc' },
    agentmap:   { title: 'Cartographie agents',     sub: 'Carte, inventaire & filtres des agents' },
    sources:    { title: 'Sources de données',      sub: 'Importez vos résultats Nmap' },
    deploy:     { title: 'Déploiement SSH',        sub: 'Déployez agents et serveur via SSH' },
    activity:   { title: 'Journal d\'activité',   sub: 'Historique des actions & événements' },
    admin:      { title: 'Administration',         sub: 'Gestion des utilisateurs & permissions' },
  },

  init() {
    document.querySelectorAll('[data-view]').forEach(item => {
      item.addEventListener('click', () => this.showView(item.dataset.view, {
        mode: item.dataset.mode,
        navEl: item.classList.contains('nav-item') ? item : null,
      }));
    });

    // Hooks additifs : basculer vers la carte après un import
    const fileInput = document.getElementById('fileInput');
    if (fileInput) {
      fileInput.addEventListener('change', () => {
        if (fileInput.files && fileInput.files.length) {
          setTimeout(() => this.showView('map'), 500);
        }
      });
    }
    const importInput = document.getElementById('importSessionInput');
    if (importInput) {
      importInput.addEventListener('change', () => setTimeout(() => this.showView('map'), 500));
    }
    document.querySelectorAll('[data-action="scanDirectory"]').forEach(btn => {
      btn.addEventListener('click', () => setTimeout(() => this.showView('map'), 800));
    });

    // sections pliables dans leurs vues
    const fc = document.getElementById('filterContent');
    if (fc) fc.classList.add('active');
    const pc = document.getElementById('pdfContent');
    if (pc) pc.classList.add('active');
    const nbc = document.getElementById('nmapBuilderContent');
    if (nbc) nbc.classList.add('active');

    ['portFilters', 'pdfReports'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = 'block';
    });

    this.showView(this.defaultView);
    this.updateVulnBadge();
    this.updateEmptyState();

    const hostEl = document.getElementById('hostCount');
    const vulnEl = document.getElementById('vulnerableCount');
    const obs = new MutationObserver(() => { this.updateVulnBadge(); this.updateEmptyState(); });
    if (hostEl) obs.observe(hostEl, { childList: true, characterData: true, subtree: true });
    if (vulnEl) obs.observe(vulnEl, { childList: true, characterData: true, subtree: true });
  },

  updateEmptyState() {
    const count = parseInt(document.getElementById('hostCount')?.textContent || '0', 10);
    const empty = document.getElementById('mapEmptyState');
    const table = document.getElementById('hosts-table');
    const viz   = document.getElementById('network-viz');
    if (empty) empty.style.display = count > 0 ? 'none' : 'block';
    if (table) table.style.display = count > 0 ? 'block' : 'none';
    if (viz)   viz.style.display   = count > 0 ? 'block' : 'none';
  },

  showView(name, opts) {
    if (!this.views[name]) name = this.defaultView;
    opts = opts || {};

    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    const view = document.getElementById('view-' + name);
    if (view) view.classList.add('active');

    // Surbrillance : l'élément cliqué en priorité (gère les vues à entrées multiples
    // comme Monitoring campagne/live), sinon repli sur le data-view.
    if (opts.navEl) {
      document.querySelectorAll('.nav-item[data-view]').forEach(i => i.classList.remove('active'));
      opts.navEl.classList.add('active');
    } else {
      document.querySelectorAll('.nav-item[data-view]').forEach(i => {
        i.classList.toggle('active', i.dataset.view === name);
      });
    }

    const meta = this.views[name];
    const t = document.getElementById('pageTitle');
    const s = document.getElementById('pageSub');
    if (t) t.textContent = meta.title;
    if (s) s.textContent = meta.sub;

    window.scrollTo({ top: 0, behavior: 'smooth' });

    if (name === 'dashboard'  && typeof renderDashboard   === 'function') renderDashboard();
    if (name === 'map') {
      // Réinitialiser le SVG si créé avec width=0 (vue était cachée au boot)
      const nvNode = document.getElementById('network-viz');
      if (nvNode && nvNode.clientWidth > 0 && typeof width !== 'undefined' && nvNode.clientWidth !== width) {
        if (typeof initializeVisualization === 'function') initializeVisualization();
        if (typeof updateVisualization === 'function') updateVisualization();
      }
    }
    // KPIs live : sur le dashboard agents uniquement
    if (name === 'agentdash'  && typeof DashboardLive     !== 'undefined') DashboardLive.startAutoRefresh();
    else if (name !== 'agentdash' && typeof DashboardLive !== 'undefined') DashboardLive.stopAutoRefresh();
    if (name === 'agentmap'   && typeof AgentMap          !== 'undefined') AgentMap.onEnter();
    else if (name !== 'agentmap' && typeof AgentMap       !== 'undefined') AgentMap.onLeave();
    if (name === 'reports'    && typeof PDFReports         !== 'undefined') PDFReports.updateHostSelector();
    if (name === 'scanner'    && typeof ScannerUI          !== 'undefined') ScannerUI.loadHistory();
    if (name === 'deploy'     && typeof Deployment         !== 'undefined') Deployment.onEnter();
    if (name === 'activity'   && typeof ActivityLog        !== 'undefined') ActivityLog.onEnter();
    else if (name !== 'activity' && typeof ActivityLog     !== 'undefined') ActivityLog.onLeave();
    if (name === 'admin'      && typeof AdminPanel         !== 'undefined') AdminPanel.onEnter();
  },

  updateVulnBadge() {
    const count = parseInt(document.getElementById('vulnerableCount')?.textContent || '0', 10);
    const badge = document.getElementById('navVulnBadge');
    if (!badge) return;
    badge.textContent = count;
    badge.style.display = count > 0 ? '' : 'none';
  }
};

document.addEventListener('DOMContentLoaded', () => NMapperShell.init());
