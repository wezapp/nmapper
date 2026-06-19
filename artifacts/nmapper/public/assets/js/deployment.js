/* deployment.js — NMAPPER Déploiement SSH v1.0 */
const Deployment = (() => {
  let _jobId       = null;
  let _pollTimer   = null;
  let _lastLogCnt  = 0;
  let _authMode    = 'password';
  let _roleMode    = 'agent';
  let _initialized = false;

  // ── Init ──────────────────────────────────────────────────────────────────

  function onEnter() {
    if (!_initialized) {
      _initAuthTabs();
      _initRoleTabs();
      _el('dep-deploy-btn')?.addEventListener('click', deploy);
      _el('dep-probe-btn')?.addEventListener('click', probe);
      // Reset probe result si l'hôte/port change
      ['dep-host', 'dep-ssh-port'].forEach(id => {
        _el(id)?.addEventListener('input', () => {
          const r = _el('dep-probe-result');
          if (r) { r.textContent = ''; r.className = 'dep-probe-result'; }
        });
      });
      _initManualSection();
      _initialized = true;
    }
    loadJobs();
    loadApiKey();
  }

  function _initAuthTabs() {
    document.querySelectorAll('.deploy-tab').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.deploy-tab').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        _authMode = btn.dataset.auth;
        _el('dep-auth-password').style.display = _authMode === 'password' ? '' : 'none';
        _el('dep-auth-key').style.display       = _authMode === 'key'      ? '' : 'none';
      });
    });
  }

  function _initRoleTabs() {
    document.querySelectorAll('.deploy-role-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.deploy-role-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        _roleMode = btn.dataset.role;
        _el('dep-config-agent').style.display  = _roleMode === 'agent'  ? '' : 'none';
        _el('dep-config-server').style.display = _roleMode === 'server' ? '' : 'none';
      });
    });
  }

  // ── Probe TCP ─────────────────────────────────────────────────────────────

  async function probe() {
    const host = _val('dep-host');
    const port = parseInt(_val('dep-ssh-port') || '22');
    if (!host) {
      _setProbe('fail', '⚠ Entrez une adresse IP ou hostname');
      return;
    }
    const btn = _el('dep-probe-btn');
    if (btn) { btn.disabled = true; btn.textContent = '⟳ Test…'; }
    _setProbe('pending', 'Test TCP en cours…');

    try {
      const resp = await fetch('/scanner-api/deploy/probe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host, port }),
        credentials: 'include',
      });
      const data = await resp.json();
      if (data.reachable) {
        _setProbe('ok', `✅ Joignable — ${data.latency_ms} ms`);
      } else {
        _setProbe('fail', `❌ ${data.error || 'Inaccessible'}`);
      }
    } catch (err) {
      _setProbe('fail', `❌ ${err.message}`);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = '📡 Tester la connexion'; }
    }
  }

  function _setProbe(state, msg) {
    const el = _el('dep-probe-result');
    if (!el) return;
    el.className = `dep-probe-result dep-probe-${state}`;
    el.textContent = msg;
  }

  // ── Deploy ────────────────────────────────────────────────────────────────

  async function deploy() {
    const host    = _val('dep-host');
    const sshPort = parseInt(_val('dep-ssh-port') || '22');
    const user    = _val('dep-user');
    const authVal = _authMode === 'password' ? _val('dep-password') : _val('dep-ssh-key');

    if (!host || !user || !authVal) {
      _logLocal('error', '⚠ Champs obligatoires : hôte, utilisateur, authentification.');
      return;
    }

    const cfg = {
      host, ssh_port: sshPort, user,
      auth_type: _authMode, auth_value: authVal,
      role:      _roleMode,
      systemd:   _el('dep-systemd')?.checked ?? true,
    };

    if (_roleMode === 'agent') {
      cfg.server_ip   = _val('dep-server-ip');
      cfg.api_key     = _val('dep-api-key');
      cfg.server_port = parseInt(_val('dep-server-port') || '25774');
      cfg.interval    = parseInt(_val('dep-interval') || '30');
      if (!cfg.server_ip || !cfg.api_key) {
        _logLocal('error', '⚠ IP serveur et clé API obligatoires pour un agent.');
        return;
      }
    } else {
      cfg.server_port = parseInt(_val('dep-nmapper-port') || '25774');
    }

    // Clear log
    const logBox = _el('dep-log-output');
    if (logBox) logBox.innerHTML = '';
    _lastLogCnt = 0;
    _setBadge('running', '⟳ En cours…');
    _setBtn(true, '⟳ Déploiement…');

    try {
      const resp = await fetch('/scanner-api/deploy/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cfg),
        credentials: 'include',
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        // 422 = erreur de validation (hostname, clé SSH, rôle…) — message explicite
        const msg = err.detail || resp.statusText;
        throw new Error(resp.status === 422 ? `⚠ Validation : ${msg}` : msg);
      }
      const { job_id } = await resp.json();
      _jobId = job_id;
      _startPolling(job_id);
    } catch (err) {
      _logLocal('error', `❌ ${err.message}`);
      _setBadge('error', '❌ Erreur');
      _setBtn(false, '🚀 Déployer');
    }
  }

  // ── Polling ───────────────────────────────────────────────────────────────

  function _startPolling(jobId) {
    if (_pollTimer) clearInterval(_pollTimer);
    _pollTimer = setInterval(() => _pollStatus(jobId), 1000);
  }

  async function _pollStatus(jobId) {
    try {
      const resp = await fetch(`/scanner-api/deploy/status/${jobId}`, { credentials: 'include' });
      if (!resp.ok) return;
      const job = await resp.json();

      job.logs.slice(_lastLogCnt).forEach(l => _appendLog(l));
      _lastLogCnt = job.logs.length;

      if (job.status !== 'running') {
        clearInterval(_pollTimer); _pollTimer = null;
        _setBadge(job.status, job.status === 'success' ? '✅ Succès' : '❌ Erreur');
        _setBtn(false, '🚀 Déployer');
        loadJobs();
      }
    } catch (_) {}
  }

  // ── Log helpers ───────────────────────────────────────────────────────────

  function _logLocal(level, msg) {
    _appendLog({ time: new Date().toTimeString().slice(0,8), level, msg });
  }

  function _appendLog(entry) {
    const box = _el('dep-log-output');
    if (!box) return;
    // Clear placeholder on first real line
    const ph = box.querySelector('.dep-log-placeholder');
    if (ph) ph.remove();

    const line = document.createElement('div');
    line.className = `dep-log-line ${entry.level || 'info'}`;
    line.innerHTML =
      `<span class="dep-log-time">${_esc(entry.time)}</span>` +
      `<span class="dep-log-msg">${_esc(entry.msg)}</span>`;
    box.appendChild(line);
    box.scrollTop = box.scrollHeight;
  }

  function _esc(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  // ── Badge & button ────────────────────────────────────────────────────────

  function _setBadge(status, label) {
    const b = _el('dep-status-badge');
    if (!b) return;
    b.className = `dep-badge dep-${status}`;
    b.textContent = label;
  }

  function _setBtn(disabled, label) {
    const btn = _el('dep-deploy-btn');
    if (!btn) return;
    btn.disabled = disabled;
    btn.textContent = label;
  }

  // ── Jobs list ──────────────────────────────────────────────────────────────

  async function loadJobs() {
    try {
      const resp = await fetch('/scanner-api/deploy/jobs', { credentials: 'include' });
      if (!resp.ok) return;
      const jobs = await resp.json();
      const el = _el('dep-jobs-list');
      if (!el) return;

      if (!jobs.length) {
        el.innerHTML = '<p style="color:var(--txt-3);font-size:13px;">Aucun déploiement dans cette session.</p>';
        return;
      }

      el.innerHTML = jobs.map(j => {
        const icon   = j.role === 'agent' ? '🤖' : '🖧';
        const age    = Math.round((Date.now() / 1000 - j.started_at) / 60);
        const ageStr = age < 1 ? "à l'instant" : `il y a ${age} min`;
        const stIcon = j.status === 'success' ? '✅' : j.status === 'error' ? '❌' : '⟳';
        const canDel = j.status !== 'running';
        return `<div class="dep-job-item" data-jobid="${_esc(j.job_id)}">
          <span class="dep-job-icon">${icon}</span>
          <div class="dep-job-info">
            <div class="dep-job-host">${_esc(j.host)}</div>
            <div class="dep-job-meta">${_esc(j.role)} · ${ageStr}</div>
          </div>
          <span class="dep-job-status ${j.status}">${stIcon}</span>
          ${canDel ? `<button class="dep-job-delete" data-jobid="${_esc(j.job_id)}" title="Supprimer">×</button>` : ''}
        </div>`;
      }).join('');

      el.querySelectorAll('.dep-job-delete').forEach(btn => {
        btn.addEventListener('click', async (e) => {
          e.stopPropagation();
          const jid = btn.dataset.jobid;
          await fetch(`/scanner-api/deploy/jobs/${jid}`, {
            method: 'DELETE',
            credentials: 'include',
          });
          loadJobs();
        });
      });

      el.querySelectorAll('.dep-job-item').forEach(item => {
        item.addEventListener('click', async () => {
          const jid   = item.dataset.jobid;
          const resp2 = await fetch(`/scanner-api/deploy/status/${jid}`, { credentials: 'include' });
          if (!resp2.ok) return;
          const job2 = await resp2.json();
          const lb = _el('dep-log-output');
          if (lb) lb.innerHTML = '';
          _lastLogCnt = 0;
          job2.logs.forEach(l => _appendLog(l));
          _lastLogCnt = job2.logs.length;
          _setBadge(job2.status,
            job2.status === 'success' ? '✅ Succès' :
            job2.status === 'error'   ? '❌ Erreur' : '⟳ En cours');
        });
      });
    } catch (_) {}
  }

  // ── API Key & instructions manuelles ──────────────────────────────────────

  let _apiKey = '';

  async function loadApiKey() {
    try {
      const resp = await fetch('/scanner-api/deploy/apikey', { credentials: 'include' });
      if (!resp.ok) return;
      const { api_key } = await resp.json();
      _apiKey = api_key || '';
      const disp = _el('dep-apikey-display');
      if (disp) disp.textContent = _apiKey || '—';
      // Auto-remplir le champ clé API si vide (évite la saisie manuelle)
      const apiKeyInput = _el('dep-api-key');
      if (apiKeyInput && !apiKeyInput.value && _apiKey) {
        apiKeyInput.value = _apiKey;
      }
      _updateManualCommands();
    } catch (_) {}
  }

  function _updateManualCommands() {
    // Remplace les placeholders dans les blocs de commande
    const nmapperIp = _val('dep-server-ip') || 'NMAPPER_IP';
    const key       = _apiKey || 'VOTRE_CLE_API';

    const replacements = {
      'dep-cmd-run':      `python3 /opt/nmapper-agent/agent.py \\\n  --server-ip ${nmapperIp} \\\n  --port 25774 \\\n  --key ${key} \\\n  --interval 30`,
      'dep-cmd-systemd':  `cat > /etc/systemd/system/nmapper-agent.service << 'EOF'\n[Unit]\nDescription=NMAPPER Agent de collecte\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nExecStart=python3 /opt/nmapper-agent/agent.py --server-ip ${nmapperIp} --port 25774 --key ${key} --interval 30\nRestart=always\nRestartSec=15\n\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl enable --now nmapper-agent`,
    };
    Object.entries(replacements).forEach(([id, cmd]) => {
      const el = _el(id);
      if (el) el.textContent = cmd;
    });
  }

  function _initManualSection() {
    // Tabs manuels
    document.querySelectorAll('.dep-manual-tab').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.dep-manual-tab').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const mode = btn.dataset.manual;
        _el('dep-manual-agent').style.display  = mode === 'agent'  ? '' : 'none';
        _el('dep-manual-server').style.display = mode === 'server' ? '' : 'none';
      });
    });

    // Copier la clé API
    _el('dep-copy-key')?.addEventListener('click', () => {
      if (_apiKey) _copyText(_apiKey, _el('dep-copy-key'));
    });

    // Boutons copier les blocs de code
    document.querySelectorAll('.dep-copy-btn[data-copy]').forEach(btn => {
      btn.addEventListener('click', () => {
        const src = _el(btn.dataset.copy);
        if (src) _copyText(src.textContent, btn);
      });
    });

    // Met à jour les commandes quand l'IP serveur change dans le formulaire
    _el('dep-server-ip')?.addEventListener('input', _updateManualCommands);
  }

  function _copyText(text, btn) {
    navigator.clipboard.writeText(text).then(() => {
      const orig = btn.textContent;
      btn.textContent = '✅ Copié !';
      setTimeout(() => { btn.textContent = orig; }, 1800);
    }).catch(() => {});
  }

  // ── Utils ─────────────────────────────────────────────────────────────────
  const _el  = id => document.getElementById(id);
  const _val = id => _el(id)?.value?.trim() ?? '';

  return { onEnter, loadJobs };
})();
