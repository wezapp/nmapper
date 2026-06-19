// scanner-ui.js — Interface de scan actif NMAPPER v2
// Dépendances (chargées avant dans index.html) :
//   utils.js        → Utils.escapeHtml()
//   file-processor.js → FileProcessor.handleFiles()
//   main.js         → showMessage(), currentVLAN (globals)

const ScannerUI = (() => {

    // ── État ────────────────────────────────────────────────────
    // _hasSession : true si un cookie de session HttpOnly est actif côté serveur
    // _apiKey : conservé en mémoire uniquement pour l'affichage masqué (jamais renvoyé
    //           après la création de session — le cookie gère l'auth)
    let _hasSession = false;
    let _apiKey = '';      // ne plus utiliser sessionStorage — trop exposé
    let _scans  = {};      // { [scanId]: ScanResponse }
    let _timer  = null;
    let _preset = 'top100';
    let _mode   = 'cidr';

    // ── Presets de ports ─────────────────────────────────────────
    const PRESETS = {
        top100:     { label: 'Top 100',       ports: null },
        top1000:    { label: 'Top 1000',       ports: null,                                    profile: 'standard' },
        web:        { label: '🌐 Web',          ports: '80,443,8080,8443,3000,8000,8888,9000'  },
        ssh_rdp:    { label: '🔑 SSH/RDP',      ports: '22,23,3389,5900,5985,5986'             },
        database:   { label: '🗄️ Bases',        ports: '1433,1521,3306,5432,27017,6379,5984,9200,5986' },
        industrial: { label: '⚙️ OT/SCADA',     ports: '102,502,4840,20000,44818,2404,47808,4000' },
        full:       { label: '🔓 1-65535',       ports: '1-65535',                               profile: 'full'    },
        custom:     { label: '✏️ Custom',         ports: null                                    },
    };

    // ── Appel API ────────────────────────────────────────────────
    async function _api(method, path, body) {
        if (!_hasSession) throw new Error('Session non active — enregistrez votre clé API ci-dessus');
        const opts = {
            method,
            credentials: 'same-origin',   // envoie automatiquement le cookie HttpOnly
            headers: { 'Content-Type': 'application/json' },
        };
        if (body !== undefined) opts.body = JSON.stringify(body);
        const res = await fetch('/scanner-api' + path, opts);
        if (res.status === 204) return null;
        if (res.status === 401) {
            // Session expirée
            _hasSession = false;
            _updateKeyStatus(false);
            throw new Error('Session expirée — re-saisissez votre clé API');
        }
        const data = await res.json().catch(() => ({ detail: res.statusText }));
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
        return data;
    }

    // ── Lecture du formulaire ─────────────────────────────────────
    function _getTargets() {
        const raw = document.getElementById('sc-target-input')?.value || '';
        // Split on newline, comma, semicolon — deduplicate
        return [...new Set(raw.split(/[\n,;]+/).map(s => s.trim()).filter(Boolean))];
    }

    function _getPorts() {
        if (_preset === 'custom') {
            return document.getElementById('sc-custom-ports')?.value.trim() || null;
        }
        return PRESETS[_preset]?.ports ?? null;
    }

    function _getProfile() {
        return PRESETS[_preset]?.profile
            || document.getElementById('sc-profile-select')?.value
            || 'quick';
    }

    // ── Actions de scan ──────────────────────────────────────────
    async function startScan() {
        const targets = _getTargets();
        if (!targets.length) { showMessage('error', 'Saisissez au moins une cible'); return; }
        if (!_hasSession)    { showMessage('error', 'Session non active — enregistrez votre clé API'); return; }

        const vlanName = document.getElementById('sc-vlan-name')?.value.trim() || null;
        const ports    = _getPorts();
        const profile  = _getProfile();

        // Envoie toutes les cibles en une seule requête (validator.py gère la liste)
        const payload = {
            target: targets.join('\n'),
            profile,
            ...(ports    ? { ports }             : {}),
            ...(vlanName ? { vlan_name: vlanName } : {}),
        };

        try {
            const scan = await _api('POST', '/scan', payload);
            _scans[scan.id] = scan;
            showMessage('success', `Scan lancé : ${targets.length} cible(s)`);
            _renderList();
            _startPolling();
        } catch (e) {
            showMessage('error', `Lancement impossible : ${e.message}`);
        }
    }

    async function cancelScan(scanId) {
        try {
            await _api('DELETE', `/scan/${scanId}`);
            if (_scans[scanId]) _scans[scanId].status = 'cancelled';
            _renderList();
        } catch (e) {
            showMessage('error', `Annulation : ${e.message}`);
        }
    }

    async function importResult(scanId) {
        try {
            showMessage('info', 'Chargement du résultat…');
            const scan = _scans[scanId] || {};
            const res  = await fetch(`/scanner-api/scan/${scanId}/result`, {
                credentials: 'same-origin',
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const xml  = await res.text();
            const name = scan.vlan_name || `scan-${scanId.slice(0, 8)}`;
            clearNetworkData();
            FileProcessor.parseNmapXML(xml, name);
            networkData.stats.files = 1;
            updateVisualization();
            updateStats();
            // Révèle les sections dépendantes des données (cf. finalizeProcessing)
            ['portFilters', 'pdfReports', 'globalSearch'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.style.display = 'block';
            });
            if (typeof PDFReports !== 'undefined') PDFReports.updateHostSelector();
            showMessage('success', `✅ ${name} chargé`);
            setTimeout(() => {
                if (typeof NMapperShell !== 'undefined') NMapperShell.showView('map');
            }, 300);
        } catch (e) {
            showMessage('error', `Import : ${e.message}`);
        }
    }

    async function loadHistory() {
        if (!_hasSession) return;
        try {
            const { scans } = await _api('GET', '/scans?limit=50');
            scans.forEach(s => { if (!_scans[s.id]) _scans[s.id] = s; });
            _renderList();
            if (scans.some(s => s.status === 'queued' || s.status === 'running')) {
                _startPolling();
            }
        } catch (e) {
            showMessage('error', `Historique : ${e.message}`);
        }
    }

    // ── Polling ──────────────────────────────────────────────────
    function _startPolling() {
        if (_timer) return;
        _timer = setInterval(_poll, 3000);
    }

    function _stopPolling() {
        clearInterval(_timer);
        _timer = null;
    }

    async function _poll() {
        const pending = Object.values(_scans).filter(
            s => s.status === 'queued' || s.status === 'running'
        );
        if (!pending.length) { _stopPolling(); return; }

        for (const s of pending) {
            try {
                const up = await _api('GET', `/scan/${s.id}`);
                _scans[s.id] = up;
                if (up.status === 'done')
                    showMessage('success', `✅ Terminé : ${up.target}`);
                else if (up.status === 'error')
                    showMessage('error', `❌ Échec : ${up.target}`);
            } catch { /* silently ignore réseau */ }
        }
        _renderList();
    }

    // ── Rendu de la liste ─────────────────────────────────────────
    function _renderList() {
        const container = document.getElementById('sc-scans-list');
        if (!container) return;

        const all = Object.values(_scans).sort(
            (a, b) => new Date(b.created_at) - new Date(a.created_at)
        );
        const pending = all.filter(s => s.status === 'queued' || s.status === 'running').length;

        // Badges
        ['sc-active-badge', 'scannerActiveBadge'].forEach(id => {
            const el = document.getElementById(id);
            if (!el) return;
            el.textContent  = pending;
            el.style.display = pending > 0 ? '' : 'none';
        });

        if (!all.length) {
            container.innerHTML = `<p style="color:var(--txt-3);text-align:center;padding:20px 0;">
                Aucun scan. Configurez votre clé API et lancez votre premier scan.</p>`;
            return;
        }

        const ICON  = { queued:'⏳', running:'🔄', done:'✅', error:'❌', cancelled:'⛔' };
        const COLOR = { done:'var(--ok)', error:'var(--danger)', running:'var(--warn)',
                        queued:'var(--txt-2)', cancelled:'var(--txt-3)' };

        container.innerHTML = all.map(s => {
            const actionBtn = s.status === 'done' && s.result_available
                ? `<button class="filter-btn apply-btn"
                     style="padding:3px 10px;font-size:11px;white-space:nowrap;flex-shrink:0;"
                     onclick="ScannerUI.importResult('${s.id}')">⬇ Charger</button>`
                : (s.status === 'queued' || s.status === 'running')
                ? `<button class="filter-btn clear-btn"
                     style="padding:3px 10px;font-size:11px;white-space:nowrap;flex-shrink:0;"
                     onclick="ScannerUI.cancelScan('${s.id}')">✕ Annuler</button>`
                : '';

            return `
            <div style="display:flex;align-items:center;gap:10px;padding:9px 0;
                        border-bottom:1px solid var(--stroke-soft);">
              <span style="font-size:16px;flex-shrink:0;">${ICON[s.status] || '?'}</span>
              <div style="flex:1;min-width:0;">
                <div style="font-size:12px;font-weight:600;color:var(--txt-1);
                            white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
                  ${Utils.escapeHtml(s.target)}
                </div>
                <div style="font-size:11px;color:var(--txt-3);margin-top:1px;">
                  ${s.vlan_name ? Utils.escapeHtml(s.vlan_name) + ' · ' : ''}${s.profile} · ${_age(s.created_at)}
                </div>
                ${s.error
                    ? `<div style="font-size:10px;color:var(--danger);margin-top:2px;">${Utils.escapeHtml(s.error)}</div>`
                    : ''}
              </div>
              <span style="font-size:11px;font-weight:600;color:${COLOR[s.status]};
                           white-space:nowrap;flex-shrink:0;">${s.status}</span>
              ${actionBtn}
            </div>`;
        }).join('');
    }

    function _age(iso) {
        const s = (Date.now() - new Date(iso)) / 1000;
        if (s < 60)   return `${Math.round(s)}s`;
        if (s < 3600) return `${Math.round(s / 60)}min`;
        return `${Math.round(s / 3600)}h`;
    }

    // ── Handlers UI ──────────────────────────────────────────────
    function setPortPreset(preset) {
        if (!PRESETS[preset]) return;
        _preset = preset;
        document.querySelectorAll('.sc-preset-chip').forEach(b =>
            b.classList.toggle('active', b.dataset.preset === preset)
        );
        const row = document.getElementById('sc-custom-ports-row');
        if (row) row.style.display = preset === 'custom' ? 'block' : 'none';
        // Synchronise le sélecteur de profil si le preset l'impose
        const forced = PRESETS[preset]?.profile;
        const sel = document.getElementById('sc-profile-select');
        if (sel && forced) sel.value = forced;
    }

    function setTargetMode(mode) {
        _mode = mode;
        document.querySelectorAll('.sc-mode-btn').forEach(b =>
            b.classList.toggle('active', b.dataset.mode === mode)
        );
        const input   = document.getElementById('sc-target-input');
        const fileRow = document.getElementById('sc-file-row');
        if (input) {
            input.rows = mode === 'list' ? 6 : 2;
            input.placeholder = {
                cidr: 'Ex: 192.168.1.0/24',
                list: 'Une cible par ligne :\n192.168.1.1\n10.0.0.0/24\n172.16.0.1-50\n10.0.0.100',
                file: '(contenu du fichier chargé ici)',
            }[mode] || '';
        }
        if (fileRow) fileRow.style.display = mode === 'file' ? 'flex' : 'none';
    }

    function _handleTargetFile(file) {
        if (!file) return;
        const reader = new FileReader();
        reader.onload = e => {
            const input = document.getElementById('sc-target-input');
            if (input) input.value = e.target.result.trim();
            setTargetMode('list');
        };
        reader.readAsText(file);
    }

    function _updateKeyStatus(active) {
        const indicator = document.getElementById('sc-session-status');
        if (!indicator) return;
        indicator.textContent = active ? '🟢 Session active' : '🔴 Non connecté';
        indicator.style.color = active ? 'var(--ok)' : 'var(--danger)';
    }

    async function saveApiKey() {
        const input = document.getElementById('sc-api-key-input');
        if (!input) return;
        const val = input.value.trim();
        if (!val || /^•+$/.test(val)) return;

        try {
            // POST /api/auth — crée un cookie HttpOnly côté serveur
            const res = await fetch('/scanner-api/auth', {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ api_key: val }),
            });
            const data = await res.json().catch(() => ({ detail: res.statusText }));
            if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);

            _apiKey = val;   // gardé uniquement pour masquage visuel
            _hasSession = true;
            input.value = '•'.repeat(Math.min(val.length, 40));
            _updateKeyStatus(true);
            showMessage('success', 'Session ouverte — clé API non conservée dans le navigateur');
            loadHistory();
        } catch (e) {
            showMessage('error', `Authentification échouée : ${e.message}`);
        }
    }

    function fillFromCurrentVlan() {
        const vlan = (typeof currentVLAN !== 'undefined') ? currentVLAN : null;
        if (!vlan) {
            showMessage('warning', 'Aucun VLAN sélectionné — naviguez d\'abord dans la cartographie');
            return;
        }
        const input     = document.getElementById('sc-target-input');
        const vlanInput = document.getElementById('sc-vlan-name');
        if (input)     input.value     = vlan;
        if (vlanInput) vlanInput.value = vlan;
        setTargetMode('cidr');
    }

    // ── Init ─────────────────────────────────────────────────────
    async function init() {
        const fileInput = document.getElementById('sc-target-file-input');
        if (fileInput) {
            fileInput.addEventListener('change', e => _handleTargetFile(e.target.files[0]));
        }
        setPortPreset('top100');
        setTargetMode('cidr');

        // Vérifie si une session cookie est déjà active (rechargement de page)
        try {
            const res = await fetch('/scanner-api/health', { credentials: 'same-origin' });
            // Si le health check passe et qu'on a des scans, tente de charger l'historique
            // via un probe sur /api/scans (retourne 401 si pas de session)
            const probe = await fetch('/scanner-api/scans?limit=1', { credentials: 'same-origin' });
            if (probe.ok) {
                _hasSession = true;
                _updateKeyStatus(true);
                const keyInput = document.getElementById('sc-api-key-input');
                if (keyInput) keyInput.placeholder = '(session active)';
                loadHistory();
            } else {
                _updateKeyStatus(false);
            }
        } catch { _updateKeyStatus(false); }
    }

    // ── API publique ─────────────────────────────────────────────
    return {
        init, startScan, cancelScan, importResult, loadHistory,
        setPortPreset, setTargetMode, saveApiKey, fillFromCurrentVlan,
    };

})();

// ── Délégation d'événements propre à ce module ───────────────────
// (s'ajoute en complément du dispatcher de main.js sans le modifier)
document.addEventListener('DOMContentLoaded', () => {
    ScannerUI.init();

    document.addEventListener('click', e => {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;
        const act = btn.dataset.action;
        const arg = btn.dataset.arg;
        ({
            startScan:           () => ScannerUI.startScan(),
            saveApiKey:          () => ScannerUI.saveApiKey(),
            setScanTargetMode:   () => ScannerUI.setTargetMode(arg),
            setScanPortPreset:   () => ScannerUI.setPortPreset(arg),
            fillFromCurrentVlan: () => ScannerUI.fillFromCurrentVlan(),
            loadScanHistory:     () => ScannerUI.loadHistory(),
        })[act]?.();
    });
});
