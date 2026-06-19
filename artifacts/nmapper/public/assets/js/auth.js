// auth.js — Système d'authentification NMAPPER (login + MFA + setup)
const Auth = (() => {
    const API = '/scanner-api';
    let _pendingToken  = null;
    let _setupUsername = null;

    async function _post(path, body) {
        const r = await fetch(API + path, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const data = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
        return data;
    }

    async function _del(path) {
        const r = await fetch(API + path, { method: 'DELETE', credentials: 'same-origin' });
        return r.json().catch(() => ({}));
    }

    function _overlay(html) {
        let el = document.getElementById('auth-overlay');
        if (!el) {
            el = document.createElement('div');
            el.id = 'auth-overlay';
            document.body.appendChild(el);
        }
        el.innerHTML = html;
        el.style.display = 'flex';
    }

    function _setErr(id, msg) {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = msg;
        el.classList.add('show');
    }

    function _clearErr(id) {
        const el = document.getElementById(id);
        if (el) { el.textContent = ''; el.classList.remove('show'); }
    }

    function _brand() {
        return `<div class="auth-brand">
          <div class="auth-brand-logo">N</div>
          <div class="auth-brand-name"><b>NM</b>APPER</div>
        </div>`;
    }

    function _dots(active) {
        return `<div class="auth-step-dots">
          ${[0,1,2].map(i => `<div class="auth-step-dot ${i===active?'active':''}"></div>`).join('')}
        </div>`;
    }

    // ── Unlock ───────────────────────────────────────────────────
    function _unlock() {
        const el = document.getElementById('auth-overlay');
        if (el) el.style.display = 'none';
        const foot = document.querySelector('.sidebar-foot');
        if (foot && !document.getElementById('auth-logout-btn')) {
            const btn = document.createElement('button');
            btn.id        = 'auth-logout-btn';
            btn.className = 'theme-toggle';
            btn.title     = 'Se déconnecter';
            btn.textContent = '🔓';
            btn.style.marginLeft = '4px';
            btn.addEventListener('click', logout);
            foot.appendChild(btn);
        }
    }

    // ── SETUP STEP 1 — créer le compte ───────────────────────────
    function _showSetup1() {
        _overlay(`<div class="auth-card">
          ${_brand()}
          ${_dots(0)}
          <div class="auth-title">Création du compte administrateur</div>
          <div class="auth-error" id="s1-err"></div>
          <div class="auth-field">
            <label>Nom d'utilisateur</label>
            <input type="text" id="s1-user" placeholder="admin" autocomplete="username">
          </div>
          <div class="auth-field">
            <label>Mot de passe (min 8 caractères)</label>
            <input type="password" id="s1-pwd" placeholder="••••••••" autocomplete="new-password">
          </div>
          <div class="auth-field">
            <label>Confirmer le mot de passe</label>
            <input type="password" id="s1-pwd2" placeholder="••••••••" autocomplete="new-password">
          </div>
          <button class="auth-btn" id="s1-btn">Créer le compte →</button>
        </div>`);
        setTimeout(() => document.getElementById('s1-user').focus(), 50);
        document.getElementById('s1-btn').addEventListener('click', _doSetup1);
        document.getElementById('s1-pwd2').addEventListener('keydown', e => { if (e.key==='Enter') _doSetup1(); });
    }

    async function _doSetup1() {
        _clearErr('s1-err');
        const u  = document.getElementById('s1-user').value.trim();
        const p  = document.getElementById('s1-pwd').value;
        const p2 = document.getElementById('s1-pwd2').value;
        if (!u || !p) return _setErr('s1-err', 'Tous les champs sont requis.');
        if (p !== p2)  return _setErr('s1-err', 'Les mots de passe ne correspondent pas.');
        const btn = document.getElementById('s1-btn');
        btn.disabled = true;
        try {
            const data = await _post('/auth/setup', { username: u, password: p });
            _setupUsername = data.username;
            _showSetup2(data.qr_url, data.totp_secret);
        } catch(e) {
            _setErr('s1-err', e.message);
        } finally { btn.disabled = false; }
    }

    // ── SETUP STEP 2 — scanner le QR ────────────────────────────
    function _showSetup2(qrUrl, secret) {
        _overlay(`<div class="auth-card">
          ${_brand()}
          ${_dots(1)}
          <div class="auth-title">Configurer l'authentification MFA</div>
          <div class="auth-qr">
            <img src="${qrUrl}" alt="QR Code MFA">
            <div class="auth-qr-secret" id="s2-secret" title="Cliquez pour copier">${secret}</div>
          </div>
          <p class="auth-hint">Scannez ce QR avec <strong>Google Authenticator</strong>,<br>
             <strong>Authy</strong> ou toute app TOTP compatible.<br>
             Cliquez sur la clé pour la copier.</p>
          <button class="auth-btn" id="s2-btn" style="margin-top:20px;">J'ai configuré l'app →</button>
        </div>`);
        document.getElementById('s2-secret').addEventListener('click', () => {
            navigator.clipboard.writeText(secret).then(() => {
                const el = document.getElementById('s2-secret');
                if (!el) return;
                el.style.borderColor = 'var(--accent,#2dd4bf)';
                setTimeout(() => { el.style.borderColor = ''; }, 1500);
            });
        });
        document.getElementById('s2-btn').addEventListener('click', _showSetup3);
    }

    // ── SETUP STEP 3 — vérifier le code ─────────────────────────
    function _showSetup3() {
        _overlay(`<div class="auth-card">
          ${_brand()}
          ${_dots(2)}
          <div class="auth-title">Vérification du code MFA</div>
          <div class="auth-error" id="s3-err"></div>
          <p class="auth-hint" style="margin-bottom:18px;">Saisissez le code à 6 chiffres<br>affiché dans votre application.</p>
          <input type="text" inputmode="numeric" pattern="[0-9]*" maxlength="6"
                 class="auth-mfa-input" id="s3-code" placeholder="000000" autocomplete="one-time-code">
          <button class="auth-btn" id="s3-btn" style="margin-top:16px;">Vérifier et terminer →</button>
        </div>`);
        const inp = document.getElementById('s3-code');
        inp.focus();
        document.getElementById('s3-btn').addEventListener('click', _doSetup3);
        inp.addEventListener('keydown', e => { if (e.key==='Enter') _doSetup3(); });
        inp.addEventListener('input', e => {
            e.target.value = e.target.value.replace(/\D/g, '');
            if (e.target.value.length === 6) _doSetup3();
        });
    }

    async function _doSetup3() {
        _clearErr('s3-err');
        const code = document.getElementById('s3-code').value.trim();
        if (code.length !== 6) return _setErr('s3-err', 'Code à 6 chiffres requis.');
        const btn = document.getElementById('s3-btn');
        btn.disabled = true;
        try {
            await _post('/auth/verify-setup-mfa', { username: _setupUsername, code });
            _showLogin();
        } catch(e) {
            _setErr('s3-err', e.message);
            const inp = document.getElementById('s3-code');
            if (inp) { inp.value = ''; inp.focus(); }
        } finally { btn.disabled = false; }
    }

    // ── LOGIN STEP 1 — identifiants ──────────────────────────────
    function _showLogin() {
        _overlay(`<div class="auth-card">
          ${_brand()}
          <div class="auth-title">Connexion</div>
          <div class="auth-error" id="lg-err"></div>
          <div class="auth-field">
            <label>Nom d'utilisateur</label>
            <input type="text" id="lg-user" placeholder="admin" autocomplete="username">
          </div>
          <div class="auth-field">
            <label>Mot de passe</label>
            <input type="password" id="lg-pwd" placeholder="••••••••" autocomplete="current-password">
          </div>
          <button class="auth-btn" id="lg-btn">Connexion →</button>
        </div>`);
        setTimeout(() => document.getElementById('lg-user').focus(), 50);
        document.getElementById('lg-btn').addEventListener('click', _doLogin);
        document.getElementById('lg-pwd').addEventListener('keydown', e => { if (e.key==='Enter') _doLogin(); });
    }

    async function _doLogin() {
        _clearErr('lg-err');
        const u = document.getElementById('lg-user').value.trim();
        const p = document.getElementById('lg-pwd').value;
        if (!u || !p) return _setErr('lg-err', 'Identifiants requis.');
        const btn = document.getElementById('lg-btn');
        btn.disabled = true;
        try {
            const data = await _post('/auth/login', { username: u, password: p });
            _pendingToken = data.temp_token;
            if (data.needs_qr_setup) {
                _showMFAResetQR(data.qr_url, data.totp_secret);
            } else {
                _showMFA();
            }
        } catch(e) {
            _setErr('lg-err', e.message);
        } finally { btn.disabled = false; }
    }

    // ── MFA reset — re-scan QR après réinitialisation ────────────
    function _showMFAResetQR(qrUrl, secret) {
        _overlay(`<div class="auth-card">
          ${_brand()}
          <div class="auth-title">Reconfigurer l'authentification MFA</div>
          <p class="auth-hint" style="margin-bottom:12px;">Votre MFA a été réinitialisée.<br>
             Scannez le nouveau QR avec votre application TOTP.</p>
          <div class="auth-qr">
            <img src="${qrUrl}" alt="QR Code MFA">
            <div class="auth-qr-secret" id="mqr-secret" title="Cliquez pour copier">${secret}</div>
          </div>
          <p class="auth-hint">Cliquez sur la clé pour la copier.</p>
          <button class="auth-btn" id="mqr-btn" style="margin-top:16px;">J'ai scanné → Entrer le code</button>
        </div>`);
        document.getElementById('mqr-secret').addEventListener('click', () => {
            navigator.clipboard.writeText(secret).then(() => {
                const el = document.getElementById('mqr-secret');
                if (el) { el.style.borderColor = 'var(--accent,#2dd4bf)'; setTimeout(() => { el.style.borderColor = ''; }, 1500); }
            });
        });
        document.getElementById('mqr-btn').addEventListener('click', _showMFA);
    }

    // ── LOGIN STEP 2 — code MFA ──────────────────────────────────
    function _showMFA() {
        _overlay(`<div class="auth-card">
          ${_brand()}
          <div class="auth-title">Authentification à deux facteurs</div>
          <div class="auth-error" id="mfa-err"></div>
          <p class="auth-hint" style="margin-bottom:18px;">Saisissez le code à 6 chiffres<br>de votre application d'authentification.</p>
          <input type="text" inputmode="numeric" pattern="[0-9]*" maxlength="6"
                 class="auth-mfa-input" id="mfa-code" placeholder="000000" autocomplete="one-time-code">
          <button class="auth-btn" id="mfa-btn" style="margin-top:16px;">Valider →</button>
          <p class="auth-hint" style="margin-top:12px;">
            <a href="#" id="mfa-back" style="color:var(--txt-3,#6e7681);font-size:12px;">← Retour à la connexion</a>
          </p>
        </div>`);
        const inp = document.getElementById('mfa-code');
        inp.focus();
        document.getElementById('mfa-btn').addEventListener('click', _doMFA);
        document.getElementById('mfa-back').addEventListener('click', e => { e.preventDefault(); _showLogin(); });
        inp.addEventListener('keydown', e => { if (e.key==='Enter') _doMFA(); });
        inp.addEventListener('input', e => {
            e.target.value = e.target.value.replace(/\D/g, '');
            if (e.target.value.length === 6) _doMFA();
        });
    }

    async function _doMFA() {
        _clearErr('mfa-err');
        const code = document.getElementById('mfa-code').value.trim();
        if (code.length !== 6) return _setErr('mfa-err', 'Code à 6 chiffres requis.');
        const btn = document.getElementById('mfa-btn');
        btn.disabled = true;
        try {
            await _post('/auth/mfa', { temp_token: _pendingToken, code });
            _unlock();
        } catch(e) {
            _setErr('mfa-err', e.message);
            const inp = document.getElementById('mfa-code');
            if (inp) { inp.value = ''; inp.focus(); }
        } finally { btn.disabled = false; }
    }

    // ── Logout ───────────────────────────────────────────────────
    async function logout() {
        await _del('/auth/logout');
        _pendingToken = null;
        const btn = document.getElementById('auth-logout-btn');
        if (btn) btn.remove();
        _showLogin();
    }

    // ── Init ─────────────────────────────────────────────────────
    async function init() {
        try {
            const r = await fetch(API + '/auth/status', { credentials: 'same-origin' });
            if (!r.ok) { _showLogin(); return; }
            const s = await r.json();
            if (!s.setup_done)    _showSetup1();
            else if (!s.authenticated) _showLogin();
            else                       _unlock();
        } catch {
            _showLogin();
        }
    }

    return { init, logout };
})();

document.addEventListener('DOMContentLoaded', () => Auth.init());
