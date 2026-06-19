// encrypt-export.js — Chiffrement AES-256-GCM des exports NMAPPER
// Format : magic(4) + salt(16) + iv(12) + ciphertext  →  extension .nmr
const EncryptExport = (() => {

    const MAGIC = 'NMR1';

    function _generatePassword() {
        const b = new Uint8Array(16);
        crypto.getRandomValues(b);
        return Array.from(b).map(x => x.toString(16).padStart(2,'0')).join('');
    }

    async function _deriveKey(password, salt) {
        const km = await crypto.subtle.importKey(
            'raw', new TextEncoder().encode(password),
            'PBKDF2', false, ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            { name:'PBKDF2', salt, iterations:120000, hash:'SHA-256' },
            km, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']
        );
    }

    async function _encrypt(data, password) {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv   = crypto.getRandomValues(new Uint8Array(12));
        const key  = await _deriveKey(password, salt);
        const ct   = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, data);

        const magic = new TextEncoder().encode(MAGIC);
        const out   = new Uint8Array(4 + 16 + 12 + ct.byteLength);
        out.set(magic, 0);
        out.set(salt,  4);
        out.set(iv,   20);
        out.set(new Uint8Array(ct), 32);
        return out;
    }

    async function _decrypt(data, password) {
        const head = new TextDecoder().decode(data.slice(0, 4));
        if (head !== MAGIC) throw new Error("Format invalide — ce fichier n'est pas un rapport NMAPPER chiffré (.nmr)");
        const salt = data.slice(4, 20);
        const iv   = data.slice(20, 32);
        const ct   = data.slice(32);
        const key  = await _deriveKey(password, salt);
        try {
            const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct);
            return new Uint8Array(pt);
        } catch {
            throw new Error('Mot de passe incorrect ou fichier corrompu');
        }
    }

    function _triggerDownload(bytes, filename, mime) {
        const url = URL.createObjectURL(new Blob([bytes], { type: mime }));
        const a   = Object.assign(document.createElement('a'), { href: url, download: filename });
        document.body.appendChild(a); a.click();
        document.body.removeChild(a); URL.revokeObjectURL(url);
    }

    // ── Modal choix de passphrase (affiché AVANT le téléchargement) ──────────
    function _showPassphraseChoiceModal(filename) {
        return new Promise((resolve, reject) => {
            let modal = document.getElementById('enc-choice-modal');
            if (modal) modal.remove();

            modal = document.createElement('div');
            modal.id = 'enc-choice-modal';
            modal.className = 'enc-modal-overlay';
            modal.innerHTML = `
              <div class="enc-modal-card">
                <div class="enc-modal-title">🔐 Chiffrement du rapport</div>
                <div class="enc-modal-sub" style="margin-bottom:14px;">Fichier : <b>${filename}.nmr</b></div>

                <div class="enc-choice-group">
                  <label class="enc-choice-opt" id="enc-opt-auto">
                    <input type="radio" name="enc-mode" value="auto" checked>
                    <div>
                      <strong>Passphrase aléatoire</strong> <span class="enc-badge-rec">recommandé</span>
                      <p>Une passphrase sécurisée est générée automatiquement. Elle vous sera affichée après le téléchargement.</p>
                    </div>
                  </label>
                  <label class="enc-choice-opt" id="enc-opt-custom">
                    <input type="radio" name="enc-mode" value="custom">
                    <div>
                      <strong>Définir ma propre passphrase</strong>
                      <p>Saisissez vous-même le mot de passe qui protégera ce rapport.</p>
                    </div>
                  </label>
                </div>

                <div id="enc-custom-input-wrap" style="display:none;margin-top:10px;">
                  <input type="password" id="enc-custom-pwd" class="enc-pwd-input"
                         placeholder="Saisissez votre passphrase (min. 8 caractères)"
                         autocomplete="new-password">
                  <div id="enc-custom-pwd-err" style="color:var(--danger,#f43f5e);font-size:12px;margin-top:4px;"></div>
                </div>

                <div class="enc-modal-actions">
                  <button class="enc-cancel-btn" id="enc-choice-cancel">Annuler</button>
                  <button class="enc-ok-btn" id="enc-choice-ok">Chiffrer & télécharger</button>
                </div>
              </div>`;
            document.body.appendChild(modal);
            requestAnimationFrame(() => modal.classList.add('show'));

            const radios   = modal.querySelectorAll('input[name="enc-mode"]');
            const customWrap = document.getElementById('enc-custom-input-wrap');
            const customPwd  = document.getElementById('enc-custom-pwd');
            const errDiv     = document.getElementById('enc-custom-pwd-err');

            radios.forEach(r => r.addEventListener('change', () => {
                customWrap.style.display = r.value === 'custom' && r.checked ? 'block' : 'none';
                errDiv.textContent = '';
            }));

            document.getElementById('enc-choice-cancel').addEventListener('click', () => {
                modal.classList.remove('show');
                setTimeout(() => modal.remove(), 250);
                reject(new Error('Annulé'));
            });

            document.getElementById('enc-choice-ok').addEventListener('click', () => {
                const mode = modal.querySelector('input[name="enc-mode"]:checked').value;
                if (mode === 'custom') {
                    const pwd = customPwd.value.trim();
                    if (pwd.length < 8) {
                        errDiv.textContent = '⚠️ La passphrase doit contenir au moins 8 caractères.';
                        return;
                    }
                    modal.classList.remove('show');
                    setTimeout(() => modal.remove(), 250);
                    resolve({ mode: 'custom', password: pwd });
                } else {
                    modal.classList.remove('show');
                    setTimeout(() => modal.remove(), 250);
                    resolve({ mode: 'auto', password: _generatePassword() });
                }
            });
        });
    }

    // ── Modal affichage passphrase aléatoire (après téléchargement) ──────────
    function _showPasswordModal(password, filename) {
        let modal = document.getElementById('enc-password-modal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'enc-password-modal';
            modal.className = 'enc-modal-overlay';
            modal.innerHTML = `
              <div class="enc-modal-card">
                <div class="enc-modal-title">✅ Rapport chiffré téléchargé</div>
                <div class="enc-modal-sub" id="enc-modal-fname"></div>
                <div class="enc-warning">
                  ⚠️ <strong>Copiez et sauvegardez cette passphrase.</strong><br>
                  Elle est impossible à récupérer. Sans elle, le fichier sera irrécupérable.
                </div>
                <div class="enc-password-box">
                  <span class="enc-password-value" id="enc-pwd-value"></span>
                  <button class="enc-copy-btn" id="enc-copy-btn" title="Copier">📋</button>
                </div>
                <button class="enc-ok-btn" id="enc-modal-ok">J'ai sauvegardé la passphrase ✓</button>
              </div>`;
            document.body.appendChild(modal);
            document.getElementById('enc-copy-btn').addEventListener('click', () => {
                const val = document.getElementById('enc-pwd-value').textContent;
                navigator.clipboard.writeText(val).then(() => {
                    const btn = document.getElementById('enc-copy-btn');
                    const orig = btn.textContent;
                    btn.textContent = '✅';
                    setTimeout(() => { btn.textContent = orig; }, 1800);
                });
            });
            document.getElementById('enc-modal-ok').addEventListener('click', () => {
                modal.classList.remove('show');
            });
        }
        document.getElementById('enc-pwd-value').textContent = password;
        document.getElementById('enc-modal-fname').textContent = 'Fichier : ' + filename + '.nmr';
        requestAnimationFrame(() => modal.classList.add('show'));
    }

    // ── Point d'entrée principal ─────────────────────────────────────────────
    async function downloadEncrypted(blob, filename) {
        let choice;
        try {
            choice = await _showPassphraseChoiceModal(filename);
        } catch {
            return; // Annulé par l'utilisateur
        }

        const raw = new Uint8Array(await blob.arrayBuffer());
        const enc = await _encrypt(raw, choice.password);
        _triggerDownload(enc, filename + '.nmr', 'application/octet-stream');

        if (choice.mode === 'auto') {
            _showPasswordModal(choice.password, filename);
        }
    }

    async function decryptFile(file, password) {
        const buf = new Uint8Array(await file.arrayBuffer());
        return _decrypt(buf, password);
    }

    function getMimeType(encFilename) {
        const base = encFilename.replace(/\.nmr$/i, '');
        return base.endsWith('.csv')
            ? { mime: 'text/csv;charset=utf-8;', name: base }
            : { mime: 'application/pdf',          name: base };
    }

    // ── UI de déchiffrement (bouton dans Sources/Import) ────────────────────
    document.addEventListener('DOMContentLoaded', () => {
        const btn = document.getElementById('dec-decrypt-btn');
        if (!btn) return;
        btn.addEventListener('click', async () => {
            const fileInp  = document.getElementById('dec-file-input');
            const password = document.getElementById('dec-password').value.trim();
            const result   = document.getElementById('dec-result');

            const warn = (msg) => { result.textContent = msg; result.style.color = 'var(--warn,#f59e0b)'; };
            const ok   = (msg) => { result.textContent = msg; result.style.color = 'var(--success,#34d399)'; };
            const err  = (msg) => { result.textContent = msg; result.style.color = 'var(--danger,#f43f5e)'; };

            if (!fileInp.files[0]) return warn('⚠️ Sélectionnez un fichier .nmr');
            if (!password)          return warn('⚠️ Saisissez le mot de passe');

            btn.disabled = true;
            result.textContent = '⏳ Déchiffrement…';
            result.style.color = 'var(--txt-3,#6e7681)';
            try {
                const bytes = await decryptFile(fileInp.files[0], password);
                const { mime, name } = getMimeType(fileInp.files[0].name);
                _triggerDownload(bytes, name, mime);
                ok('✅ Déchiffrement réussi — ' + name);
            } catch(e) {
                err('❌ ' + e.message);
            } finally {
                btn.disabled = false;
            }
        });
    });

    return { downloadEncrypted, decryptFile, getMimeType };
})();
