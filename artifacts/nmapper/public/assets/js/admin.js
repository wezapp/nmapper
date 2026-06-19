// admin.js — Panneau d'administration NMAPPER (gestion utilisateurs)

const AdminPanel = (() => {
  let _currentRole = null;

  const ROLE_LABELS = {
    admin:  '👑 Admin',
    it:     '🔧 IT',
    viewer: '👁️ Viewer',
  };

  async function onEnter() {
    // Vérifier le rôle de l'utilisateur courant
    try {
      const r = await fetch('/scanner-api/auth/status', { credentials: 'include' });
      if (r.ok) {
        const d = await r.json();
        _currentRole = d.role;
      }
    } catch (_) {}

    const denied  = document.getElementById('admin-denied');
    const content = document.getElementById('admin-content');

    if (_currentRole !== 'admin') {
      if (denied)  denied.style.display  = '';
      if (content) content.style.display = 'none';
      return;
    }

    if (denied)  denied.style.display  = 'none';
    if (content) content.style.display = '';
    _loadUsers();
  }

  async function _loadUsers() {
    const listEl = document.getElementById('admin-users-list');
    if (!listEl) return;
    listEl.innerHTML = '<p style="color:var(--txt-3);text-align:center;padding:16px;">Chargement…</p>';

    try {
      const r = await fetch('/scanner-api/admin/users', { credentials: 'include' });
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        listEl.innerHTML = `<p style="color:var(--danger);padding:12px;">${d.detail || 'Erreur de chargement'}</p>`;
        return;
      }
      const { users } = await r.json();
      _renderUsers(users);
    } catch (e) {
      listEl.innerHTML = `<p style="color:var(--danger);padding:12px;">Erreur réseau : ${e.message}</p>`;
    }
  }

  function _renderUsers(users) {
    const listEl = document.getElementById('admin-users-list');
    if (!listEl) return;

    if (!users || users.length === 0) {
      listEl.innerHTML = '<p style="color:var(--txt-3);padding:16px;">Aucun utilisateur trouvé.</p>';
      return;
    }

    const rows = users.map(u => {
      const created = u.created_at
        ? new Date(u.created_at * 1000).toLocaleDateString('fr-FR')
        : '—';
      const mfa = u.mfa_verified
        ? '<span style="color:var(--ok)">✅ Activé</span>'
        : '<span style="color:var(--warn)">⚠️ Non vérifié</span>';

      const isSelf = false; // On n'a pas le username de session ici, on suppose qu'il faut protéger le dernier admin côté serveur

      return `<tr class="admin-user-row">
        <td><strong>${_esc(u.username)}</strong></td>
        <td>
          <select class="adm-role-sel" data-user="${_esc(u.username)}" onchange="AdminPanel.changeRole(this)">
            <option value="admin"  ${u.role==='admin'  ?'selected':''}>👑 Admin</option>
            <option value="it"     ${u.role==='it'     ?'selected':''}>🔧 IT</option>
            <option value="viewer" ${u.role==='viewer' ?'selected':''}>👁️ Viewer</option>
          </select>
        </td>
        <td>${mfa}</td>
        <td style="color:var(--txt-3);font-size:12px;">${created}</td>
        <td>
          <button class="adm-del-btn" onclick="AdminPanel.deleteUser('${_esc(u.username)}')" title="Supprimer">🗑</button>
        </td>
      </tr>`;
    }).join('');

    listEl.innerHTML = `
      <table class="admin-users-table">
        <thead><tr>
          <th>Utilisateur</th><th>Rôle</th><th>MFA</th><th>Créé le</th><th></th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  }

  function showAddModal() {
    const modal = document.getElementById('admin-modal');
    if (!modal) return;
    document.getElementById('adm-new-username').value = '';
    document.getElementById('adm-new-password').value = '';
    document.getElementById('adm-new-role').value     = 'viewer';
    document.getElementById('adm-modal-error').textContent = '';
    document.getElementById('adm-qr-section').style.display = 'none';
    document.getElementById('adm-create-btn').textContent = 'Créer';
    document.getElementById('adm-create-btn').disabled = false;
    modal.style.display = '';
  }

  function closeModal() {
    const modal = document.getElementById('admin-modal');
    if (modal) modal.style.display = 'none';
  }

  async function createUser() {
    const username = document.getElementById('adm-new-username').value.trim();
    const password = document.getElementById('adm-new-password').value;
    const role     = document.getElementById('adm-new-role').value;
    const errEl    = document.getElementById('adm-modal-error');
    const btn      = document.getElementById('adm-create-btn');

    errEl.textContent = '';
    if (!username || !password) { errEl.textContent = 'Remplissez tous les champs.'; return; }

    btn.disabled = true;
    btn.textContent = 'Création…';

    try {
      const r = await fetch('/scanner-api/admin/users', {
        method:  'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ username, password, role }),
      });
      const d = await r.json();
      if (!r.ok) {
        errEl.textContent = d.detail || 'Erreur lors de la création';
        btn.disabled = false;
        btn.textContent = 'Créer';
        return;
      }

      // Afficher QR code MFA
      const qrSection   = document.getElementById('adm-qr-section');
      const qrImg       = document.getElementById('adm-qr-img');
      const totpSecret  = document.getElementById('adm-totp-secret');
      if (qrSection && qrImg && d.qr_url) {
        qrImg.src = d.qr_url;
        if (totpSecret) totpSecret.textContent = d.totp_secret || '';
        qrSection.style.display = '';
      }
      btn.textContent = 'Fermez après avoir partagé le QR code';
      btn.disabled = true;

      // Rafraîchir la liste
      _loadUsers();
    } catch (e) {
      errEl.textContent = `Erreur réseau : ${e.message}`;
      btn.disabled = false;
      btn.textContent = 'Créer';
    }
  }

  async function changeRole(sel) {
    const username = sel.dataset.user;
    const newRole  = sel.value;
    try {
      const r = await fetch(`/scanner-api/admin/users/${encodeURIComponent(username)}/role`, {
        method:  'PUT',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ role: newRole }),
      });
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        alert(`Erreur : ${d.detail || r.status}`);
        _loadUsers(); // reset
      }
    } catch (e) {
      alert(`Erreur réseau : ${e.message}`);
      _loadUsers();
    }
  }

  async function deleteUser(username) {
    if (!confirm(`Supprimer l'utilisateur « ${username} » ? Cette action est irréversible.`)) return;
    try {
      const r = await fetch(`/scanner-api/admin/users/${encodeURIComponent(username)}`, {
        method: 'DELETE',
        credentials: 'include',
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) { alert(`Erreur : ${d.detail || r.status}`); return; }
      _loadUsers();
    } catch (e) {
      alert(`Erreur réseau : ${e.message}`);
    }
  }

  function _esc(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  return { onEnter, showAddModal, closeModal, createUser, changeRole, deleteUser };
})();
