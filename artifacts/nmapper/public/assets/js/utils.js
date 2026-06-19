// utils.js - Utilitaires partagés : sécurité DOM + session
const Utils = {

    // Encode les caractères HTML spéciaux pour prévenir les injections XSS.
    // À utiliser sur toute donnée externe (nmap, JSON importé) avant insertion dans innerHTML.
    escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    },

    // --- Export / Import de session ---

    exportSession() {
        const data = filteredData || networkData;
        if (!data || data.hosts.length === 0) {
            showMessage('error', 'Aucune donnée à exporter.');
            return;
        }
        const payload = JSON.stringify(data, null, 2);
        const blob = new Blob([payload], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `nmapper-session-${new Date().toISOString().slice(0, 10)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showMessage('success', '✅ Session exportée.');
    },

    importSession(file) {
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (e) => {
            let parsed;
            try {
                parsed = JSON.parse(e.target.result);
            } catch {
                showMessage('error', '❌ Fichier JSON invalide.');
                return;
            }

            const error = this.validateSessionData(parsed);
            if (error) {
                showMessage('error', `❌ Session rejetée : ${Utils.escapeHtml(error)}`);
                return;
            }

            clearNetworkData();
            networkData.vlans = parsed.vlans;
            networkData.hosts = parsed.hosts;
            networkData.stats = parsed.stats;
            updateVisualization();
            updateStats();
            document.getElementById('portFilters').style.display = 'block';
            document.getElementById('pdfReports').style.display = 'block';
            PDFReports.updateHostSelector();
            showMessage('success', `✅ Session restaurée — ${networkData.hosts.length} hôte(s) chargé(s).`);
        };
        reader.readAsText(file);
    },

    // Retourne null si valide, sinon un message d'erreur.
    validateSessionData(data) {
        if (typeof data !== 'object' || data === null || Array.isArray(data))
            return 'structure racine invalide';
        if (typeof data.vlans !== 'object' || Array.isArray(data.vlans))
            return 'champ vlans manquant ou invalide';
        if (!Array.isArray(data.hosts))
            return 'champ hosts manquant ou invalide';
        if (typeof data.stats !== 'object' || data.stats === null)
            return 'champ stats manquant ou invalide';

        if (data.hosts.length > 50000)
            return 'trop d\'entrées (> 50 000 hôtes)';

        for (const host of data.hosts) {
            if (typeof host !== 'object' || host === null) return 'hôte invalide';
            if (typeof host.ip !== 'string') return 'ip manquante';
            if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host.ip)) return `ip invalide : ${host.ip}`;
            if (typeof host.vlan !== 'string' || host.vlan.length > 200) return 'vlan invalide';
            if (!Array.isArray(host.ports)) return `ports invalides pour ${host.ip}`;
            if (host.ports.length > 65536) return `trop de ports pour ${host.ip}`;

            for (const port of host.ports) {
                if (typeof port !== 'object' || port === null) return 'port invalide';
                if (typeof port.port !== 'number' || port.port < 0 || port.port > 65535)
                    return `numéro de port invalide pour ${host.ip}`;
                if (typeof port.state !== 'string' || port.state.length > 20)
                    return `état de port invalide pour ${host.ip}`;
                if (typeof port.service !== 'string' || port.service.length > 200)
                    return `nom de service invalide pour ${host.ip}`;
            }
        }
        return null;
    }
};
