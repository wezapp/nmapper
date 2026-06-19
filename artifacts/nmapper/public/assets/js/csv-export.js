// csv-export.js — Export CSV des hôtes (UTF-8 BOM, séparateur ;)
const CSVExport = {

    SEP: ';',

    // Escape une valeur CSV : neutralise les formules tableur puis
    // entoure de guillemets si nécessaire
    esc(val) {
        if (val == null) return '';
        let s = String(val);
        // Préfixe ' pour neutraliser =, +, -, @, tab, CR (Excel/LibreOffice/Sheets)
        if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
        if (s.includes(this.SEP) || s.includes('"') || s.includes('\n') || s.includes('\r')) {
            return '"' + s.replace(/"/g, '""') + '"';
        }
        return s;
    },

    buildCSV(hosts) {
        const sep = this.SEP;

        const headers = [
            'IP', 'Hostname', 'VLAN', 'Vendor', 'MAC',
            'OS', 'Confiance OS (%)',
            'Score', 'Niveau de risque', 'Type dispositif',
            'Nb ports ouverts', 'Ports ouverts',
            'Vulnérable', 'CVEs détectées', 'Scripts NSE'
        ];

        const rows = [ headers.map(h => this.esc(h)).join(sep) ];

        hosts.forEach(host => {
            const openPorts = host.ports.filter(p => p.state === 'open');
            const risk   = SecurityAnalyzer.calculateRiskScore(host);
            const device = SecurityAnalyzer.categorizeDevice(host);

            const hostname = (host.hostnames && host.hostnames.length > 0)
                ? host.hostnames.map(h => h.name).join(' | ')
                : '';

            const osName = host.os ? host.os.name      : '';
            const osAcc  = host.os ? host.os.accuracy  : '';

            const portsDetail = openPorts
                .map(p => `${p.port}/${p.service || '?'}`)
                .join(' ');

            // CVEs uniques issues des findings NSE
            const cves = [...new Set(
                (risk.nseFindings || []).flatMap(f => f.cves || [])
            )].join(' | ');

            // IDs de scripts NSE avec leur sévérité
            const nseIds = (risk.nseFindings || [])
                .map(f => `${f.scriptId}(${f.severity})`)
                .join(' | ');

            const row = [
                host.ip,
                hostname,
                host.vlan,
                host.vendor    || '',
                host.macAddress || '',
                osName,
                osAcc,
                risk.score,
                SecurityAnalyzer.getScoreLabel(risk.level),
                device.category,
                openPorts.length,
                portsDetail,
                host.vulnerable ? 'Oui' : 'Non',
                cves,
                nseIds
            ].map(v => this.esc(v)).join(sep);

            rows.push(row);
        });

        return rows.join('\r\n');
    },

    // Déclenche le téléchargement avec BOM UTF-8 pour Excel
    download(content, filename) {
        const bom  = '﻿';
        const blob = new Blob([bom + content], { type: 'text/csv;charset=utf-8;' });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href     = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    },

    async exportAll() {
        if (!networkData.hosts.length) {
            showMessage('warning', '⚠️ Aucune donnée à exporter.');
            return;
        }
        const date    = new Date().toISOString().slice(0, 10);
        const bom     = '\uFEFF';
        const content = this.buildCSV(networkData.hosts);
        const blob    = new Blob([bom + content], { type: 'text/csv;charset=utf-8;' });
        const name    = `nmapper-export-${date}.csv`;
        await EncryptExport.downloadEncrypted(blob, name);
        showMessage('success', `✅ ${networkData.hosts.length} hôte(s) exporté(s) en CSV chiffré.`);
        if (typeof ActivityLog !== 'undefined') ActivityLog.logEvent('export_csv', name, 'success', `${networkData.hosts.length} hôtes`);
    },

    async exportFiltered() {
        const hosts = filteredData ? filteredData.hosts : null;
        if (!hosts || !hosts.length) {
            showMessage('warning', '⚠️ Aucun hôte filtré à exporter.');
            return;
        }
        const date    = new Date().toISOString().slice(0, 10);
        const bom     = '\uFEFF';
        const content = this.buildCSV(hosts);
        const blob    = new Blob([bom + content], { type: 'text/csv;charset=utf-8;' });
        const name    = `nmapper-export-filtré-${date}.csv`;
        await EncryptExport.downloadEncrypted(blob, name);
        showMessage('success', `✅ ${hosts.length} hôte(s) filtré(s) exporté(s) en CSV chiffré.`);
        if (typeof ActivityLog !== 'undefined') ActivityLog.logEvent('export_csv', name, 'success', `${hosts.length} hôtes filtrés`);
    }
};
