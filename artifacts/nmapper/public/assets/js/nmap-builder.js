// nmap-builder.js - Générateur de commandes Nmap avec multi-étapes
const NmapBuilder = {

    STORAGE_KEY: 'nmapper-builder-config',

    timingProfiles: [
        { name: 'Paranoïaque (-T0)', time: '~25 min/host', noise: 5, ids: 'Très faible', idsClass: 'low' },
        { name: 'Sneaky (-T1)', time: '~15 min/host', noise: 15, ids: 'Faible', idsClass: 'low' },
        { name: 'Poli (-T2)', time: '~5 min', noise: 30, ids: 'Faible', idsClass: 'low' },
        { name: 'Normal (-T3)', time: '~2-5 min', noise: 50, ids: 'Moyen', idsClass: 'medium' },
        { name: 'Agressif (-T4)', time: '~1-2 min', noise: 75, ids: 'Élevé', idsClass: 'high' },
        { name: 'Insane (-T5)', time: '~30 sec', noise: 100, ids: 'Très élevé', idsClass: 'high' }
    ],

    explanations: {
        '-sS': { text: 'SYN scan (semi-ouvert) — Plus discret que -sT, ne complète pas le handshake TCP. Nécessite root.', impact: 'discret' },
        '-sT': { text: 'Connect scan — Complète le handshake TCP, plus visible mais ne nécessite pas root.', impact: 'bruyant' },
        '-sU': { text: 'Scan UDP — Très lent mais détecte SNMP, DNS, DHCP, etc.', impact: 'lent' },
        '-sn': { text: 'Ping sweep — Découverte d\'hôtes uniquement, pas de scan de ports.', impact: 'rapide' },
        '-sV': { text: 'Détection des versions de services — Envoie des sondes spécifiques.', impact: 'modéré' },
        '-O': { text: 'Détection de l\'OS via fingerprinting TCP/IP. Nécessite root.', impact: 'modéré' },
        '--traceroute': { text: 'Trace la route vers chaque hôte.', impact: 'neutre' },
        '-f': { text: 'Fragmente les paquets pour contourner les IDS/firewalls.', impact: 'discret' },
        '-D RND:5': { text: 'Utilise 5 adresses IP leurres pour masquer le scan.', impact: 'discret' },
        '--randomize-hosts': { text: 'Scanne les hôtes dans un ordre aléatoire.', impact: 'discret' },
        '--spoof-mac 0': { text: 'Utilise une adresse MAC aléatoire (nécessite root).', impact: 'discret' },
        '-g 53': { text: 'Utilise le port source 53 (DNS) — souvent autorisé par les firewalls.', impact: 'discret' },
        '-n': { text: 'Pas de résolution DNS — Plus rapide et discret.', impact: 'discret' },
        '-R': { text: 'Résolution DNS inverse pour tous les hôtes.', impact: 'neutre' },
        '-Pn': { text: 'Pas de ping préalable — Scanne même si l\'hôte semble down (utile derrière firewall).', impact: 'neutre' },
        '--top-ports': { text: 'Scanne les N ports les plus courants selon Nmap.', impact: 'neutre' },
        '-p': { text: 'Spécifie les ports à scanner.', impact: 'neutre' },
        '--script': { text: 'Exécute des scripts NSE pour détecter vulnérabilités/infos.', impact: 'bruyant' },
        '--exclude': { text: 'Exclut des hôtes du scan.', impact: 'neutre' },
        '-oX': { text: 'Output XML — Compatible avec NMAPPER pour import.', impact: 'neutre' },
        '-T': { text: 'Template de timing (0=paranoïaque → 5=insane).', impact: 'variable' }
    },

    presets: {
        stealth: {
            timing: 1, services: false, os: false, scripts: false,
            traceroute: false, dns: false, udp: false, pingSweep: false, pn: true,
            fragment: true, decoy: true, randomize: true, spoofMAC: false, sourcePort: true,
            customPorts: 'top100'
        },
        discovery: {
            timing: 4, services: false, os: false, scripts: false,
            traceroute: false, dns: true, udp: false, pingSweep: true, pn: false,
            fragment: false, decoy: false, randomize: false, spoofMAC: false, sourcePort: false,
            customPorts: ''
        },
        full: {
            timing: 3, services: true, os: true, scripts: true,
            traceroute: true, dns: true, udp: false, pingSweep: false, pn: false,
            fragment: false, decoy: false, randomize: false, spoofMAC: false, sourcePort: false,
            customPorts: 'top1000'
        },
        ot: {
            timing: 2, services: true, os: false, scripts: true,
            traceroute: false, dns: false, udp: false, pingSweep: false, pn: true,
            fragment: false, decoy: false, randomize: false, spoofMAC: false, sourcePort: false,
            customPorts: '102,502,1911,2404,4840,20000,44818,47808,80,443,22,23,161'
        }
    },

    // checkbox id → preset property name
    fieldMap: {
        nmapServices: 'services', nmapOS: 'os', nmapScripts: 'scripts',
        nmapTraceroute: 'traceroute', nmapDNS: 'dns', nmapUDP: 'udp',
        nmapPingSweep: 'pingSweep', nmapPn: 'pn', nmapFragment: 'fragment',
        nmapDecoy: 'decoy', nmapRandomize: 'randomize', nmapSpoofMAC: 'spoofMAC',
        nmapSourcePort: 'sourcePort'
    },

    init() {
        if (!document.getElementById('nmapBuilderContent')) return;
        this.bindEvents();
        this.restoreConfig();
        this.updateCommand();
    },

    bindEvents() {
        const slider = document.getElementById('nmapTiming');
        if (slider) slider.addEventListener('input', () => this.onUserChange());

        document.querySelectorAll('#nmapBuilderContent input[type="checkbox"]').forEach(cb => {
            cb.addEventListener('change', () => this.onUserChange());
        });

        ['nmapTarget', 'nmapPorts2', 'nmapExclude', 'nmapOutputName'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.addEventListener('input', () => this.onUserChange());
        });
    },

    onUserChange() {
        document.querySelectorAll('.preset-btn').forEach(btn => btn.classList.remove('active'));

        const nseGroup = document.getElementById('nseScriptsGroup');
        if (nseGroup) {
            nseGroup.style.display = document.getElementById('nmapScripts').checked ? 'block' : 'none';
        }

        this.updateDisabledState();
        this.validateInputs();
        this.updateCommand();

        if (document.getElementById('multiStepSection').style.display === 'block') {
            this.generateMultiStep();
        }

        this.saveConfig();
    },

    updateDisabledState() {
        const pingSweep = document.getElementById('nmapPingSweep').checked;
        ['nmapServices', 'nmapOS', 'nmapScripts', 'nmapTraceroute', 'nmapUDP'].forEach(id => {
            const el = document.getElementById(id);
            const label = el.closest('.obj-check');
            el.disabled = pingSweep;
            label.classList.toggle('disabled', pingSweep);
        });
    },

    validateInputs() {
        const target = document.getElementById('nmapTarget');
        const ports = document.getElementById('nmapPorts2');
        const targetVal = target.value.trim();
        const targetValid = !targetVal || /^[\w\.\-\/,\s]+$/.test(targetVal);
        target.classList.toggle('invalid', !targetValid);

        const portsVal = ports.value.trim();
        const portsValid = !portsVal || /^top\d*$/i.test(portsVal) || /^[\d,\-\s]+$/.test(portsVal);
        ports.classList.toggle('invalid', !portsValid);
    },

    applyPreset(name) {
        if (name === 'multistep') {
            this.generateMultiStep();
            document.getElementById('multiStepSection').style.display = 'block';
            document.querySelectorAll('.preset-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelector('[data-arg="multistep"]').classList.add('active');
            return;
        }

        const preset = this.presets[name];
        if (!preset) return;

        document.getElementById('multiStepSection').style.display = 'none';
        document.getElementById('nmapTiming').value = preset.timing;

        Object.entries(this.fieldMap).forEach(([id, propName]) => {
            const el = document.getElementById(id);
            if (el && preset[propName] !== undefined) {
                el.checked = preset[propName];
            }
        });

        if (preset.customPorts !== undefined) {
            document.getElementById('nmapPorts2').value = preset.customPorts;
        }

        document.getElementById('nseScriptsGroup').style.display = preset.scripts ? 'block' : 'none';
        this.updateDisabledState();

        document.querySelectorAll('.preset-btn').forEach(btn => btn.classList.remove('active'));
        document.querySelector(`[data-arg="${name}"]`).classList.add('active');

        this.updateCommand();
        this.saveConfig();
    },

    useLoadedHosts() {
        if (typeof networkData === 'undefined' || !networkData.hosts || networkData.hosts.length === 0) {
            this.flashMessage('⚠️ Aucun hôte chargé', true);
            return;
        }
        const ips = networkData.hosts.map(h => h.ip);
        const netCount = {};
        ips.forEach(ip => {
            const net = ip.split('.').slice(0, 3).join('.') + '.0/24';
            netCount[net] = (netCount[net] || 0) + 1;
        });
        const sorted = Object.entries(netCount).sort((a, b) => b[1] - a[1]);
        const target = sorted[0][1] > ips.length * 0.7
            ? sorted[0][0]
            : ips.slice(0, 50).join(',');
        document.getElementById('nmapTarget').value = target;
        this.onUserChange();
        this.flashMessage(`✅ ${ips.length} hôte(s) chargé(s) dans la cible`);
    },

    reset() {
        document.getElementById('nmapTiming').value = 3;
        Object.keys(this.fieldMap).forEach(id => {
            document.getElementById(id).checked = false;
        });
        document.getElementById('nmapServices').checked = true;
        document.getElementById('nmapDNS').checked = true;
        ['nmapTarget', 'nmapPorts2', 'nmapExclude', 'nmapOutputName'].forEach(id => {
            document.getElementById(id).value = '';
        });
        document.getElementById('nseScriptsGroup').style.display = 'none';
        document.getElementById('multiStepSection').style.display = 'none';
        document.querySelectorAll('.preset-btn').forEach(btn => btn.classList.remove('active'));
        this.updateDisabledState();
        this.updateCommand();
        this.saveConfig();
        this.flashMessage('🔄 Configuration réinitialisée');
    },

    buildCommand() {
        const get = id => document.getElementById(id);
        const timing = parseInt(get('nmapTiming').value);
        const services = get('nmapServices').checked;
        const os = get('nmapOS').checked;
        const scripts = get('nmapScripts').checked;
        const traceroute = get('nmapTraceroute').checked;
        const dns = get('nmapDNS').checked;
        const udp = get('nmapUDP').checked;
        const pingSweep = get('nmapPingSweep').checked;
        const pn = get('nmapPn').checked;
        const fragment = get('nmapFragment').checked;
        const decoy = get('nmapDecoy').checked;
        const randomize = get('nmapRandomize').checked;
        const spoofMAC = get('nmapSpoofMAC').checked;
        const sourcePort = get('nmapSourcePort').checked;

        const target = get('nmapTarget').value.trim() || '192.168.1.0/24';
        const portsInput = get('nmapPorts2').value.trim();
        const exclude = get('nmapExclude').value.trim();
        const outputName = get('nmapOutputName').value.trim() || 'scan_results';

        const parts = ['nmap'];
        const usedFlags = [];
        const warnings = [];

        if (pingSweep) {
            parts.push('-sn');
            usedFlags.push('-sn');
        } else {
            parts.push('-sS');
            usedFlags.push('-sS');
            if (udp) {
                parts.push('-sU');
                usedFlags.push('-sU');
                warnings.push('⚠️ Scan UDP très lent — privilégiez un nombre limité de ports');
            }
        }

        if (pn) { parts.push('-Pn'); usedFlags.push('-Pn'); }
        if (services && !pingSweep) { parts.push('-sV'); usedFlags.push('-sV'); }
        if (os && !pingSweep) {
            parts.push('-O'); usedFlags.push('-O');
            warnings.push('🔑 -O nécessite des privilèges root/admin');
        }
        if (scripts && !pingSweep) {
            parts.push(`--script=${this.getSelectedScripts()}`);
            usedFlags.push('--script');
        }
        if (traceroute && !pingSweep) { parts.push('--traceroute'); usedFlags.push('--traceroute'); }

        parts.push(`-T${timing}`);
        usedFlags.push('-T');

        if (!dns) { parts.push('-n'); usedFlags.push('-n'); }
        else { parts.push('-R'); usedFlags.push('-R'); }

        if (fragment) { parts.push('-f'); usedFlags.push('-f'); }
        if (decoy) { parts.push('-D RND:5'); usedFlags.push('-D RND:5'); }
        if (randomize) { parts.push('--randomize-hosts'); usedFlags.push('--randomize-hosts'); }
        if (spoofMAC) {
            parts.push('--spoof-mac 0'); usedFlags.push('--spoof-mac 0');
            warnings.push('🔑 --spoof-mac nécessite des privilèges root');
        }
        if (sourcePort) { parts.push('-g 53'); usedFlags.push('-g 53'); }

        if (!pingSweep) {
            if (portsInput) {
                if (/^top/i.test(portsInput)) {
                    const num = portsInput.replace(/\D/g, '') || '1000';
                    parts.push(`--top-ports ${num}`);
                    usedFlags.push('--top-ports');
                } else {
                    parts.push(`-p ${portsInput}`);
                    usedFlags.push('-p');
                }
            } else {
                parts.push('--top-ports 1000');
                usedFlags.push('--top-ports');
            }
        }

        if (exclude) { parts.push(`--exclude ${exclude}`); usedFlags.push('--exclude'); }

        parts.push(`-oX ${outputName}.xml`);
        usedFlags.push('-oX');

        parts.push(target);

        // Combo warnings
        if (timing >= 4 && (fragment || decoy)) {
            warnings.push('⚠️ Timing rapide avec options furtives : effet contradictoire');
        }
        if (udp && /1-65535/.test(portsInput)) {
            warnings.push('🐌 Scan UDP sur tous les ports peut prendre des heures');
        }

        return { command: parts.join(' '), flags: usedFlags, timing, warnings, target };
    },

    estimateHostCount(target) {
        if (!target) return 1;
        const cidrMatch = target.match(/\/(\d+)/);
        if (cidrMatch) {
            const bits = parseInt(cidrMatch[1]);
            return Math.max(1, Math.pow(2, 32 - bits) - 2);
        }
        const rangeMatch = target.match(/(\d+)-(\d+)/);
        if (rangeMatch) return parseInt(rangeMatch[2]) - parseInt(rangeMatch[1]) + 1;
        if (target.includes(',')) return target.split(',').length;
        return 1;
    },

    getSelectedScripts() {
        const scripts = [];
        if (document.getElementById('nseDefault').checked) scripts.push('default');
        if (document.getElementById('nseVuln').checked) scripts.push('vuln');
        if (document.getElementById('nseSmb').checked) scripts.push('smb-vuln-*');
        if (document.getElementById('nseFtp').checked) scripts.push('ftp-anon');
        if (document.getElementById('nseSslEnum').checked) scripts.push('ssl-enum-ciphers');
        if (document.getElementById('nseHttpEnum').checked) scripts.push('http-enum');
        return scripts.length > 0 ? scripts.join(',') : 'default';
    },

    formatDuration(seconds) {
        if (seconds < 60) return `~${Math.round(seconds)} sec`;
        if (seconds < 3600) return `~${Math.round(seconds / 60)} min`;
        return `~${(seconds / 3600).toFixed(1)} h`;
    },

    updateCommand() {
        const { command, flags, timing, warnings, target } = this.buildCommand();

        document.getElementById('nmapCommand').textContent = command;

        const profile = this.timingProfiles[timing];
        const hostCount = this.estimateHostCount(target);
        const isPingSweep = document.getElementById('nmapPingSweep').checked;
        const isUDP = document.getElementById('nmapUDP').checked;
        const hasNSE = document.getElementById('nmapScripts').checked;
        const hasOS = document.getElementById('nmapOS').checked;

        // Time estimate
        let mult = 1;
        if (isUDP) mult *= 8;
        if (hasNSE) mult *= 2;
        if (hasOS) mult *= 1.3;
        const baseSec = [1500, 900, 300, 150, 75, 30][timing];
        const scaledSec = isPingSweep
            ? Math.max(5, hostCount * 0.05)
            : Math.min(86400, baseSec * Math.min(Math.max(hostCount / 50, 0.1), 100) * mult);
        document.getElementById('indTime').textContent = this.formatDuration(scaledSec);

        document.getElementById('indNoise').style.width = profile.noise + '%';
        const idsEl = document.getElementById('indIDS');
        idsEl.textContent = profile.ids;
        idsEl.className = `ids-tag ${profile.idsClass}`;

        const hostCountEl = document.getElementById('indHostCount');
        if (hostCountEl) hostCountEl.textContent = `${hostCount.toLocaleString('fr-FR')} cible(s)`;

        // Explanations (dedupe by key)
        const explContainer = document.getElementById('nmapExplanations');
        const seen = new Set();
        explContainer.innerHTML = flags.map(flag => {
            const key = Object.keys(this.explanations).find(k => flag.startsWith(k)) || flag;
            if (seen.has(key)) return '';
            seen.add(key);
            const info = this.explanations[key];
            if (!info) return '';
            const impactClass = info.impact === 'discret' ? 'exp-stealth' : info.impact === 'bruyant' ? 'exp-loud' : 'exp-neutral';
            return `<div class="explanation-item ${impactClass}">
                <code>${Utils.escapeHtml(flag)}</code>
                <span>${info.text}</span>
            </div>`;
        }).filter(Boolean).join('');

        // Warnings
        const warnContainer = document.getElementById('nmapWarnings');
        if (warnContainer) {
            warnContainer.innerHTML = warnings.length > 0
                ? warnings.map(w => `<div class="builder-warning">${Utils.escapeHtml(w)}</div>`).join('')
                : '';
        }
    },

    generateMultiStep() {
        const target = document.getElementById('nmapTarget').value.trim() || '192.168.1.0/24';
        const outputName = document.getElementById('nmapOutputName').value.trim() || 'scan';
        const timing = parseInt(document.getElementById('nmapTiming').value);
        const pn = document.getElementById('nmapPn').checked ? ' -Pn' : '';
        const scriptList = this.getSelectedScripts();

        const steps = [
            {
                title: '🔍 Étape 1 — Découverte d\'hôtes (Ping Sweep)',
                cmd: `nmap -sn -T${Math.min(timing, 3)} -n -oX ${outputName}_discovery.xml ${target}`,
                desc: 'Identifie rapidement les hôtes actifs sans scanner de ports.',
                postCmd: `grep -oE 'addr="([0-9]+\\.){3}[0-9]+"' ${outputName}_discovery.xml | cut -d'"' -f2 > hosts_alive.txt`,
                time: '~30 sec', noise: 'Faible'
            },
            {
                title: '🔌 Étape 2 — Scan de ports (Top 100)',
                cmd: `nmap -sS${pn} -T${timing} --top-ports 100 -n -oX ${outputName}_ports.xml -iL hosts_alive.txt`,
                desc: 'Scan SYN rapide des 100 ports les plus courants sur les hôtes découverts.',
                time: '~1-3 min', noise: 'Modéré'
            },
            {
                title: '⚙️ Étape 3 — Détection services & versions',
                cmd: `nmap -sV -sS${pn} -T${Math.min(timing, 3)} -p <ports_ouverts> -oX ${outputName}_services.xml -iL hosts_alive.txt`,
                desc: 'Identifie les versions des services sur les ports ouverts trouvés à l\'étape 2.',
                time: '~3-8 min', noise: 'Modéré'
            },
            {
                title: '🔬 Étape 4 — Scripts NSE ciblés',
                cmd: `nmap --script=${scriptList} -sV${pn} -T${Math.min(timing, 3)} -p <ports_ouverts> -oX ${outputName}_vuln.xml -iL hosts_interesting.txt`,
                desc: `Lance les scripts NSE choisis (${scriptList}) sur les hôtes intéressants.`,
                time: '~5-15 min', noise: 'Élevé'
            },
            {
                title: '💻 Étape 5 — OS & Fingerprinting (optionnel)',
                cmd: `nmap -O -sV${pn} -T${Math.min(timing, 2)} --osscan-guess -oX ${outputName}_os.xml -iL hosts_interesting.txt`,
                desc: 'Fingerprinting OS ciblé. Nécessite des privilèges root.',
                time: '~5-10 min', noise: 'Élevé'
            }
        ];

        document.getElementById('multiStepList').innerHTML = steps.map(step => `
            <div class="multistep-item">
                <div class="step-header">
                    <strong>${step.title}</strong>
                    <div class="step-meta">
                        <span class="step-time">⏱️ ${step.time}</span>
                        <span class="step-noise">📡 ${step.noise}</span>
                    </div>
                </div>
                <p class="step-desc">${step.desc}</p>
                <pre class="step-cmd">${Utils.escapeHtml(step.cmd)}</pre>
                ${step.postCmd ? `<details class="step-post"><summary>📤 Extraction des résultats</summary><pre class="step-cmd">${Utils.escapeHtml(step.postCmd)}</pre></details>` : ''}
            </div>
        `).join('');
    },

    copyCommand() {
        const cmd = document.getElementById('nmapCommand').textContent;
        navigator.clipboard.writeText(cmd).then(() => this.flashMessage('📋 Commande copiée !'));
    },

    copyMultiStep() {
        const items = document.querySelectorAll('#multiStepList .multistep-item');
        const text = Array.from(items).map((item, i) => {
            const cmd = item.querySelector('.step-cmd').textContent;
            return `# Étape ${i + 1}\n${cmd}`;
        }).join('\n\n');
        navigator.clipboard.writeText(text).then(() => this.flashMessage('📋 Plan multi-étapes copié !'));
    },

    exportSh(multi = false) {
        let content = '#!/bin/bash\n# Commande Nmap générée par NMAPPER\n# Date: ' + new Date().toISOString().split('T')[0] + '\nset -e\n\n';

        if (multi) {
            const items = document.querySelectorAll('#multiStepList .multistep-item');
            content += '# Plan de scan multi-étapes\n# Adaptez les fichiers intermédiaires selon vos résultats\n\n';
            items.forEach((item, i) => {
                const cmd = item.querySelector('.step-cmd').textContent;
                const desc = item.querySelector('.step-desc').textContent;
                content += `# === Étape ${i + 1} : ${desc}\n${cmd}\n\n`;
            });
        } else {
            content += document.getElementById('nmapCommand').textContent + '\n';
        }

        const blob = new Blob([content], { type: 'text/x-shellscript' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = multi ? 'nmap_multistep.sh' : 'nmap_scan.sh';
        a.click();
        URL.revokeObjectURL(url);
        this.flashMessage('💾 Script exporté');
    },

    saveConfig() {
        const config = {
            timing: document.getElementById('nmapTiming').value,
            target: document.getElementById('nmapTarget').value,
            ports: document.getElementById('nmapPorts2').value,
            exclude: document.getElementById('nmapExclude').value,
            outputName: document.getElementById('nmapOutputName').value,
            checks: {}
        };
        const allIds = Object.keys(this.fieldMap).concat(
            ['nseDefault', 'nseVuln', 'nseSmb', 'nseFtp', 'nseSslEnum', 'nseHttpEnum']
        );
        allIds.forEach(id => {
            const el = document.getElementById(id);
            if (el) config.checks[id] = el.checked;
        });
        try { localStorage.setItem(this.STORAGE_KEY, JSON.stringify(config)); } catch (e) {}
    },

    restoreConfig() {
        try {
            const raw = localStorage.getItem(this.STORAGE_KEY);
            if (!raw) return;
            const config = JSON.parse(raw);
            if (config.timing) document.getElementById('nmapTiming').value = config.timing;
            const elMap = { target: 'nmapTarget', ports: 'nmapPorts2', exclude: 'nmapExclude', outputName: 'nmapOutputName' };
            Object.entries(elMap).forEach(([key, id]) => {
                if (config[key] !== undefined) document.getElementById(id).value = config[key];
            });
            if (config.checks) {
                Object.entries(config.checks).forEach(([id, val]) => {
                    const el = document.getElementById(id);
                    if (el) el.checked = val;
                });
            }
            this.updateDisabledState();
            if (document.getElementById('nmapScripts').checked) {
                document.getElementById('nseScriptsGroup').style.display = 'block';
            }
        } catch (e) {}
    },

    flashMessage(msg, isError = false) {
        const el = document.createElement('div');
        el.className = 'builder-flash' + (isError ? ' error' : '');
        el.textContent = msg;
        document.getElementById('nmapBuilderContent').prepend(el);
        setTimeout(() => el.remove(), 2000);
    }
};

document.addEventListener('DOMContentLoaded', () => NmapBuilder.init());
