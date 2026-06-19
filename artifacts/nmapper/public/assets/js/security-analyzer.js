// security-analyzer.js - Module d'analyse de sécurité
const SecurityAnalyzer = {
    
    // Classification des ports par niveau de risque
    criticalRiskPorts: [
        23,    // Telnet - critique car non chiffré
        102,   // Siemens S7 - automates programmables
        502,   // Modbus TCP - communication industrielle
        1911,  // Siemens TIA Portal - programmation PLC
        2404,  // IEC 61850 - sous-stations électriques
        4840,  // OPC UA - communication inter-systèmes
        44818, // EtherNet/IP - Rockwell Allen-Bradley
        47808, // BACnet - automatisation process
        20000  // DNP3 - SCADA
    ],

    highRiskPorts: [
        161,   // SNMP
        162,   // SNMP Trap
        9200,   // Elasticsearch
        5800    // VNC-HTTP
    ],

    mediumRiskPorts: [
        22,    // SSH
        80,    // HTTP (devrait être HTTPS)
        8000,  // HTTP alternatif
        8080,  // HTTP alternatif
        5060,  // SIP
        5061,   // SIP TLS
        21,    // FTP
        53,    // DNS ouvert
        135,   // RPC
        139,   // NetBIOS
        445,   // SMB
        1433,  // SQL Server
        3389,  // RDP
        5900,  // VNC
        5901,  // VNC
    ],

    // Analyse des vulnérabilités d'un hôte
    analyzeVulnerabilities(ports) {
        const openPorts = ports.filter(p => p.state === 'open');
        
        // Classification des ports ouverts
        const criticalPorts = openPorts.filter(p => this.criticalRiskPorts.includes(p.port));
        const highRiskOpenPorts = openPorts.filter(p => this.highRiskPorts.includes(p.port));
        const mediumRiskOpenPorts = openPorts.filter(p => this.mediumRiskPorts.includes(p.port));
        
        // Critères de vulnérabilité
        
        // 1. Présence d'un seul port critique industriel = vulnérable
        if (criticalPorts.length >= 1) {
            return true;
        }
        
        // 2. Combinaison de 2 ports à risque élevé
        if (highRiskOpenPorts.length >= 2) {
            return true;
        }

        // 2. Combinaison de 3 ports à risque moyen
        if (mediumRiskOpenPorts.length >= 3) {
            return true;
        }
        
        // 4. Profil à risque : beaucoup de services exposés
        if (openPorts.length >= 8) {
            return true;
        }
        
        // 5. Services non sécurisés multiples
        const unsecureServices = openPorts.filter(p => [21, 23, 80, 8000, 8080, 161].includes(p.port));
        if (unsecureServices.length >= 3) {
            return true;
        }
        
        // 6. Détection de patterns dangereux par service
        const dangerousServices = openPorts.filter(port => {
            if (port.service) {
                const service = port.service.toLowerCase();
                return (
                    service.includes('telnet') ||
                    service.includes('ftp') ||
                    service.includes('modbus') ||
                    service.includes('s7') ||
                    service.includes('opcua') ||
                    service.includes('vnc') ||
                    service.includes('snmp')
                );
            }
            return false;
        });
        
        if (dangerousServices.length >= 1) {
            return true;
        }
        
        return false;
    },

    // Évaluer le niveau de risque d'un port
    evaluatePortRisk(port, service) {
        if (this.criticalRiskPorts.includes(port)) return 'critical';
        if (this.highRiskPorts.includes(port)) return 'high';
        if (this.mediumRiskPorts.includes(port)) return 'medium';
        
        // Analyse par service
        if (service) {
            const serviceLower = service.toLowerCase();
            
            // Services industriels critiques
            if (serviceLower.includes('modbus') || serviceLower.includes('s7') || 
                serviceLower.includes('opcua') || serviceLower.includes('ethernet/ip') ||
                serviceLower.includes('profinet') || serviceLower.includes('bacnet')) {
                return 'critical';
            }
            
            // Services dangereux classiques
            if (serviceLower.includes('telnet') || serviceLower.includes('ftp') || 
                serviceLower.includes('rlogin') || serviceLower.includes('vnc') ||
                serviceLower.includes('snmp')) {
                return 'high';
            }
            
            if (serviceLower.includes('ssh') || serviceLower.includes('http') || 
                serviceLower.includes('smtp')) {
                return 'medium';
            }
        }
        
        return 'low';
    },

    // Générer des recommandations de sécurité pour un hôte
    generateSecurityRecommendations(host) {
        const recommendations = [];
        const openPorts = host.ports.filter(p => p.state === 'open');
        
        recommendations.push('Effectuer régulièrement des scans de vulnérabilités pour identifier les failles de sécurité.');
        recommendations.push('Maintenir tous les logiciels et systèmes à jour avec les derniers correctifs de sécurité.');
        recommendations.push('Déployer un pare-feu industriel pour filtrer le trafic entre les zones critiques.');
        
        // Recommandations spécifiques par port
        openPorts.forEach(port => {
            const portRecommendations = this.getPortRecommendations(port);
            if (portRecommendations) {
                recommendations.push(portRecommendations);
            }
        });
        
        // Recommandations spécifiques selon le profil de risque
        if (host.vulnerable) {
            recommendations.push('PRIORITÉ CRITIQUE: Équipement à vérifier.');
        }
        
        // Recommandations par type d'équipement
        const industrialPorts = openPorts.filter(p => this.criticalRiskPorts.includes(p.port));
        if (industrialPorts.length > 0) {
            recommendations.push('Équipement industriel détecté: Implémenter une surveillance réseau ICS/SCADA dédiée.');
        }
        
        const webPorts = openPorts.filter(p => [80, 443, 8000, 8080, 8443].includes(p.port));
        if (webPorts.length > 0) {
            recommendations.push('Interfaces web détectées: Vérifier l\'authentification, les certificats et la configuration HTTPS.');
        }
        
        const remoteAccessPorts = openPorts.filter(p => [22, 23, 3389, 5900, 5901].includes(p.port));
        if (remoteAccessPorts.length > 0) {
            recommendations.push('Accès distant détecté: Implémenter un VPN industriel et une authentification multi-facteurs.');
            recommendations.push('Surveiller et auditer tous les accès distants aux systèmes critiques.');
        }
        
        return [...new Set(recommendations)];
    },

    // Obtenir des recommandations spécifiques pour un port
    getPortRecommendations(port) {
        const portRecommendations = {
            21: 'Port 21 (FTP) ouvert: CRITIQUE en environnement industriel - Remplacer par SFTP ou FTPS avec authentification forte.',
            22: 'Port 22 (SSH) ouvert: MOYEN - Vérifier la sécurité des configurations, désactiver les connexions root et implémenter l\'authentification par clés.',
            23: 'Port 23 (Telnet) ouvert: CRITIQUE - Remplacer immédiatement par SSH. Telnet transmet les mots de passe en clair.',
            53: 'Port 53 (DNS) ouvert: Configurer des serveurs DNS sécurisés et implémenter DNS over TLS si possible.',
            80: 'Port 80 (HTTP) ouvert: Migrer vers HTTPS (443) pour chiffrer les communications des interfaces web.',
            102: 'Port 102 (Siemens S7) ouvert: CRITIQUE - Protocole industriel sans sécurité native. Isoler dans un VLAN dédié avec pare-feu strict.',
            135: 'Port 135 (RPC) ouvert: Limiter l\'accès RPC aux seuls systèmes autorisés et surveiller les tentatives de connexion.',
            139: 'Ports SMB (139/445) ouverts: RISQUE ÉLEVÉ - Désactiver SMBv1, activer la signature SMB et limiter l\'accès aux partages nécessaires.',
            445: 'Ports SMB (139/445) ouverts: RISQUE ÉLEVÉ - Désactiver SMBv1, activer la signature SMB et limiter l\'accès aux partages nécessaires.',
            161: 'Ports SNMP (161/162) ouverts: Utiliser SNMPv3 avec chiffrement, changer les community strings par défaut.',
            162: 'Ports SNMP (161/162) ouverts: Utiliser SNMPv3 avec chiffrement, changer les community strings par défaut.',
            443: 'Port 443 (HTTPS) ouvert: Vérifier les certificats SSL/TLS et utiliser des protocoles sécurisés (TLS 1.2+).',
            502: 'Port 502 (Modbus TCP) ouvert: CRITIQUE - Protocole industriel sans sécurité. Isoler dans un VLAN OT avec authentification réseau.',
            1433: 'Port 1433 (SQL Server) ouvert: Sécuriser avec authentification Windows, chiffrer les connexions et surveiller les accès.',
            1911: 'Port 1911 (Siemens TIA Portal) ouvert: CRITIQUE - Interface de programmation des automates. Restriction d\'accès maximale requise.',
            2404: 'Port 2404 (IEC 61850) ouvert: CRITIQUE - Protocole pour sous-stations électriques. Segmentation réseau obligatoire.',
            3389: 'Port 3389 (RDP) ouvert: RISQUE ÉLEVÉ - Implémenter l\'authentification multi-facteurs, VPN obligatoire et surveillance des connexions.',
            4840: 'Port 4840 (OPC UA) ouvert: Configurer l\'authentification et le chiffrement OPC UA. Surveiller les certificats clients.',
            5060: 'Ports SIP (5060/5061) ouverts: Sécuriser la VoIP industrielle avec chiffrement SRTP et authentification forte.',
            5061: 'Ports SIP (5060/5061) ouverts: Sécuriser la VoIP industrielle avec chiffrement SRTP et authentification forte.',
            5900: 'Ports VNC ouverts: RISQUE ÉLEVÉ - Remplacer par une solution de bureau à distance sécurisée ou utiliser un tunnel VPN.',
            5901: 'Ports VNC ouverts: RISQUE ÉLEVÉ - Remplacer par une solution de bureau à distance sécurisée ou utiliser un tunnel VPN.',
            8000: 'Ports HTTP alternatifs ouverts: Migrer vers HTTPS et implémenter l\'authentification pour les interfaces web industrielles.',
            8080: 'Ports HTTP alternatifs ouverts: Migrer vers HTTPS et implémenter l\'authentification pour les interfaces web industrielles.',
            9200: 'Port 9200 (Elasticsearch) ouvert: Sécuriser avec authentification X-Pack et chiffrement des communications.',
            20000: 'Port 20000 (DNP3) ouvert: CRITIQUE - Protocole SCADA. Implémenter DNP3 Secure Authentication v5 et segmentation réseau.',
            44818: 'Port 44818 (EtherNet/IP) ouvert: CRITIQUE - Protocole Rockwell/Allen-Bradley. Isolation réseau OT obligatoire.',
            47808: 'Port 47808 (BACnet) ouvert: CRITIQUE - Protocole domotique industrielle. Segmentation et authentification requises.'
        };

        return portRecommendations[port.port] || null;
    },

    // Analyser les services critiques d'un hôte
    analyzeCriticalServices(ports) {
        const criticalServices = [];
        const openPorts = ports.filter(p => p.state === 'open');
        
        const criticalPortsMap = {
            21: { service: 'FTP', risk: 'medium', riskText: 'MOYEN', description: 'Protocole non chiffré - Remplacer par SFTP' },
            22: { service: 'SSH', risk: 'medium', riskText: 'MOYEN', description: 'Accès distant - Vérifier la configuration' },
            23: { service: 'Telnet', risk: 'critical', riskText: 'CRITIQUE', description: 'Protocole non sécurisé - À remplacer immédiatement' },
            80: { service: 'HTTP', risk: 'medium', riskText: 'MOYEN', description: 'Trafic non chiffré - Migrer vers HTTPS' },
            102: { service: 'Siemens S7', risk: 'critical', riskText: 'CRITIQUE', description: 'Protocole industriel - Isoler réseau' },
            135: { service: 'RPC', risk: 'medium', riskText: 'MOYEN', description: 'Service Windows - Limiter l\'accès' },
            139: { service: 'NetBIOS', risk: 'medium', riskText: 'MOYEN', description: 'Partage Windows - Sécuriser' },
            445: { service: 'SMB', risk: 'medium', riskText: 'MOYEN', description: 'Partage fichiers - Désactiver SMBv1' },
            502: { service: 'Modbus TCP', risk: 'critical', riskText: 'CRITIQUE', description: 'Protocole industriel sans sécurité' },
            1433: { service: 'SQL Server', risk: 'medium', riskText: 'MOYEN', description: 'Base de données - Sécuriser l\'accès' },
            3389: { service: 'RDP', risk: 'medium', riskText: 'MOYEN', description: 'Bureau à distance - MFA recommandé' },
            5900: { service: 'VNC', risk: 'medium', riskText: 'MOYEN', description: 'Contrôle distant - Chiffrer connexions' }
        };
        
        openPorts.forEach(port => {
            if (criticalPortsMap[port.port]) {
                const info = criticalPortsMap[port.port];
                criticalServices.push({
                    port: port.port,
                    service: port.service || info.service,
                    risk: info.risk,
                    riskText: info.riskText,
                    description: info.description
                });
            }
        });
        
        return criticalServices;
    },

    // Obtenir le label de risque
    getRiskLabel(risk) {
        const labels = {
            'critical': 'CRITIQUE',
            'high': 'ÉLEVÉ',
            'medium': 'MOYEN',
            'low': 'INCONNU/FAIBLE'
        };
        return labels[risk] || 'INCONNU';
    },

    // Générer des recommandations pour un hôte spécifique (version courte)
    generateHostRecommendations(host) {
        const recommendations = [];
        const openPorts = host.ports.filter(p => p.state === 'open');

        // Recommandations générales
        recommendations.push('Effectuer régulièrement des audits de sécurité sur cet équipement');
        recommendations.push('Maintenir le système à jour avec les derniers correctifs de sécurité');

        // Recommandations basées sur les ports
        if (openPorts.some(p => [21, 23].includes(p.port))) {
            recommendations.push('URGENT: Désactiver les protocoles non chiffrés (FTP, Telnet)');
        }

        if (openPorts.some(p => [80, 8000, 8080].includes(p.port))) {
            recommendations.push('Migrer les interfaces web vers HTTPS pour chiffrer les communications');
        }

        if (openPorts.some(p => [22, 3389, 5900].includes(p.port))) {
            recommendations.push('Verifier config et si possible configurer l\'authentification multi-facteurs pour l\'accès distant');
        }

        if (openPorts.some(p => [102, 502, 1911, 4840].includes(p.port))) {
            recommendations.push('CRITIQUE: Isoler les protocoles industriels dans un VLAN dédié');
        }

        if (host.vulnerable) {
            recommendations.push('PRIORITÉ ÉLEVÉE: Audit de sécurité approfondi recommandé');
        }

        return recommendations;
    },

    // Catégoriser le type de dispositif (Windows/Linux/IoT/Industriel)
    categorizeDevice(host) {
        const openPorts = host.ports.filter(p => p.state === 'open');
        const portNumbers = openPorts.map(p => p.port);
        const vendor = (host.vendor || '').toLowerCase();

        // 1. DÉTECTION PAR VENDOR EN PRIORITÉ

        // Détecter équipements INDUSTRIELS via vendor
        const industrialVendors = [
            'siemens', 'beckhoff', 'advantech', 'schneider', 'rockwell',
            'allen-bradley', 'omron', 'mitsubishi', 'abb', 'phoenix contact',
            'wago', 'b&r', 'ge fanuc', 'automation', 'plc', 'scada'
        ];
        if (industrialVendors.some(v => vendor.includes(v))) {
            return { category: 'Industriel', icon: '🏭', color: '#9c27b0' };
        }

        // Détecter ÉCRANS via vendor
        const screenVendors = ['kyocera'];
        if (screenVendors.some(v => vendor.includes(v))) {
            return { category: 'Écran', icon: '🖥️', color: '#00bcd4' };
        }

        // Détecter IMPRIMANTES via vendor
        const printerVendors = [
            'hewlett-packard', 'hp', 'canon', 'epson', 'brother', 'xerox',
            'lexmark', 'samsung', 'ricoh', 'konica', 'sharp',
            'dell printer', 'oki', 'zebra technologies', 'toshiba tec'
        ];
        if (printerVendors.some(v => vendor.includes(v))) {
            return { category: 'Imprimante', icon: '🖨️', color: '#009688' };
        }

        // Détecter Windows via vendor
        const windowsVendors = ['microsoft', 'vmware', 'dell', 'hp', 'hewlett', 'lenovo'];
        if (windowsVendors.some(v => vendor.includes(v)) && portNumbers.includes(445)) {
            return { category: 'Windows', icon: '🪟', color: '#0078d4' };
        }

        // Détecter IoT / embarqué via vendor
        const iotVendors = [
            'raspberry', 'arduino', 'espressif', 'tp-link', 'tplink',
            'netgear', 'ubiquiti', 'hikvision', 'dahua', 'axis',
            'samsung', 'lg', 'xiaomi', 'huawei', 'zte', 'asus',
            'synology', 'qnap', 'buffalo', 'western digital', 'seagate',
            'zebra', 'honeywell', 'elo', 'touch', 'kiosk',
            'embedded', 'iot', 'smart', 'sensor'
        ];
        if (iotVendors.some(v => vendor.includes(v))) {
            return { category: 'IoT', icon: '📡', color: '#4caf50' };
        }

        // 2. DÉTECTION PAR PORTS (si vendor non détecté)

        // Détecter équipements INDUSTRIELS via ports
        const industrialPorts = [102, 502, 1911, 2404, 4840, 44818, 47808, 20000];
        if (portNumbers.some(port => industrialPorts.includes(port))) {
            return { category: 'Industriel', icon: '🏭', color: '#9c27b0' };
        }

        // Détecter IMPRIMANTES via ports
        const printerPorts = [515, 631, 9100]; // printer, IPP (CUPS), jetdirect
        if (portNumbers.some(port => printerPorts.includes(port))) {
            return { category: 'Imprimante', icon: '🖨️', color: '#009688' };
        }

        // Détecter WINDOWS (ports SMB + RPC + netbios)
        const windowsPorts = [135, 139, 445, 3389]; // RPC, NetBIOS, SMB, RDP
        const hasWindowsPorts = windowsPorts.filter(port => portNumbers.includes(port)).length >= 2;
        if (hasWindowsPorts) {
            return { category: 'Windows', icon: '🪟', color: '#0078d4' };
        }

        // Détecter LINUX (SSH sans Windows ou avec ports typiques Linux)
        const hasSSH = portNumbers.includes(22);
        const hasLinuxPorts = portNumbers.some(p => [631, 9100, 10000].includes(p)); // CUPS, Webmin

        if (hasSSH && !hasWindowsPorts) {
            return { category: 'Linux', icon: '🐧', color: '#ff9800' };
        }

        if (hasLinuxPorts) {
            return { category: 'Linux', icon: '🐧', color: '#ff9800' };
        }

        // Ports IoT typiques
        const iotPorts = [1883, 8883, 5683, 8080, 80, 443]; // MQTT, CoAP, HTTP
        const hasIoTPattern = portNumbers.includes(80) && openPorts.length <= 5;
        if (hasIoTPattern) {
            return { category: 'IoT', icon: '📡', color: '#4caf50' };
        }

        // 3. Catégorie par défaut selon les indices disponibles
        // Si SSH seul ou peu de ports = probable Linux/IoT
        if (hasSSH && openPorts.length <= 3) {
            return { category: 'Linux', icon: '🐧', color: '#ff9800' };
        }

        // Si RDP seul = probable Windows
        if (portNumbers.includes(3389)) {
            return { category: 'Windows', icon: '🪟', color: '#0078d4' };
        }

        // Par défaut : Unknown
        return { category: 'Inconnu', icon: '❓', color: '#757575' };
    },

    // Obtenir l'icône de la catégorie
    getCategoryIcon(category) {
        const icons = {
            'Windows': '🪟',
            'Linux': '🐧',
            'IoT': '📡',
            'Industriel': '🏭',
            'Écran': '🖥️',
            'Imprimante': '🖨️',
            'Inconnu': '❓'
        };
        return icons[category] || '❓';
    },

    // ============================================================
    // LOT PRIORITÉ 1 — Analyse enrichie (NSE, versions, OS, score)
    // ============================================================

    // Comparateur de versions sémantiques simplifié : -1, 0, 1
    compareVersions(a, b) {
        const pa = String(a).split('.').map(n => parseInt(n, 10) || 0);
        const pb = String(b).split('.').map(n => parseInt(n, 10) || 0);
        const len = Math.max(pa.length, pb.length);
        for (let i = 0; i < len; i++) {
            const x = pa[i] || 0, y = pb[i] || 0;
            if (x < y) return -1;
            if (x > y) return 1;
        }
        return 0;
    },

    // Extrait un numéro de version (ex: "2.4.41") d'une chaîne libre
    extractVersionNumber(str) {
        const m = String(str || '').match(/(\d+(?:\.\d+){1,3})/);
        return m ? m[1] : null;
    },

    // ---- A2 : Analyse des findings NSE (déjà fournis par Nmap) ----
    analyzeNSEFindings(host) {
        const findings = [];
        const cveRegex = /CVE-\d{4}-\d{4,7}/gi;

        // Mots-clés indiquant une vulnérabilité dans l'output NSE
        const isVuln = txt => /\bVULNERABLE\b|\bexploit/i.test(txt);
        const isWeak = txt => /weak|deprecated|expired|self-signed|sslv2|sslv3|tls.?1\.0|tls.?1\.1|rc4|md5|cleartext|anonymous|null session|default (?:password|credential)/i.test(txt);

        // Scripts à sévérité connue
        const criticalScripts = ['smb-vuln-ms17-010', 'smb-vuln-ms08-067', 'rdp-vuln-ms12-020', 'smb-vuln-cve-2017-7494'];
        const highScripts = ['ftp-anon', 'ftp-vsftpd-backdoor', 'http-shellshock', 'ssl-heartbleed', 'rdp-ntlm-info'];

        const scanScript = (script, source) => {
            if (!script || !script.id) return;
            const id = script.id.toLowerCase();
            const output = script.output || '';
            const text = id + ' ' + output;
            const cves = [...new Set((output.match(cveRegex) || []).map(c => c.toUpperCase()))];

            let severity = null;
            let title = script.id;

            if (criticalScripts.includes(id) || (isVuln(text) && cves.length > 0)) {
                severity = 'critical';
            } else if (highScripts.includes(id) || isVuln(text)) {
                severity = 'high';
            } else if (isWeak(text)) {
                severity = 'medium';
            }

            if (severity) {
                findings.push({
                    source,
                    scriptId: script.id,
                    severity,
                    cves,
                    detail: output.split('\n')[0].slice(0, 160).trim() || title
                });
            }
        };

        (host.hostScripts || []).forEach(s => scanScript(s, 'host'));
        (host.ports || []).filter(p => p.state === 'open').forEach(p => {
            (p.scripts || []).forEach(s => scanScript(s, `port ${p.port}`));
        });

        return findings;
    },

    // ---- A3 : Analyse des versions de service obsolètes/vulnérables ----
    analyzeServiceVersions(host) {
        const findings = [];

        // Règles { match: regex sur "service version", check(version)→bool, severity, title, reco }
        const rules = [
            { svc: /openssh/i, max: '7.0', sev: 'medium', name: 'OpenSSH', reco: 'Mettre à jour OpenSSH (≥ 8.x) — versions < 7.0 multiples CVE.' },
            { svc: /apache|httpd/i, max: '2.4.0', sev: 'medium', name: 'Apache httpd', reco: 'Migrer vers Apache 2.4.x maintenu.' },
            { svc: /nginx/i, max: '1.14.0', sev: 'medium', name: 'nginx', reco: 'Mettre à jour nginx (≥ 1.20).' },
            { svc: /microsoft.?iis|iis httpd/i, max: '8.0', sev: 'high', name: 'Microsoft IIS', reco: 'IIS ≤ 7.5 EOL — migrer vers une version supportée.' },
            { svc: /exim/i, max: '4.92', sev: 'high', name: 'Exim', reco: 'Exim < 4.92 : RCE CVE-2019-10149 — mettre à jour d\'urgence.' },
            { svc: /proftpd/i, max: '1.3.6', sev: 'high', name: 'ProFTPD', reco: 'ProFTPD < 1.3.6 vulnérable — mettre à jour.' },
            { svc: /openssl/i, max: '1.0.2', sev: 'high', name: 'OpenSSL', reco: 'OpenSSL 1.0.x EOL — migrer vers 1.1.1+/3.x.' },
            { svc: /php/i, max: '7.4.0', sev: 'medium', name: 'PHP', reco: 'PHP < 7.4 EOL — mettre à jour.' }
        ];

        // Signatures textuelles dures (pas de comparaison numérique)
        const textSignatures = [
            { re: /vsftpd 2\.3\.4/i, sev: 'critical', name: 'vsftpd 2.3.4', reco: 'Backdoor connue (CVE-2011-2523) — remplacer immédiatement.' },
            { re: /smbv1|smb1|samba 3\./i, sev: 'high', name: 'SMBv1 / Samba 3', reco: 'Désactiver SMBv1 (EternalBlue) — activer SMBv2/3.' },
            { re: /\btls\s?1\.0|sslv3|sslv2\b/i, sev: 'medium', name: 'TLS/SSL obsolète', reco: 'Désactiver SSLv2/v3 et TLS 1.0/1.1.' }
        ];

        (host.ports || []).filter(p => p.state === 'open' && p.version).forEach(p => {
            const vstr = `${p.service || ''} ${p.version}`.trim();

            textSignatures.forEach(sig => {
                if (sig.re.test(vstr)) {
                    findings.push({ port: p.port, severity: sig.sev, name: sig.name, version: p.version, reco: sig.reco });
                }
            });

            rules.forEach(rule => {
                if (!rule.svc.test(vstr)) return;
                const num = this.extractVersionNumber(p.version);
                if (num && this.compareVersions(num, rule.max) < 0) {
                    findings.push({ port: p.port, severity: rule.sev, name: rule.name, version: num, reco: rule.reco });
                }
            });
        });

        return findings;
    },

    // ---- A4 : Détection d'OS obsolète / en fin de vie ----
    analyzeOSRisk(host) {
        if (!host.os || !host.os.name) return null;
        const name = host.os.name;
        const accuracy = parseInt(host.os.accuracy || '0', 10);

        const eolPatterns = [
            { re: /windows\s?(xp|2000|me|vista|nt)/i, sev: 'critical', label: 'Windows EOL (XP/2000/Vista/NT)' },
            { re: /windows\s?7|windows\sserver\s?2008(?!\sr2)?|windows\sserver\s?2003/i, sev: 'high', label: 'Windows 7 / Server 2003-2008 (EOL)' },
            { re: /windows\s?8(?!\.1)|windows\sserver\s?2012(?!\sr2)/i, sev: 'medium', label: 'Windows 8 / Server 2012 (fin de support proche/atteinte)' },
            { re: /linux\s?2\.[0-6]|kernel\s?2\./i, sev: 'high', label: 'Noyau Linux 2.x (EOL)' },
            { re: /ubuntu\s?(1[0-6]\.|[0-9]\.)|debian\s?[0-7]\b/i, sev: 'medium', label: 'Distribution Linux ancienne (EOL probable)' }
        ];

        for (const p of eolPatterns) {
            if (p.re.test(name)) {
                return { severity: p.sev, label: p.label, os: name, accuracy };
            }
        }
        return null;
    },

    // ---- A1 : Score de risque pondéré 0-100 + niveau + facteurs ----
    calculateRiskScore(host) {
        const factors = [];
        let score = 0;
        const add = (pts, label) => { score += pts; factors.push({ pts, label }); };

        const openPorts = (host.ports || []).filter(p => p.state === 'open');

        // 1. Ports par niveau de risque
        const crit = openPorts.filter(p => this.criticalRiskPorts.includes(p.port));
        const high = openPorts.filter(p => this.highRiskPorts.includes(p.port));
        const med = openPorts.filter(p => this.mediumRiskPorts.includes(p.port));
        if (crit.length) add(Math.min(40, crit.length * 22), `${crit.length} port(s) critique(s) OT/non chiffré`);
        if (high.length) add(Math.min(20, high.length * 10), `${high.length} port(s) à risque élevé`);
        if (med.length) add(Math.min(15, med.length * 4), `${med.length} port(s) à risque moyen`);

        // 2. Services non chiffrés
        const cleartext = openPorts.filter(p => [21, 23, 80, 8000, 8080, 161].includes(p.port));
        if (cleartext.length) add(Math.min(15, cleartext.length * 5), `${cleartext.length} service(s) non chiffré(s)`);

        // 3. Findings NSE (faits Nmap)
        const nse = this.analyzeNSEFindings(host);
        const nseW = { critical: 40, high: 25, medium: 10 };
        nse.forEach(f => add(nseW[f.severity] || 0, `NSE ${f.scriptId} (${f.severity})`));

        // 4. Versions obsolètes
        const ver = this.analyzeServiceVersions(host);
        const verW = { critical: 30, high: 18, medium: 8 };
        ver.forEach(f => add(verW[f.severity] || 0, `${f.name} obsolète (${f.severity})`));

        // 5. OS EOL
        const os = this.analyzeOSRisk(host);
        if (os) add({ critical: 30, high: 20, medium: 10 }[os.severity] || 0, `OS EOL : ${os.label}`);

        // 6. Surface d'exposition
        if (openPorts.length >= 10) add(10, `Surface large (${openPorts.length} ports ouverts)`);
        else if (openPorts.length >= 6) add(5, `Surface modérée (${openPorts.length} ports ouverts)`);

        score = Math.max(0, Math.min(100, Math.round(score)));

        let level;
        if (score >= 70) level = 'critical';
        else if (score >= 45) level = 'high';
        else if (score >= 20) level = 'medium';
        else if (score > 0) level = 'low';
        else level = 'info';

        // Escalade sémantique : un finding confirmé impose un plancher de gravité
        // (ex: une RCE NSE "VULNERABLE" = hôte critique quel que soit le score brut)
        const order = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
        const allSeverities = [
            ...nse.map(f => f.severity),
            ...ver.map(f => f.severity),
            ...(os ? [os.severity] : [])
        ];
        allSeverities.forEach(sev => {
            if ((order[sev] || 0) > (order[level] || 0)) level = sev;
        });

        return {
            score,
            level,
            factors,
            nseFindings: nse,
            versionFindings: ver,
            osFinding: os
        };
    },

    // Label lisible d'un niveau de score
    getScoreLabel(level) {
        return {
            critical: 'CRITIQUE',
            high: 'ÉLEVÉ',
            medium: 'MOYEN',
            low: 'FAIBLE',
            info: 'OK'
        }[level] || 'INCONNU';
    },

    // Couleur d'un niveau (alignée sur la palette UI)
    getScoreColor(level) {
        return {
            critical: '#f43f5e',
            high: '#f59e0b',
            medium: '#eab308',
            low: '#22c55e',
            info: '#5f6b85'
        }[level] || '#5f6b85';
    }
};