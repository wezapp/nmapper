// file-processor.js - Module de traitement des fichiers Nmap

// Détecte le VLAN depuis l'IP (convention 10.x.VLAN.host ou 192.168.VLAN.host)
function _detectVlanFromIp(ip) {
    let m = ip.match(/^10\.\d+\.(\d+)\.\d+$/);
    if (m) return 'VLAN' + parseInt(m[1], 10);
    m = ip.match(/^172\.(1[6-9]|2\d|3[01])\.(\d+)\.\d+$/);
    if (m) return 'VLAN' + parseInt(m[2], 10);
    m = ip.match(/^192\.168\.(\d+)\.\d+$/);
    if (m) return 'VLAN' + parseInt(m[1], 10);
    return null;
}

const FileProcessor = {
    
    handleFiles(files) {
        if (files.length === 0) return;
        
        showLoading(true);
        clearNetworkData();
        
        const fileListContainer = document.getElementById('selectedFiles');
        fileListContainer.innerHTML = '';
        
        let processedFiles = 0;
        const totalFiles = files.length;
        
        files.forEach(file => {
            const fileItem = document.createElement('div');
            fileItem.className = 'file-item';
            fileItem.innerHTML = `<span>📄 ${Utils.escapeHtml(file.name)}</span><span>${formatFileSize(file.size)}</span>`;
            fileListContainer.appendChild(fileItem);
            
            const reader = new FileReader();
            reader.onload = (e) => {
                const content = e.target.result;
                const fileName = file.name.replace(/\.(xml|txt)$/, '');
                
                try {
                    if (file.name.endsWith('.xml')) {
                        this.parseNmapXML(content, fileName);
                    } else if (file.name.endsWith('.txt')) {
                        this.parseNmapText(content, fileName);
                    }
                    
                    fileItem.style.background = 'rgba(76, 175, 80, 0.2)';
                } catch (error) {
                    console.error(`Erreur lors du traitement de ${file.name}:`, error);
                    fileItem.style.background = 'rgba(244, 67, 54, 0.2)';
                    fileItem.innerHTML += '<span style="color: #FF5722;"> ❌ Erreur</span>';
                    showMessage('error', `❌ Erreur sur ${Utils.escapeHtml(file.name)} : format non reconnu`);
                }
                
                processedFiles++;
                if (processedFiles === totalFiles) {
                    this.finalizeProcessing(totalFiles);
                }
            };
            reader.readAsText(file);
        });
    },

    finalizeProcessing(totalFiles) {
        networkData.stats.files = totalFiles;
        updateVisualization();
        updateStats();
        showLoading(false);
        showMessage('success', `✅ ${totalFiles} fichier(s) traité(s) avec succès !`);
        if (typeof ActivityLog !== 'undefined') {
          ActivityLog.logEvent('import_file', `${totalFiles} fichier(s)`, 'success', `${networkData.hosts.length} hôtes chargés`);
        }
        
        // Afficher les sections après le chargement
        document.getElementById('portFilters').style.display = 'block';
        document.getElementById('pdfReports').style.display = 'block';
        PDFReports.updateHostSelector();
    },
    
    // Parser XML Nmap 
    parseNmapXML(xmlContent, fileName) {
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(xmlContent, 'text/xml');
        const hosts = xmlDoc.querySelectorAll('host');
        
        hosts.forEach(host => {
            const ipElement = host.querySelector('address[addrtype="ipv4"]');
            if (!ipElement) return;
            
            const ip = ipElement.getAttribute('addr');
            
            // Récupérer les informations vendor depuis l'adresse MAC
            let vendor = null;
            let macAddress = null;
            const macElement = host.querySelector('address[addrtype="mac"]');
            if (macElement) {
                macAddress = macElement.getAttribute('addr');
                vendor = macElement.getAttribute('vendor') || 'Inconnu';
            }
            
            const ports = [];
            const portElements = host.querySelectorAll('port');
            portElements.forEach(port => {
                const portId = port.getAttribute('portid');
                const state = port.querySelector('state').getAttribute('state');
                const serviceElement = port.querySelector('service');
                const service = serviceElement ? serviceElement.getAttribute('name') : 'unknown';

                // A3: capturer produit / version / extrainfo (issus de -sV)
                const product = serviceElement ? (serviceElement.getAttribute('product') || '') : '';
                const version = serviceElement ? (serviceElement.getAttribute('version') || '') : '';
                const extrainfo = serviceElement ? (serviceElement.getAttribute('extrainfo') || '') : '';
                const versionStr = [product, version, extrainfo].filter(Boolean).join(' ').trim();

                // S2: Parser les scripts NSE attachés au port
                const scripts = [];
                const scriptElements = port.querySelectorAll('script');
                scriptElements.forEach(script => {
                    scripts.push({
                        id: script.getAttribute('id'),
                        output: script.getAttribute('output') || script.textContent
                    });
                });

                ports.push({ port: parseInt(portId), state: state, service: service, version: versionStr, product: product, scripts: scripts });
            });
            
            // S2: Parser les scripts NSE au niveau host (hostscript)
            const hostScripts = [];
            const hostScriptElements = host.querySelectorAll('hostscript > script');
            hostScriptElements.forEach(script => {
                hostScripts.push({
                    id: script.getAttribute('id'),
                    output: script.getAttribute('output') || script.textContent
                });
            });
            
            // S3: Parser les hostnames (PTR, user)
            const hostnames = [];
            const hostnameElements = host.querySelectorAll('hostnames > hostname');
            hostnameElements.forEach(hn => {
                hostnames.push({
                    name: hn.getAttribute('name'),
                    type: hn.getAttribute('type')
                });
            });
            
            // S3: Parser l'OS detection
            let os = null;
            const osMatchElement = host.querySelector('osmatch');
            if (osMatchElement) {
                os = {
                    name: osMatchElement.getAttribute('name'),
                    accuracy: osMatchElement.getAttribute('accuracy')
                };
            }
            
            const hostData = {
                ip: ip,
                vlan: _detectVlanFromIp(ip) || fileName,
                ports: ports,
                vulnerable: SecurityAnalyzer.analyzeVulnerabilities(ports),
                source: fileName,
                vendor: vendor,
                macAddress: macAddress,
                hostnames: hostnames,
                os: os,
                hostScripts: hostScripts
            };

            // LOT P1 : score de risque pondéré + findings détaillés
            const risk = SecurityAnalyzer.calculateRiskScore(hostData);
            hostData.riskScore = risk.score;
            hostData.riskLevel = risk.level;
            hostData.riskFactors = risk.factors;
            hostData.nseFindings = risk.nseFindings;
            hostData.versionFindings = risk.versionFindings;
            hostData.osFinding = risk.osFinding;

            addHostToData(hostData);
        });
    },
    
    // Parser texte Nmap
    parseNmapText(textContent, fileName) {
        const lines = textContent.split('\n');
        let currentHost = null;
        let currentPort = null;
        let currentNseScript = null;

        const finalizeHost = () => {
            if (currentHost && currentHost.ports.length > 0) {
                currentHost.vulnerable = SecurityAnalyzer.analyzeVulnerabilities(currentHost.ports);
                const risk = SecurityAnalyzer.calculateRiskScore(currentHost);
                currentHost.riskScore = risk.score;
                currentHost.riskLevel = risk.level;
                currentHost.riskFactors = risk.factors;
                currentHost.nseFindings = risk.nseFindings;
                currentHost.versionFindings = risk.versionFindings;
                currentHost.osFinding = risk.osFinding;
                addHostToData(currentHost);
            }
            currentHost = null;
            currentPort = null;
            currentNseScript = null;
        };

        lines.forEach((line, index) => {
            const trimmed = line.trim();

            // Nmap scan report for [hostname (]IP[)]
            const hostMatch = trimmed.match(/Nmap scan report for (?:(\S+) \()?(\d+\.\d+\.\d+\.\d+)\)?/);
            if (hostMatch) {
                finalizeHost();
                currentHost = {
                    ip: hostMatch[2],
                    vlan: _detectVlanFromIp(hostMatch[2]) || fileName,
                    ports: [],
                    vulnerable: false,
                    source: fileName,
                    vendor: null,
                    macAddress: null,
                    hostnames: hostMatch[1] ? [{ name: hostMatch[1], type: 'PTR' }] : [],
                    os: null,
                    hostScripts: []
                };
                return;
            }

            if (!currentHost) return;

            // MAC address + vendor
            const macMatch = trimmed.match(/MAC Address: ([0-9A-Fa-f:]{17}) \((.+)\)/);
            if (macMatch) {
                currentHost.macAddress = macMatch[1];
                currentHost.vendor = macMatch[2];
                return;
            }

            // Port line — resets NSE context
            const portMatch = trimmed.match(/^(\d+)\/tcp\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?/);
            if (portMatch) {
                currentNseScript = null;
                currentPort = {
                    port: parseInt(portMatch[1]),
                    state: portMatch[2],
                    service: portMatch[3],
                    version: (portMatch[4] || '').trim(),
                    scripts: []
                };
                currentHost.ports.push(currentPort);
                return;
            }

            // NSE single-line: |_scriptname: output  (no space between |_ and name)
            const nseSingle = trimmed.match(/^\|_([a-z][\w-]*):\s*(.*)/i);
            if (nseSingle && currentPort) {
                currentPort.scripts.push({ id: nseSingle[1], output: nseSingle[2].trim() });
                currentNseScript = null;
                return;
            }

            // NSE continuation: |   line or |_  line (space after |_ means continuation)
            if (currentNseScript && (trimmed.startsWith('|_') || trimmed.startsWith('|'))) {
                const content = trimmed.replace(/^\|_?\s*/, '');
                currentNseScript.output += (currentNseScript.output ? '\n' : '') + content;
                if (trimmed.startsWith('|_')) currentNseScript = null;
                return;
            }

            // NSE multi-line start: | scriptname:
            const nseStart = trimmed.match(/^\|\s+([a-z][\w-]*):/i);
            if (nseStart && currentPort) {
                currentNseScript = { id: nseStart[1], output: '' };
                currentPort.scripts.push(currentNseScript);
                return;
            }

            // Host boundary
            if (trimmed === '' || trimmed.startsWith('Nmap done') || index === lines.length - 1) {
                finalizeHost();
            }
        });

        if (currentHost && currentHost.ports.length > 0) {
            finalizeHost();
        }
    },

    // Fonction pour obtenir une icône basée sur le vendor
    getVendorIcon(vendor) {
        if (!vendor) return '?';
        
        const vendorLower = vendor.toLowerCase();
        
        // Équipements réseau et sécurité
        if (vendorLower.includes('cisco')) return '🌐';
        if (vendorLower.includes('netgear')) return '📡';
        if (vendorLower.includes('tp-link') || vendorLower.includes('tplink')) return '📡';
        if (vendorLower.includes('trendnet')) return '📡';
        if (vendorLower.includes('palo alto')) return '🛡️';
        if (vendorLower.includes('synology')) return '💾';
        
        // Systèmes industriels et automation
        if (vendorLower.includes('siemens')) return '🏭';
        if (vendorLower.includes('beckhoff')) return '⚙️';
        if (vendorLower.includes('advantech')) return '🔧';
        if (vendorLower.includes('lippert')) return '🔧';
        if (vendorLower.includes('sma regelsysteme') || vendorLower.includes('sma')) return '⚡';
        if (vendorLower.includes('axiom technology')) return '🔧';
        if (vendorLower.includes('asem')) return '🏭';
        if (vendorLower.includes('aaeon')) return '💻';
        
        // Serveurs et informatique d'entreprise
        if (vendorLower.includes('hewlett packard') || vendorLower.includes('hp')) return 'HP';
        if (vendorLower.includes('dell')) return 'Dell';
        if (vendorLower.includes('vmware')) return '☁️';
        if (vendorLower.includes('microsoft')) return '🪟';
        if (vendorLower.includes('intel')) return '💡';
        if (vendorLower.includes('broadcom')) return '🔌';
        if (vendorLower.includes('fujitsu')) return '🖥️';
        
        // Équipements spécialisés
        if (vendorLower.includes('zebra')) return '🏷️';
        if (vendorLower.includes('elo touch') || vendorLower.includes('elo')) return '🖥️';
        if (vendorLower.includes('kyocera')) return '🖨️';
        
        // Par défaut selon le type d'équipement détecté
        if (vendorLower.includes('automation') || vendorLower.includes('industrial')) return '🏭';
        if (vendorLower.includes('network') || vendorLower.includes('switch') || vendorLower.includes('router')) return '🌐';
        if (vendorLower.includes('technology') || vendorLower.includes('tech')) return '💻';
        
        return '?';
    }
};