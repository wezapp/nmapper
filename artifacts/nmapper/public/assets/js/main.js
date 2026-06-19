// main.js - Fichier principal et gestionnaire d'état
// Variables globales
let networkData = { vlans: {}, hosts: [], stats: { vlans: 0, hosts: 0, ports: 0, vulnerable: 0, files: 0 } };
let filteredData = null;
let currentView = 'vlans';
let currentVLAN = null;
let svg, width, height, simulation, zoomBehavior;
let currentMethod = 'files';
let activeFilters = {
    ports: [],
    services: [],
    states: ['open'],
    minPorts: 0,
    onlyVulnerable: false,
    excludeVulnerable: false,
    ipPattern: '',
    vendor: ''
};

// ── Overlay agents live (T4) ──────────────────────────────────────────────────
window._liveAgentIPs = new Set();
let _agentPollInterval = null;

async function fetchLiveAgents() {
    try {
        const res = await fetch('/scanner-api/monitor/hosts', {credentials: 'include'});
        if (!res.ok) return;
        const data = await res.json();
        const ips = new Set((data.hosts || []).map(h => h.ip).filter(Boolean));
        const changed = ips.size !== window._liveAgentIPs.size ||
            [...ips].some(ip => !window._liveAgentIPs.has(ip));
        window._liveAgentIPs = ips;
        if (changed && (currentView === 'vlans' || currentView === 'hosts')) {
            // Re-render to reflect live badges without full reload
            const g = svg.select('.main-group');
            g.selectAll('.nv-pulse-live').style('stroke-opacity', '0.7');
        }
    } catch (_) {}
}

function startAgentOverlay() {
    fetchLiveAgents();
    if (!_agentPollInterval) {
        _agentPollInterval = setInterval(fetchLiveAgents, 30_000);
    }
}

// Initialisation
document.addEventListener('DOMContentLoaded', function() {
    initializeVisualization();
    setupEventHandlers();
    setupGlobalSearch();
    startAgentOverlay();
});

function initializeVisualization() {
    const container = d3.select('#network-viz');
    const containerNode = container.node();

    // Supprimer le SVG existant pour permettre la réinitialisation
    container.select('svg').remove();
    if (simulation) { simulation.stop(); simulation = null; }

    width  = containerNode.clientWidth  || (window.innerWidth  - 260);
    height = Math.max(600, containerNode.clientHeight || 600);

    svg = container.append('svg').attr('width', width).attr('height', height);
    
    // Groupe principal pour le zoom
    const g = svg.append('g').attr('class', 'main-group');
    
    // Configuration zoom améliorée
    zoomBehavior = d3.zoom()
        .scaleExtent([0.1, 8])
        .on('zoom', (event) => {
            NetworkVisualization.hideTooltip();
            g.attr('transform', event.transform);
        })
        .on('end', () => {
            if (simulation) {
                simulation.alpha(0.1).restart();
            }
        });
    
    svg.call(zoomBehavior);
    
    // Ajouter des contrôles de zoom
    const controls = svg.append('g').attr('class', 'zoom-controls');
    
    // Boutons de zoom
    addZoomControls(controls, zoomBehavior);
}

function addZoomControls(controls, zoom) {
    // Bouton Zoom In
    controls.append('rect')
        .attr('x', 10).attr('y', 10).attr('width', 30).attr('height', 30)
        .attr('fill', 'rgba(0,0,0,0.7)').attr('stroke', '#fff').attr('rx', 5)
        .style('cursor', 'pointer')
        .on('click', () => {
            svg.transition().call(zoom.scaleBy, 1.5);
        });
    
    controls.append('text')
        .attr('x', 25).attr('y', 30).attr('text-anchor', 'middle')
        .attr('fill', 'white').text('+').style('font-size', '20px').style('pointer-events', 'none');
    
    // Bouton Zoom Out
    controls.append('rect')
        .attr('x', 10).attr('y', 45).attr('width', 30).attr('height', 30)
        .attr('fill', 'rgba(0,0,0,0.7)').attr('stroke', '#fff').attr('rx', 5)
        .style('cursor', 'pointer')
        .on('click', () => {
            svg.transition().call(zoom.scaleBy, 0.7);
        });
    
    controls.append('text')
        .attr('x', 25).attr('y', 65).attr('text-anchor', 'middle')
        .attr('fill', 'white').text('-').style('font-size', '20px').style('pointer-events', 'none');
    
    // Bouton Reset
    controls.append('rect')
        .attr('x', 10).attr('y', 80).attr('width', 30).attr('height', 30)
        .attr('fill', 'rgba(0,0,0,0.7)').attr('stroke', '#fff').attr('rx', 5)
        .style('cursor', 'pointer')
        .on('click', () => {
            svg.transition().call(zoom.transform, d3.zoomIdentity);
        });
    
    controls.append('text')
        .attr('x', 25).attr('y', 100).attr('text-anchor', 'middle')
        .attr('fill', 'white').text('☖').style('font-size', '16px').style('pointer-events', 'none');
}

function setupEventHandlers() {
    document.getElementById('fileInput').addEventListener('change', function(event) {
        FileProcessor.handleFiles(Array.from(event.target.files));
    });

    // Import session file input
    const importInput = document.getElementById('importSessionInput');
    if (importInput) {
        importInput.addEventListener('change', function() {
            Utils.importSession(this.files[0]);
            this.value = '';
        });
    }

    // Delegated event handler — replaces all inline onclick attributes (CSP-safe)
    document.addEventListener('click', function(event) {
        const el = event.target.closest('[data-action]');
        if (!el) return;

        const action = el.dataset.action;
        const arg = el.dataset.arg;

        const actions = {
            selectMethod:              () => selectMethod(arg),
            scanDirectory:             () => scanDirectory(document.getElementById('directoryPath').value),
            exportSession:             () => Utils.exportSession(),
            toggleFilters:             () => toggleFilters(),
            addPortFilter:             () => addPortFilter(arg),
            addServiceFilter:          () => addServiceFilter(arg),
            applyFilters:              () => applyFilters(),
            clearFilters:              () => clearFilters(),
            resetView:                 () => resetView(),
            togglePDFSection:          () => togglePDFSection(),
            generateGlobalReport:      () => generateGlobalReport(),
            generateSelectedHostReport:() => generateSelectedHostReport(),
            generateFilteredReport:    () => generateFilteredReport(),
            exportCSVAll:              () => CSVExport.exportAll(),
            exportCSVFiltered:         () => CSVExport.exportFiltered(),
            monSetModeCampaign:        () => Monitoring.setMode('campaign'),
            monSetModeLive:            () => Monitoring.setMode('live'),
            monRefresh:                () => Monitoring.refresh(),
            monClearEvents:            () => Monitoring.clearEvents(),
            showVLANView:              () => showVLANView(),
            showFilteredVLANView:      () => NetworkVisualization.showFilteredVLANView(),
            closePopup:                () => NetworkVisualization.closePopup(),
            closePopupOverlay:         () => { if (event.target === el) NetworkVisualization.closePopup(); },
            toggleTheme:               () => toggleTheme(),
            toggleNmapBuilder:         () => { const c = document.getElementById('nmapBuilderContent'); c.classList.toggle('active'); },
            nmapPreset:                () => NmapBuilder.applyPreset(arg),
            copyNmapCmd:               () => NmapBuilder.copyCommand(),
            exportNmapSh:              () => NmapBuilder.exportSh(false),
            copyMultiStep:             () => NmapBuilder.copyMultiStep(),
            exportMultiSh:             () => NmapBuilder.exportSh(true),
            useLoadedHosts:            () => NmapBuilder.useLoadedHosts(),
            resetNmapBuilder:          () => NmapBuilder.reset()
        };

        if (actions[action]) {
            event.preventDefault();
            actions[action]();
        }
    });
}

// Fonctions utilitaires globales
function showLoading(show) {
    document.getElementById('loadingIndicator').style.display = show ? 'block' : 'none';
}

function clearNetworkData() {
    networkData = { vlans: {}, hosts: [], stats: { vlans: 0, hosts: 0, ports: 0, vulnerable: 0, files: 0 } };
    filteredData = null;
    document.getElementById('portFilters').style.display = 'none';
}

function showMessage(type, message) {
    const existingMessage = document.querySelector('.message-box');
    if (existingMessage) existingMessage.remove();
    
    const messageBox = document.createElement('div');
    messageBox.className = `message-box ${type}-box`;
    messageBox.textContent = message;
    
    const controls = document.querySelector('.controls');
    controls.parentNode.insertBefore(messageBox, controls);
    
    if (type === 'success' || type === 'info') {
        setTimeout(() => {
            if (messageBox.parentNode) messageBox.remove();
        }, 5000);
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function addHostToData(host) {
    if (!networkData.vlans[host.vlan]) {
        networkData.vlans[host.vlan] = { id: host.vlan, hosts: [] };
    }
    networkData.vlans[host.vlan].hosts.push(host);
    networkData.hosts.push(host);
}

function updateStats() {
    const data = filteredData || networkData;
    document.getElementById('vlanCount').textContent = Object.keys(data.vlans).length;
    document.getElementById('hostCount').textContent = data.hosts.length;
    document.getElementById('portCount').textContent = data.hosts.reduce((sum, host) => sum + host.ports.filter(p => p.state === 'open').length, 0);
    document.getElementById('vulnerableCount').textContent = data.hosts.filter(h => h.vulnerable).length;
    document.getElementById('fileCount').textContent = networkData.stats.files;
}

function updateVisualization() {
    if (currentView === 'vlans') {
        NetworkVisualization.showVLANView();
        // Afficher le tableau avec tous les hôtes en vue générale
        if (networkData.hosts.length > 0) {
            initHostTable(networkData.hosts, null);
        }
    } else if (currentView === 'hosts' && currentVLAN) {
        NetworkVisualization.showHostView(currentVLAN);
        // Afficher le tableau avec les hôtes du VLAN
        const data = filteredData || networkData;
        const vlan = data.vlans[currentVLAN];
        if (vlan && vlan.hosts.length > 0) {
            initHostTable(vlan.hosts, currentVLAN);
        }
    }
    const dashView = document.getElementById('view-dashboard');
    if (dashView && dashView.classList.contains('active')) renderDashboard();
}

document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        const popup = document.getElementById('statsPopup');
        if (popup && popup.classList.contains('active')) {
            NetworkVisualization.closePopup();
        }
    }
});

// Gestion du redimensionnement
window.addEventListener('resize', function() {
    const container = d3.select('#network-viz');
    const containerNode = container.node();
    width = containerNode.clientWidth;
    height = Math.max(600, containerNode.clientHeight);
    
    svg.attr('width', width).attr('height', height);
    
    if (simulation) {
        simulation.force('center', d3.forceCenter(width / 2, height / 2));
        simulation.alpha(0.3).restart();
    }
});

// Fonctions pour la sélection de méthode
function selectMethod(method) {
    document.querySelectorAll('.method-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelector(`[data-action="selectMethod"][data-arg="${method}"]`).classList.add('active');
    document.querySelectorAll('.method-content').forEach(content => content.classList.remove('active'));
    document.getElementById(`method-${method}`).classList.add('active');
    currentMethod = method;
}

// Scanner le répertoire via serveur local
async function scanDirectory(dir) {
    const baseUrl = window.location.origin +dir;
    showLoading(true);
    clearNetworkData();
    
    try {
        showMessage('info', '🔍 Scan du répertoire en cours...');
        const response = await fetch(baseUrl);

        if (!response.ok) {
            throw new Error(`Erreur HTTP: ${response.status}`);
        }
        
        const html = await response.text();
        const nmapFiles = parseDirectoryListing(html);

        if (nmapFiles.length === 0) {
            showMessage('warning', '⚠️ Aucun fichier Nmap (.xml/.txt) trouvé dans le répertoire');
            showLoading(false);
            return;
        }
        
        showMessage('info', `🔍 ${nmapFiles.length} fichier(s) Nmap trouvé(s). Téléchargement en cours...`);
        await downloadAndProcessFiles(nmapFiles, baseUrl);
        
    } catch (error) {
        console.error('Erreur lors du scan du répertoire:', error);
        showMessage('error', `❌ Erreur: ${error.message}. Vérifiez que le serveur local fonctionne.`);
        showLoading(false);
    }
}

// Parser la liste HTML du répertoire
function parseDirectoryListing(html) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');
    const links = doc.querySelectorAll('a[href]');
    
    const nmapFiles = [];
    links.forEach(link => {
        const href = link.getAttribute('href');
        const fileName = href.replace('/', '');
        
        if ((fileName.endsWith('.xml') || fileName.endsWith('.txt')) && 
            !fileName.includes('alive') && 
            !fileName.includes('sample') &&
            !fileName.includes('.html')) {
            
            const sizeSpan = link.querySelector('.size');
            const size = sizeSpan ? parseInt(sizeSpan.textContent) : 0;
            
            nmapFiles.push({ name: fileName, path: href, size: size });
        }
    });
    
    return nmapFiles;
}

// Télécharger et traiter les fichiers depuis le serveur
async function downloadAndProcessFiles(files, baseUrl) {
    const fileListContainer = document.getElementById('selectedFiles');
    fileListContainer.innerHTML = '<h4>📥 Fichiers téléchargés :</h4>';
    
    let processedFiles = 0;
    let successCount = 0;
    const totalFiles = files.length;
    
    for (const file of files) {
        const fileItem = document.createElement('div');
        fileItem.className = 'file-item';
        fileItem.innerHTML = `<span>⏳ ${Utils.escapeHtml(file.name)}</span><span>${formatFileSize(file.size)}</span>`;
        fileListContainer.appendChild(fileItem);

        try {
            const response = await fetch(baseUrl + "/" + file.path);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);

            const content = await response.text();
            const fileName = file.name.replace(/\.(xml|txt)$/, '');

            if (file.name.endsWith('.xml')) {
                FileProcessor.parseNmapXML(content, fileName);
            } else if (file.name.endsWith('.txt')) {
                FileProcessor.parseNmapText(content, fileName);
            }

            fileItem.style.background = 'rgba(76, 175, 80, 0.2)';
            fileItem.innerHTML = `<span>✅ ${Utils.escapeHtml(file.name)}</span><span>${formatFileSize(file.size)}</span>`;
            successCount++;

        } catch (error) {
            console.error(`Erreur lors du traitement de ${file.name}:`, error);
            fileItem.style.background = 'rgba(244, 67, 54, 0.2)';
            fileItem.innerHTML = `<span>❌ ${Utils.escapeHtml(file.name)}</span><span>${Utils.escapeHtml(error.message)}</span>`;
        }
        
        processedFiles++;
        const progress = Math.round((processedFiles / totalFiles) * 100);
        showMessage('info', `⌛ Progression: ${progress}% (${processedFiles}/${totalFiles})`);
    }
    
    networkData.stats.files = successCount;
    updateVisualization();
    updateStats();
    showLoading(false);

    if (successCount > 0) {
        showMessage('success', `✅ ${successCount}/${totalFiles} fichier(s) traité(s) avec succès !`);
        document.getElementById('portFilters').style.display = 'block';
        PDFReports.updateHostSelector();
    } else {
        showMessage('error', '❌ Aucun fichier n\'a pu être traité correctement.');
    }
}

// ============================
// Feature 1: Theme Toggle
// ============================
function toggleTheme() {
    document.body.classList.toggle('light-theme');
    const btn = document.querySelector('[data-action="toggleTheme"]');
    if (document.body.classList.contains('light-theme')) {
        btn.textContent = '☀️';
        localStorage.setItem('nmapper-theme', 'light');
    } else {
        btn.textContent = '🌙';
        localStorage.setItem('nmapper-theme', 'dark');
    }
    // Les couleurs de nœuds sont mises en cache : invalider après bascule de thème
    if (typeof NetworkVisualization !== 'undefined' && NetworkVisualization.invalidateThemeColors) {
        NetworkVisualization.invalidateThemeColors();
    }
}

// Restore theme on load
(function() {
    document.addEventListener('DOMContentLoaded', () => {
        if (localStorage.getItem('nmapper-theme') === 'light') {
            document.body.classList.add('light-theme');
            const btn = document.querySelector('[data-action="toggleTheme"]');
            if (btn) btn.textContent = '☀️';
        }
    });
})();

// ============================
// Feature 3: Global Search
// ============================
function setupGlobalSearch() {
    const input = document.getElementById('globalSearchInput');
    const results = document.getElementById('searchResults');
    if (!input || !results) return;

    input.addEventListener('input', function() {
        const query = this.value.trim().toLowerCase();
        if (query.length < 2) { results.innerHTML = ''; return; }

        const matches = networkData.hosts.filter(host => {
            const openPorts = host.ports.filter(p => p.state === 'open');
            const searchable = [
                host.ip,
                host.vendor || '',
                host.vlan,
                ...(host.hostnames || []).map(h => h.name),
                host.os ? host.os.name : '',
                ...openPorts.map(p => `${p.port}`),
                ...openPorts.map(p => p.service || '')
            ].join(' ').toLowerCase();
            return searchable.includes(query);
        }).slice(0, 15);

        if (matches.length === 0) {
            results.innerHTML = '<div class="search-no-result">Aucun résultat</div>';
            return;
        }

        results.innerHTML = matches.map(host => {
            const hostname = (host.hostnames && host.hostnames.length > 0) ? host.hostnames[0].name : '';
            const openCount = host.ports.filter(p => p.state === 'open').length;
            return `<div class="search-result-item" data-ip="${Utils.escapeHtml(host.ip)}">
                <span class="sr-ip">${Utils.escapeHtml(host.ip)}</span>
                ${hostname ? `<span class="sr-hostname">${Utils.escapeHtml(hostname)}</span>` : ''}
                <span class="sr-meta">${Utils.escapeHtml(host.vendor || '?')} · ${openCount} ports · ${host.vulnerable ? '⚠️' : '✅'}</span>
            </div>`;
        }).join('');
    });

    results.addEventListener('click', function(e) {
        const item = e.target.closest('.search-result-item');
        if (!item) return;
        const ip = item.dataset.ip;
        NetworkVisualization.navigateToHost(ip);
        results.innerHTML = '';
        input.value = '';
    });

    // Keyboard shortcut: / to focus search
    document.addEventListener('keydown', function(e) {
        if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
            e.preventDefault();
            input.focus();
        }
        if (e.key === 'Escape') {
            if (document.activeElement === input) {
                input.blur();
                results.innerHTML = '';
                input.value = '';
            }
            NetworkVisualization.closePopup();
        }
    });
}

// ============================
// Feature 4: Dashboard Stats
// ============================
function renderDashboard() {
    const empty   = document.getElementById('dashEmptyState');
    const content = document.getElementById('dashContent');
    if (!empty || !content) return;

    if (networkData.hosts.length === 0) {
        empty.style.display   = 'block';
        content.style.display = 'none';
        return;
    }
    empty.style.display   = 'none';
    content.style.display = 'block';

    renderScoreBreakdown();
    renderRiskChart();
    renderDeviceTypes();
    renderTopPorts();
    renderVendorChart();
    renderNSEChart();
}

function renderScoreBreakdown() {
    const container = document.getElementById('dashKpiRow');
    if (!container) return;

    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    networkData.hosts.forEach(h => {
        const { level } = SecurityAnalyzer.calculateRiskScore(h);
        counts[level] = (counts[level] || 0) + 1;
    });

    const levels = [
        { key: 'critical', label: 'Critique', color: 'var(--danger)', glow: 'var(--danger-dim)' },
        { key: 'high',     label: 'Élevé',    color: 'var(--warn)',   glow: 'var(--warn-dim)'   },
        { key: 'medium',   label: 'Moyen',    color: '#eab308',       glow: 'rgba(234,179,8,.14)'},
        { key: 'low',      label: 'Faible',   color: 'var(--ok)',     glow: 'var(--ok-dim)'     },
        { key: 'info',     label: 'OK',       color: 'var(--txt-3)',  glow: 'rgba(95,107,133,.14)'}
    ];

    container.innerHTML = levels.map(l => `
        <div class="dash-kpi" style="--kpi-color:${l.color}; --kpi-glow:${l.glow};">
            <div class="dash-kpi-count">${counts[l.key] || 0}</div>
            <div class="dash-kpi-label">${l.label}</div>
        </div>`).join('');
}

function renderDeviceTypes() {
    const container = document.getElementById('dashDeviceTypes');
    if (!container) return;

    const typeCounts = {};
    networkData.hosts.forEach(h => {
        const cat = SecurityAnalyzer.categorizeDevice(h);
        const key = `${cat.icon} ${cat.category}`;
        typeCounts[key] = (typeCounts[key] || 0) + 1;
    });

    const sorted = Object.entries(typeCounts).sort((a, b) => b[1] - a[1]);
    if (sorted.length === 0) {
        container.innerHTML = '<div class="text-muted" style="text-align:center;padding:20px;color:var(--txt-3);">Aucun dispositif détecté</div>';
        return;
    }
    const max = sorted[0][1];

    container.innerHTML = sorted.map(([name, count]) => {
        const pct = Math.round((count / max) * 100);
        return `<div class="dash-bar-row">
            <span class="dash-bar-label">${Utils.escapeHtml(name)}</span>
            <div class="dash-bar-track"><div class="dash-bar-fill device" style="width:${pct}%"></div></div>
            <span class="dash-bar-value">${count}</span>
        </div>`;
    }).join('');
}

function renderTopPorts() {
    const container = document.getElementById('dashTopPorts');
    const portCount = {};
    networkData.hosts.forEach(h => {
        h.ports.filter(p => p.state === 'open').forEach(p => {
            const key = `${p.port}/${p.service || '?'}`;
            portCount[key] = (portCount[key] || 0) + 1;
        });
    });
    const sorted = Object.entries(portCount).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const max = sorted.length > 0 ? sorted[0][1] : 1;

    container.innerHTML = sorted.map(([name, count]) => {
        const pct = Math.round((count / max) * 100);
        return `<div class="dash-bar-row">
            <span class="dash-bar-label">${Utils.escapeHtml(name)}</span>
            <div class="dash-bar-track"><div class="dash-bar-fill" style="width:${pct}%"></div></div>
            <span class="dash-bar-value">${count}</span>
        </div>`;
    }).join('');
}

function renderRiskChart() {
    const container = document.getElementById('dashRiskChart');
    const vuln = networkData.hosts.filter(h => h.vulnerable).length;
    const safe = networkData.hosts.length - vuln;
    const total = networkData.hosts.length || 1;

    container.innerHTML = `
        <div class="dash-donut-wrapper">
            <svg viewBox="0 0 36 36" class="dash-donut">
                <circle cx="18" cy="18" r="15.9" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="3"/>
                <circle cx="18" cy="18" r="15.9" fill="none" stroke="#e74c3c" stroke-width="3"
                    stroke-dasharray="${(vuln/total)*100} ${100-(vuln/total)*100}" stroke-dashoffset="25"/>
                <circle cx="18" cy="18" r="15.9" fill="none" stroke="#27ae60" stroke-width="3"
                    stroke-dasharray="${(safe/total)*100} ${100-(safe/total)*100}" stroke-dashoffset="${25-(vuln/total)*100}"/>
            </svg>
            <div class="dash-donut-center">${Math.round((vuln/total)*100)}%</div>
        </div>
        <div class="dash-donut-legend">
            <span class="dash-legend-item"><span class="dot" style="background:#e74c3c"></span>${vuln} à risque</span>
            <span class="dash-legend-item"><span class="dot" style="background:#27ae60"></span>${safe} sécurisés</span>
        </div>`;
}

function renderVendorChart() {
    const container = document.getElementById('dashVendorChart');
    const vendorCount = {};
    networkData.hosts.forEach(h => {
        const v = h.vendor || 'Inconnu';
        vendorCount[v] = (vendorCount[v] || 0) + 1;
    });
    const sorted = Object.entries(vendorCount).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const max = sorted.length > 0 ? sorted[0][1] : 1;

    container.innerHTML = sorted.map(([name, count]) => {
        const pct = Math.round((count / max) * 100);
        return `<div class="dash-bar-row">
            <span class="dash-bar-label">${Utils.escapeHtml(name)}</span>
            <div class="dash-bar-track"><div class="dash-bar-fill vendor" style="width:${pct}%"></div></div>
            <span class="dash-bar-value">${count}</span>
        </div>`;
    }).join('');
}

function renderNSEChart() {
    const container = document.getElementById('dashNSEChart');
    const scriptCount = {};
    networkData.hosts.forEach(h => {
        const openPorts = h.ports.filter(p => p.state === 'open');
        const allScripts = (h.hostScripts || []).concat(openPorts.flatMap(p => p.scripts || []));
        allScripts.forEach(s => {
            scriptCount[s.id] = (scriptCount[s.id] || 0) + 1;
        });
    });
    const sorted = Object.entries(scriptCount).sort((a, b) => b[1] - a[1]).slice(0, 8);

    if (sorted.length === 0) {
        container.innerHTML = '<div class="text-muted" style="text-align:center;padding:20px;">Aucun script NSE détecté</div>';
        return;
    }
    const max = sorted[0][1];

    container.innerHTML = sorted.map(([name, count]) => {
        const isVuln = /vuln|exploit|anon|bypass/i.test(name);
        const pct = Math.round((count / max) * 100);
        return `<div class="dash-bar-row">
            <span class="dash-bar-label ${isVuln ? 'nse-vuln-label' : ''}">${isVuln ? '🚨' : '📜'} ${Utils.escapeHtml(name)}</span>
            <div class="dash-bar-track"><div class="dash-bar-fill ${isVuln ? 'vuln' : 'nse'}" style="width:${pct}%"></div></div>
            <span class="dash-bar-value">${count}</span>
        </div>`;
    }).join('');
}