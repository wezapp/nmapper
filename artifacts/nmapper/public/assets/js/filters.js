// filters.js - Module de gestion des filtres
const Filters = {
    
    // Fonctions de filtrage
    toggleFilters() {
        const content = document.getElementById('filterContent');
        content.classList.toggle('active');
    },

    addPortFilter(ports) {
        document.getElementById('portFilter').value = ports;
    },

    addServiceFilter(services) {
        document.getElementById('serviceFilter').value = services;
    },

    parsePortRange(portString) {
        const ports = [];
        const parts = portString.split(',');
        
        for (const part of parts) {
            const trimmed = part.trim();
            if (trimmed.includes('-')) {
                const [start, end] = trimmed.split('-').map(p => parseInt(p.trim()));
                for (let port = start; port <= end; port++) {
                    ports.push(port);
                }
            } else {
                const port = parseInt(trimmed);
                if (!isNaN(port)) {
                    ports.push(port);
                }
            }
        }
        
        return ports;
    },

    matchesIPPattern(ip, pattern) {
        if (!pattern) return true;
        
        const regexPattern = pattern
            .replace(/\./g, '\\.')
            .replace(/\*/g, '.*')
            .replace(/\?/g, '.');
        
        return new RegExp('^' + regexPattern + '$').test(ip);
    },

    matchesVendorPattern(vendor, pattern) {
        if (!pattern) return true;
        if (!vendor) return false;
        
        return vendor.toLowerCase().includes(pattern.toLowerCase());
    },

    applyFilters() {
        // Récupérer les valeurs des filtres
        const portFilterValue = document.getElementById('portFilter').value.trim();
        const serviceFilterValue = document.getElementById('serviceFilter').value.trim();
        const showOpen = document.getElementById('showOpen').checked;
        const showClosed = document.getElementById('showClosed').checked;
        const showFiltered = document.getElementById('showFiltered').checked;
        const minPorts = parseInt(document.getElementById('minPorts').value) || 0;
        const onlyVulnerable = document.getElementById('onlyVulnerable').checked;
        const excludeVulnerable = document.getElementById('excludeVulnerable').checked;
        const ipPattern = document.getElementById('ipFilter').value.trim();
        
        // Configurer les filtres actifs
        const vendorFilterValue = document.getElementById('vendorFilter')?.value.trim() || '';
        activeFilters = {
            ports: portFilterValue ? this.parsePortRange(portFilterValue) : [],
            services: serviceFilterValue ? serviceFilterValue.split(',').map(s => s.trim().toLowerCase()) : [],
            states: [],
            minPorts: minPorts,
            onlyVulnerable: onlyVulnerable,
            excludeVulnerable: excludeVulnerable,
            ipPattern: ipPattern,
            vendor: vendorFilterValue,
        };
        
        if (showOpen) activeFilters.states.push('open');
        if (showClosed) activeFilters.states.push('closed');
        if (showFiltered) activeFilters.states.push('filtered');
        
        // Filtrer les hôtes
        filteredData = {
            vlans: {},
            hosts: [],
            stats: { vlans: 0, hosts: 0, ports: 0, vulnerable: 0, files: networkData.stats.files }
        };
        
        let matchedHosts = 0;
        
        networkData.hosts.forEach(host => {
            let matches = true;
            
            // Filtre par IP
            if (!this.matchesIPPattern(host.ip, activeFilters.ipPattern)) {
                matches = false;
            }
            
            // Filtre par vendor
            if (!this.matchesVendorPattern(host.vendor, activeFilters.vendor)) {
                matches = false;
            }
            
            // Filtre par vulnérabilité
            if (activeFilters.onlyVulnerable && !host.vulnerable) {
                matches = false;
            }
            if (activeFilters.excludeVulnerable && host.vulnerable) {
                matches = false;
            }
            
            // Filtre par nombre minimum de ports
            const relevantPorts = host.ports.filter(p => activeFilters.states.includes(p.state));
            if (relevantPorts.length < activeFilters.minPorts) {
                matches = false;
            }
            
            // Filtre par ports spécifiques
            if (activeFilters.ports.length > 0) {
                const hostPorts = relevantPorts.map(p => p.port);
                const hasMatchingPort = activeFilters.ports.some(port => hostPorts.includes(port));
                if (!hasMatchingPort) {
                    matches = false;
                }
            }
            
            // Filtre par services
            if (activeFilters.services.length > 0) {
                const hostServices = relevantPorts.map(p => p.service.toLowerCase());
                const hasMatchingService = activeFilters.services.some(service => 
                    hostServices.some(hostService => hostService.includes(service))
                );
                if (!hasMatchingService) {
                    matches = false;
                }
            }
            
            if (matches) {
                matchedHosts++;
                filteredData.hosts.push(host);
                
                if (!filteredData.vlans[host.vlan]) {
                    filteredData.vlans[host.vlan] = { id: host.vlan, hosts: [] };
                }
                filteredData.vlans[host.vlan].hosts.push(host);
            }
        });
        
        // Mettre à jour les statistiques
        filteredData.stats.vlans = Object.keys(filteredData.vlans).length;
        filteredData.stats.hosts = filteredData.hosts.length;
        filteredData.stats.ports = filteredData.hosts.reduce((sum, host) => 
            sum + host.ports.filter(p => activeFilters.states.includes(p.state)).length, 0);
        filteredData.stats.vulnerable = filteredData.hosts.filter(h => h.vulnerable).length;
        
        // Afficher les résultats
        const resultsDiv = document.getElementById('filterResults');
        resultsDiv.style.display = 'block';
        resultsDiv.innerHTML = `
            <strong>📊 Résultats du filtrage :</strong><br>
            ${matchedHosts} hôte(s) trouvé(s) sur ${networkData.hosts.length} total<br>
            ${filteredData.stats.vlans} VLAN(s) contiennent des hôtes correspondants<br>
            ${filteredData.stats.ports} port(s) correspondent aux critères
        `;
        
        // Mettre à jour la visualisation
        this.updateVisualizationWithFilters();
        this.updateStatsWithFilters();

        const filteredReportGroup = document.getElementById('filteredReportGroup');
        if (filteredReportGroup) filteredReportGroup.style.display = 'block';
        const csvFilteredGroup = document.getElementById('csvFilteredGroup');
        if (csvFilteredGroup) csvFilteredGroup.style.display = 'block';

        this.renderFilterChips();
    },

    clearFilters() {
        // Réinitialiser tous les contrôles
        document.getElementById('portFilter').value = '';
        document.getElementById('serviceFilter').value = '';
        document.getElementById('showOpen').checked = true;
        document.getElementById('showClosed').checked = false;
        document.getElementById('showFiltered').checked = false;
        document.getElementById('minPorts').value = '';
        document.getElementById('onlyVulnerable').checked = false;
        document.getElementById('excludeVulnerable').checked = false;
        document.getElementById('ipFilter').value = '';
        
        document.getElementById('filterResults').style.display = 'none';
        const filteredReportGroup = document.getElementById('filteredReportGroup');
        if (filteredReportGroup) filteredReportGroup.style.display = 'none';
        const csvFilteredGroup = document.getElementById('csvFilteredGroup');
        if (csvFilteredGroup) csvFilteredGroup.style.display = 'none';
        const bar = document.getElementById('filterChipsBar');
        if (bar) bar.style.display = 'none';
        
        // Réinitialiser les boutons actifs
        document.querySelectorAll('.quick-filter-btn').forEach(btn => {
            btn.classList.remove('active');
        });
    },

    resetView() {
        this.clearFilters();
        filteredData = null;
        updateVisualization();
        updateStats();
    },

    updateVisualizationWithFilters() {
        if (!filteredData) return;
        
        if (currentView === 'vlans') {
            NetworkVisualization.showFilteredVLANView();
        } else if (currentView === 'hosts' && currentVLAN) {
            NetworkVisualization.showFilteredHostView(currentVLAN);
        }
    },

    updateStatsWithFilters() {
        if (!filteredData) return;
        
        document.getElementById('vlanCount').textContent = filteredData.stats.vlans;
        document.getElementById('hostCount').textContent = filteredData.stats.hosts;
        document.getElementById('portCount').textContent = filteredData.stats.ports;
        document.getElementById('vulnerableCount').textContent = filteredData.stats.vulnerable;
        document.getElementById('fileCount').textContent = filteredData.stats.files;
    },

    // Filtres rapides prédéfinis
    applyQuickFilter(type) {
        // Réinitialiser d'abord
        this.clearFilters();
        
        document.querySelectorAll('.quick-filter-btn').forEach(btn => btn.classList.remove('active'));
        
        switch(type) {
            case 'vulnerable':
                document.getElementById('onlyVulnerable').checked = true;
                break;
                
            case 'critical-ports':
                this.addPortFilter('21,22,23,80,102,135,139,445,502,1433,3389,5900');
                break;
                
            case 'industrial':
                this.addPortFilter('102,502,1911,2404,4840,44818,47808,20000');
                break;
                
            case 'remote-access':
                this.addPortFilter('22,23,3389,5900,5901');
                break;
                
            case 'web-services':
                this.addPortFilter('80,443,8000,8080,8443');
                this.addServiceFilter('http,https,web');
                break;
                
            case 'databases':
                this.addPortFilter('1433,3306,5432,1521,27017');
                this.addServiceFilter('mysql,postgresql,mssql,oracle,mongodb');
                break;
                
            case 'many-ports':
                document.getElementById('minPorts').value = '10';
                break;
        }
        
        // Appliquer automatiquement
        this.applyFilters();
    },

    renderFilterChips() {
        const bar = document.getElementById('filterChipsBar');
        if (!bar) return;

        const chips = [];

        if (activeFilters.ports.length > 0) {
            const label = activeFilters.ports.length <= 4
                ? activeFilters.ports.join(', ')
                : `${activeFilters.ports.slice(0, 3).join(', ')} +${activeFilters.ports.length - 3}`;
            chips.push({ icon: '🔌', text: `port: ${label}`, remove: 'ports' });
        }
        if (activeFilters.services.length > 0) {
            chips.push({ icon: '⚙️', text: `svc: ${activeFilters.services.join(', ')}`, remove: 'services' });
        }
        if (activeFilters.ipPattern) {
            chips.push({ icon: '🌐', text: `ip: ${activeFilters.ipPattern}`, remove: 'ip' });
        }
        if (activeFilters.minPorts > 0) {
            chips.push({ icon: '📊', text: `≥ ${activeFilters.minPorts} ports`, remove: 'minPorts' });
        }
        if (activeFilters.onlyVulnerable) {
            chips.push({ icon: '⚠️', text: 'vulnérables seulement', vuln: true, remove: 'onlyVuln' });
        }
        if (activeFilters.excludeVulnerable) {
            chips.push({ icon: '✅', text: 'exclure vulnérables', remove: 'exclVuln' });
        }

        if (chips.length === 0) {
            bar.style.display = 'none';
            return;
        }

        bar.style.display = 'flex';
        bar.innerHTML =
            `<span class="filter-chips-label">Filtres actifs</span>` +
            chips.map(c => `
                <span class="filter-chip${c.vuln ? ' vuln-chip' : ''}">
                    ${c.icon} ${Utils.escapeHtml(c.text)}
                    <span class="filter-chip-x" data-remove="${c.remove}">×</span>
                </span>`).join('') +
            `<span class="filter-chip clear-chip" data-action="clearFilters">🗑️ Tout effacer</span>`;

        const self = this;
        bar.querySelectorAll('.filter-chip-x[data-remove]').forEach(x => {
            x.addEventListener('click', (e) => {
                e.stopPropagation();
                switch (x.dataset.remove) {
                    case 'ports':    document.getElementById('portFilter').value = '';           break;
                    case 'services': document.getElementById('serviceFilter').value = '';        break;
                    case 'ip':       document.getElementById('ipFilter').value = '';             break;
                    case 'minPorts': document.getElementById('minPorts').value = '';             break;
                    case 'onlyVuln': document.getElementById('onlyVulnerable').checked = false;  break;
                    case 'exclVuln': document.getElementById('excludeVulnerable').checked = false; break;
                }
                self.applyFilters();
            });
        });
    },

    // Exportation des résultats filtrés
    exportFilteredResults() {
        if (!filteredData || filteredData.hosts.length === 0) {
            showMessage('warning', 'Aucun résultat filtré à exporter');
            return;
        }
        
        const csvEscape = v => {
            const s = String(v ?? '');
            // Neutralise les formules Excel et échappe les guillemets internes
            const safe = s.startsWith('=') || s.startsWith('+') || s.startsWith('-') || s.startsWith('@') ? "'" + s : s;
            return '"' + safe.replace(/"/g, '""') + '"';
        };
        const csvContent = [
            'IP,VLAN,Vendor,MAC,Ports_Ouverts,Vulnerable,Source',
            ...filteredData.hosts.map(host =>
                [
                    csvEscape(host.ip),
                    csvEscape(host.vlan),
                    csvEscape(host.vendor || ''),
                    csvEscape(host.macAddress || ''),
                    csvEscape(host.ports.filter(p => p.state === 'open').length),
                    csvEscape(host.vulnerable ? 'Oui' : 'Non'),
                    csvEscape(host.source),
                ].join(',')
            )
        ].join('\n');
        
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `resultats_filtres_${new Date().toISOString().slice(0, 10)}.csv`;
        a.click();
        window.URL.revokeObjectURL(url);
        
        showMessage('success', 'Résultats filtrés exportés en CSV');
    }
};

// Fonctions globales pour la compatibilité avec les événements onclick du HTML
function toggleFilters() {
    Filters.toggleFilters();
}

function addPortFilter(ports) {
    Filters.addPortFilter(ports);
}

function addServiceFilter(services) {
    Filters.addServiceFilter(services);
}

function applyFilters() {
    Filters.applyFilters();
}

function clearFilters() {
    Filters.clearFilters();
}

function resetView() {
    Filters.resetView();
}

function applyQuickFilter(type) {
    Filters.applyQuickFilter(type);
}