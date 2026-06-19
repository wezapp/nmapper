// table.js - Module de tableau des hôtes avec design moderne en cartes
class HostTable {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.data = [];
        this.filteredData = [];
        this.sortConfig = { key: null, direction: 'asc' };
        this.filters = {
            search: '',
            criticality: '',
            vendor: '',
            deviceCategory: ''
        };
    }

    // Initialiser le tableau avec les données
    setData(hosts, vlanId = null) {
        this.vlanId = vlanId;
        this.data = hosts.map(host => {
            const openPorts = host.ports.filter(p => p.state === 'open');
            const criticalPorts = openPorts.filter(port =>
                SecurityAnalyzer.evaluatePortRisk(port.port, port.service) === 'critical'
            );
            const highRiskPorts = openPorts.filter(port =>
                SecurityAnalyzer.evaluatePortRisk(port.port, port.service) === 'high'
            );

            let criticality = 'Low';
            if (host.vulnerable) {
                if (criticalPorts.length > 0) {
                    criticality = 'Critical';
                } else if (highRiskPorts.length >= 2) {
                    criticality = 'High';
                } else if (highRiskPorts.length > 0 || openPorts.length >= 8) {
                    criticality = 'Medium';
                }
            } else if (openPorts.length >= 5) {
                criticality = 'Low';
            }

            // Catégoriser le dispositif
            const deviceInfo = SecurityAnalyzer.categorizeDevice(host);

            return {
                ip: host.ip,
                vlan: host.vlan,
                vendor: host.vendor || 'Unknown',
                macAddress: host.macAddress || 'N/A',
                openPorts: openPorts.length,
                totalPorts: host.ports.length,
                criticalPorts: criticalPorts.length,
                highRiskPorts: highRiskPorts.length,
                criticality: criticality,
                vulnerable: host.vulnerable,
                riskScore: typeof host.riskScore === 'number' ? host.riskScore : 0,
                riskLevel: host.riskLevel || 'info',
                nseFindings: host.nseFindings || [],
                versionFindings: host.versionFindings || [],
                osFinding: host.osFinding || null,
                topPorts: openPorts.slice(0, 5).map(p => `${p.port}/${p.service}`).join(', '),
                deviceCategory: deviceInfo.category,
                deviceIcon: deviceInfo.icon,
                deviceColor: deviceInfo.color,
                _original: host
            };
        });
        this.filteredData = [...this.data];
        this.render();
    }

    // Fonction de tri
    sort(key) {
        // Le score de risque se trie en décroissant par défaut (plus critique en premier)
        let direction = (key === 'riskScore') ? 'desc' : 'asc';
        if (this.sortConfig.key === key) {
            direction = this.sortConfig.direction === 'asc' ? 'desc' : 'asc';
        }

        this.sortConfig = { key, direction };

        this.filteredData.sort((a, b) => {
            let valueA = a[key];
            let valueB = b[key];

            if (key === 'ip') {
                const ipA = this.ipToNumber(valueA);
                const ipB = this.ipToNumber(valueB);
                valueA = ipA;
                valueB = ipB;
            }

            if (key === 'criticality') {
                const criticalityOrder = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1 };
                valueA = criticalityOrder[valueA] || 0;
                valueB = criticalityOrder[valueB] || 0;
            }

            if (key === 'deviceCategory') {
                const categoryOrder = { 'Industriel': 6, 'Écran': 5, 'Imprimante': 4, 'Windows': 3, 'Linux': 2, 'IoT': 1, 'Inconnu': 0 };
                valueA = categoryOrder[valueA] || 0;
                valueB = categoryOrder[valueB] || 0;
            }

            if (valueA < valueB) {
                return direction === 'asc' ? -1 : 1;
            }
            if (valueA > valueB) {
                return direction === 'asc' ? 1 : -1;
            }
            return 0;
        });

        this.render();
    }

    ipToNumber(ip) {
        if (!ip || ip === 'N/A') return 0;
        return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0);
    }

    // Fonction de filtrage
    applyFilters() {
        this.filteredData = this.data.filter(host => {
            const searchLower = this.filters.search.toLowerCase();
            const matchesSearch =
                host.ip.toLowerCase().includes(searchLower) ||
                host.vendor.toLowerCase().includes(searchLower) ||
                host.macAddress.toLowerCase().includes(searchLower);

            const matchesCriticality =
                !this.filters.criticality ||
                host.criticality === this.filters.criticality;

            const matchesVendor =
                !this.filters.vendor ||
                host.vendor.toLowerCase().includes(this.filters.vendor.toLowerCase());

            const matchesDeviceCategory =
                !this.filters.deviceCategory ||
                host.deviceCategory === this.filters.deviceCategory;

            return matchesSearch && matchesCriticality && matchesVendor && matchesDeviceCategory;
        });

        if (this.sortConfig.key) {
            this.sort(this.sortConfig.key);
        } else {
            this.render();
        }
    }

    updateFilter(key, value) {
        this.filters[key] = value;
        this.applyFilters();
    }

    getCriticalityClass(criticality) {
        const classes = {
            'Critical': 'critical',
            'High': 'high',
            'Medium': 'medium',
            'Low': 'low'
        };
        return classes[criticality] || 'low';
    }

    getCriticalityIcon(criticality) {
        const icons = {
            'Critical': '🔴',
            'High': '🟠',
            'Medium': '🟡',
            'Low': '🟢'
        };
        return icons[criticality] || '⚪';
    }

    // Calculer les statistiques pour l'affichage
    calculateStats() {
        const hosts = this.data.map(h => h._original);

        // Statistiques par vendor
        const vendorCount = {};
        hosts.forEach(host => {
            const vendor = host.vendor || 'Unknown';
            vendorCount[vendor] = (vendorCount[vendor] || 0) + 1;
        });

        const topVendors = Object.entries(vendorCount)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 5);

        // Statistiques des ports
        const portCount = {};
        hosts.forEach(host => {
            host.ports.filter(p => p.state === 'open').forEach(port => {
                const key = `${port.port}/${port.service || 'unknown'}`;
                portCount[key] = (portCount[key] || 0) + 1;
            });
        });

        const topPorts = Object.entries(portCount)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 5);

        // Statistiques par type d'équipement
        const deviceTypeCount = {};
        this.data.forEach(host => {
            const category = host.deviceCategory || 'Inconnu';
            deviceTypeCount[category] = (deviceTypeCount[category] || 0) + 1;
        });

        const topDeviceTypes = Object.entries(deviceTypeCount)
            .sort(([,a], [,b]) => b - a);

        // Statistiques de sécurité
        const totalHosts = hosts.length;
        const vulnerableHosts = hosts.filter(h => h.vulnerable).length;
        const secureHosts = totalHosts - vulnerableHosts;
        const totalOpenPorts = hosts.reduce((sum, h) =>
            sum + h.ports.filter(p => p.state === 'open').length, 0);
        const avgPortsPerHost = totalHosts > 0 ? Math.round(totalOpenPorts / totalHosts) : 0;

        return {
            topVendors,
            topPorts,
            topDeviceTypes,
            totalHosts,
            vulnerableHosts,
            secureHosts,
            totalOpenPorts,
            avgPortsPerHost,
            riskPercentage: totalHosts > 0 ? Math.round((vulnerableHosts / totalHosts) * 100) : 0
        };
    }

    // Générer le HTML des statistiques
    generateStatsHTML() {
        const title = this.vlanId
            ? `📊 Statistiques du VLAN ${this.vlanId}`
            : '📊 Statistiques Globales du Réseau';

        return `
            <div class="table-stats-section">
                <h3 class="stats-section-title">${title}</h3>

                <!-- Statistiques principales avec jauge de risque -->

                <div class="stats-grid">
                    <!-- Top Vendors avec graphique -->
                    <div class="stats-card">
                        <div class="stats-card-header">
                            <span class="stats-icon">🏢</span>
                            <span class="stats-card-title">Top Vendors</span>
                        </div>
                        <div class="stats-card-body">
                            <canvas id="vendorsBarChart" width="350" height="180"></canvas>
                        </div>
                    </div>

                    <!-- Top Types avec graphique -->
                    <div class="stats-card">
                        <div class="stats-card-header">
                            <span class="stats-icon">💻</span>
                            <span class="stats-card-title">Top Types d'Équipements</span>
                        </div>
                        <div class="stats-card-body">
                            <canvas id="topTypesChart" width="350" height="180"></canvas>
                        </div>
                    </div>

                    <!-- Top Ports avec graphique -->
                    <div class="stats-card">
                        <div class="stats-card-header">
                            <span class="stats-icon">🔥</span>
                            <span class="stats-card-title">Ports les Plus Ouverts</span>
                        </div>
                        <div class="stats-card-body">
                            <canvas id="topPortsChart" width="350" height="180"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    // Rendre le tableau en cartes
    render() {
        const title = this.vlanId
            ? `Hôtes du VLAN ${this.vlanId}`
            : 'Tous les hôtes du réseau';

        const stats = this.calculateStats();
        const statsHTML = this.generateStatsHTML(stats);

        const html = `
            <div class="host-cards-container">
                ${statsHTML}

                <div class="cards-header">
                    <div class="cards-title">
                        <h3>${title} (${this.filteredData.length} hôte${this.filteredData.length > 1 ? 's' : ''})</h3>
                        <div class="cards-stats">
                            <span class="stat-badge critical">${this.filteredData.filter(h => h.criticality === 'Critical').length} Critical</span>
                            <span class="stat-badge high">${this.filteredData.filter(h => h.criticality === 'High').length} High</span>
                            <span class="stat-badge medium">${this.filteredData.filter(h => h.criticality === 'Medium').length} Medium</span>
                            <span class="stat-badge low">${this.filteredData.filter(h => h.criticality === 'Low').length} Low</span>
                        </div>
                    </div>
                    <div class="cards-actions">
                        <button class="btn btn-secondary" data-table-action="exportCSV">
                            📥 Exporter CSV
                        </button>
                        <button class="btn btn-secondary" data-table-action="clearFilters">
                            🗑️ Effacer filtres
                        </button>
                        <button class="btn btn-sort" data-table-action="toggleSort">
                            🔄 Trier
                        </button>
                    </div>
                </div>

                <div class="cards-filters">
                    <div class="filter-group">
                        <input type="text"
                               class="filter-input"
                               data-table-filter="search"
                               placeholder="🔍 Rechercher par IP, vendor, MAC..."
                               value="${this.filters.search}">
                    </div>
                    <div class="filter-group">
                        <select class="filter-select" data-table-filter="criticality">
                            <option value="">Toutes criticités</option>
                            <option value="Critical" ${this.filters.criticality === 'Critical' ? 'selected' : ''}>🔴 Critical</option>
                            <option value="High" ${this.filters.criticality === 'High' ? 'selected' : ''}>🟠 High</option>
                            <option value="Medium" ${this.filters.criticality === 'Medium' ? 'selected' : ''}>🟡 Medium</option>
                            <option value="Low" ${this.filters.criticality === 'Low' ? 'selected' : ''}>🟢 Low</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <select class="filter-select" data-table-filter="deviceCategory">
                            <option value="">Tous types</option>
                            <option value="Industriel" ${this.filters.deviceCategory === 'Industriel' ? 'selected' : ''}>🏭 Industriel</option>
                            <option value="Écran" ${this.filters.deviceCategory === 'Écran' ? 'selected' : ''}>🖥️ Écran</option>
                            <option value="Imprimante" ${this.filters.deviceCategory === 'Imprimante' ? 'selected' : ''}>🖨️ Imprimante</option>
                            <option value="Windows" ${this.filters.deviceCategory === 'Windows' ? 'selected' : ''}>🪟 Windows</option>
                            <option value="Linux" ${this.filters.deviceCategory === 'Linux' ? 'selected' : ''}>🐧 Linux</option>
                            <option value="IoT" ${this.filters.deviceCategory === 'IoT' ? 'selected' : ''}>📡 IoT</option>
                            <option value="Inconnu" ${this.filters.deviceCategory === 'Inconnu' ? 'selected' : ''}>❓ Inconnu</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <input type="text"
                               class="filter-input"
                               data-table-filter="vendor"
                               placeholder="Filtrer par vendor..."
                               value="${this.filters.vendor}">
                    </div>
                </div>

                <div id="sortMenu" class="sort-menu" style="display: none;">
                    <button data-table-sort="riskScore">Trier par Score de risque</button>
                    <button data-table-sort="ip">Trier par IP</button>
                    <button data-table-sort="criticality">Trier par Criticité</button>
                    <button data-table-sort="deviceCategory">Trier par Type</button>
                    <button data-table-sort="openPorts">Trier par Ports ouverts</button>
                    <button data-table-sort="vendor">Trier par Vendor</button>
                </div>

                <div class="host-cards-grid">
                    ${this.filteredData.length === 0 ? 
                        '<div class="no-data-card">Aucun hôte trouvé avec ces critères</div>' :
                        this.filteredData.map(host => this.renderHostCard(host)).join('')
                    }
                </div>
            </div>
        `;

        this.container.innerHTML = html;

        // Action buttons (CSP-safe replacements for inline onclick)
        this.container.querySelector('[data-table-action="exportCSV"]')
            ?.addEventListener('click', () => this.exportToCSV());
        this.container.querySelector('[data-table-action="clearFilters"]')
            ?.addEventListener('click', () => this.clearFilters());
        this.container.querySelector('[data-table-action="toggleSort"]')
            ?.addEventListener('click', () => this.toggleSortMenu());

        this.container.querySelectorAll('[data-table-filter]').forEach(el => {
            const key = el.dataset.tableFilter;
            const evt = el.tagName === 'SELECT' ? 'change' : 'input';
            el.addEventListener(evt, e => this.updateFilter(key, e.target.value));
        });

        this.container.querySelectorAll('[data-table-sort]').forEach(btn => {
            btn.addEventListener('click', () => this.sort(btn.dataset.tableSort));
        });

        this.container.querySelectorAll('[data-action="details"]').forEach(btn => {
            const ip = btn.dataset.ip;
            btn.addEventListener('click', () => {
                const host = networkData.hosts.find(h => h.ip === ip);
                if (host) NetworkVisualization.showHostDetails(host);
            });
        });
        this.container.querySelectorAll('[data-action="pdf"]').forEach(btn => {
            const ip = btn.dataset.ip;
            btn.addEventListener('click', () => PDFReports.generateHostReport(ip));
        });

        // Dessiner les graphiques après le rendu
        this.drawCharts(stats);
    }

    // Initialiser tous les graphiques
    drawCharts(stats) {
        // Jauge de risque
        this.drawRiskGauge('riskGaugeChart', stats.riskPercentage);

        // Graphique donut des ports
        const topPortsData = stats.topPorts.slice(0, 5).map(([port, count]) => ({
            label: port,
            value: count
        }));
        const portColors = ['#e74c3c', '#f39c12', '#f1c40f', '#3498db', '#9b59b6'];
        this.drawDonutChart('portsDonutChart', topPortsData, portColors);

        // Légende du donut
        this.createLegend('portsLegend', topPortsData, portColors);

        // Graphique en barres des vendors
        const vendorData = stats.topVendors.slice(0, 5).map(([vendor, count]) => ({
            label: vendor,
            value: count
        }));
        const vendorColors = ['#3498db', '#2ecc71', '#f39c12', '#9b59b6', '#e74c3c'];
        this.drawBarChart('vendorsBarChart', vendorData, vendorColors);

        // Graphique en barres verticales des types d'équipements
        const deviceTypeData = stats.topDeviceTypes.map(([type, count]) => ({
            label: type,
            value: count,
            icon: SecurityAnalyzer.getCategoryIcon(type)
        }));
        this.drawDeviceTypeBarChart('topTypesChart', deviceTypeData);

        // Graphique en barres verticales des ports
        const portChartData = stats.topPorts.slice(0, 10).map(([port, count]) => ({
            label: port.split('/')[0],
            value: count
        }));
        this.drawVerticalBarChart('topPortsChart', portChartData, '#e74c3c');
    }

    // Créer une légende pour les graphiques
    createLegend(elementId, data, colors) {
        const legendElement = document.getElementById(elementId);
        if (!legendElement) return;

        const legendHTML = data.map((item, index) => `
            <div class="legend-item">
                <span class="legend-color" style="background: ${colors[index % colors.length]}"></span>
                <span class="legend-label">${Utils.escapeHtml(item.label)}</span>
                <span class="legend-value">${item.value}</span>
            </div>
        `).join('');

        legendElement.innerHTML = legendHTML;
    }

    renderHostCard(host) {
        const criticalityClass = this.getCriticalityClass(host.criticality);
        const criticalityIcon = this.getCriticalityIcon(host.criticality);
        const vendorIcon = FileProcessor.getVendorIcon(host.vendor);
        const scoreColor = SecurityAnalyzer.getScoreColor(host.riskLevel);
        const scoreLabel = SecurityAnalyzer.getScoreLabel(host.riskLevel);
        const findingsCount = host.nseFindings.length + host.versionFindings.length + (host.osFinding ? 1 : 0);
        const cveSet = new Set();
        host.nseFindings.forEach(f => (f.cves || []).forEach(c => cveSet.add(c)));

        return `
            <div class="host-card ${criticalityClass}" data-ip="${Utils.escapeHtml(host.ip)}">
                <div class="card-header">
                    <div class="card-title">
                        <span class="vendor-icon">${vendorIcon}</span>
                        <span class="ip-address">${Utils.escapeHtml(host.ip)}</span>
                    </div>
                    <div class="criticality-badge ${criticalityClass}">
                        ${criticalityIcon} ${Utils.escapeHtml(host.criticality)}
                    </div>
                </div>

                <div class="risk-score-bar" title="Score de risque pondéré : ${host.riskScore}/100">
                    <div class="risk-score-badge" style="background:${scoreColor}">
                        <span class="risk-score-value">${host.riskScore}</span>
                        <span class="risk-score-max">/100</span>
                    </div>
                    <div class="risk-score-meta">
                        <span class="risk-score-level" style="color:${scoreColor}">${scoreLabel}</span>
                        <div class="risk-score-track">
                            <div class="risk-score-fill" style="width:${host.riskScore}%;background:${scoreColor}"></div>
                        </div>
                    </div>
                </div>

                <div class="card-body">
                    <div class="card-info-row">
                        <span class="info-label">💻 Type:</span>
                        <span class="info-value" style="color: ${host.deviceColor}; font-weight: bold;">
                            ${Utils.escapeHtml(host.deviceIcon)} ${Utils.escapeHtml(host.deviceCategory)}
                        </span>
                    </div>

                    <div class="card-info-row">
                        <span class="info-label">🏢 Vendor:</span>
                        <span class="info-value">${Utils.escapeHtml(host.vendor)}</span>
                    </div>

                    ${host.macAddress !== 'N/A' ? `
                    <div class="card-info-row">
                        <span class="info-label">🔧 MAC:</span>
                        <span class="info-value mac-address">${Utils.escapeHtml(host.macAddress)}</span>
                    </div>
                    ` : ''}

                    <div class="card-info-row">
                        <span class="info-label">🌐 VLAN:</span>
                        <span class="info-value">${Utils.escapeHtml(host.vlan)}</span>
                    </div>

                    <div class="card-ports-section">
                        <div class="ports-stats">
                            <div class="port-stat">
                                <span class="port-stat-number">${host.openPorts}</span>
                                <span class="port-stat-label">Ouverts</span>
                            </div>
                            ${host.criticalPorts > 0 ? `
                            <div class="port-stat critical">
                                <span class="port-stat-number">${host.criticalPorts}</span>
                                <span class="port-stat-label">Critiques</span>
                            </div>
                            ` : ''}
                            ${host.highRiskPorts > 0 ? `
                            <div class="port-stat high">
                                <span class="port-stat-number">${host.highRiskPorts}</span>
                                <span class="port-stat-label">Risque élevé</span>
                            </div>
                            ` : ''}
                        </div>

                        ${host.openPorts > 0 ? `
                        <div class="top-ports">
                            <span class="top-ports-label">Top ports:</span>
                            <span class="top-ports-list">${Utils.escapeHtml(host.topPorts)}</span>
                        </div>
                        ` : ''}
                    </div>

                    ${findingsCount > 0 ? `
                    <div class="card-findings">
                        <span class="findings-chip findings-total">⚠️ ${findingsCount} finding${findingsCount > 1 ? 's' : ''}</span>
                        ${host.nseFindings.length ? `<span class="findings-chip findings-nse">🔬 ${host.nseFindings.length} NSE</span>` : ''}
                        ${host.versionFindings.length ? `<span class="findings-chip findings-version">📦 ${host.versionFindings.length} version</span>` : ''}
                        ${host.osFinding ? `<span class="findings-chip findings-os">💿 OS EOL</span>` : ''}
                        ${cveSet.size ? `<span class="findings-chip findings-cve">🛡️ ${cveSet.size} CVE</span>` : ''}
                    </div>
                    ` : ''}
                </div>

                <div class="card-actions">
                    <button class="card-btn primary" data-action="details" data-ip="${Utils.escapeHtml(host.ip)}">
                        👁️ Détails
                    </button>
                    <button class="card-btn secondary" data-action="pdf" data-ip="${Utils.escapeHtml(host.ip)}">
                        📄 Rapport
                    </button>
                </div>
            </div>
        `;
    }

    toggleSortMenu() {
        const menu = document.getElementById('sortMenu');
        menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
    }

    clearFilters() {
        this.filters = {
            search: '',
            criticality: '',
            vendor: '',
            deviceCategory: ''
        };
        this.applyFilters();
    }

    exportToCSV() {
        // Échappe + neutralise les formules tableur sur chaque champ
        const esc = v => {
            let s = String(v ?? '');
            if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
            return '"' + s.replace(/"/g, '""') + '"';
        };
        const headers = ['IP', 'Type', 'VLAN', 'Vendor', 'MAC', 'Nb Ports Ouverts', 'Liste Ports Ouverts', 'Ports Critiques', 'Criticité'];
        const csvContent = [
            headers.map(esc).join(','),
            ...this.filteredData.map(host => {
                const openPortList = (host._original?.ports || [])
                    .filter(p => p.state === 'open')
                    .map(p => p.service ? `${p.port}/${p.service}` : `${p.port}`)
                    .join(' | ');
                return [
                    host.ip,
                    host.deviceCategory,
                    host.vlan,
                    host.vendor || '',
                    host.macAddress,
                    host.openPorts,
                    openPortList,
                    host.criticalPorts,
                    host.criticality
                ].map(esc).join(',');
            })
        ].join('\n');

        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `hosts_${this.vlanId || 'all'}_${new Date().toISOString().split('T')[0]}.csv`;
        a.click();
        window.URL.revokeObjectURL(url);
    }

    // Dessiner un graphique en barres horizontales
    drawBarChart(canvasId, data, colors) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        const { width, height } = canvas;

        ctx.clearRect(0, 0, width, height);

        if (data.length === 0) {
            ctx.fillStyle = 'rgba(255, 255, 255, 0.5)';
            ctx.font = '14px Arial';
            ctx.textAlign = 'center';
            ctx.fillText('Aucune donnée', width / 2, height / 2);
            return;
        }

        const maxValue = Math.max(...data.map(d => d.value));
        const barHeight = (height - 20) / data.length;
        const maxBarWidth = width - 150;

        data.forEach((item, index) => {
            const y = index * barHeight + 10;
            const barWidth = (item.value / maxValue) * maxBarWidth;

            // Barre
            ctx.fillStyle = colors[index % colors.length];
            ctx.fillRect(120, y, barWidth, barHeight - 8);

            // Label
            ctx.fillStyle = 'white';
            ctx.font = '12px Arial';
            ctx.textAlign = 'right';
            ctx.fillText(item.label.substring(0, 15), 115, y + barHeight / 2 + 4);

            // Valeur
            ctx.textAlign = 'left';
            ctx.fillText(item.value.toString(), 125 + barWidth, y + barHeight / 2 + 4);
        });
    }

    // Dessiner un graphique circulaire (donut chart)
    drawDonutChart(canvasId, data, colors) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        const { width, height } = canvas;

        ctx.clearRect(0, 0, width, height);

        const total = data.reduce((sum, d) => sum + d.value, 0);
        if (total === 0) {
            ctx.fillStyle = 'rgba(255, 255, 255, 0.5)';
            ctx.font = '14px Arial';
            ctx.textAlign = 'center';
            ctx.fillText('Aucune donnée', width / 2, height / 2);
            return;
        }

        const centerX = width / 2;
        const centerY = height / 2;
        const radius = Math.min(width, height) / 2 - 10;
        const innerRadius = radius * 0.6;

        let currentAngle = -Math.PI / 2;

        data.forEach((item, index) => {
            const sliceAngle = (item.value / total) * 2 * Math.PI;

            // Dessiner la portion
            ctx.beginPath();
            ctx.arc(centerX, centerY, radius, currentAngle, currentAngle + sliceAngle);
            ctx.arc(centerX, centerY, innerRadius, currentAngle + sliceAngle, currentAngle, true);
            ctx.closePath();
            ctx.fillStyle = colors[index % colors.length];
            ctx.fill();

            // Ajouter un contour
            ctx.strokeStyle = '#1a1a1a';
            ctx.lineWidth = 2;
            ctx.stroke();

            currentAngle += sliceAngle;
        });

        // Texte central
        ctx.fillStyle = 'white';
        ctx.font = 'bold 24px Arial';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(total.toString(), centerX, centerY - 5);
        ctx.font = '12px Arial';
        ctx.fillText('Total', centerX, centerY + 15);
    }

    // Dessiner un graphique en barres verticales
    drawVerticalBarChart(canvasId, data, color) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        const { width, height } = canvas;

        ctx.clearRect(0, 0, width, height);

        if (data.length === 0) {
            ctx.fillStyle = 'rgba(255, 255, 255, 0.5)';
            ctx.font = '14px Arial';
            ctx.textAlign = 'center';
            ctx.fillText('Aucune donnée', width / 2, height / 2);
            return;
        }

        const maxValue = Math.max(...data.map(d => d.value));
        const barWidth = (width - 40) / data.length;
        // Augmenter l'espace en bas pour les labels (60px au lieu de 40px)
        const maxBarHeight = height - 60;
        const bottomMargin = 50;

        data.forEach((item, index) => {
            const x = 20 + index * barWidth;
            const barHeight = (item.value / maxValue) * maxBarHeight;
            const y = height - bottomMargin - barHeight;

            // Barre avec gradient
            const gradient = ctx.createLinearGradient(x, y, x, height - bottomMargin);
            gradient.addColorStop(0, color);
            gradient.addColorStop(1, color + '80');
            ctx.fillStyle = gradient;
            ctx.fillRect(x, y, barWidth - 5, barHeight);

            // Valeur au-dessus
            ctx.fillStyle = 'white';
            ctx.font = 'bold 11px Arial';
            ctx.textAlign = 'center';
            ctx.fillText(item.value.toString(), x + (barWidth - 5) / 2, y - 5);

            // Label en bas (non incliné pour meilleure lisibilité)
            ctx.font = '11px Arial';
            ctx.fillStyle = 'white';
            const label = item.label.length > 6 ? item.label.substring(0, 6) + '..' : item.label;
            ctx.textAlign = 'center';
            ctx.fillText(label, x + (barWidth - 5) / 2, height - bottomMargin + 20);
        });
    }

    // Dessiner une jauge de risque
    drawRiskGauge(canvasId, percentage) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        const { width, height } = canvas;

        ctx.clearRect(0, 0, width, height);

        const centerX = width / 2;
        const centerY = height / 2 + 10;
        const radius = Math.min(width, height) / 2 - 20;
        const startAngle = Math.PI;
        const endAngle = 2 * Math.PI;
        const currentAngle = startAngle + (percentage / 100) * (endAngle - startAngle);

        // Fond de la jauge
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, startAngle, endAngle);
        ctx.lineWidth = 20;
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
        ctx.stroke();

        // Gradient de couleur pour la jauge
        const gradient = ctx.createLinearGradient(centerX - radius, 0, centerX + radius, 0);
        if (percentage < 25) {
            gradient.addColorStop(0, '#2ecc71');
            gradient.addColorStop(1, '#27ae60');
        } else if (percentage < 50) {
            gradient.addColorStop(0, '#f1c40f');
            gradient.addColorStop(1, '#f39c12');
        } else if (percentage < 75) {
            gradient.addColorStop(0, '#f39c12');
            gradient.addColorStop(1, '#e67e22');
        } else {
            gradient.addColorStop(0, '#e74c3c');
            gradient.addColorStop(1, '#c0392b');
        }

        // Jauge remplie
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, startAngle, currentAngle);
        ctx.lineWidth = 20;
        ctx.strokeStyle = gradient;
        ctx.lineCap = 'round';
        ctx.stroke();

        // Pourcentage au centre
        ctx.fillStyle = 'white';
        ctx.font = 'bold 32px Arial';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(`${percentage}%`, centerX, centerY - 10);

        ctx.font = '14px Arial';
        ctx.fillText('À risque', centerX, centerY + 20);
    }

    // Dessiner un graphique en barres verticales pour les types d'équipements avec couleurs et icônes
    drawDeviceTypeBarChart(canvasId, data) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        const { width, height } = canvas;

        ctx.clearRect(0, 0, width, height);

        if (data.length === 0) {
            ctx.fillStyle = 'rgba(255, 255, 255, 0.5)';
            ctx.font = '14px Arial';
            ctx.textAlign = 'center';
            ctx.fillText('Aucune donnée', width / 2, height / 2);
            return;
        }

        // Couleurs par catégorie
        const categoryColors = {
            'Industriel': '#9c27b0',
            'Écran': '#00bcd4',
            'Imprimante': '#009688',
            'Windows': '#0078d4',
            'Linux': '#ff9800',
            'IoT': '#4caf50',
            'Inconnu': '#757575'
        };

        const maxValue = Math.max(...data.map(d => d.value));
        const barWidth = (width - 40) / data.length;
        const maxBarHeight = height - 60;
        const bottomMargin = 50;

        data.forEach((item, index) => {
            const x = 20 + index * barWidth;
            const barHeight = (item.value / maxValue) * maxBarHeight;
            const y = height - bottomMargin - barHeight;
            const color = categoryColors[item.label] || '#757575';

            // Barre avec gradient
            const gradient = ctx.createLinearGradient(x, y, x, height - bottomMargin);
            gradient.addColorStop(0, color);
            gradient.addColorStop(1, color + '80');
            ctx.fillStyle = gradient;
            ctx.fillRect(x, y, barWidth - 5, barHeight);

            // Valeur au-dessus
            ctx.fillStyle = 'white';
            ctx.font = 'bold 11px Arial';
            ctx.textAlign = 'center';
            ctx.fillText(item.value.toString(), x + (barWidth - 5) / 2, y - 5);

            // Icône en bas
            ctx.font = '20px Arial';
            ctx.fillText(item.icon, x + (barWidth - 5) / 2, height - bottomMargin + 15);

            // Label en bas
            ctx.font = '10px Arial';
            ctx.fillStyle = 'white';
            const label = item.label.length > 8 ? item.label.substring(0, 8) + '..' : item.label;
            ctx.fillText(label, x + (barWidth - 5) / 2, height - bottomMargin + 35);
        });
    }
}

// Initialiser le tableau global
let hostTable = null;

// Fonction pour initialiser ou mettre à jour le tableau
function initHostTable(hosts, vlanId = null) {
    if (!hostTable) {
        hostTable = new HostTable('hosts-table');
    }
    hostTable.setData(hosts, vlanId);
}