// network-visualization.js - Module de visualisation réseau

// Lit une variable CSS sur :root (avec fallback). Permet de piloter les couleurs
// des nœuds depuis le thème (v2) sans casser l'ancienne page (fallback = couleurs d'origine).
// Perf : getComputedStyle force un recalcul de style coûteux ; on mémorise le résultat
// et on l'invalide uniquement lors d'un changement de thème (voir invalidateThemeColors).
const _cssVarCache = new Map();
function cssVar(name, fallback) {
    if (_cssVarCache.has(name)) {
        return _cssVarCache.get(name) || fallback;
    }
    try {
        const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
        _cssVarCache.set(name, v);
        return v || fallback;
    } catch (e) { return fallback; }
}

const NetworkVisualization = {

    _highlightIp: null,

    // Invalide le cache des couleurs de thème (à appeler après un toggle de thème).
    invalidateThemeColors() {
        _cssVarCache.clear();
    },

    // Met à jour la légende selon la vue affichée (overview = VLANs, détail = hôtes)
    updateLegend(mode) {
        const legend = document.querySelector('#network-viz .legend');
        if (!legend) return;
        const c = {
            vlan:     cssVar('--node-vlan', '#4CAF50'),
            vlanVuln: cssVar('--node-vlan-vuln', '#f43f5e'),
            host:     cssVar('--node-host', '#2196F3'),
            vuln:     cssVar('--node-vuln', '#FF5722'),
            filtered: cssVar('--node-filtered', '#9C27B0')
        };
        const item = (color, label) =>
            `<div class="legend-item"><div class="legend-color" style="background:${color};"></div><span>${label}</span></div>`;

        if (mode === 'host') {
            legend.innerHTML =
                item(c.host, 'Hôte normal') +
                item(c.vuln, 'Hôte à risque') +
                item(c.filtered, 'Hôte filtré');
        } else {
            legend.innerHTML =
                item(c.vlan, 'VLAN') +
                item(c.vlanVuln, 'VLAN à risque');
        }
    },

    // Navigate D3 graph to a host: go to its VLAN, highlight + pan to its node, open details
    navigateToHost(ip) {
        const host = networkData.hosts.find(h => h.ip === ip);
        if (!host) return;
        this._highlightIp = ip;
        this.showHostView(host.vlan);
        this.showHostDetails(host);
    },

    _panToHighlighted() {
        const ip = this._highlightIp;
        if (!ip || !svg || !zoomBehavior) return;
        const g = svg.select('.main-group');
        g.selectAll('.node-group').each(function(d) {
            if (d.type === 'host' && d.data && d.data.ip === ip && d.x != null) {
                svg.transition().duration(600).call(
                    zoomBehavior.transform,
                    d3.zoomIdentity.translate(width / 2 - d.x, height / 2 - d.y)
                );
            }
        });
        this._highlightIp = null;
    },

    // Menu contextuel
    createContextMenu() {
        const menu = document.createElement('div');
        menu.id = 'contextMenu';
        menu.style.cssText = `
            position: absolute;
            background: #2c3e50;
            border: 1px solid #34495e;
            border-radius: 5px;
            padding: 5px 0;
            display: none;
            z-index: 1000;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            min-width: 150px;
        `;
        document.body.appendChild(menu);
        
        // Fermer le menu quand on clique ailleurs
        document.addEventListener('click', () => {
            menu.style.display = 'none';
        });
        
        return menu;
    },

    addMenuOption(menu, text, onClick) {
        const option = document.createElement('div');
        option.textContent = text;
        option.style.cssText = `
            padding: 10px 15px;
            color: white;
            cursor: pointer;
            font-size: 14px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        `;
        
        option.addEventListener('mouseenter', () => {
            option.style.background = '#3498db';
        });
        
        option.addEventListener('mouseleave', () => {
            option.style.background = 'transparent';
        });
        
        option.addEventListener('click', (e) => {
            e.stopPropagation();
            onClick();
            menu.style.display = 'none';
        });
        
        menu.appendChild(option);
    },

    // ── SentinelOne-style defs (gradients + glow) ────────────────────────────
    _setupSvgDefs() {
        const existingDefs = svg.select('defs');
        const defs = existingDefs.empty() ? svg.insert('defs', ':first-child') : existingDefs;

        // Dot-grid background pattern
        if (defs.select('#nv-dots').empty()) {
            const pat = defs.append('pattern')
                .attr('id', 'nv-dots').attr('x', 0).attr('y', 0)
                .attr('width', 28).attr('height', 28)
                .attr('patternUnits', 'userSpaceOnUse');
            pat.append('circle').attr('cx', 1).attr('cy', 1).attr('r', 0.8)
                .attr('fill', 'rgba(255,255,255,0.06)');
        }

        // Glow filter
        if (defs.select('#nv-glow').empty()) {
            const f = defs.append('filter').attr('id', 'nv-glow')
                .attr('x', '-40%').attr('y', '-40%').attr('width', '180%').attr('height', '180%');
            f.append('feGaussianBlur').attr('stdDeviation', '4').attr('result', 'blur');
            const m = f.append('feMerge');
            m.append('feMergeNode').attr('in', 'blur');
            m.append('feMergeNode').attr('in', 'SourceGraphic');
        }

        // Radial gradients for node fills
        const schemes = {
            'safe':     { inner: 'rgba(0,229,160,0.22)', outer: 'rgba(0,229,160,0.04)' },
            'warn':     { inner: 'rgba(245,158,11,0.25)', outer: 'rgba(245,158,11,0.05)' },
            'danger':   { inner: 'rgba(239,68,68,0.28)',  outer: 'rgba(239,68,68,0.06)' },
            'filtered': { inner: 'rgba(139,92,246,0.22)', outer: 'rgba(139,92,246,0.04)' },
            'agent':    { inner: 'rgba(59,130,246,0.25)', outer: 'rgba(59,130,246,0.04)' },
        };
        Object.entries(schemes).forEach(([key, { inner, outer }]) => {
            const gid = `nv-grad-${key}`;
            if (defs.select(`#${gid}`).empty()) {
                const g = defs.append('radialGradient').attr('id', gid)
                    .attr('cx', '38%').attr('cy', '35%').attr('r', '65%');
                g.append('stop').attr('offset', '0%').attr('stop-color', inner);
                g.append('stop').attr('offset', '100%').attr('stop-color', outer);
            }
        });

        // Add dot-grid rect behind main-group
        if (svg.select('.bg-dots').empty()) {
            svg.insert('rect', '.main-group')
                .attr('class', 'bg-dots')
                .attr('width', '100%').attr('height', '100%')
                .attr('fill', 'url(#nv-dots)');
        }
    },

    _nvColor(d) {
        if (d.filtered || d.isFiltered) return '#8b5cf6';
        if ((d.vulnerableCount || 0) > 0 || (d.vulnerable)) return '#ef4444';
        if ((d.criticalCount   || 0) > 0) return '#ef4444';
        if (d.live) return '#3b82f6';
        return '#00e5a0';
    },

    _nvGrad(d) {
        if (d.filtered || d.isFiltered) return 'url(#nv-grad-filtered)';
        if ((d.vulnerableCount || 0) > 0 || (d.vulnerable)) return 'url(#nv-grad-danger)';
        if (d.live) return 'url(#nv-grad-agent)';
        return 'url(#nv-grad-safe)';
    },

    // Returns OS logo data-URI (Ubuntu / Debian) or null
    _osLogoURI(osStr) {
        if (!osStr) return null;
        const s = osStr.toLowerCase();
        if (s.includes('ubuntu')) {
            return `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Ccircle cx='12' cy='12' r='11' fill='%23E95420'/%3E%3Ccircle cx='12' cy='4.5' r='2.2' fill='white'/%3E%3Ccircle cx='5' cy='18' r='2.2' fill='white'/%3E%3Ccircle cx='19' cy='18' r='2.2' fill='white'/%3E%3Cpath d='M12 6.7L5.8 16.5h12.4Z' stroke='white' stroke-width='1.3' fill='none' stroke-linejoin='round'/%3E%3C/svg%3E`;
        }
        if (s.includes('debian')) {
            return `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Ccircle cx='12' cy='12' r='11' fill='%23A80030'/%3E%3Cpath d='M15.5 7.5c0-2.2-2-3.5-4-2.5-2 1-2.8 3.3-1.8 5.3 1 2 3.2 2.2 4.2 1 1-1.2.8-3.2-1.2-3.2' stroke='white' stroke-width='1.2' fill='none' stroke-linecap='round'/%3E%3Ccircle cx='11' cy='17' r='1.2' fill='white'/%3E%3C/svg%3E`;
        }
        if (s.includes('windows')) {
            return `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Ccircle cx='12' cy='12' r='11' fill='%230078D4'/%3E%3Crect x='6' y='6' width='7' height='7' fill='white' rx='0.5'/%3E%3Crect x='14' y='6' width='4.5' height='7' fill='white' rx='0.5'/%3E%3Crect x='6' y='14' width='7' height='4.5' fill='white' rx='0.5'/%3E%3Crect x='14' y='14' width='4.5' height='4.5' fill='white' rx='0.5'/%3E%3C/svg%3E`;
        }
        return null;
    },

    renderVLANNodes(nodes, isFiltered = false) {
        this.updateLegend('vlan');
        this._setupSvgDefs();
        const maxRadius = Math.min(80, Math.max(30, 400 / Math.sqrt(nodes.length)));
        const forceStrength = Math.max(-500, -100 * Math.sqrt(nodes.length));
        
        if (simulation) simulation.stop();
        
        simulation = d3.forceSimulation(nodes)
            .force('charge', d3.forceManyBody().strength(forceStrength))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(d => Math.min(maxRadius, Math.max(25, Math.sqrt(d.hostCount) * 8)) + 5))
            .force('x', d3.forceX(width / 2).strength(0.1))
            .force('y', d3.forceY(height / 2).strength(0.1))
            .alpha(0.8)
            .alphaDecay(0.02);
        
        const g = svg.select('.main-group');
        g.selectAll('*').remove();
        
        // Créer le menu contextuel s'il n'existe pas
        if (!document.getElementById('contextMenu')) {
            this.createContextMenu();
        }
        
        const nodeGroups = g.selectAll('.node-group')
            .data(nodes).enter().append('g').attr('class', 'node-group')
            .style('cursor', 'pointer')
            .on('click', (event, d) => {
                if (event.button === 0) {
                    event.stopPropagation();
                    if (isFiltered) {
                        this.showFilteredHostView(d.id);
                    } else {
                        this.showHostView(d.id);
                    }
                }
            })
            .on('contextmenu', (event, d) => {
                event.preventDefault();
                event.stopPropagation();
                
                const menu = document.getElementById('contextMenu');
                menu.innerHTML = '';
                
                this.addMenuOption(menu, `📊 Rapport VLAN ${d.id}`, () => {
                    PDFReports.generateVLANReport(d.id);
                });
                
                this.addMenuOption(menu, `👁️ Voir les hôtes`, () => {
                    if (isFiltered) {
                        this.showFilteredHostView(d.id);
                    } else {
                        this.showHostView(d.id);
                    }
                });
                
                menu.style.left = event.pageX + 'px';
                menu.style.top = event.pageY + 'px';
                menu.style.display = 'block';
            })
            .on('mouseover', (event, d) => {
                d3.select(event.currentTarget).select('circle').style('stroke-width', '4px');
                this.showTooltip(event, d);
            })
            .on('mouseout', (event, d) => {
                d3.select(event.currentTarget).select('circle').style('stroke-width', '3px');
                this.hideTooltip();
            });
        
        // ── SentinelOne-style VLAN nodes ────────────────────────────────────────
        nodeGroups.each(function(d) {
            const ng   = d3.select(this);
            const r    = Math.min(maxRadius, Math.max(25, Math.sqrt(d.hostCount) * 8));
            const col  = NetworkVisualization._nvColor(d.filtered ? {...d, filtered: true} : d);
            const grad = NetworkVisualization._nvGrad(d.filtered ? {...d, filtered: true} : d);

            // Outer pulse ring
            ng.append('circle')
                .attr('class', 'nv-pulse')
                .attr('r', r + 6)
                .style('fill', 'none')
                .style('stroke', col)
                .style('stroke-width', '1px')
                .style('stroke-opacity', d.vulnerableCount > 0 ? '0.6' : '0.3');

            // Main circle — gradient fill + glow border
            ng.append('circle')
                .attr('class', 'nv-main')
                .attr('r', r)
                .style('fill', grad)
                .style('stroke', col)
                .style('stroke-width', '1.5px')
                .style('filter', 'url(#nv-glow)');

            // Labels
            const fs = Math.max(10, Math.min(15, r / 3));
            ng.append('text').attr('dy', '-0.5em')
                .style('font', `700 ${fs}px Inter,system-ui,sans-serif`)
                .style('fill', '#fff').style('text-anchor', 'middle')
                .style('pointer-events', 'none')
                .text(`VLAN ${d.id}`);
            ng.append('text').attr('dy', `${fs * 0.08 + 1}em`)
                .style('font', `400 ${Math.max(8, fs - 2)}px Inter,system-ui,sans-serif`)
                .style('fill', 'rgba(255,255,255,0.6)').style('text-anchor', 'middle')
                .style('pointer-events', 'none')
                .text(`${d.hostCount} hôte${d.hostCount > 1 ? 's' : ''}`);
            if (d.vulnerableCount > 0) {
                ng.append('text').attr('dy', `${fs * 0.08 + 2.2}em`)
                    .style('font', `600 ${Math.max(8, fs - 2)}px Inter,system-ui,sans-serif`)
                    .style('fill', '#ef4444').style('text-anchor', 'middle')
                    .style('pointer-events', 'none')
                    .text(`⚠ ${d.vulnerableCount} risque${d.vulnerableCount > 1 ? 's' : ''}`);
            }
        });
        
        let tickCount = 0;
        simulation.on('tick', () => {
            tickCount++;
            nodeGroups.attr('transform', d => `translate(${d.x},${d.y})`);
            if (tickCount > 300) simulation.stop();
        });

        // Centrer et adapter le zoom une fois la simulation convergée
        setTimeout(() => {
            try {
                const gNode = svg.select('.main-group').node();
                if (!gNode || !zoomBehavior) return;
                const bbox = gNode.getBBox();
                if (!bbox || bbox.width < 1 || bbox.height < 1) return;
                const pad = 60;
                const scale = Math.min(
                    (width  - pad * 2) / bbox.width,
                    (height - pad * 2) / bbox.height,
                    1.4
                );
                const tx = (width  - bbox.width  * scale) / 2 - bbox.x * scale;
                const ty = (height - bbox.height * scale) / 2 - bbox.y * scale;
                svg.transition().duration(600).call(
                    zoomBehavior.transform,
                    d3.zoomIdentity.translate(tx, ty).scale(scale)
                );
            } catch (_) {}
        }, 900);

        const viewType = isFiltered ? 'Résultats filtrés' : 'Vue d\'ensemble';
        this.updateBreadcrumb([viewType]);
    },

    renderHostNodes(hosts, vlanId, isFiltered = false) {
        this.updateLegend('host');
        this._setupSvgDefs();
        const totalHosts = hosts.length;
        const displayHosts = hosts;
        
        const nodes = displayHosts.map((host, index) => ({
            id: host.ip,
            type: 'host',
            data: host,
            index: index,
            filtered: isFiltered
        }));
        
        nodes.unshift({
            id: `vlan-${vlanId}`,
            type: 'vlan-center',
            vlanId: vlanId,
            totalHosts: totalHosts,
            displayedHosts: displayHosts.length,
            filtered: isFiltered
        });
        
        const links = displayHosts.map(host => ({
            source: `vlan-${vlanId}`,
            target: host.ip
        }));
        
        if (simulation) simulation.stop();
        
        const hostCount = displayHosts.length;
        const linkDistance = Math.max(80, Math.min(200, 300 - hostCount * 2));
        const chargeStrength = Math.max(-100, -20 - hostCount);
        const collisionRadius = Math.max(20, 35 - hostCount * 0.3);
        
        simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id(d => d.id).distance(linkDistance).strength(0.3))
            .force('charge', d3.forceManyBody().strength(chargeStrength))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(collisionRadius))
            .force('radial', d3.forceRadial(linkDistance, width / 2, height / 2).strength(0.1))
            .alpha(0.6)
            .alphaDecay(0.02);
        
        const g = svg.select('.main-group');
        g.selectAll('*').remove();
        
        if (!document.getElementById('contextMenu')) {
            this.createContextMenu();
        }
        
        const linkElements = g.selectAll('.link')
            .data(links).enter().append('line')
            .attr('class', 'link')
            .style('stroke', 'rgba(0,229,160,0.18)')
            .style('stroke-width', '1px')
            .style('stroke-dasharray', '4,4')
            .style('opacity', 1);
        
        const nodeGroups = g.selectAll('.node-group')
            .data(nodes).enter().append('g')
            .attr('class', 'node-group')
            .style('cursor', 'pointer')
            .on('mouseover', (event, d) => {
                d3.select(event.currentTarget).select('circle').style('stroke-width', '3px');
                
                if (d.type === 'host') {
                    linkElements.style('opacity', l => 
                        l.source.id === d.id || l.target.id === d.id ? 1 : 0.2
                    );
                }
                
                this.showTooltip(event, d);
            })
            .on('mouseout', (event, d) => {
                d3.select(event.currentTarget).select('circle').style('stroke-width', d.type === 'vlan-center' ? '3px' : '2px');
                linkElements.style('opacity', 0.6);
                this.hideTooltip();
            })
            .on('click', (event, d) => {
                event.stopPropagation();
                if (d.type === 'vlan-center') {
                    if (isFiltered) {
                        this.showFilteredVLANView();
                    } else {
                        this.showVLANView();
                    }
                } else if (d.type === 'host') {
                    this.showHostDetails(d.data);
                }
            })
            .on('contextmenu', (event, d) => {
                event.preventDefault();
                event.stopPropagation();
                
                if (d.type === 'vlan-center') {
                    const menu = document.getElementById('contextMenu');
                    menu.innerHTML = '';
                    
                    this.addMenuOption(menu, `📊 Rapport VLAN ${d.vlanId}`, () => {
                        PDFReports.generateVLANReport(d.vlanId);
                    });
                    
                    this.addMenuOption(menu, `🔙 Retour réseau`, () => {
                        if (isFiltered) {
                            this.showFilteredVLANView();
                        } else {
                            this.showVLANView();
                        }
                    });
                    
                    menu.style.left = event.pageX + 'px';
                    menu.style.top = event.pageY + 'px';
                    menu.style.display = 'block';
                }
            });
        
        // ── SentinelOne-style Host nodes ──────────────────────────────────────
        nodeGroups.each(function(d) {
            const ng = d3.select(this);
            const isCenter = d.type === 'vlan-center';
            const r = isCenter
                ? Math.max(30, Math.min(60, 40 + totalHosts * 0.5))
                : Math.max(13, Math.min(22, 16 - hostCount * 0.1));

            const nodeData = isCenter ? { vulnerableCount: 0 } : (d.data || {});
            const isLive = !isCenter && window._liveAgentIPs && window._liveAgentIPs.has(d.id);
            const fakeD = isCenter
                ? { filtered: isFiltered }
                : { vulnerable: nodeData.vulnerable, filtered: isFiltered, live: isLive };
            const col  = NetworkVisualization._nvColor(fakeD);
            const grad = NetworkVisualization._nvGrad(fakeD);

            // Pulse ring
            ng.append('circle')
                .attr('class', isLive ? 'nv-pulse nv-pulse-live' : 'nv-pulse')
                .attr('r', r + 4)
                .style('fill', 'none')
                .style('stroke', col)
                .style('stroke-width', '1px')
                .style('stroke-opacity', isCenter ? '0.25' : (nodeData.vulnerable || isLive ? '0.5' : '0.2'));

            // Main circle
            ng.append('circle')
                .attr('class', 'nv-main')
                .attr('r', r)
                .style('fill', grad)
                .style('stroke', col)
                .style('stroke-width', isCenter ? '2px' : '1.5px')
                .style('filter', 'url(#nv-glow)');

            // OS logo (host nodes only)
            if (!isCenter && nodeData.os) {
                const logo = NetworkVisualization._osLogoURI(
                    typeof nodeData.os === 'object' ? nodeData.os.name : nodeData.os
                );
                if (logo) {
                    ng.append('image')
                        .attr('href', logo)
                        .attr('x', -r * 0.55).attr('y', -r * 0.55)
                        .attr('width', r * 1.1).attr('height', r * 1.1)
                        .style('pointer-events', 'none').style('opacity', '0.85');
                }
            }

            // LIVE badge
            if (isLive) {
                ng.append('circle')
                    .attr('cx', r * 0.7).attr('cy', -r * 0.7).attr('r', 5)
                    .style('fill', '#3b82f6').style('stroke', '#fff').style('stroke-width', '1.2px');
            }

            // NSE vuln badge
            if (!isCenter && d.data) {
                const openPorts  = d.data.ports.filter(p => p.state === 'open');
                const allScripts = (d.data.hostScripts || []).concat(openPorts.flatMap(p => p.scripts || []));
                const vulnCount  = allScripts.filter(s => /vuln|exploit|VULNERABLE|anon|bypass/i.test(s.id + ' ' + (s.output || ''))).length;
                if (vulnCount > 0) {
                    ng.append('circle')
                        .attr('cx', r * 0.7).attr('cy', -r * 0.7).attr('r', 6)
                        .style('fill', '#ef4444').style('stroke', '#fff').style('stroke-width', '1.2px');
                    ng.append('text')
                        .attr('x', r * 0.7).attr('y', -r * 0.7 + 3)
                        .attr('text-anchor', 'middle')
                        .style('font', '700 7px Inter,sans-serif').style('fill', 'white')
                        .style('pointer-events', 'none').text(vulnCount);
                }
            }

            // Labels
            if (isCenter) {
                ng.append('text').attr('dy', '-0.4em')
                    .style('font', '700 13px Inter,system-ui,sans-serif')
                    .style('fill', '#fff').style('text-anchor', 'middle').style('pointer-events', 'none')
                    .text(`VLAN ${d.vlanId}`);
                ng.append('text').attr('dy', '0.9em')
                    .style('font', '400 10px Inter,system-ui,sans-serif')
                    .style('fill', 'rgba(255,255,255,0.5)').style('text-anchor', 'middle').style('pointer-events', 'none')
                    .text(`${d.displayedHosts}/${d.totalHosts}`);
            } else {
                const lastOctet = d.id.split('.').pop();
                ng.append('text').attr('dy', '0.35em')
                    .style('font', `600 ${Math.max(7, Math.min(11, 10 - hostCount * 0.05))}px Inter,monospace,sans-serif`)
                    .style('fill', '#fff').style('text-anchor', 'middle').style('pointer-events', 'none')
                    .text(lastOctet);
                ng.append('text').attr('dy', `${r + 13}px`)
                    .style('font', '400 9px Inter,system-ui,sans-serif')
                    .style('fill', 'rgba(255,255,255,0.45)').style('text-anchor', 'middle').style('pointer-events', 'none')
                    .text(d.id);
            }
        });
        
        let tickCount = 0;
        simulation.on('tick', () => {
            tickCount++;

            nodes.forEach(d => {
                d.x = Math.max(50, Math.min(width - 50, d.x));
                d.y = Math.max(50, Math.min(height - 50, d.y));
            });

            linkElements
                .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x).attr('y2', d => d.target.y);

            nodeGroups.attr('transform', d => `translate(${d.x},${d.y})`);

            // Pan to highlighted node once simulation has mostly settled
            if (tickCount === 80 && NetworkVisualization._highlightIp) {
                NetworkVisualization._panToHighlighted();
            }

            if (tickCount > 500) {
                simulation.stop();
            }
        });

        const viewType = isFiltered ? 'Résultats filtrés' : 'Vue d\'ensemble';
        this.updateBreadcrumb([viewType, `VLAN ${vlanId} (${displayHosts.length}/${totalHosts} hôtes)`]);
    },

    showVLANView() {
        currentView = 'vlans';
        currentVLAN = null;

        const data = filteredData || networkData;
        const vlans = Object.values(data.vlans);
        if (vlans.length === 0) return;

        const nodes = vlans.map(vlan => ({
            id: vlan.id,
            type: 'vlan',
            hostCount: vlan.hosts.length,
            vulnerableCount: vlan.hosts.filter(h => h.vulnerable).length
        }));

        this.renderVLANNodes(nodes, !!filteredData);

        // Mettre à jour le tableau avec tous les hôtes
        initHostTable(data.hosts, null);
    },

    showHostView(vlanId) {
        currentView = 'hosts';
        currentVLAN = vlanId;

        const data = filteredData || networkData;
        const vlan = data.vlans[vlanId];
        if (!vlan || vlan.hosts.length === 0) return;

        this.renderHostNodes(vlan.hosts, vlanId, !!filteredData);

        // Mettre à jour le tableau avec les hôtes du VLAN
        initHostTable(vlan.hosts, vlanId);
    },

    showFilteredVLANView() {
        const vlans = Object.values(filteredData.vlans);
        if (vlans.length === 0) {
            const g = svg.select('.main-group');
            g.selectAll('*').remove();
            g.append('text')
                .attr('x', width / 2)
                .attr('y', height / 2)
                .attr('text-anchor', 'middle')
                .attr('fill', 'white')
                .attr('font-size', '18px')
                .text('Aucun hôte ne correspond aux critères de filtrage');
            return;
        }

        const nodes = vlans.map(vlan => ({
            id: vlan.id,
            type: 'vlan',
            hostCount: vlan.hosts.length,
            vulnerableCount: vlan.hosts.filter(h => h.vulnerable).length,
            filtered: true
        }));

        this.renderVLANNodes(nodes, true);

        // Mettre à jour le tableau avec tous les hôtes filtrés
        initHostTable(filteredData.hosts, null);
    },

    showFilteredHostView(vlanId) {
        const vlan = filteredData.vlans[vlanId];
        if (!vlan || vlan.hosts.length === 0) return;

        this.renderHostNodes(vlan.hosts, vlanId, true);

        // Mettre à jour le tableau avec les hôtes filtrés du VLAN
        initHostTable(vlan.hosts, vlanId);
    },

    showTooltip(event, d) {
        const tooltip = document.getElementById('tooltip');
        let content = '';
        
        if (d.type === 'vlan' || d.type === 'vlan-center') {
            const data = filteredData || networkData;
            const vlan = data.vlans[d.id || d.vlanId];
            if (!vlan) return;
            content = `<strong>VLAN ${Utils.escapeHtml(d.id || d.vlanId)}</strong><br>🖥️ Hôtes: ${vlan.hosts.length}<br>⚠️ Hôtes à risque: ${vlan.hosts.filter(h => h.vulnerable).length}<br>🔌 Ports ouverts: ${vlan.hosts.reduce((sum, h) => sum + h.ports.filter(p => p.state === 'open').length, 0)}`;
        } else if (d.type === 'host' && d.data) {
            const host = d.data;
            const openPorts = host.ports.filter(p => p.state === 'open');
            const filteredPorts = host.ports.filter(p => p.state === 'filtered');

            content = `<strong>${FileProcessor.getVendorIcon(host.vendor)} ${Utils.escapeHtml(host.ip)}</strong>`;

            // Hostname
            if (host.hostnames && host.hostnames.length > 0) {
                content += `<br>🏷️ ${Utils.escapeHtml(host.hostnames[0].name)}`;
            }
            // OS
            if (host.os) {
                const acc = parseInt(host.os.accuracy || 0, 10);
                const accColor = acc >= 90 ? 'var(--ok)' : acc >= 70 ? 'var(--warn)' : 'var(--danger)';
                content += `<br>💻 ${Utils.escapeHtml(host.os.name)} <small style="color:${accColor}">(${acc}%)</small>`;
            }

            content += `<br>📁 Source: ${Utils.escapeHtml(host.source)}`;

            if (host.vendor) {
                content += `<br>🏭 Fabricant: ${Utils.escapeHtml(host.vendor)}`;
            }
            if (host.macAddress) {
                content += `<br>🔧 MAC: ${Utils.escapeHtml(host.macAddress)}`;
            }

            // NSE scripts count
            const nseCount = (host.hostScripts ? host.hostScripts.length : 0) +
                openPorts.reduce((sum, p) => sum + (p.scripts ? p.scripts.length : 0), 0);
            const vulnScripts = ((host.hostScripts || []).concat(openPorts.flatMap(p => p.scripts || [])))
                .filter(s => /vuln|exploit|VULNERABLE|anon|bypass/i.test(s.id + ' ' + (s.output || '')));

            if (nseCount > 0) {
                content += `<br>🔬 Scripts NSE: ${nseCount}`;
                if (vulnScripts.length > 0) {
                    content += ` <span style="color:#FF5722;">(${vulnScripts.length} vuln!)</span>`;
                }
            }

            const _SAFE_STATES = new Set(['open', 'closed', 'filtered', 'open|filtered', 'unfiltered']);
            content += `<br>${host.vulnerable ? '⚠️ <span style="color: #FF5722;">Hôte à risque</span><br>' : ''}🔌 Ports ouverts: ${openPorts.length}${filteredPorts.length > 0 ? `<br>🛡️ Ports filtrés: ${filteredPorts.length}` : ''}<br><div class="port-grid">${openPorts.slice(0, 20).map(port => { const safeState = _SAFE_STATES.has(port.state) ? port.state : 'unknown'; return `<div class="port-item port-${safeState}">${Utils.escapeHtml(port.port)}/${Utils.escapeHtml(port.service)}</div>`; }).join('')}${openPorts.length > 20 ? `<div class="port-item">+${openPorts.length - 20} autres...</div>` : ''}</div>`;
        }
        
        tooltip.innerHTML = content;
        tooltip.style.display = 'block';
        tooltip.style.left = (event.pageX + 10) + 'px';
        tooltip.style.top = (event.pageY - 10) + 'px';
    },

    hideTooltip() {
        document.getElementById('tooltip').style.display = 'none';
    },

    updateBreadcrumb(path) {
        const breadcrumb = document.getElementById('breadcrumb');
        const links = path.map((item, index) => {
            const safe = Utils.escapeHtml(item);
            if (index === 0) {
                if (filteredData) {
                    return `<a data-action="showFilteredVLANView" style="cursor:pointer">🔍 ${safe}</a>`;
                } else {
                    return `<a data-action="showVLANView" style="cursor:pointer">🏠 ${safe}</a>`;
                }
            } else {
                return `<span> > ${safe}</span>`;
            }
        });
        breadcrumb.innerHTML = links.join('');
    },

    createVLANStatsSection() {
        // La section existe déjà dans le HTML, on la récupère
        return document.getElementById('vlanStatsSection');
    },

    // Fonction pour générer le HTML des statistiques
    generateVLANStatsHTML(stats, vlanId) {
        return `
            <div class="stats-grid">
                <div class="stats-chart-container">
                    <h4 class="stats-chart-title vendor">📊 Répartition par Fabricant</h4>
                    <canvas id="vendorChart" width="280" height="120" class="stats-chart-canvas"></canvas>
                    <div class="stats-chart-info">
                        ${stats.vendorStats.map(v => `${Utils.escapeHtml(v.vendor)}: ${v.count} hôte(s)`).join(' • ')}
                    </div>
                </div>

                <div class="stats-chart-container">
                    <h4 class="stats-chart-title ports">🔌 Ports les Plus Ouverts</h4>
                    <canvas id="portsChart" width="280" height="120" class="stats-chart-canvas"></canvas>
                    <div class="stats-chart-info">
                        Top ${stats.topPorts.length} ports sur ${stats.securityStats.totalPorts} ouverts
                    </div>
                </div>

                <div class="stats-chart-container">
                    <h4 class="stats-chart-title security">🛡️ État de Sécurité</h4>
                    <canvas id="securityChart" width="280" height="80" class="stats-chart-canvas"></canvas>
                    <div class="stats-security-details">
                        <div class="stats-security-row">
                            <span>🔴 À risque: ${stats.securityStats.vulnerable}</span>
                            <span>🟢 Sécurisés: ${stats.securityStats.secure}</span>
                        </div>
                        <div class="stats-risk-info">
                            📈 Taux de risque: ${stats.securityStats.riskPercentage}% 
                            (${stats.securityStats.avgPorts} ports/hôte en moyenne)
                        </div>
                    </div>
                </div>
            </div>

            <button class="stats-pdf-button" data-vlan-id="${Utils.escapeHtml(vlanId)}">
                📄 Générer Rapport PDF
            </button>
        `;
    },

    // Modifier la fonction showVLANStats
    showVLANStats(vlanId) {
        const data = filteredData || networkData;
        const vlan = data.vlans[vlanId];

        if (!vlan || vlan.hosts.length === 0) {
            return;
        }

        // Utiliser le popup au lieu de vlanStatsSection
        const popup = document.getElementById('statsPopup');
        const popupTitle = document.getElementById('popupTitle');
        const popupContent = document.getElementById('popupContent');

        if (!popup || !popupTitle || !popupContent) return;

        popupTitle.textContent = `📊 Statistiques VLAN ${vlanId}`;
        const stats = this.calculateVLANStats(vlan);
        const content = this.generateVLANStatsHTML(stats, vlanId);
        popupContent.innerHTML = content;

        const pdfBtn = popupContent.querySelector('.stats-pdf-button');
        if (pdfBtn) {
            pdfBtn.addEventListener('click', () => PDFReports.generateVLANReport(vlanId));
        }

        // Afficher le popup avec l'animation
        popup.classList.add('active');
        document.body.classList.add('modal-open');

        setTimeout(() => {
            this.drawVendorChart(stats.vendorStats, 'vendorChart');
            this.drawPortsChart(stats.topPorts, 'portsChart');
            this.drawSecurityChart(stats.securityStats, 'securityChart');
        }, 100);
    },

    // Fonction pour fermer les statistiques
    closeVLANStats() {
        const statsSection = document.getElementById('vlanStatsSection');
        if (statsSection) {
            statsSection.style.display = 'none';
        }
    },

    // Fonction pour calculer les statistiques d'un VLAN
    calculateVLANStats(vlan) {
        const hosts = vlan.hosts;
        
        // Statistiques par vendor
        const vendorCount = {};
        hosts.forEach(host => {
            const vendor = host.vendor || 'Inconnu';
            vendorCount[vendor] = (vendorCount[vendor] || 0) + 1;
        });
        
        // Top 5 des vendors
        const vendorStats = Object.entries(vendorCount)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 5)
            .map(([vendor, count]) => ({ vendor, count }));

        // Statistiques des ports
        const portCount = {};
        hosts.forEach(host => {
            host.ports.filter(p => p.state === 'open').forEach(port => {
                const key = `${port.port}/${port.service}`;
                portCount[key] = (portCount[key] || 0) + 1;
            });
        });
        
        // Top 8 des ports les plus ouverts
        const topPorts = Object.entries(portCount)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 8)
            .map(([portService, count]) => ({ portService, count }));

        // Statistiques de sécurité
        const vulnerableHosts = hosts.filter(h => h.vulnerable).length;
        const secureHosts = hosts.length - vulnerableHosts;
        const totalOpenPorts = hosts.reduce((sum, h) => sum + h.ports.filter(p => p.state === 'open').length, 0);
        const avgPortsPerHost = Math.round(totalOpenPorts / hosts.length);

        const securityStats = {
            vulnerable: vulnerableHosts,
            secure: secureHosts,
            total: hosts.length,
            totalPorts: totalOpenPorts,
            avgPorts: avgPortsPerHost,
            riskPercentage: Math.round((vulnerableHosts / hosts.length) * 100)
        };

        return {
            vendorStats,
            topPorts,
            securityStats
        };
    },

    // Fonction pour générer le HTML des statistiques
    generateVLANStatsHTML(stats, vlanId) {
        return `
            <div style="margin-bottom: 20px;">
                <h4 style="color: #f39c12; font-size: 14px; margin-bottom: 10px;">📊 Répartition par Fabricant</h4>
                <canvas id="vendorChart" width="320" height="120" style="background: rgba(255,255,255,0.1); border-radius: 5px;"></canvas>
                <div style="font-size: 11px; margin-top: 5px; color: #bdc3c7;">
                    ${stats.vendorStats.map(v => `${Utils.escapeHtml(v.vendor)}: ${v.count} hôte(s)`).join(' • ')}
                </div>
            </div>

            <div style="margin-bottom: 20px;">
                <h4 style="color: #e74c3c; font-size: 14px; margin-bottom: 10px;">🔌 Ports les Plus Ouverts</h4>
                <canvas id="portsChart" width="320" height="120" style="background: rgba(255,255,255,0.1); border-radius: 5px;"></canvas>
                <div style="font-size: 11px; margin-top: 5px; color: #bdc3c7;">
                    Top ${stats.topPorts.length} ports sur ${stats.securityStats.totalPorts} ouverts
                </div>
            </div>

            <div style="margin-bottom: 15px;">
                <h4 style="color: #27ae60; font-size: 14px; margin-bottom: 10px;">🛡️ État de Sécurité</h4>
                <canvas id="securityChart" width="320" height="80" style="background: rgba(255,255,255,0.1); border-radius: 5px;"></canvas>
                <div style="font-size: 12px; margin-top: 8px;">
                    <div style="display: flex; justify-content: space-between;">
                        <span>🔴 À risque: ${stats.securityStats.vulnerable}</span>
                        <span>🟢 Sécurisés: ${stats.securityStats.secure}</span>
                    </div>
                    <div style="margin-top: 5px; color: #f39c12;">
                        📈 Taux de risque: ${stats.securityStats.riskPercentage}% 
                        (${stats.securityStats.avgPorts} ports/hôte en moyenne)
                    </div>
                </div>
            </div>

            <button class="stats-pdf-button" data-vlan-id="${Utils.escapeHtml(vlanId)}" style="
                width: 100%;
                background: #3498db;
                border: none;
                color: white;
                padding: 8px;
                border-radius: 5px;
                cursor: pointer;
                font-size: 12px;
                margin-top: 10px;
            ">📄 Générer Rapport PDF</button>
        `;
    },

    // Fonction pour dessiner le graphique des vendors
    drawVendorChart(vendorStats, canvasId) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        
        const ctx = canvas.getContext('2d');
        const { width, height } = canvas;
        
        // Nettoyer le canvas
        ctx.clearRect(0, 0, width, height);
        
        if (vendorStats.length === 0) return;
        
        // Couleurs pour les vendors
        const colors = ['#e74c3c', '#3498db', '#f39c12', '#27ae60', '#9b59b6', '#e67e22'];
        
        // Calculer les dimensions
        const maxValue = Math.max(...vendorStats.map(v => v.count));
        const barWidth = (width - 60) / vendorStats.length;
        const maxBarHeight = height - 40;
        
        // Dessiner les barres
        vendorStats.forEach((vendor, index) => {
            const barHeight = (vendor.count / maxValue) * maxBarHeight;
            const x = 30 + index * barWidth;
            const y = height - 20 - barHeight;
            
            // Barre
            ctx.fillStyle = colors[index % colors.length];
            ctx.fillRect(x, y, barWidth - 5, barHeight);
            
            // Valeur au-dessus de la barre
            ctx.fillStyle = 'white';
            ctx.font = '10px Arial';
            ctx.textAlign = 'center';
            ctx.fillText(vendor.count.toString(), x + barWidth/2 - 2.5, y - 5);
            
            // Nom du vendor (tronqué)
            let vendorName = vendor.vendor.length > 8 ? vendor.vendor.substring(0, 8) + '...' : vendor.vendor;
            ctx.font = '9px Arial';
            ctx.fillText(vendorName, x + barWidth/2 - 2.5, height - 5);
        });
    },

    // Fonction pour dessiner le graphique des ports
    drawPortsChart(topPorts, canvasId) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        
        const ctx = canvas.getContext('2d');
        const { width, height } = canvas;
        
        ctx.clearRect(0, 0, width, height);
        
        if (topPorts.length === 0) return;
        
        const colors = ['#e74c3c', '#c0392b', '#a93226', '#922b21', '#7b241c', '#641e16', '#58181d', '#4a1516'];
        const maxValue = Math.max(...topPorts.map(p => p.count));
        const barWidth = (width - 60) / topPorts.length;
        const maxBarHeight = height - 40;
        
        topPorts.forEach((port, index) => {
            const barHeight = (port.count / maxValue) * maxBarHeight;
            const x = 30 + index * barWidth;
            const y = height - 20 - barHeight;
            
            // Barre
            ctx.fillStyle = colors[index % colors.length];
            ctx.fillRect(x, y, barWidth - 3, barHeight);
            
            // Valeur
            ctx.fillStyle = 'white';
            ctx.font = '9px Arial';
            ctx.textAlign = 'center';
            ctx.fillText(port.count.toString(), x + barWidth/2 - 1.5, y - 3);
            
            // Port (seulement le numéro)
            const portNum = port.portService.split('/')[0];
            ctx.font = '8px Arial';
            ctx.fillText(portNum, x + barWidth/2 - 1.5, height - 5);
        });
    },

    // Fonction pour dessiner le graphique de sécurité
    drawSecurityChart(securityStats, canvasId) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        
        const ctx = canvas.getContext('2d');
        const { width, height } = canvas;
        
        ctx.clearRect(0, 0, width, height);
        
        // Graphique en barres horizontales
        const barHeight = 25;
        const y1 = 15;
        const y2 = 45;
        
        const total = securityStats.total;
        const vulnerableWidth = (securityStats.vulnerable / total) * (width - 100);
        const secureWidth = (securityStats.secure / total) * (width - 100);
        
        // Barre vulnérable
        ctx.fillStyle = '#e74c3c';
        ctx.fillRect(50, y1, vulnerableWidth, barHeight);
        
        // Barre sécurisée
        ctx.fillStyle = '#27ae60';
        ctx.fillRect(50, y2, secureWidth, barHeight);
        
        // Labels
        ctx.fillStyle = 'white';
        ctx.font = '11px Arial';
        ctx.textAlign = 'left';
        ctx.fillText('Vulnérables', 5, y1 + 15);
        ctx.fillText('Sécurisés', 5, y2 + 15);
        
        // Valeurs
        ctx.textAlign = 'right';
        ctx.fillText(securityStats.vulnerable.toString(), width - 10, y1 + 15);
        ctx.fillText(securityStats.secure.toString(), width - 10, y2 + 15);
    },

    showHostDetails(host) {
        // Utiliser le popup au lieu de vlanStatsSection
        const popup = document.getElementById('statsPopup');
        const popupTitle = document.getElementById('popupTitle');
        const popupContent = document.getElementById('popupContent');

        if (!popup || !popupTitle || !popupContent) return;

        popupTitle.textContent = `🖥️ Détails de l'hôte ${host.ip}`;
        const content = this.generateHostDetailsHTML(host);
        popupContent.innerHTML = content;

        popupContent.querySelector('[data-action="pdf"]')
            ?.addEventListener('click', () => PDFReports.generateHostReport(host.ip));
        popupContent.querySelector('[data-action="csv"]')
            ?.addEventListener('click', () => NetworkVisualization.exportHostToCSV(host.ip));
        popupContent.querySelector('[data-action="close"]')
            ?.addEventListener('click', () => NetworkVisualization.closeHostDetails());

        // Lien "méthodologie" : ferme le popup puis ouvre la vue Scoring
        popupContent.querySelector('.score-method-link')
            ?.addEventListener('click', (e) => {
                e.preventDefault();
                NetworkVisualization.closePopup();
                if (typeof NMapperShell !== 'undefined') NMapperShell.showView('scoring');
            });

        // Afficher le popup avec l'animation
        popup.classList.add('active');
        document.body.classList.add('modal-open');
    },

    generateHostDetailsHTML(host) {
        const openPorts = host.ports.filter(p => p.state === 'open');
        const filteredPorts = host.ports.filter(p => p.state === 'filtered');
        
        const criticalServices = SecurityAnalyzer.analyzeCriticalServices(host.ports);

        // Hostname / OS / NSE sections
        const hostnameHTML = (host.hostnames && host.hostnames.length > 0)
            ? host.hostnames.map(h => `<span class="host-hostname-tag">${Utils.escapeHtml(h.name)} <small>(${h.type})</small></span>`).join(' ')
            : '<span class="text-muted">Non résolu</span>';

        const osHTML = host.os
            ? (() => {
                const acc = parseInt(host.os.accuracy || 0, 10);
                const [cls, icon] = acc >= 90 ? ['os-conf-high', '']
                                  : acc >= 70 ? ['os-conf-med',  '']
                                  :             ['os-conf-low',  '⚠️ '];
                return `${Utils.escapeHtml(host.os.name)}<span class="os-conf-badge ${cls}">${icon}${acc}%</span>`;
            })()
            : '<span class="text-muted">Non détecté</span>';

        // Collect all NSE scripts (host-level + port-level)
        const allScripts = [];
        if (host.hostScripts && host.hostScripts.length > 0) {
            host.hostScripts.forEach(s => allScripts.push({ ...s, scope: 'host' }));
        }
        openPorts.forEach(p => {
            if (p.scripts && p.scripts.length > 0) {
                p.scripts.forEach(s => allScripts.push({ ...s, scope: `port ${p.port}` }));
            }
        });

        const nseSection = allScripts.length > 0 ? `
                <div class="nse-section">
                    <h4 class="host-section-title">🔬 Scripts NSE (${allScripts.length})</h4>
                    <div class="nse-list">
                        ${allScripts.map(s => {
                            const isVuln = /vuln|exploit|VULNERABLE|anon|bypass/i.test(s.id + ' ' + s.output);
                            return `
                            <div class="nse-item ${isVuln ? 'nse-vuln' : ''}">
                                <div class="nse-header">
                                    <span class="nse-id">${isVuln ? '🚨' : '📜'} ${Utils.escapeHtml(s.id)}</span>
                                    <span class="nse-scope">${Utils.escapeHtml(s.scope)}</span>
                                </div>
                                <pre class="nse-output">${Utils.escapeHtml(s.output || '').trim()}</pre>
                            </div>`;
                        }).join('')}
                    </div>
                </div>
        ` : '';

        // ===== LOT P1 : Score de risque pondéré + findings agrégés =====
        const risk = (typeof host.riskScore === 'number')
            ? { score: host.riskScore, level: host.riskLevel, factors: host.riskFactors || [], nseFindings: host.nseFindings || [], versionFindings: host.versionFindings || [], osFinding: host.osFinding }
            : SecurityAnalyzer.calculateRiskScore(host);
        const scoreColor = SecurityAnalyzer.getScoreColor(risk.level);
        const scoreLabel = SecurityAnalyzer.getScoreLabel(risk.level);
        const sevIcon = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', info: 'ℹ️' };

        const findingRows = [];
        (risk.nseFindings || []).forEach(f => findingRows.push(`
            <div class="finding-row ${f.severity}">
                <span class="finding-sev">${sevIcon[f.severity] || '•'}</span>
                <span class="finding-type">NSE</span>
                <span class="finding-where">${Utils.escapeHtml(f.source)}</span>
                <span class="finding-desc">${Utils.escapeHtml(f.scriptId)}${f.cves && f.cves.length ? ' — ' + Utils.escapeHtml(f.cves.join(', ')) : ''}${f.detail ? ' : ' + Utils.escapeHtml(f.detail) : ''}</span>
            </div>`));
        (risk.versionFindings || []).forEach(f => findingRows.push(`
            <div class="finding-row ${f.severity}">
                <span class="finding-sev">${sevIcon[f.severity] || '•'}</span>
                <span class="finding-type">Version</span>
                <span class="finding-where">port ${Utils.escapeHtml(f.port)}</span>
                <span class="finding-desc">${Utils.escapeHtml(f.name)} <code>${Utils.escapeHtml(f.version)}</code> — ${Utils.escapeHtml(f.reco)}</span>
            </div>`));
        if (risk.osFinding) findingRows.push(`
            <div class="finding-row ${risk.osFinding.severity}">
                <span class="finding-sev">${sevIcon[risk.osFinding.severity] || '•'}</span>
                <span class="finding-type">OS</span>
                <span class="finding-where">système</span>
                <span class="finding-desc">${Utils.escapeHtml(risk.osFinding.label)} — ${Utils.escapeHtml(risk.osFinding.os)}</span>
            </div>`);

        const factors = (risk.factors || []).slice().sort((a, b) => b.pts - a.pts);
        const factorsHTML = factors.length > 0 ? `
                    <details class="score-breakdown">
                        <summary>🧮 Détail du calcul (${factors.length} facteur${factors.length > 1 ? 's' : ''}) · <a href="#" data-view="scoring" class="score-method-link">méthodologie</a></summary>
                        <ul class="score-factors">
                            ${factors.map(f => `<li><span class="sf-pts">+${f.pts}</span><span class="sf-label">${Utils.escapeHtml(f.label)}</span></li>`).join('')}
                            <li class="sf-total"><span class="sf-pts">${risk.score}</span><span class="sf-label">Score final (plafonné à 100)</span></li>
                        </ul>
                    </details>` : '';

        const riskSection = `
                <div class="risk-overview-section">
                    <div class="risk-overview-gauge" style="--rs-color:${scoreColor}">
                        <div class="risk-gauge-num">${risk.score}<small>/100</small></div>
                        <div class="risk-gauge-level" style="color:${scoreColor}">${scoreLabel}</div>
                        <div class="risk-gauge-track"><div class="risk-gauge-fill" style="width:${risk.score}%;background:${scoreColor}"></div></div>
                    </div>
                    <div class="risk-overview-findings">
                        <h4 class="host-section-title">🎯 Findings détectés (${findingRows.length})</h4>
                        ${findingRows.length > 0
                            ? `<div class="findings-table">${findingRows.join('')}</div>`
                            : '<p class="text-muted">Aucun finding NSE / version / OS — risque basé sur l\'exposition des ports.</p>'}
                        ${factorsHTML}
                    </div>
                </div>
        `;

        return `
            <div class="host-details-container">
                ${riskSection}
                <div class="host-info-section">
                    <h4 class="host-section-title">📋 Informations Générales</h4>
                    <div class="host-info-grid">
                        <div class="host-info-item">
                            <strong>IP:</strong> <span class="host-ip">${Utils.escapeHtml(host.ip)}</span>
                        </div>
                        <div class="host-info-item">
                            <strong>Hostname:</strong> ${hostnameHTML}
                        </div>
                        <div class="host-info-item">
                            <strong>OS:</strong> ${osHTML}
                        </div>
                        <div class="host-info-item">
                            <strong>VLAN:</strong> <span class="host-vlan">${Utils.escapeHtml(host.vlan)}</span>
                        </div>
                        <div class="host-info-item">
                            <strong>Fabricant:</strong> <span class="host-vendor">${Utils.escapeHtml(host.vendor || 'Non identifié')}</span>
                        </div>
                        <div class="host-info-item">
                            <strong>Adresse MAC:</strong> <span class="host-mac">${Utils.escapeHtml(host.macAddress || 'Non disponible')}</span>
                        </div>
                        <div class="host-info-item">
                            <strong>Source:</strong> <span class="host-source">${Utils.escapeHtml(host.source)}</span>
                        </div>
                        <div class="host-info-item">
                            <strong>Statut sécurité:</strong>
                            <span class="security-status ${host.vulnerable ? 'vulnerable' : 'secure'}">
                                ${host.vulnerable ? '⚠️ À RISQUE' : '✅ Sécurisé'}
                            </span>
                        </div>
                    </div>
                </div>

                <div class="host-stats-section">
                    <h4 class="host-section-title">📊 Statistiques des Ports</h4>
                    <div class="port-stats-grid">
                        <div class="port-stat-item open">
                            <div class="port-stat-number">${openPorts.length}</div>
                            <div class="port-stat-label">Ports Ouverts</div>
                        </div>
                        <div class="port-stat-item filtered">
                            <div class="port-stat-number">${filteredPorts.length}</div>
                            <div class="port-stat-label">Ports Filtrés</div>
                        </div>
                    </div>
                </div>

                ${criticalServices.length > 0 ? `
                <div class="critical-services-section">
                    <h4 class="host-section-title critical">🚨 Services Critiques Détectés</h4>
                    <div class="critical-services-list">
                        ${criticalServices.map(service => `
                            <div class="critical-service-item ${service.risk}">
                                <div class="service-port">${Utils.escapeHtml(service.port)}</div>
                                <div class="service-name">${Utils.escapeHtml(service.service)}</div>
                                <div class="service-risk">${Utils.escapeHtml(service.riskText)}</div>
                                <div class="service-description">${Utils.escapeHtml(service.description)}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
                ` : ''}

                ${openPorts.length > 0 ? `
                <div class="ports-section">
                    <h4 class="host-section-title">🔌 Ports Ouverts (${openPorts.length})</h4>
                    <div class="ports-table">
                        <div class="ports-header">
                            <div>Port</div>
                            <div>Protocole</div>
                            <div>Service</div>
                            <div>État</div>
                            <div>Risque</div>
                        </div>
                        ${openPorts.map(port => {
                            const risk = SecurityAnalyzer.evaluatePortRisk(port.port, port.service);
                            return `
                            <div class="port-row ${risk}">
                                <div class="port-number">${Utils.escapeHtml(port.port)}</div>
                                <div class="port-protocol">TCP</div>
                                <div class="port-service">${Utils.escapeHtml(port.service || 'unknown')}</div>
                                <div class="port-state ${port.state}">${port.state.toUpperCase()}</div>
                                <div class="port-risk ${risk}">${SecurityAnalyzer.getRiskLabel(risk)}</div>
                            </div>
                            `;
                        }).join('')}
                    </div>
                </div>
                ` : ''}

                ${nseSection}

                <div class="recommendations-section">
                    <h4 class="host-section-title">🛡️ Recommandations de Sécurité</h4>
                    <div class="recommendations-list">
                        ${SecurityAnalyzer.generateHostRecommendations(host).map(rec => `
                            <div class="recommendation-item">
                                <div class="recommendation-icon">💡</div>
                                <div class="recommendation-text">${Utils.escapeHtml(rec)}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <div class="host-actions">
                    <button class="host-action-btn primary" data-action="pdf" data-ip="${Utils.escapeHtml(host.ip)}">
                        📄 Générer Rapport PDF
                    </button>
                    <button class="host-action-btn secondary" data-action="csv" data-ip="${Utils.escapeHtml(host.ip)}">
                        📊 Exporter CSV
                    </button>
                    <button class="host-action-btn danger" data-action="close">
                        ✖️ Fermer
                    </button>
                </div>
            </div>
        `;
    },

    // Fonction pour fermer les détails d'hôte (alias pour closePopup)
    closeHostDetails() {
        this.closePopup();
    },

    // Fonction pour fermer le popup
    closePopup() {
        const popup = document.getElementById('statsPopup');
        if (popup) {
            popup.classList.remove('active');
        }
        document.body.classList.remove('modal-open');
    },

    exportVLANToCSV(vlanId) {
        const data = filteredData || networkData;
        const vlan = data.vlans[vlanId];
        if (!vlan) return;
        
        const csvContent = [
            'IP,VLAN,Vendor,MAC,Ports_Ouverts,Vulnerable,Source',
            ...vlan.hosts.map(host => 
                `${host.ip},${host.vlan},"${host.vendor || ''}","${host.macAddress || ''}",${host.ports.filter(p => p.state === 'open').length},${host.vulnerable ? 'Oui' : 'Non'},${host.source}`
            )
        ].join('\n');
        
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `vlan_${vlanId}_hosts.csv`;
        a.click();
        window.URL.revokeObjectURL(url);
    },

    exportHostToCSV(hostIP) {
        const host = networkData.hosts.find(h => h.ip === hostIP);
        if (!host) return;
        
        const openPorts = host.ports.filter(p => p.state === 'open');
        const csvContent = [
            'Port,Service,État,Protocole',
            ...openPorts.map(port => `${port.port},${port.service || 'unknown'},${port.state},TCP`)
        ].join('\n');
        
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `ports_${hostIP.replace(/\./g, '_')}.csv`;
        a.click();
        window.URL.revokeObjectURL(url);
    }
};