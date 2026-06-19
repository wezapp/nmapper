// monitoring.js — Mode Monitoring NMAPPER v2
// Mode Campaign : graphe VLAN bubbles (existant)
// Mode Live     : graphe neural par hôte individuel + fix VLAN "VLAN VLAN0"

const Monitoring = (() => {

    let _mode      = 'campaign'; // 'campaign' | 'live'
    let _pollTimer = null;
    let _monSim    = null;
    let _events    = [];

    // ── Normalisation VLAN (fix "VLAN VLAN0" → "VLAN0") ─────────────────────

    function _normVlan(v) {
        if (!v) return 'Unknown';
        v = v.trim().replace(/^vlan\s+vlan/i, 'VLAN');
        if (/^\d+$/.test(v)) v = 'VLAN' + v;
        return v;
    }

    // ── Utilitaires ──────────────────────────────────────────────────────────

    const _HIGH_PORTS = new Set([21, 23, 445, 3389, 5900, 6379, 27017, 9200, 1433, 3306]);
    const _MED_PORTS  = new Set([22, 25, 80, 110, 143, 443, 8080, 8443]);

    function _scoreHost(ports, vuln) {
        let s = 0;
        (ports || []).filter(p => p.state === 'open').forEach(p => {
            s += _HIGH_PORTS.has(p.port) ? 20 : _MED_PORTS.has(p.port) ? 5 : 2;
        });
        if (vuln) s += 30;
        return Math.min(100, s);
    }

    function _hostColor(d) {
        if (d.isUnknown)  return '#6b7280';         // gris   : inconnu
        if (d.vulnerable || d.score >= 80) return '#ef4444';  // rouge  : vulnérable
        if (d.score >= 40) return '#f59e0b';         // orange : à risque
        if (d.isAgent)    return '#00e5a0';          // vert   : agent sain
        return '#3b82f6';                            // bleu   : connu sans agent
    }

    function _hostRadius(d) {
        if (d.vulnerable || d.score >= 80) return 13;
        if (d.isAgent)   return 11;
        if (d.isUnknown) return 8;
        return 9;
    }

    function _ts() {
        return new Date().toLocaleTimeString('fr-FR', { hour:'2-digit', minute:'2-digit', second:'2-digit' });
    }

    // ── Construction données — mode Campaign ──────────────────────────────────

    function _buildFromCampaignData() {
        const nodes = [];
        Object.entries(networkData.vlans || {}).forEach(([id, v]) => {
            const hosts = v.hosts || [];
            const vulnerableCount = hosts.filter(h => h.vulnerable).length;
            nodes.push({
                id:             _normVlan(id),
                hostCount:      hosts.length,
                vulnerableCount,
                criticalCount:  0,
                source: 'campaign',
            });
        });
        return { nodes, links: [] };
    }

    // ── Construction données — mode Live (hôtes individuels) ─────────────────

    function _buildFromLiveData(data, connEdges = []) {
        const hosts  = data.hosts  || [];
        const agents = data.agents || [];

        // Index : IP → agent (pour savoir si un hôte a un agent)
        const agentByIP = {};
        agents.forEach(a => { if (a.ip) agentByIP[a.ip] = a; });

        // Construire les nœuds individuels
        const nodes = hosts.map(h => {
            const vlan      = _normVlan(h.vlan || 'Unknown');
            const ports     = Array.isArray(h.ports) ? h.ports : [];
            const isAgent   = Boolean(agentByIP[h.ip] || h.agent_id);
            const isUnknown = !h.hostname && !isAgent;
            const score     = _scoreHost(ports, h.vulnerable);

            return {
                id:         h.ip,
                ip:         h.ip,
                hostname:   h.hostname || '',
                vlan,
                os:         h.os || '',
                ports,
                openPorts:  ports.filter(p => p.state === 'open').length,
                vulnerable: h.vulnerable,
                isAgent,
                isUnknown,
                agent_id:   h.agent_id || '',
                score,
            };
        });

        // Liens depuis la matrice de connectivité (host → host)
        const links    = [];
        const linkSet  = new Set();
        connEdges.forEach(e => {
            if (!e.from_ip || !e.to_ip) return;
            const key = [e.from_ip, e.to_ip].sort().join('|');
            if (linkSet.has(key)) return;
            const srcNode = nodes.find(n => n.id === e.from_ip);
            const dstNode = nodes.find(n => n.id === e.to_ip);
            if (!srcNode || !dstNode) return;
            linkSet.add(key);
            const ratio = e.total_ports > 0 ? e.reachable_ports / e.total_ports : 0;
            links.push({
                source:  e.from_ip,
                target:  e.to_ip,
                ratio,
                color:   ratio === 1 ? '#00e5a0' : ratio > 0 ? '#f59e0b' : '#ef4444',
            });
        });

        return { nodes, links, agents };
    }

    // ── Fetch helpers ─────────────────────────────────────────────────────────

    async function _fetchLiveData() {
        try {
            const r = await fetch('/scanner-api/monitor/hosts', { credentials: 'include' });
            if (r.status === 401) return null;
            if (!r.ok) return null;
            return await r.json();
        } catch { return null; }
    }

    async function _fetchConnectivity() {
        try {
            const r = await fetch('/scanner-api/monitor/connectivity?summary=true', { credentials: 'include' });
            if (!r.ok) return [];
            return (await r.json()).edges || [];
        } catch { return []; }
    }

    async function _fetchEvents() {
        try {
            const r = await fetch('/scanner-api/monitor/events', { credentials: 'include' });
            if (!r.ok) return [];
            return (await r.json()).events || [];
        } catch { return []; }
    }

    // ── Rendu D3 commun (setup SVG + defs) ───────────────────────────────────

    function _setupSVG(container) {
        if (_monSim) { _monSim.stop(); _monSim = null; }
        container.innerHTML = '';
        const W = container.clientWidth  || 700;
        const H = Math.max(420, container.clientHeight || 500);
        const svg = d3.select(container).append('svg')
            .attr('width', W).attr('height', H)
            .style('background', '#07090f')
            .style('border-radius', '10px');

        const g = svg.append('g');
        svg.call(d3.zoom().scaleExtent([0.3, 4]).on('zoom', e => g.attr('transform', e.transform)));

        const defs = svg.append('defs');
        // Dot-grid background
        const pat = defs.append('pattern').attr('id','mon-dots')
            .attr('width',28).attr('height',28).attr('patternUnits','userSpaceOnUse');
        pat.append('circle').attr('cx',1).attr('cy',1).attr('r',0.8)
            .attr('fill','rgba(255,255,255,0.05)');
        svg.insert('rect','g').attr('width','100%').attr('height','100%')
            .attr('fill','url(#mon-dots)');

        // Glow filter
        const filt = defs.append('filter').attr('id','mon-glow')
            .attr('x','-40%').attr('y','-40%').attr('width','180%').attr('height','180%');
        filt.append('feGaussianBlur').attr('stdDeviation','4').attr('result','blur');
        const merge = filt.append('feMerge');
        merge.append('feMergeNode').attr('in','blur');
        merge.append('feMergeNode').attr('in','SourceGraphic');

        return { svg, g, defs, W, H };
    }

    // ── Rendu graphe VLAN bubbles (mode Campaign) ─────────────────────────────

    function _renderVlanGraph(nodes, links, cid, eid) {
        cid = cid || 'mon-graph';
        eid = eid || 'mon-empty';
        const container = document.getElementById(cid);
        const empty     = document.getElementById(eid);
        if (!container) return;

        if (!nodes || nodes.length === 0) {
            container.innerHTML = '';
            if (empty) { empty.style.display = 'flex'; empty.innerHTML = '<span>Importez des données Nmap pour visualiser la topologie inter-VLAN</span>'; }
            return;
        }
        if (empty) empty.style.display = 'none';

        const { svg, g, defs, W, H } = _setupSVG(container);
        const maxHosts = Math.max(...nodes.map(n => n.hostCount), 1);

        function vlanRadius(n) { return Math.max(34, Math.min(80, 22 + (n.hostCount / maxHosts) * 58)); }
        function vlanCol(n) { return n.criticalCount > 0 ? '#ef4444' : n.vulnerableCount > 0 ? '#f59e0b' : '#00e5a0'; }

        // Gradients radiaux (rgba hardcodés — les hex ne supportent pas l'alpha via replace)
        const _monSchemes = {
            safe:   { c0:'rgba(0,229,160,0.28)',   c1:'rgba(0,229,160,0.04)'  },
            warn:   { c0:'rgba(245,158,11,0.30)',   c1:'rgba(245,158,11,0.04)' },
            danger: { c0:'rgba(239,68,68,0.32)',    c1:'rgba(239,68,68,0.05)'  },
        };
        Object.entries(_monSchemes).forEach(([k, { c0, c1 }]) => {
            const gr = defs.append('radialGradient').attr('id',`mon-grad-${k}`)
                .attr('cx','38%').attr('cy','35%').attr('r','65%');
            gr.append('stop').attr('offset','0%').attr('stop-color', c0);
            gr.append('stop').attr('offset','100%').attr('stop-color', c1);
        });

        const link = g.selectAll('.mon-link').data(links).enter().append('line')
            .attr('stroke', d => d.color || 'rgba(0,229,160,0.15)')
            .attr('stroke-width', d => d.ratio != null ? 2 : 1)
            .attr('stroke-dasharray', d => d.ratio != null ? 'none' : '5,4')
            .attr('stroke-opacity', d => d.ratio != null ? 0.7 : 0.3);

        const node = g.selectAll('.mon-node').data(nodes).enter().append('g')
            .attr('class','mon-node').style('cursor','grab');

        node.each(function(d) {
            const nd  = d3.select(this);
            const r   = vlanRadius(d);
            const col = vlanCol(d);
            const gid = d.criticalCount > 0 ? 'mon-grad-danger' : d.vulnerableCount > 0 ? 'mon-grad-warn' : 'mon-grad-safe';
            nd.append('circle').attr('r', r + 9).attr('fill','none').attr('stroke', col)
                .attr('stroke-width','0.8').attr('stroke-opacity','0.25').attr('class','mon-pulse');
            nd.append('circle').attr('r', r).attr('fill',`url(#${gid})`).attr('stroke', col)
                .attr('stroke-width','1.8').attr('filter','url(#mon-glow)');
            const lbl = d.id.length > 12 ? d.id.slice(0,11)+'…' : d.id;
            nd.append('text').attr('text-anchor','middle').attr('dy','-0.3em').attr('fill','#fff')
                .style('font',`700 ${Math.max(10,Math.min(14,r/3))}px Inter,system-ui,sans-serif`)
                .style('pointer-events','none').text(lbl);
            nd.append('text').attr('text-anchor','middle').attr('dy','1em').attr('fill', col)
                .style('font',`400 ${Math.max(8,Math.min(11,r/4))}px Inter,system-ui,sans-serif`)
                .style('pointer-events','none').text(`${d.hostCount} hôte${d.hostCount!==1?'s':''}`);
            if (d.vulnerableCount > 0)
                nd.append('text').attr('text-anchor','middle').attr('dy','2.4em').attr('fill','#ef4444')
                    .style('font','600 9px Inter,system-ui,sans-serif').style('pointer-events','none')
                    .text(`⚠ ${d.vulnerableCount}`);
        });

        node.on('mouseover', function() { d3.select(this).select('circle:nth-child(2)').attr('stroke-width','3'); })
            .on('mouseout',  function() { d3.select(this).select('circle:nth-child(2)').attr('stroke-width','1.8'); });

        _monSim = d3.forceSimulation(nodes)
            .force('link',      d3.forceLink(links).id(d => d.id).distance(180))
            .force('charge',    d3.forceManyBody().strength(-400))
            .force('center',    d3.forceCenter(W/2, H/2))
            .force('collision', d3.forceCollide().radius(d => vlanRadius(d) + 14))
            .alpha(0.8).alphaDecay(0.025)
            .on('tick', () => {
                link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y)
                    .attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
                node.attr('transform',d=>`translate(${d.x??W/2},${d.y??H/2})`);
            });

        node.call(d3.drag()
            .on('start',(e,d)=>{ if(!e.active)_monSim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
            .on('drag', (e,d)=>{ d.fx=e.x; d.fy=e.y; })
            .on('end',  (e,d)=>{ if(!e.active)_monSim.alphaTarget(0); d.fx=null; d.fy=null; })
        );
    }

    // ── Rendu graphe hôtes individuels (mode Live — neural-style) ────────────

    function _renderHostGraph(nodes, links) {
        const container = document.getElementById('mon-graph');
        const empty     = document.getElementById('mon-empty');
        if (!container) return;

        if (!nodes || nodes.length === 0) {
            container.innerHTML = '';
            if (empty) { empty.style.display = 'flex'; empty.innerHTML = '<span>Aucun hôte surveillé — attendez la prochaine collecte agent</span>'; }
            _renderHostLegend([]);
            return;
        }
        if (empty) empty.style.display = 'none';

        // ── Attribution IDs courts ─────────────────────────────────────────
        let aIdx = 0, hIdx = 0;
        [...nodes].sort((a, b) => {
            if (a.isAgent && !b.isAgent) return -1;
            if (!a.isAgent && b.isAgent) return 1;
            return a.ip.localeCompare(b.ip);
        }).forEach(n => { n.nodeId = n.isAgent ? `A${++aIdx}` : `H${++hIdx}`; });

        const { svg, g, defs, W, H } = _setupSVG(container);

        // ── Fond : halo radial vert centré (style GitHub) ────────────────
        const bgGrad = defs.append('radialGradient')
            .attr('id','bg-radial').attr('cx','50%').attr('cy','50%').attr('r','55%');
        bgGrad.append('stop').attr('offset','0%')  .attr('stop-color','rgba(0,229,160,0.06)');
        bgGrad.append('stop').attr('offset','100%').attr('stop-color','rgba(0,0,0,0)');
        svg.insert('rect','g').attr('width',W).attr('height',H)
            .attr('fill','url(#bg-radial)').style('pointer-events','none');

        // ── Marqueurs flèches ─────────────────────────────────────────────
        ['white','green','orange','red'].forEach((name, i) => {
            const colors = ['rgba(255,255,255,0.55)','#00e5a0','#f59e0b','#ef4444'];
            defs.append('marker')
                .attr('id',`arrow-${name}`).attr('viewBox','0 0 10 10')
                .attr('refX',9).attr('refY',5)
                .attr('markerWidth',5).attr('markerHeight',5)
                .attr('orient','auto-start-reverse')
              .append('path').attr('d','M0,0 L10,5 L0,10 z').attr('fill',colors[i]);
        });

        // ── Palette VLAN ──────────────────────────────────────────────────
        const PALETTE = ['#3b82f6','#8b5cf6','#ec4899','#f59e0b','#10b981','#06b6d4','#84cc16','#f97316'];
        const vlans   = [...new Set(nodes.map(n => n.vlan))];
        const vlanCol = {};
        vlans.forEach((v, i) => { vlanCol[v] = PALETTE[i % PALETTE.length]; });

        const vlanPos = {};
        const Rv = Math.min(W, H) * 0.30;
        vlans.forEach((v, i) => {
            const a = (2 * Math.PI * i) / vlans.length - Math.PI / 2;
            vlanPos[v] = { x: W/2 + Rv * Math.cos(a), y: H/2 + Rv * Math.sin(a) };
        });

        // Labels VLAN (plus visibles — style GitHub)
        vlans.forEach(v => {
            const pos = vlanPos[v];
            g.append('text')
                .attr('x', pos.x).attr('y', pos.y - 22)
                .attr('text-anchor','middle').attr('fill', vlanCol[v])
                .attr('opacity', 0.45)
                .style('font','600 11px Inter,system-ui,sans-serif')
                .style('pointer-events','none').text(v);
        });

        // ── Liens ─────────────────────────────────────────────────────────
        function _arrowMarker(d) {
            if (!d.ratio && d.ratio !== 0) return 'url(#arrow-white)';
            if (d.ratio === 1)  return 'url(#arrow-green)';
            if (d.ratio > 0)    return 'url(#arrow-orange)';
            return 'url(#arrow-red)';
        }
        const link = g.selectAll('.host-link').data(links).enter().append('line')
            .attr('class','host-link')
            .attr('stroke',          d => d.color || 'rgba(255,255,255,0.15)')
            .attr('stroke-width',    1.2)
            .attr('stroke-dasharray','4,3')
            .attr('stroke-opacity',  0.6)
            .attr('marker-end',      d => _arrowMarker(d));

        // ── Nœuds (taille originale `_hostRadius`, IP sous le nœud, ID centré) ─
        const node = g.selectAll('.host-node').data(nodes).enter().append('g')
            .attr('class','host-node').style('cursor','grab');

        node.each(function(d) {
            const nd  = d3.select(this);
            const r   = _hostRadius(d);   // 13 vulnérable · 11 agent · 9 hôte · 8 inconnu
            const col = d.isUnknown ? '#6b7280' : _hostColor(d);
            const vc  = vlanCol[d.vlan] || '#3b82f6';

            // Anneau VLAN extérieur discret
            if (!d.isUnknown)
                nd.append('circle').attr('r', r + 5)
                    .attr('fill','none').attr('stroke', vc)
                    .attr('stroke-width','0.7').attr('stroke-opacity','0.2');

            // Pulse ring pour agents
            if (d.isAgent)
                nd.append('circle').attr('r', r + 3)
                    .attr('fill','none').attr('stroke', col)
                    .attr('stroke-width','0.8').attr('stroke-opacity','0.3')
                    .attr('class','mon-pulse');

            // Cercle principal
            nd.append('circle').attr('r', r)
                .attr('fill', col + '22').attr('stroke', col)
                .attr('stroke-width', d.isAgent ? 2 : 1.5)
                .attr('filter', d.isAgent ? 'url(#mon-glow)' : 'none');

            // ID centré (très petit — style A1/H1)
            nd.append('text').attr('text-anchor','middle').attr('dominant-baseline','middle')
                .attr('fill', col).attr('opacity', 0.85)
                .style('font', `700 ${d.isAgent ? 6 : 5.5}px Inter,system-ui,sans-serif`)
                .style('pointer-events','none').text(d.nodeId);

            // Label IP/hostname SOUS le nœud (style GitHub)
            const lbl = d.hostname && d.hostname !== d.ip
                ? (d.hostname.length > 12 ? d.hostname.slice(0,11)+'…' : d.hostname)
                : (d.isUnknown ? 'INCONNU' : d.ip);
            nd.append('text').attr('text-anchor','middle').attr('dy', r + 12)
                .attr('fill', d.isUnknown ? '#4b5563' : '#8899b0')
                .style('font','400 9px Inter,system-ui,sans-serif')
                .style('pointer-events','none').text(lbl);

            if (d.hostname && d.hostname !== d.ip)
                nd.append('text').attr('text-anchor','middle').attr('dy', r + 22)
                    .attr('fill','#4b5563')
                    .style('font','400 8px Inter,system-ui,sans-serif')
                    .style('pointer-events','none').text(d.ip);

            // Badge vulnérabilité (coin haut-droit)
            if (d.vulnerable || d.openPorts > 5) {
                nd.append('circle').attr('r',7).attr('cx', r - 2).attr('cy', -(r - 2))
                    .attr('fill','#ef4444').attr('stroke','#07090f').attr('stroke-width',1.5);
                nd.append('text').attr('x', r - 2).attr('y', -(r - 2))
                    .attr('text-anchor','middle').attr('dy','0.35em')
                    .attr('fill','#fff').style('font','700 7px Inter,system-ui,sans-serif')
                    .style('pointer-events','none').text(d.openPorts);
            }
        });

        // ── Tooltip ───────────────────────────────────────────────────────
        node.on('mouseover', function(e, d) {
            const tip = document.getElementById('tooltip');
            if (!tip) return;
            const risk = d.score > 70 ? '🔴' : d.score > 40 ? '🟡' : '🟢';
            tip.innerHTML = [
                `<strong>${d.nodeId} — ${d.hostname || d.ip}</strong>`,
                d.hostname && d.hostname !== d.ip ? `IP : ${d.ip}` : '',
                `VLAN : ${d.vlan}`,
                d.os ? `OS : ${d.os}` : '',
                `Ports ouverts : ${d.openPorts ?? 0}`,
                d.isAgent ? '🤖 Agent actif' : d.isUnknown ? '❓ Hôte inconnu' : '📡 Hôte connu',
                `${risk} Score risque : ${d.score ?? 0}/100`,
            ].filter(Boolean).join('<br>');
            tip.style.display = 'block';
            tip.style.left  = (e.pageX + 14) + 'px';
            tip.style.top   = (e.pageY - 10) + 'px';
        }).on('mousemove', function(e) {
            const tip = document.getElementById('tooltip');
            if (tip) { tip.style.left=(e.pageX+14)+'px'; tip.style.top=(e.pageY-10)+'px'; }
        }).on('mouseout', function() {
            const tip = document.getElementById('tooltip');
            if (tip) tip.style.display = 'none';
        });

        // ── Simulation D3 ─────────────────────────────────────────────────
        _monSim = d3.forceSimulation(nodes)
            .force('link',      d3.forceLink(links).id(d => d.id).distance(90).strength(0.35))
            .force('charge',    d3.forceManyBody().strength(-220))
            .force('center',    d3.forceCenter(W/2, H/2).strength(0.05))
            .force('collision', d3.forceCollide().radius(d => _hostRadius(d) + 18))
            .force('vlan', function(alpha) {
                nodes.forEach(n => {
                    const c = vlanPos[n.vlan];
                    if (c) { n.vx += (c.x - n.x) * 0.05 * alpha; n.vy += (c.y - n.y) * 0.05 * alpha; }
                });
            })
            .alpha(0.9).alphaDecay(0.018)
            .on('tick', () => {
                link.each(function(d) {
                    const dx   = (d.target.x ?? 0) - (d.source.x ?? 0);
                    const dy   = (d.target.y ?? 0) - (d.source.y ?? 0);
                    const dist = Math.sqrt(dx*dx + dy*dy) || 1;
                    const rS   = _hostRadius(d.source) + 3;
                    const rT   = _hostRadius(d.target) + 10;
                    d3.select(this)
                        .attr('x1', (d.source.x ?? 0) + (dx/dist) * rS)
                        .attr('y1', (d.source.y ?? 0) + (dy/dist) * rS)
                        .attr('x2', (d.target.x ?? 0) - (dx/dist) * rT)
                        .attr('y2', (d.target.y ?? 0) - (dy/dist) * rT);
                });
                node.attr('transform', d => `translate(${d.x??W/2},${d.y??H/2})`);
            });

        node.call(d3.drag()
            .on('start', (e,d) => { if(!e.active) _monSim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
            .on('drag',  (e,d) => { d.fx=e.x; d.fy=e.y; })
            .on('end',   (e,d) => { if(!e.active) _monSim.alphaTarget(0); d.fx=null; d.fy=null; })
        );

        _renderHostLegend(nodes);
    }

    // ── Légende des nœuds (tableau HTML séparé) ───────────────────────────────

    function _renderHostLegend(nodes) {
        const el = document.getElementById('mon-legend');
        if (!el) return;
        if (!nodes || nodes.length === 0) { el.style.display = 'none'; return; }
        el.style.display = '';

        const riskInfo = s => s > 70 ? ['Critique','#ef4444'] : s > 40 ? ['Élevé','#f59e0b'] : s > 15 ? ['Moyen','#eab308'] : ['Faible','#22c55e'];

        const sorted = [...nodes].sort((a, b) => {
            // Trier par ID assigné : A1 < A2 < ... < H1 < H2 ...
            const ap = a.nodeId?.[0] || 'Z', bp = b.nodeId?.[0] || 'Z';
            if (ap !== bp) return ap.localeCompare(bp);
            return (parseInt(a.nodeId?.slice(1) || 0) - parseInt(b.nodeId?.slice(1) || 0));
        });

        const rows = sorted.map(n => {
            const [rl, rc] = riskInfo(n.score || 0);
            const status   = n.isAgent
                ? `<span style="color:#00e5a0;font-weight:600;">🤖 Agent</span>`
                : n.isUnknown
                    ? `<span style="color:#6b7280;">❓ Inconnu</span>`
                    : `<span style="color:#64748b;">📡 Connu</span>`;
            const hostname = (n.hostname && n.hostname !== n.ip) ? n.hostname : `<span style="color:#374151;">—</span>`;
            const os       = n.os ? n.os.split(/\s+/).slice(0,2).join(' ') : `<span style="color:#374151;">—</span>`;
            return `<tr>
              <td><span class="mon-node-id${n.isAgent ? ' is-agent' : ''}">${n.nodeId}</span></td>
              <td class="mono">${n.ip}</td>
              <td>${hostname}</td>
              <td style="color:#64748b;">${n.vlan}</td>
              <td style="color:#64748b;font-size:11px;">${os}</td>
              <td class="mono">${n.openPorts ?? 0}</td>
              <td><span style="color:${rc};font-weight:600;">${rl}</span></td>
              <td>${status}</td>
            </tr>`;
        }).join('');

        el.innerHTML = `
        <div class="filter-section">
          <div class="filter-header"><h3>📋 Légende des nœuds</h3></div>
          <div class="filter-content active" style="padding:0;overflow-x:auto;">
            <table class="mon-legend-table">
              <thead><tr>
                <th>ID</th><th>IP</th><th>Hostname</th><th>VLAN</th>
                <th>OS</th><th>Ports ouverts</th><th>Risque</th><th>Statut</th>
              </tr></thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        </div>`;
    }

    // ── Stats bar ─────────────────────────────────────────────────────────────

    function _renderStatsVlan(nodes) {
        const total = nodes.reduce((s, n) => s + n.hostCount, 0);
        const vuln  = nodes.reduce((s, n) => s + (n.vulnerableCount || 0), 0);
        const vlans = nodes.length;
        const el    = id => document.getElementById(id);
        if (el('mon-stat-vlans')) el('mon-stat-vlans').textContent = vlans + ' VLAN' + (vlans!==1?'s':'');
        if (el('mon-stat-hosts')) el('mon-stat-hosts').textContent = total + ' hôte' + (total!==1?'s':'');
        if (el('mon-stat-vuln'))  el('mon-stat-vuln').textContent  = vuln  + ' vulnérable' + (vuln!==1?'s':'');
        if (el('mon-last-update')) el('mon-last-update').textContent = 'Mis à jour : ' + _ts();
    }

    function _renderStatsHosts(nodes) {
        const vlans = new Set(nodes.map(n => n.vlan)).size;
        const total = nodes.length;
        const vuln  = nodes.filter(n => n.vulnerable || n.score >= 80).length;
        const el    = id => document.getElementById(id);
        if (el('mon-stat-vlans')) el('mon-stat-vlans').textContent = vlans + ' VLAN' + (vlans!==1?'s':'');
        if (el('mon-stat-hosts')) el('mon-stat-hosts').textContent = total + ' hôte' + (total!==1?'s':'');
        if (el('mon-stat-vuln'))  el('mon-stat-vuln').textContent  = vuln  + ' vulnérable' + (vuln!==1?'s':'');
        if (el('mon-last-update')) el('mon-last-update').textContent = 'Mis à jour : ' + _ts();
    }

    // ── Rendu agents ─────────────────────────────────────────────────────────

    const _CRIT_META = {
        critical: { label:'CRITICAL', color:'#ef4444', interval:'30min' },
        high:     { label:'HIGH',     color:'#f59e0b', interval:'1h'   },
        normal:   { label:'NORMAL',   color:'#00e5a0', interval:'3h'   },
        low:      { label:'LOW',      color:'#6b7280', interval:'6h'   },
    };

    function _renderAgents(agents) {
        const list = document.getElementById('mon-agents-list');
        if (!list) return;
        if (!agents || agents.length === 0) {
            list.innerHTML = '<p style="color:var(--txt-3);padding:12px 0;">Aucun agent connecté.</p>';
            return;
        }
        const now = Date.now() / 1000;
        list.innerHTML = agents.map(a => {
            const age   = Math.round(now - a.last_seen);
            const online = age < 120;
            const dot   = online ? '#00e5a0' : '#f59e0b';
            const crit  = a.criticality || 'normal';
            const meta  = _CRIT_META[crit] || _CRIT_META.normal;
            const ageStr = age < 60 ? `${age}s` : age < 3600 ? `${Math.round(age/60)}min` : `${Math.round(age/3600)}h`;
            return `
            <div class="mon-agent-row">
              <span class="mon-agent-dot" style="background:${dot};"></span>
              <div style="flex:1;min-width:0;">
                <div style="font-weight:600;color:var(--txt-1);font-size:13px;">${a.hostname||a.agent_id.slice(0,12)}</div>
                <div style="color:var(--txt-3);font-size:11px;">${a.ip||''}</div>
              </div>
              <span style="font-size:10px;font-weight:700;padding:2px 6px;border-radius:4px;
                background:${meta.color}22;color:${meta.color};border:1px solid ${meta.color}55;
                letter-spacing:0.5px;white-space:nowrap;"
                title="Scan toutes les ${meta.interval}">${meta.label}</span>
              <span style="color:var(--txt-3);font-size:11px;margin-left:8px;white-space:nowrap;">
                ${online?'🟢':'🟡'} ${ageStr}
              </span>
            </div>`;
        }).join('');
    }

    // ── Rendu événements ─────────────────────────────────────────────────────

    function _renderEvents(events) {
        _events = events;
        const list = document.getElementById('mon-events-list');
        if (!list) return;
        if (!events || events.length === 0) {
            list.innerHTML = '<p style="color:var(--txt-3);text-align:center;padding:20px 0;">Aucun événement — les changements détectés entre scans apparaîtront ici.</p>';
            return;
        }
        list.innerHTML = events.slice().reverse().map(ev => `
            <div class="mon-event-row mon-event-${ev.level||'info'}">
              <span class="mon-event-time">${ev.time||''}</span>
              <span class="mon-event-icon">${{warn:'⚠️',danger:'🔴',info:'ℹ️'}[ev.level]||'ℹ️'}</span>
              <span>${ev.message}</span>
            </div>`).join('');
    }

    // ── Refresh principal ─────────────────────────────────────────────────────

    async function refresh() {
        if (_mode === 'campaign') {
            const { nodes, links } = _buildFromCampaignData();
            _renderVlanGraph(nodes, links);
            _renderStatsVlan(nodes);
        } else {
            const [data, connEdges, evts] = await Promise.all([
                _fetchLiveData(),
                _fetchConnectivity(),
                _fetchEvents(),
            ]);

            if (!data) {
                const empty = document.getElementById('mon-empty');
                if (empty) { empty.style.display='flex'; empty.innerHTML='<span>Aucun agent connecté ou session expirée</span>'; }
                if (_monSim) { _monSim.stop(); _monSim=null; }
                const gc = document.getElementById('mon-graph');
                if (gc) gc.innerHTML='';
            } else {
                const { nodes, links, agents } = _buildFromLiveData(data, connEdges);
                _renderHostGraph(nodes, links);
                _renderStatsHosts(nodes);
                _renderAgents(agents);
                _renderEvents(evts);
            }
        }
    }

    // ── Mode switch ───────────────────────────────────────────────────────────

    function setMode(mode) {
        _mode = mode;
        const btnC   = document.getElementById('mon-btn-campaign');
        const btnL   = document.getElementById('mon-btn-live');
        const agSec  = document.getElementById('mon-agents-section');
        const agInstr = document.getElementById('mon-agent-instructions');

        if (btnC)   btnC.classList.toggle('active',   mode === 'campaign');
        if (btnL)   btnL.classList.toggle('active',   mode === 'live');
        if (agSec)  agSec.style.display  = mode === 'live' ? '' : 'none';
        if (agInstr) agInstr.style.display = mode === 'live' ? '' : 'none';

        if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }
        refresh();
        if (mode === 'live') _pollTimer = setInterval(refresh, 10000);
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    function onEnter() { setMode(_mode); }

    function onLeave() {
        if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }
        if (_monSim)    { _monSim.stop(); _monSim = null; }
    }

    function clearEvents() {
        _events = [];
        _renderEvents([]);
    }

    function renderCampaign(cid, eid) {
        const { nodes, links } = _buildFromCampaignData();
        _renderVlanGraph(nodes, links, cid, eid);
    }

    return { onEnter, onLeave, setMode, refresh, clearEvents, renderCampaign };
})();
