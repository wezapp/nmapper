// agent-map.js — Cartographie agents NMAPPER v2 (vue unifiée)
// Graphe neural D3 · Agents connectés · Événements · Inventaire
// Sources : /scanner-api/monitor/hosts + connectivity + events

const AgentMap = (() => {

    let _sim   = null;
    let _poll  = null;
    let _data  = { nodes: [], agents: [], links: [] };
    const _f   = { search: '', vlan: '', risk: '' };

    // ── Utilitaires ───────────────────────────────────────────────────────────

    function _esc(v) {
        return String(v == null ? '' : v)
            .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
            .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
    }

    function _ts() {
        return new Date().toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
    }

    function _normVlan(v) {
        if (!v) return 'Unknown';
        v = String(v).trim().replace(/^vlan\s+vlan/i,'VLAN');
        if (/^\d+$/.test(v)) v = 'VLAN' + v;
        return v;
    }

    // ── Scoring ───────────────────────────────────────────────────────────────

    const _HIGH_P = new Set([21,23,445,3389,5900,6379,27017,9200,1433,3306]);
    const _MED_P  = new Set([22,25,80,110,143,443,8080,8443]);

    function _score(ports, vuln) {
        let s = 0;
        (ports||[]).filter(p=>p.state==='open').forEach(p => {
            s += _HIGH_P.has(p.port) ? 20 : _MED_P.has(p.port) ? 5 : 2;
        });
        if (vuln) s += 30;
        return Math.min(100, s);
    }

    function _level(d) {
        if (d.vulnerable || d.score >= 80) return 'critical';
        if (d.score >= 40) return 'high';
        if (d.score >= 15) return 'medium';
        return 'low';
    }

    const _RISK_LABEL = { critical:'Critique', high:'Élevé', medium:'Moyen', low:'Faible', unknown:'Inconnu' };
    const _RISK_COLOR = { critical:'#ef4444',  high:'#f59e0b', medium:'#eab308', low:'#3b82f6', unknown:'#6b7280' };

    function _nodeColor(d) {
        if (d.isUnknown) return '#6b7280';
        if (d.vulnerable || d.score >= 80) return '#ef4444';
        if (d.score >= 40) return '#f59e0b';
        if (d.isAgent)    return '#00e5a0';
        return '#3b82f6';
    }

    function _nodeR(d) {
        if (d.vulnerable || d.score >= 80) return 13;
        if (d.isAgent)    return 11;
        if (d.isUnknown)  return 8;
        return 9;
    }

    // ── Fetch ─────────────────────────────────────────────────────────────────

    async function _fetchHosts() {
        try {
            const r = await fetch('/scanner-api/monitor/hosts',{credentials:'include'});
            if (!r.ok) return null;
            return await r.json();
        } catch { return null; }
    }

    async function _fetchConn() {
        try {
            const r = await fetch('/scanner-api/monitor/connectivity?summary=true',{credentials:'include'});
            if (!r.ok) return [];
            return (await r.json()).edges || [];
        } catch { return []; }
    }

    async function _fetchEvents() {
        try {
            const r = await fetch('/scanner-api/monitor/events',{credentials:'include'});
            if (!r.ok) return [];
            return (await r.json()).events || [];
        } catch { return []; }
    }

    // ── Build ─────────────────────────────────────────────────────────────────

    function _build(data, edges) {
        const hosts  = data.hosts  || [];
        const agents = data.agents || [];
        const byIP   = {};
        agents.forEach(a => { if (a.ip) byIP[a.ip] = a; });

        const nodes = hosts.map(h => {
            const ports     = Array.isArray(h.ports) ? h.ports : [];
            const isAgent   = Boolean(byIP[h.ip] || h.agent_id);
            const isUnknown = !h.hostname && !isAgent;
            const score     = _score(ports, h.vulnerable);
            const n = {
                id: h.ip, ip: h.ip,
                hostname: h.hostname || '',
                vlan: _normVlan(h.vlan || 'Unknown'),
                os: h.os || '',
                ports,
                openPorts: ports.filter(p => p.state === 'open').length,
                vulnerable: Boolean(h.vulnerable),
                isAgent, isUnknown,
                agent_id: h.agent_id || (byIP[h.ip] && byIP[h.ip].agent_id) || '',
                score,
            };
            n.level = _level(n);
            return n;
        });

        const links   = [];
        const linkSet = new Set();
        const nodeMap = new Map(nodes.map(n => [n.id, n]));
        (edges||[]).forEach(e => {
            if (!e.from_ip || !e.to_ip) return;
            const key = [e.from_ip, e.to_ip].sort().join('|');
            if (linkSet.has(key)) return;
            if (!nodeMap.has(e.from_ip) || !nodeMap.has(e.to_ip)) return;
            linkSet.add(key);
            const ratio = e.total_ports > 0 ? e.reachable_ports / e.total_ports : 0;
            const srcVlan = nodeMap.get(e.from_ip)?.vlan;
            const tgtVlan = nodeMap.get(e.to_ip)?.vlan;
            links.push({ source:e.from_ip, target:e.to_ip, ratio,
                interVlan: srcVlan !== tgtVlan,
                color: ratio===1 ? '#00e5a0' : ratio>0 ? '#f59e0b' : '#ef4444' });
        });

        return { nodes, agents, links };
    }

    // ── Filtres ───────────────────────────────────────────────────────────────

    function _filtered() {
        const q = _f.search.trim().toLowerCase();
        return (_data.nodes||[]).filter(n => {
            if (_f.vlan && n.vlan !== _f.vlan) return false;
            if (_f.risk && n.level !== _f.risk) return false;
            if (q) {
                const hay = `${n.ip} ${n.hostname} ${n.os} ${n.ports.map(p=>p.service||'').join(' ')}`.toLowerCase();
                if (!hay.includes(q)) return false;
            }
            return true;
        });
    }

    function _refreshVlanOpts() {
        const sel = document.getElementById('am-filter-vlan');
        if (!sel) return;
        const vlans = [...new Set((_data.nodes||[]).map(n => n.vlan))].sort();
        const cur = sel.value;
        sel.innerHTML = '<option value="">Tous les VLANs</option>' +
            vlans.map(v => `<option value="${_esc(v)}">${_esc(v)}</option>`).join('');
        sel.value = vlans.includes(cur) ? cur : '';
        if (sel.value !== cur) _f.vlan = '';
    }

    // ── SVG setup (dot-grid + glow) ───────────────────────────────────────────

    function _setupSVG(container) {
        if (_sim) { _sim.stop(); _sim = null; }
        // Supprimer les SVG précédents sans toucher à #am-empty
        container.querySelectorAll('svg').forEach(s => s.remove());
        const W = container.clientWidth  || 800;
        const H = Math.max(500, container.clientHeight || 540);

        const svg = d3.select(container).append('svg')
            .attr('width', W).attr('height', H)
            .style('background','#07090f').style('border-radius','10px');

        const g = svg.append('g');
        svg.call(d3.zoom().scaleExtent([0.15,6]).on('zoom', e => g.attr('transform', e.transform)));

        const defs = svg.append('defs');

        const pat = defs.append('pattern').attr('id','am-dots')
            .attr('width',28).attr('height',28).attr('patternUnits','userSpaceOnUse');
        pat.append('circle').attr('cx',1).attr('cy',1).attr('r',0.8).attr('fill','rgba(255,255,255,0.04)');
        svg.insert('rect','g').attr('width','100%').attr('height','100%').attr('fill','url(#am-dots)');

        const bgGrad = defs.append('radialGradient')
            .attr('id','am-bg-radial').attr('cx','50%').attr('cy','50%').attr('r','55%');
        bgGrad.append('stop').attr('offset','0%') .attr('stop-color','rgba(0,229,160,0.05)');
        bgGrad.append('stop').attr('offset','100%').attr('stop-color','rgba(0,0,0,0)');
        svg.insert('rect','g').attr('width',W).attr('height',H)
            .attr('fill','url(#am-bg-radial)').style('pointer-events','none');

        const filt = defs.append('filter').attr('id','am-glow')
            .attr('x','-40%').attr('y','-40%').attr('width','180%').attr('height','180%');
        filt.append('feGaussianBlur').attr('stdDeviation','3.5').attr('result','blur');
        const merge = filt.append('feMerge');
        merge.append('feMergeNode').attr('in','blur');
        merge.append('feMergeNode').attr('in','SourceGraphic');

        ['white','green','orange','red'].forEach((name, i) => {
            const colors = ['rgba(255,255,255,0.55)','#00e5a0','#f59e0b','#ef4444'];
            defs.append('marker').attr('id',`am-arrow-${name}`)
                .attr('viewBox','0 0 10 10').attr('refX',9).attr('refY',5)
                .attr('markerWidth',5).attr('markerHeight',5).attr('orient','auto-start-reverse')
              .append('path').attr('d','M0,0 L10,5 L0,10 z').attr('fill',colors[i]);
        });

        return { svg, g, defs, W, H };
    }

    // ── Graphe neural ─────────────────────────────────────────────────────────

    function _renderGraph(nodes, links) {
        const container = document.getElementById('am-graph');
        const empty     = document.getElementById('am-empty');
        if (!container) return;

        if (!nodes.length) {
            container.innerHTML = '';
            if (empty) empty.style.display = 'flex';
            return;
        }
        if (empty) empty.style.display = 'none';

        // IDs courts A1/H1
        let aIdx=0, hIdx=0;
        [...nodes].sort((a,b) => {
            if (a.isAgent && !b.isAgent) return -1;
            if (!a.isAgent && b.isAgent) return 1;
            return a.ip.localeCompare(b.ip);
        }).forEach(n => { n.nodeId = n.isAgent ? `A${++aIdx}` : `H${++hIdx}`; });

        const { svg, g, defs, W, H } = _setupSVG(container);

        // Palette VLAN
        const PALETTE = ['#3b82f6','#8b5cf6','#ec4899','#f59e0b','#10b981','#06b6d4','#84cc16','#f97316'];
        const vlans   = [...new Set(nodes.map(n => n.vlan))];
        const vlanCol = {};
        vlans.forEach((v,i) => { vlanCol[v] = PALETTE[i % PALETTE.length]; });

        const Rv = Math.min(W,H) * 0.38;
        const vlanPos = {};
        vlans.forEach((v,i) => {
            const a = (2*Math.PI*i)/vlans.length - Math.PI/2;
            vlanPos[v] = { x: W/2 + Rv*Math.cos(a), y: H/2 + Rv*Math.sin(a) };
        });

        // Labels VLAN
        vlans.forEach(v => {
            const p = vlanPos[v];
            g.append('text').attr('x',p.x).attr('y',p.y-24)
                .attr('text-anchor','middle').attr('fill',vlanCol[v]).attr('opacity',0.4)
                .style('font','600 11px Inter,system-ui,sans-serif')
                .style('pointer-events','none').text(v);
        });

        // Liens
        function _arrow(d) {
            if (!d.ratio && d.ratio!==0) return 'url(#am-arrow-white)';
            if (d.ratio===1) return 'url(#am-arrow-green)';
            if (d.ratio>0)   return 'url(#am-arrow-orange)';
            return 'url(#am-arrow-red)';
        }

        const link = g.selectAll('.am-link').data(links).enter().append('path')
            .attr('class','am-link').attr('fill','none')
            .attr('stroke', d => d.color||'rgba(255,255,255,0.15)')
            .attr('stroke-width', d => d.interVlan ? 1.6 : 1.0)
            .attr('stroke-dasharray', d => d.interVlan ? '6,3' : '3,3')
            .attr('stroke-opacity', d => d.interVlan ? 0.75 : 0.35)
            .attr('marker-end', d => _arrow(d));

        // Nœuds
        const node = g.selectAll('.am-node').data(nodes).enter().append('g')
            .attr('class','am-node').style('cursor','grab');

        node.each(function(d) {
            const nd  = d3.select(this);
            const r   = _nodeR(d);
            const col = _nodeColor(d);
            const vc  = vlanCol[d.vlan] || '#3b82f6';

            if (!d.isUnknown)
                nd.append('circle').attr('r', r+5).attr('fill','none')
                    .attr('stroke',vc).attr('stroke-width','0.7').attr('stroke-opacity','0.2');

            if (d.isAgent)
                nd.append('circle').attr('r', r+3).attr('fill','none')
                    .attr('stroke',col).attr('stroke-width','0.8').attr('stroke-opacity','0.3')
                    .attr('class','mon-pulse');

            nd.append('circle').attr('r',r)
                .attr('fill', col+'22').attr('stroke',col)
                .attr('stroke-width', d.isAgent?2:1.5)
                .attr('filter', d.isAgent?'url(#am-glow)':'none');

            nd.append('text').attr('text-anchor','middle').attr('dominant-baseline','middle')
                .attr('fill',col).attr('opacity',0.85)
                .style('font',`700 ${d.isAgent?6:5.5}px Inter,system-ui,sans-serif`)
                .style('pointer-events','none').text(d.nodeId);

            const lbl = (d.hostname && d.hostname!==d.ip)
                ? (d.hostname.length>13 ? d.hostname.slice(0,12)+'…' : d.hostname)
                : (d.isUnknown ? 'INCONNU' : d.ip);
            nd.append('text').attr('text-anchor','middle').attr('dy', r+12)
                .attr('fill', d.isUnknown?'#4b5563':'#8899b0')
                .style('font','400 9px Inter,system-ui,sans-serif')
                .style('pointer-events','none').text(lbl);

            if (d.hostname && d.hostname!==d.ip)
                nd.append('text').attr('text-anchor','middle').attr('dy', r+22)
                    .attr('fill','#4b5563')
                    .style('font','400 8px Inter,system-ui,sans-serif')
                    .style('pointer-events','none').text(d.ip);

            if (d.vulnerable || d.openPorts>5) {
                nd.append('circle').attr('r',7).attr('cx',r-2).attr('cy',-(r-2))
                    .attr('fill','#ef4444').attr('stroke','#07090f').attr('stroke-width',1.5);
                nd.append('text').attr('x',r-2).attr('y',-(r-2))
                    .attr('text-anchor','middle').attr('dy','0.35em')
                    .attr('fill','#fff').style('font','700 7px Inter,system-ui,sans-serif')
                    .style('pointer-events','none').text(d.openPorts);
            }
        });

        // Tooltip
        const tip = document.getElementById('tooltip');
        node.on('mouseover', function(e,d) {
            if (!tip) return;
            const risk = d.score>70?'🔴':d.score>40?'🟡':'🟢';
            tip.innerHTML = [
                `<strong>${d.nodeId} — ${_esc(d.hostname||d.ip)}</strong>`,
                d.hostname&&d.hostname!==d.ip ? `IP : ${d.ip}` : '',
                `VLAN : ${_esc(d.vlan)}`,
                d.os ? `OS : ${_esc(d.os)}` : '',
                `Ports ouverts : ${d.openPorts??0}`,
                d.isAgent?'🤖 Agent actif':d.isUnknown?'❓ Hôte inconnu':'📡 Hôte connu',
                `${risk} Score risque : ${d.score??0}/100`,
            ].filter(Boolean).join('<br>');
            tip.style.display='block';
            tip.style.left=(e.pageX+14)+'px'; tip.style.top=(e.pageY-10)+'px';
        }).on('mousemove', function(e) {
            if (tip) { tip.style.left=(e.pageX+14)+'px'; tip.style.top=(e.pageY-10)+'px'; }
        }).on('mouseout', function() {
            if (tip) tip.style.display='none';
        });

        // Drag
        node.call(d3.drag()
            .on('start',(e,d)=>{ if(!e.active)_sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
            .on('drag', (e,d)=>{ d.fx=e.x; d.fy=e.y; })
            .on('end',  (e,d)=>{ if(!e.active)_sim.alphaTarget(0); d.fx=null; d.fy=null; })
        );

        // Simulation
        _sim = d3.forceSimulation(nodes)
            .force('link',    d3.forceLink(links).id(d=>d.id).distance(130).strength(0.3))
            .force('charge',  d3.forceManyBody().strength(-420))
            .force('center',  d3.forceCenter(W/2,H/2).strength(0.04))
            .force('collide', d3.forceCollide().radius(d=>_nodeR(d)+28))
            .force('vlan', function(alpha) {
                nodes.forEach(n => {
                    const c = vlanPos[n.vlan];
                    if (c) { n.vx += (c.x-n.x)*0.10*alpha; n.vy += (c.y-n.y)*0.10*alpha; }
                });
            })
            .alpha(0.9).alphaDecay(0.018)
            .on('tick', () => {
                link.each(function(d) {
                    const sx = d.source.x??0, sy = d.source.y??0;
                    const tx = d.target.x??0, ty = d.target.y??0;
                    const dx = tx - sx, dy = ty - sy;
                    const dist = Math.sqrt(dx*dx+dy*dy)||1;
                    const rS = _nodeR(d.source)+3, rT = _nodeR(d.target)+10;
                    const x1 = sx+(dx/dist)*rS, y1 = sy+(dy/dist)*rS;
                    const x2 = tx-(dx/dist)*rT, y2 = ty-(dy/dist)*rT;
                    let pathD;
                    if (d.interVlan) {
                        // Courbe quadratique pour liens inter-VLAN
                        const cx = (x1+x2)/2 - dy*0.35;
                        const cy = (y1+y2)/2 + dx*0.35;
                        pathD = `M${x1},${y1} Q${cx},${cy} ${x2},${y2}`;
                    } else {
                        pathD = `M${x1},${y1} L${x2},${y2}`;
                    }
                    d3.select(this).attr('d', pathD);
                });
                node.attr('transform', d=>`translate(${d.x??W/2},${d.y??H/2})`);
            });

        // Fit-to-bounds après convergence
        setTimeout(() => {
            try {
                const gNode = g.node();
                if (!gNode) return;
                const bbox = gNode.getBBox();
                if (!bbox||bbox.width<1||bbox.height<1) return;
                const pad = 48;
                const scale = Math.min((W-pad*2)/bbox.width,(H-pad*2)/bbox.height,1.4);
                const tx = (W-bbox.width*scale)/2-bbox.x*scale;
                const ty = (H-bbox.height*scale)/2-bbox.y*scale;
                svg.transition().duration(600).call(
                    d3.zoom().scaleExtent([0.15,6]).on('zoom', e => g.attr('transform',e.transform)).transform,
                    d3.zoomIdentity.translate(tx,ty).scale(scale)
                );
            } catch(_) {}
        }, 900);
    }

    // ── KPIs ──────────────────────────────────────────────────────────────────

    function _renderKpis(nodes) {
        const vlans  = new Set(nodes.map(n=>n.vlan)).size;
        const crithi = nodes.filter(n=>n.level==='critical'||n.level==='high').length;
        _s('am-kpi-agents', (_data.agents||[]).length);
        _s('am-kpi-hosts',  nodes.length);
        _s('am-kpi-vlans',  vlans);
        _s('am-kpi-risk',   crithi);
        _s('am-kpi-time',   _ts());
    }

    function _s(id, val) { const el=document.getElementById(id); if(el) el.textContent=val; }

    // ── Agents connectés ──────────────────────────────────────────────────────

    const _CRIT_META = {
        critical: { label:'CRITICAL', color:'#ef4444' },
        high:     { label:'HIGH',     color:'#f59e0b' },
        normal:   { label:'NORMAL',   color:'#00e5a0' },
        low:      { label:'LOW',      color:'#6b7280' },
    };

    function _renderAgents(agents) {
        const list = document.getElementById('am-agents-list');
        if (!list) return;
        if (!agents||!agents.length) {
            list.innerHTML = '<p style="color:var(--txt-3);padding:12px 0;font-size:13px;">Aucun agent connecté.</p>';
            return;
        }
        const now = Date.now()/1000;
        list.innerHTML = agents.map(a => {
            const age    = Math.round(now - a.last_seen);
            const online = age < 120;
            const dot    = online ? '#00e5a0' : '#f59e0b';
            const meta   = _CRIT_META[a.criticality||'normal'] || _CRIT_META.normal;
            const ageStr = age<60?`${age}s`:age<3600?`${Math.round(age/60)}min`:`${Math.round(age/3600)}h`;
            return `
            <div class="mon-agent-row">
              <span class="mon-agent-dot" style="background:${dot};"></span>
              <div style="flex:1;min-width:0;">
                <div style="font-weight:600;color:var(--txt-1);font-size:13px;">${_esc(a.hostname||a.agent_id.slice(0,12))}</div>
                <div style="color:var(--txt-3);font-size:11px;">${_esc(a.ip||'')}</div>
              </div>
              <span style="font-size:10px;font-weight:700;padding:2px 6px;border-radius:4px;
                background:${meta.color}22;color:${meta.color};border:1px solid ${meta.color}55;
                letter-spacing:.5px;white-space:nowrap;">${meta.label}</span>
              <span style="color:var(--txt-3);font-size:11px;margin-left:8px;white-space:nowrap;">
                ${online?'🟢':'🟡'} ${ageStr}
              </span>
            </div>`;
        }).join('');
    }

    // ── Événements ────────────────────────────────────────────────────────────

    function _renderEvents(events) {
        const list = document.getElementById('am-events-list');
        if (!list) return;
        if (!events||!events.length) {
            list.innerHTML = '<p style="color:var(--txt-3);font-size:13px;padding:12px 0;text-align:center;">Aucun événement — les changements détectés entre scans apparaîtront ici.</p>';
            return;
        }
        const ICONS = { warn:'⚠️', danger:'🔴', info:'ℹ️' };
        list.innerHTML = events.slice().reverse().map(ev => `
            <div class="mon-event-row mon-event-${ev.level||'info'}">
              <span class="mon-event-time">${_esc(ev.time||'')}</span>
              <span class="mon-event-icon">${ICONS[ev.level]||'ℹ️'}</span>
              <span>${_esc(ev.message||'')}</span>
            </div>`).join('');
    }

    // ── Légende / inventaire ──────────────────────────────────────────────────

    function _renderLegend(nodes) {
        const el = document.getElementById('am-legend');
        if (!el) return;
        if (!nodes.length) { el.innerHTML=''; return; }

        const sorted = [...nodes].sort((a,b) => {
            const ap = a.nodeId?.[0]||'Z', bp = b.nodeId?.[0]||'Z';
            if (ap!==bp) return ap.localeCompare(bp);
            return (parseInt(a.nodeId?.slice(1)||0)-parseInt(b.nodeId?.slice(1)||0));
        });

        const rows = sorted.map(n => {
            const [rl,rc] = n.score>70?['Critique','#ef4444']:n.score>40?['Élevé','#f59e0b']:n.score>15?['Moyen','#eab308']:['Faible','#22c55e'];
            const status  = n.isAgent
                ? `<span style="color:#00e5a0;font-weight:600;">🤖 Agent</span>`
                : n.isUnknown
                    ? `<span style="color:#6b7280;">❓ Inconnu</span>`
                    : `<span style="color:#64748b;">📡 Connu</span>`;
            const hn = (n.hostname&&n.hostname!==n.ip)?n.hostname:`<span style="color:#374151;">—</span>`;
            const os = n.os?n.os.split(/\s+/).slice(0,2).join(' '):`<span style="color:#374151;">—</span>`;
            return `<tr>
              <td><span class="mon-node-id${n.isAgent?' is-agent':''}">${_esc(n.nodeId)}</span></td>
              <td class="mono">${_esc(n.ip)}</td>
              <td>${typeof hn==='string'&&hn.startsWith('<')?hn:_esc(hn)}</td>
              <td style="color:#64748b;">${_esc(n.vlan)}</td>
              <td style="color:#64748b;font-size:11px;">${typeof os==='string'&&os.startsWith('<')?os:_esc(os)}</td>
              <td class="mono">${n.openPorts??0}</td>
              <td><span style="color:${rc};font-weight:600;">${rl}</span></td>
              <td>${status}</td>
            </tr>`;
        }).join('');

        el.innerHTML = `
        <div class="filter-section" style="margin-top:14px;">
          <div class="filter-header" style="display:flex;align-items:center;gap:8px;">
            <h3 style="flex:1;">📋 Inventaire des nœuds</h3>
            <span style="font-size:11px;color:var(--txt-3);">${sorted.length} hôte${sorted.length!==1?'s':''}</span>
          </div>
          <div class="filter-content active" style="padding:0;overflow-x:auto;">
            <table class="mon-legend-table">
              <thead><tr>
                <th>ID</th><th>IP</th><th>Hostname</th><th>VLAN</th>
                <th>OS</th><th>Ports</th><th>Risque</th><th>Statut</th>
              </tr></thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        </div>`;
    }

    // ── Render principal ──────────────────────────────────────────────────────

    function _render() {
        const nodes = _filtered();
        const ids   = new Set(nodes.map(n=>n.id));
        const links = (_data.links||[]).filter(l => {
            const s = typeof l.source==='object'?l.source.id:l.source;
            const t = typeof l.target==='object'?l.target.id:l.target;
            return ids.has(s)&&ids.has(t);
        }).map(l => ({...l,
            source: typeof l.source==='object'?l.source.id:l.source,
            target: typeof l.target==='object'?l.target.id:l.target,
        }));

        _renderKpis(nodes);
        _renderGraph(nodes, links);
        _renderAgents(_data.agents||[]);
        _renderLegend(nodes);
    }

    // ── Refresh ───────────────────────────────────────────────────────────────

    async function refresh() {
        const [data, conn, evts] = await Promise.all([_fetchHosts(), _fetchConn(), _fetchEvents()]);
        if (!data) {
            _data = { nodes:[], agents:[], links:[] };
        } else {
            const built = _build(data, conn);
            _data = built;
        }
        _renderEvents(evts||[]);
        _refreshVlanOpts();
        _render();
    }

    // ── Filtres bindings ──────────────────────────────────────────────────────

    function _bindFilters() {
        const bind = (id, key) => {
            const el = document.getElementById(id);
            if (el && !el.dataset.amBound) {
                el.dataset.amBound='1';
                el.addEventListener('input',  () => { _f[key]=el.value; _render(); });
                el.addEventListener('change', () => { _f[key]=el.value; _render(); });
            }
        };
        bind('am-search','search');
        bind('am-filter-vlan','vlan');
        bind('am-filter-risk','risk');

        const clrBtn = document.getElementById('am-clear-events');
        if (clrBtn && !clrBtn.dataset.amBound) {
            clrBtn.dataset.amBound='1';
            clrBtn.addEventListener('click', () => {
                _renderEvents([]);
            });
        }
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    function onEnter() {
        _bindFilters();
        refresh();
        if (_poll) clearInterval(_poll);
        _poll = setInterval(refresh, 15000);
    }

    function onLeave() {
        if (_poll) { clearInterval(_poll); _poll=null; }
        if (_sim)  { _sim.stop(); _sim=null; }
    }

    return { onEnter, onLeave, refresh };
})();
