#!/usr/bin/env python3
"""Complete dashboard rebuild — adds ALL visual pages + API endpoints.

Rebuilds dashboard.py from the stock 378-line version into a full visual
dashboard with 8 pages and 20+ API endpoints.

Pages:  /  /ids  /ips  /wifi  /cloaking  /explorer  /auditor  /ai
"""

import sys, textwrap

DASHBOARD = "network_guardian/interface/dashboard.py"

# ── Read current file ──────────────────────────────────────────────
with open(DASHBOARD) as f:
    src = f.read()

# ── 1) Bump rate limit  ───────────────────────────────────────────
src = src.replace("RATE_LIMIT_MAX = 120", "RATE_LIMIT_MAX = 600")

# ── 2) Add event subscriptions for IDS / IPS ─────────────────────
OLD_SUBS = '''        for topic in ("audit.finding", "monitor.anomaly", "ai.anomaly_detected",
                       "explorer.discovery_complete", "automator.task_complete"):'''
NEW_SUBS = '''        for topic in ("audit.finding", "monitor.anomaly", "ai.anomaly_detected",
                       "explorer.discovery_complete", "automator.task_complete",
                       "ips.block", "ips.unblock", "ips.rate_limit",
                       "ips.quarantine", "ips.quarantine_release", "ips.started",
                       "ids.alert", "ids.started", "ids.correlation"):'''
src = src.replace(OLD_SUBS, NEW_SUBS)

# ── 3) Replace routes dict ────────────────────────────────────────
OLD_ROUTES = '''    def _route(self, path: str) -> str:
        routes: dict[str, Any] = {
            "/": self._page_index,
            "/api/status": self._api_status,
            "/api/findings": self._api_findings,
            "/api/events": self._api_events,
            "/api/hosts": self._api_hosts,
            "/api/tasks": self._api_tasks,
            "/api/health": self._api_health,
        }'''
NEW_ROUTES = '''    def _route(self, path: str) -> str:
        routes: dict[str, Any] = {
            "/": self._page_index,
            "/ids": self._page_ids,
            "/ips": self._page_ips,
            "/wifi": self._page_wifi,
            "/cloaking": self._page_cloaking,
            "/explorer": self._page_explorer,
            "/auditor": self._page_auditor,
            "/ai": self._page_ai,
            "/api/status": self._api_status,
            "/api/findings": self._api_findings,
            "/api/events": self._api_events,
            "/api/hosts": self._api_hosts,
            "/api/tasks": self._api_tasks,
            "/api/health": self._api_health,
            "/api/ips/stats": self._api_ips_stats,
            "/api/ips/blocklist": self._api_ips_blocklist,
            "/api/ips/ratelimits": self._api_ips_ratelimits,
            "/api/ips/quarantine": self._api_ips_quarantine,
            "/api/ips/history": self._api_ips_history,
            "/api/ips/allowlist": self._api_ips_allowlist,
            "/api/ids/stats": self._api_ids_stats,
            "/api/ids/alerts": self._api_ids_alerts,
            "/api/ids/rules": self._api_ids_rules,
            "/api/wifi/networks": self._api_wifi_networks,
            "/api/wifi/status": self._api_wifi_status,
            "/api/cloaking/status": self._api_cloaking_status,
            "/api/explorer/topology": self._api_explorer_topology,
            "/api/ai/metrics": self._api_ai_metrics,
        }'''
src = src.replace(OLD_ROUTES, NEW_ROUTES)

# ── 4) Insert all new API methods + page methods before response helpers
# We'll insert a huge block before "    # -- Response helpers"

API_AND_PAGES = r'''
    # -- IPS API endpoints -----------------------------------------------

    def _api_ips_stats(self) -> str:
        ips = self.engine.ips if self.engine._ips else None
        if ips is None:
            return self._json_response({"running": False})
        return self._json_response(ips.stats)

    def _api_ips_blocklist(self) -> str:
        ips = self.engine.ips if self.engine._ips else None
        if ips is None:
            return self._json_response([])
        return self._json_response([e.as_dict for e in ips.blocked_ips])

    def _api_ips_ratelimits(self) -> str:
        ips = self.engine.ips if self.engine._ips else None
        if ips is None:
            return self._json_response([])
        entries = []
        for ip, entry in list(ips._rate_limits.items()):
            if not entry.is_expired:
                entries.append({"ip": ip, "max_rps": entry.max_requests_per_second,
                                "burst_size": entry.burst_size,
                                "tokens_remaining": round(entry.tokens, 2)})
        return self._json_response(entries)

    def _api_ips_quarantine(self) -> str:
        ips = self.engine.ips if self.engine._ips else None
        if ips is None:
            return self._json_response([])
        return self._json_response(sorted(ips.quarantined_ips))

    def _api_ips_history(self) -> str:
        ips = self.engine.ips if self.engine._ips else None
        if ips is None:
            return self._json_response([])
        return self._json_response([e.as_dict for e in ips.history[-100:]])

    def _api_ips_allowlist(self) -> str:
        ips = self.engine.ips if self.engine._ips else None
        if ips is None:
            return self._json_response([])
        return self._json_response(sorted(ips.allowlist))

    # -- IDS API endpoints -----------------------------------------------

    def _api_ids_stats(self) -> str:
        ids = self.engine.ids if self.engine._ids else None
        if ids is None:
            return self._json_response({"running": False})
        alerts = ids.alerts
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_method: dict[str, int] = {}
        for a in alerts:
            by_severity[a.severity.value] = by_severity.get(a.severity.value, 0) + 1
            by_category[a.category.value] = by_category.get(a.category.value, 0) + 1
            by_method[a.method.value] = by_method.get(a.method.value, 0) + 1
        rules = ids.rules
        return self._json_response({
            "total_alerts": len(alerts), "rules_loaded": len(rules),
            "rules_enabled": sum(1 for r in rules if r.enabled),
            "by_severity": by_severity, "by_category": by_category, "by_method": by_method,
        })

    def _api_ids_alerts(self) -> str:
        ids = self.engine.ids if self.engine._ids else None
        if ids is None:
            return self._json_response([])
        return self._json_response([a.as_dict for a in ids.alerts[-100:]])

    def _api_ids_rules(self) -> str:
        ids = self.engine.ids if self.engine._ids else None
        if ids is None:
            return self._json_response([])
        return self._json_response([
            {"sid": r.sid, "name": r.name, "category": r.category.value,
             "severity": r.severity.value, "description": r.description, "enabled": r.enabled}
            for r in ids.rules
        ])

    # -- WiFi API endpoints -----------------------------------------------

    def _api_wifi_networks(self) -> str:
        ws = self.engine._wifi_stealth
        if ws is None:
            return self._json_response([])
        scanner = ws._scanner if hasattr(ws, '_scanner') else None
        if scanner is None:
            return self._json_response([])
        nets = getattr(scanner, '_last_scan', None) or []
        return self._json_response([n.as_dict if hasattr(n, 'as_dict') else _serialise(n) for n in nets])

    def _api_wifi_status(self) -> str:
        ws = self.engine._wifi_stealth
        if ws is None:
            return self._json_response({"scans": 0, "connected": None})
        connected = getattr(ws, '_last_connected', None)
        return self._json_response({
            "scans": getattr(ws, '_stats_scans', 0),
            "connected": connected.as_dict if connected and hasattr(connected, 'as_dict') else None,
            "stealth_active": getattr(ws, '_stealth_active', False),
            "home_ssid": getattr(ws, '_home_ssid', None),
        })

    # -- Cloaking API endpoints -------------------------------------------

    def _api_cloaking_status(self) -> str:
        ip_system = self.engine._cloaking
        if ip_system is None:
            return self._json_response({"mode": "disabled"})
        stats = ip_system.stats if hasattr(ip_system, 'stats') else {}
        identities = ip_system.list_identities() if hasattr(ip_system, 'list_identities') else []
        proxy_chain = ip_system.proxy_chain if hasattr(ip_system, 'proxy_chain') else []
        rotator = ip_system._rotator if hasattr(ip_system, '_rotator') else None
        masker = ip_system._masker if hasattr(ip_system, '_masker') else None
        return self._json_response({
            "mode": stats.get("mode", "disabled") if isinstance(stats, dict) else "disabled",
            "masked_ips": stats.get("stats_masked", 0) if isinstance(stats, dict) else 0,
            "rotated_sources": stats.get("stats_rotated", 0) if isinstance(stats, dict) else 0,
            "decoys_generated": stats.get("stats_decoys", 0) if isinstance(stats, dict) else 0,
            "proxy_chain_length": len(proxy_chain),
            "proxy_chain": [p.as_dict if hasattr(p, 'as_dict') else _serialise(p) for p in proxy_chain],
            "identities_count": len(identities),
            "identities": [i.as_dict if hasattr(i, 'as_dict') else _serialise(i) for i in identities],
            "active_identity": ip_system.active_identity if hasattr(ip_system, 'active_identity') else None,
            "source_pool": rotator.sources if rotator and hasattr(rotator, 'sources') else [],
            "mapping_count": masker.mapping_count if masker and hasattr(masker, 'mapping_count') else 0,
        })

    # -- Explorer API endpoints -------------------------------------------

    def _api_explorer_topology(self) -> str:
        explorer = self.engine._explorer
        if explorer is None:
            return self._json_response({})
        topo = getattr(explorer, '_topology', None) or {}
        return self._json_response({k: list(v) if isinstance(v, (set, frozenset)) else v for k, v in topo.items()})

    # -- AI / Monitor API endpoints ---------------------------------------

    def _api_ai_metrics(self) -> str:
        monitor = self.engine._monitor
        metrics = {}
        anomaly_count = 0
        prediction_count = 0
        latest_score = 0.0
        if monitor and hasattr(monitor, '_history'):
            for name, vals in monitor._history.items():
                metrics[name] = list(vals)[-20:]
        for evt in self._recent_events:
            topic = evt.get("topic", "")
            if topic == "ai.anomaly_detected":
                anomaly_count += 1
                data = evt.get("data", {})
                if isinstance(data, dict):
                    latest_score = max(latest_score, data.get("score", 0))
            elif topic in ("ai.prediction", "ai.recommendation"):
                prediction_count += 1
        return self._json_response({
            "metrics": metrics, "anomaly_count": anomaly_count,
            "prediction_count": prediction_count, "latest_anomaly_score": latest_score,
        })

    # -- Page renderers (use _TMPL_ constants to avoid f-string brace issues) -

    def _page_index(self) -> str:
        return self._http_response(200, "text/html",
            _TMPL_INDEX.replace("{{NONCE}}", Dashboard._csp_nonce))

    def _page_ids(self) -> str:
        return self._http_response(200, "text/html",
            _TMPL_IDS.replace("{{NONCE}}", Dashboard._csp_nonce))

    def _page_ips(self) -> str:
        return self._http_response(200, "text/html",
            _TMPL_IPS.replace("{{NONCE}}", Dashboard._csp_nonce))

    def _page_wifi(self) -> str:
        return self._http_response(200, "text/html",
            _TMPL_WIFI.replace("{{NONCE}}", Dashboard._csp_nonce))

    def _page_cloaking(self) -> str:
        return self._http_response(200, "text/html",
            _TMPL_CLOAKING.replace("{{NONCE}}", Dashboard._csp_nonce))

    def _page_explorer(self) -> str:
        return self._http_response(200, "text/html",
            _TMPL_EXPLORER.replace("{{NONCE}}", Dashboard._csp_nonce))

    def _page_auditor(self) -> str:
        return self._http_response(200, "text/html",
            _TMPL_AUDITOR.replace("{{NONCE}}", Dashboard._csp_nonce))

    def _page_ai(self) -> str:
        return self._http_response(200, "text/html",
            _TMPL_AI.replace("{{NONCE}}", Dashboard._csp_nonce))

'''

# Insert before "    # -- Response helpers"
marker = "    # -- Response helpers"
idx = src.find(marker)
if idx == -1:
    print("ERROR: marker not found"); sys.exit(1)

# Also remove the old _page_index method (between "    # -- HTML page" and marker)
html_marker = "    # -- HTML page"
html_idx = src.find(html_marker)
if html_idx == -1:
    print("ERROR: HTML page marker not found"); sys.exit(1)

src = src[:html_idx] + API_AND_PAGES + src[idx:]

# ── 5) Add template constants at module level (before class definition)
# Insert after the logger line

TEMPLATES_INSERT_MARKER = 'logger = logging.getLogger("network_guardian.interface.dashboard")\n\n_CONTENT_TEXT = "text/plain"'

# ====================================================================
# SHARED CSS (used in all 8 pages)
# ====================================================================
_SHARED_CSS = """
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;
  --dim:#8b949e;--blue:#58a6ff;--green:#3fb950;--yellow:#d29922;
  --orange:#db6d28;--red:#f85149;--purple:#bc8cff;--cyan:#39d2e0;--pink:#f778ba}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;overflow-x:hidden}
.wrap{max-width:1400px;margin:0 auto;padding:20px}
.banner{display:flex;align-items:center;gap:16px;padding:16px 24px;background:var(--card);border:1px solid var(--border);border-radius:12px;margin-bottom:20px;flex-wrap:wrap}
.banner h1{font-size:1.4rem;white-space:nowrap}
.badge{padding:4px 12px;border-radius:20px;font-size:.75rem;font-weight:700;letter-spacing:.5px}
.nav{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}
.nav a{padding:8px 18px;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--blue);text-decoration:none;font-size:.85rem;cursor:pointer;transition:.2s}
.nav a:hover{background:var(--border)}
.nav a.active{background:var(--blue);color:#fff;border-color:var(--blue)}
.grid{display:grid;gap:16px}
.g2{grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px}
.card h2{font-size:1rem;color:var(--blue);text-transform:uppercase;letter-spacing:1px;margin-bottom:14px}
table{width:100%;border-collapse:collapse;font-size:.82rem}
th{text-align:left;color:var(--dim);text-transform:uppercase;font-size:.7rem;letter-spacing:.8px;padding:8px 6px;border-bottom:1px solid var(--border)}
td{padding:8px 6px;border-bottom:1px solid rgba(48,54,61,.4)}
canvas{display:block}
.kpi-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}
.kpi{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 20px;min-width:130px;flex:1}
.kpi .v{font-size:1.6rem;font-weight:700;color:var(--blue)}
.kpi .l{font-size:.7rem;color:var(--dim);text-transform:uppercase;letter-spacing:.5px}
.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.7rem;font-weight:600}
.sev-critical{background:rgba(248,81,73,.2);color:var(--red)}
.sev-high{background:rgba(219,109,40,.2);color:var(--orange)}
.sev-medium{background:rgba(210,153,34,.2);color:var(--yellow)}
.sev-low{background:rgba(63,185,80,.2);color:var(--green)}
.empty{color:var(--dim);font-style:italic;padding:20px;text-align:center}
"""

def NAV(active):
    links = [("/","Dashboard"),("/ids","IDS"),("/ips","IPS"),("/wifi","WiFi"),
             ("/cloaking","Cloaking"),("/explorer","Explorer"),
             ("/auditor","Auditor"),("/ai","AI Engine")]
    parts = []
    for h,l in links:
        cls = ' class="active"' if h == active else ''
        parts.append(f'<a href="{h}"{cls}>{l}</a>')
    return '<div class="nav">' + ''.join(parts) + '</div>'

# ── INDEX PAGE ─────────────────────────────────────────────────────
INDEX_HTML = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1">'
    '<title>Network Guardian</title>'
    '<style nonce="{{NONCE}}">' + _SHARED_CSS + """
.radar-wrap{position:relative;width:120px;height:120px;margin-right:20px}
.cap-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}
.cap-tile{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px;position:relative;transition:.2s}
.cap-tile:hover{border-color:var(--blue);transform:translateY(-2px)}
.cap-tile .icon{font-size:1.6rem;margin-bottom:6px}
.cap-tile .name{font-weight:700;font-size:.9rem}
.cap-tile .sub{color:var(--dim);font-size:.75rem;margin-top:2px}
.cap-tile .led{position:absolute;top:10px;right:10px;width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green)}
.cap-tile .bar{height:4px;border-radius:2px;margin-top:8px;background:var(--border);overflow:hidden}
.cap-tile .bar .fill{height:100%;border-radius:2px;transition:width .5s}
.evt{display:flex;gap:8px;padding:6px 0;border-bottom:1px solid rgba(48,54,61,.3);font-size:.8rem}
.evt:last-child{border-bottom:none}
.evt .time{color:var(--dim);min-width:80px}
.evt .topic{color:var(--blue);font-family:monospace;font-size:.75rem}
</style></head><body>
<div class="wrap">
  <div class="banner">
    <canvas id="radar" width="100" height="100" style="border-radius:50%"></canvas>
    <h1>&#128737; Network Guardian</h1>
    <span id="engSt" style="margin-left:12px"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green);margin-right:6px"></span>Engine Active</span>
    <span id="threat" class="badge" style="background:rgba(63,185,80,.15);color:var(--green)">Threat: LOW</span>
    <span id="clock" style="margin-left:auto;color:var(--dim);font-size:.85rem"></span>
  </div>
  <div class="kpi-row">
    <div class="kpi"><div class="v" id="kH">0</div><div class="l">Hosts</div></div>
    <div class="kpi"><div class="v" id="kA">0</div><div class="l">IDS Alerts</div></div>
    <div class="kpi"><div class="v" id="kB">0</div><div class="l">IPS Blocks</div></div>
    <div class="kpi"><div class="v" id="kF">0</div><div class="l">Findings</div></div>
    <div class="kpi"><div class="v" id="kR">0</div><div class="l">IDS Rules</div></div>
    <div class="kpi"><div class="v" id="kE">0</div><div class="l">Events</div></div>
  </div>
""" + NAV("/") + """
  <div class="grid g2">
    <div class="card" style="grid-column:1/-1">
      <h2>&#9889; Active Capabilities</h2>
      <div id="caps" class="cap-grid"></div>
    </div>
    <div class="card"><h2>&#9889; Live Event Stream</h2><div id="evts" style="max-height:300px;overflow-y:auto"></div></div>
    <div class="card"><h2>&#128270; Security Findings</h2><div id="finds"></div></div>
  </div>
</div>
<script nonce="{{NONCE}}">
// Radar animation
(function(){
  const c=document.getElementById('radar'),ctx=c.getContext('2d');
  let angle=0;
  function draw(){
    const W=c.width,H=c.height,cx=W/2,cy=H/2,r=W/2-4;
    ctx.clearRect(0,0,W,H);
    ctx.beginPath();ctx.arc(cx,cy,r,0,Math.PI*2);ctx.fillStyle='#0d1117';ctx.fill();
    ctx.strokeStyle='#30363d';ctx.lineWidth=1;
    [.33,.66,1].forEach(f=>{ctx.beginPath();ctx.arc(cx,cy,r*f,0,Math.PI*2);ctx.stroke();});
    ctx.beginPath();ctx.moveTo(cx,cy-r);ctx.lineTo(cx,cy+r);ctx.stroke();
    ctx.beginPath();ctx.moveTo(cx-r,cy);ctx.lineTo(cx+r,cy);ctx.stroke();
    const grd=ctx.createConicalGradient?null:null;
    ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,r,angle-0.5,angle);ctx.closePath();
    const g=ctx.createRadialGradient(cx,cy,0,cx,cy,r);
    g.addColorStop(0,'rgba(63,185,80,.4)');g.addColorStop(1,'transparent');
    ctx.fillStyle=g;ctx.fill();
    ctx.beginPath();ctx.moveTo(cx,cy);
    ctx.lineTo(cx+r*Math.cos(angle),cy+r*Math.sin(angle));
    ctx.strokeStyle='#3fb950';ctx.lineWidth=2;ctx.stroke();
    angle+=0.03;
    requestAnimationFrame(draw);
  }
  draw();
})();

async function load(){
  try{
    const [stR,evR,fR,hR,idR,ipR]=await Promise.all([
      fetch('/api/status'),fetch('/api/events'),fetch('/api/findings'),
      fetch('/api/hosts'),fetch('/api/ids/stats'),fetch('/api/ips/stats')
    ]);
    const st=await stR.json(),ev=await evR.json(),fi=await fR.json(),
          ho=await hR.json(),ids=await idR.json(),ips=await ipR.json();
    const hc=Object.keys(ho).length;
    document.getElementById('kH').textContent=hc;
    document.getElementById('kA').textContent=ids.total_alerts||0;
    document.getElementById('kB').textContent=ips.blocked_ips||0;
    document.getElementById('kF').textContent=fi.length;
    document.getElementById('kR').textContent=ids.rules_loaded||0;
    document.getElementById('kE').textContent=ev.length;
    document.getElementById('clock').textContent=new Date().toLocaleTimeString();
    // Threat level
    const t=document.getElementById('threat');
    const al=ids.total_alerts||0;
    if((ids.by_severity||{}).critical){t.textContent='Threat: CRITICAL';t.style.background='rgba(248,81,73,.15)';t.style.color='var(--red)';}
    else if((ids.by_severity||{}).high){t.textContent='Threat: HIGH';t.style.background='rgba(219,109,40,.15)';t.style.color='var(--orange)';}
    else if(al>0){t.textContent='Threat: MEDIUM';t.style.background='rgba(210,153,34,.15)';t.style.color='var(--yellow)';}
    else{t.textContent='Threat: LOW';t.style.background='rgba(63,185,80,.15)';t.style.color='var(--green)';}
    // Capabilities
    const caps=[
      {icon:'&#128272;',name:'Intrusion Detection',sub:(ids.rules_loaded||0)+' rules, '+(ids.total_alerts||0)+' alerts',pct:ids.rules_loaded?100:30,color:'var(--blue)'},
      {icon:'&#128737;',name:'Intrusion Prevention',sub:ips.running===false?'Standby':'Active',pct:ips.running===false?20:100,color:'var(--red)'},
      {icon:'&#128225;',name:'WiFi Scanner',sub:'system_profiler SPAirPort',pct:80,color:'var(--green)'},
      {icon:'&#129302;',name:'AI / Anomaly',sub:'ML + NLP + Forecasting',pct:70,color:'var(--purple)'},
      {icon:'&#128270;',name:'Auditor',sub:'CVSS / OWASP scanning',pct:60,color:'var(--orange)'},
      {icon:'&#127760;',name:'Network Explorer',sub:hc+' hosts discovered',pct:hc?100:40,color:'var(--cyan)'}
    ];
    document.getElementById('caps').innerHTML=caps.map(c=>
      '<div class="cap-tile"><div class="led"></div><div class="icon">'+c.icon+'</div><div class="name">'+c.name+'</div><div class="sub">'+c.sub+'</div><div class="bar"><div class="fill" style="width:'+c.pct+'%;background:'+c.color+'"></div></div></div>'
    ).join('');
    // Events
    const eEl=document.getElementById('evts');
    if(!ev.length){eEl.innerHTML='<div class="empty">No events yet</div>';}
    else{eEl.innerHTML=ev.slice(-20).reverse().map(e=>'<div class="evt"><span class="time">'+new Date(e.timestamp).toLocaleTimeString()+'</span><span class="topic">'+e.topic+'</span></div>').join('');}
    // Findings
    const fEl=document.getElementById('finds');
    if(!fi.length){fEl.innerHTML='<div class="empty">No findings - system clean</div>';}
    else{fEl.innerHTML=fi.slice(-10).map(f=>'<div style="padding:6px 0;border-bottom:1px solid rgba(48,54,61,.3);font-size:.82rem">'+(f.title||f.description||'Finding')+'</div>').join('');}
  }catch(e){console.error(e);}
}
load();setInterval(load,5000);
</script></body></html>"""
)

# ── IDS PAGE ───────────────────────────────────────────────────────
IDS_HTML = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1">'
    '<title>IDS Monitor - Network Guardian</title>'
    '<style nonce="{{NONCE}}">' + _SHARED_CSS + """
.sev-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:4px}
.rule-row{display:flex;align-items:center;gap:10px;padding:8px;border-bottom:1px solid rgba(48,54,61,.3);font-size:.82rem}
.alert-row{display:flex;gap:8px;padding:10px;border-left:3px solid var(--border);margin-bottom:6px;font-size:.82rem;background:rgba(22,27,34,.5);border-radius:0 8px 8px 0}
.alert-row.sev-critical{border-left-color:var(--red)}
.alert-row.sev-high{border-left-color:var(--orange)}
.alert-row.sev-medium{border-left-color:var(--yellow)}
.alert-row.sev-low{border-left-color:var(--green)}
</style></head><body>
<div class="wrap">
  <div class="banner">
    <h1>&#128272; IDS Monitor</h1>
    <span id="st" class="badge" style="background:rgba(88,166,255,.15);color:var(--blue)">Loading</span>
    <span id="ts" style="margin-left:auto;color:var(--dim);font-size:.85rem"></span>
  </div>
  <div class="kpi-row">
    <div class="kpi"><div class="v" id="kA">0</div><div class="l">Total Alerts</div></div>
    <div class="kpi"><div class="v" id="kC" style="color:var(--red)">0</div><div class="l">Critical</div></div>
    <div class="kpi"><div class="v" id="kH" style="color:var(--orange)">0</div><div class="l">High</div></div>
    <div class="kpi"><div class="v" id="kM" style="color:var(--yellow)">0</div><div class="l">Medium</div></div>
    <div class="kpi"><div class="v" id="kR">0</div><div class="l">Rules Loaded</div></div>
  </div>
""" + NAV("/ids") + """
  <div class="grid g2">
    <div class="card"><h2>&#128200; Severity Distribution</h2><canvas id="sevChart" height="200"></canvas></div>
    <div class="card"><h2>&#128202; Detection Methods</h2><canvas id="methChart" height="200"></canvas></div>
    <div class="card" style="grid-column:1/-1"><h2>&#128196; Signature Rules</h2><div id="rules" style="max-height:300px;overflow-y:auto"></div></div>
    <div class="card" style="grid-column:1/-1"><h2>&#9888; Alert Feed</h2><div id="alerts"></div></div>
  </div>
</div>
<script nonce="{{NONCE}}">
function drawDonut(vals,colors,labels){
  const c=document.getElementById('sevChart'),ctx=c.getContext('2d');
  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;
  ctx.clearRect(0,0,W,H);
  const total=Object.values(vals).reduce((a,b)=>a+b,0);
  if(!total){ctx.fillStyle='#8b949e';ctx.textAlign='center';ctx.fillText('No alerts',W/2,H/2);return;}
  const cx=90,cy=H/2,r=75;
  let angle=-Math.PI/2;
  const entries=Object.entries(vals).filter(e=>e[1]>0);
  entries.forEach(([k,v])=>{
    const slice=v/total*Math.PI*2;
    ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,r,angle,angle+slice);ctx.closePath();
    ctx.fillStyle=colors[k]||'#8b949e';ctx.fill();
    angle+=slice;
  });
  ctx.beginPath();ctx.arc(cx,cy,45,0,Math.PI*2);ctx.fillStyle='#161b22';ctx.fill();
  ctx.fillStyle='#c9d1d9';ctx.font='bold 18px sans-serif';ctx.textAlign='center';ctx.fillText(total,cx,cy+6);
  let ly=20;
  entries.forEach(([k,v])=>{
    ctx.fillStyle=colors[k]||'#8b949e';ctx.fillRect(W-150,ly,10,10);
    ctx.fillStyle='#c9d1d9';ctx.font='12px sans-serif';ctx.textAlign='left';
    ctx.fillText(k+' ('+v+')',W-134,ly+9);ly+=20;
  });
}
function drawMethods(vals){
  const c=document.getElementById('methChart'),ctx=c.getContext('2d');
  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;
  ctx.clearRect(0,0,W,H);
  const entries=Object.entries(vals||{});
  if(!entries.length){ctx.fillStyle='#8b949e';ctx.textAlign='center';ctx.fillText('No data',W/2,H/2);return;}
  const max=Math.max(...entries.map(e=>e[1]));
  const barH=Math.min(30,(H-20)/entries.length-8);
  const colors={'signature':'#58a6ff','anomaly':'#bc8cff','heuristic':'#d29922','correlation':'#39d2e0'};
  entries.forEach(([k,v],i)=>{
    const y=20+i*(barH+8);
    const w=(v/max)*(W-140);
    ctx.fillStyle='#8b949e';ctx.font='11px sans-serif';ctx.textAlign='right';ctx.fillText(k,100,y+barH/2+4);
    const grd=ctx.createLinearGradient(110,y,110+w,y);
    grd.addColorStop(0,colors[k]||'#58a6ff');grd.addColorStop(1,(colors[k]||'#58a6ff')+'44');
    ctx.fillStyle=grd;ctx.beginPath();ctx.roundRect(110,y,w,barH,4);ctx.fill();
    ctx.fillStyle='#c9d1d9';ctx.font='bold 11px sans-serif';ctx.textAlign='left';ctx.fillText(v,114+w,y+barH/2+4);
  });
}
async function load(){
  try{
    const [sR,aR,rR]=await Promise.all([fetch('/api/ids/stats'),fetch('/api/ids/alerts'),fetch('/api/ids/rules')]);
    const s=await sR.json(),alerts=await aR.json(),rules=await rR.json();
    document.getElementById('kA').textContent=s.total_alerts||0;
    document.getElementById('kC').textContent=(s.by_severity||{}).critical||0;
    document.getElementById('kH').textContent=(s.by_severity||{}).high||0;
    document.getElementById('kM').textContent=(s.by_severity||{}).medium||0;
    document.getElementById('kR').textContent=s.rules_loaded||0;
    const badge=document.getElementById('st');
    if(s.running===false){badge.textContent='NOT RUNNING';badge.style.color='var(--red)';}
    else{badge.textContent=(s.total_alerts||0)+' Alerts';badge.style.color=s.total_alerts?'var(--orange)':'var(--green)';}
    const sevC={critical:'#f85149',high:'#db6d28',medium:'#d29922',low:'#3fb950',info:'#58a6ff'};
    drawDonut(s.by_severity||{},sevC);
    drawMethods(s.by_method||{});
    // Rules
    const rEl=document.getElementById('rules');
    if(!rules.length){rEl.innerHTML='<div class="empty">No rules loaded</div>';}
    else{rEl.innerHTML=rules.map(r=>'<div class="rule-row"><span class="sev-dot" style="background:'+(sevC[r.severity]||'#8b949e')+'"></span><span style="font-family:monospace;min-width:50px;color:var(--dim)">'+r.sid+'</span><span style="flex:1;font-weight:600">'+r.name+'</span><span class="pill sev-'+r.severity+'">'+r.severity.toUpperCase()+'</span><span style="color:var(--dim);font-size:.75rem;min-width:80px">'+r.category+'</span></div>').join('');}
    // Alerts
    const aEl=document.getElementById('alerts');
    if(!alerts.length){aEl.innerHTML='<div class="empty">No alerts</div>';}
    else{aEl.innerHTML=alerts.slice(-30).reverse().map(a=>'<div class="alert-row sev-'+(a.severity||'info')+'"><span style="min-width:80px;color:var(--dim);font-size:.75rem">'+new Date(a.timestamp).toLocaleTimeString()+'</span><span style="font-weight:600;min-width:140px">'+a.rule_name+'</span><span class="pill sev-'+(a.severity||'info')+'">'+(a.severity||'info').toUpperCase()+'</span><span style="color:var(--dim);flex:1">'+(a.description||'')+'</span></div>').join('');}
    document.getElementById('ts').textContent=new Date().toLocaleTimeString()+' | Auto 3s';
  }catch(e){console.error(e);}
}
load();setInterval(load,3000);
</script></body></html>"""
)

# ── IPS PAGE ───────────────────────────────────────────────────────
IPS_HTML = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1">'
    '<title>IPS Monitor - Network Guardian</title>'
    '<style nonce="{{NONCE}}">' + _SHARED_CSS + """
.ip-tile{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:10px;font-family:monospace;font-size:.85rem;display:flex;justify-content:space-between;align-items:center}
</style></head><body>
<div class="wrap">
  <div class="banner">
    <h1>&#128737; IPS Monitor</h1>
    <span id="st" class="badge" style="background:rgba(88,166,255,.15);color:var(--blue)">Loading</span>
    <span id="ts" style="margin-left:auto;color:var(--dim);font-size:.85rem"></span>
  </div>
  <div class="kpi-row">
    <div class="kpi"><div class="v" id="kBl" style="color:var(--red)">0</div><div class="l">Blocked IPs</div></div>
    <div class="kpi"><div class="v" id="kRL" style="color:var(--yellow)">0</div><div class="l">Rate-Limited</div></div>
    <div class="kpi"><div class="v" id="kQ" style="color:var(--purple)">0</div><div class="l">Quarantined</div></div>
    <div class="kpi"><div class="v" id="kAl" style="color:var(--green)">0</div><div class="l">Allowlisted</div></div>
    <div class="kpi"><div class="v" id="kEv" style="color:var(--blue)">0</div><div class="l">Total Events</div></div>
  </div>
""" + NAV("/ips") + """
  <div class="grid g2">
    <div class="card"><h2>&#128202; Actions Breakdown</h2><canvas id="actChart" height="200"></canvas></div>
    <div class="card"><h2>&#128683; Protection Gauge</h2><canvas id="gauge" height="200"></canvas></div>
    <div class="card"><h2>&#128683; Blocklist</h2><div id="bl" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:6px"></div></div>
    <div class="card"><h2>&#128337; Rate Limits</h2><div id="rl"></div></div>
    <div class="card" style="grid-column:1/-1"><h2>&#128196; Event History</h2><div id="hist" style="max-height:300px;overflow-y:auto"></div></div>
  </div>
</div>
<script nonce="{{NONCE}}">
function drawGauge(blocked,total){
  const c=document.getElementById('gauge'),ctx=c.getContext('2d');
  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;
  ctx.clearRect(0,0,W,H);
  const cx=W/2,cy=H-20,r=80;
  ctx.beginPath();ctx.arc(cx,cy,r,-Math.PI,0);ctx.strokeStyle='#30363d';ctx.lineWidth=20;ctx.lineCap='round';ctx.stroke();
  const pct=total?Math.min(1,blocked/Math.max(1,total)):0;
  const col=pct<0.3?'#3fb950':pct<0.6?'#d29922':'#f85149';
  if(pct>0){ctx.beginPath();ctx.arc(cx,cy,r,-Math.PI,-Math.PI+pct*Math.PI);ctx.strokeStyle=col;ctx.lineWidth=20;ctx.lineCap='round';ctx.stroke();}
  ctx.fillStyle='#c9d1d9';ctx.font='bold 24px sans-serif';ctx.textAlign='center';ctx.fillText(blocked,cx,cy-10);
  ctx.fillStyle='#8b949e';ctx.font='11px sans-serif';ctx.fillText('Blocked / '+total+' events',cx,cy+8);
}
function drawActions(byAction){
  const c=document.getElementById('actChart'),ctx=c.getContext('2d');
  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;
  ctx.clearRect(0,0,W,H);
  const entries=Object.entries(byAction||{});
  if(!entries.length){ctx.fillStyle='#8b949e';ctx.textAlign='center';ctx.fillText('No data',W/2,H/2);return;}
  const max=Math.max(...entries.map(e=>e[1]));
  const barW=Math.min(50,(W-40)/entries.length-10);
  const colors={block:'#f85149',rate_limit:'#d29922',quarantine:'#bc8cff',allow:'#3fb950',unblock:'#58a6ff'};
  entries.forEach(([k,v],i)=>{
    const x=30+i*(barW+10);
    const h=(v/max)*(H-50);
    const col=colors[k]||'#58a6ff';
    const grd=ctx.createLinearGradient(x,H-30-h,x,H-30);
    grd.addColorStop(0,col);grd.addColorStop(1,col+'44');
    ctx.fillStyle=grd;ctx.beginPath();ctx.roundRect(x,H-30-h,barW,h,4);ctx.fill();
    ctx.fillStyle='#c9d1d9';ctx.font='bold 10px sans-serif';ctx.textAlign='center';ctx.fillText(v,x+barW/2,H-34-h);
    ctx.fillStyle='#8b949e';ctx.font='9px sans-serif';ctx.fillText(k,x+barW/2,H-16);
  });
}
async function load(){
  try{
    const [sR,bR,rR,qR,aR,hR]=await Promise.all([
      fetch('/api/ips/stats'),fetch('/api/ips/blocklist'),fetch('/api/ips/ratelimits'),
      fetch('/api/ips/quarantine'),fetch('/api/ips/allowlist'),fetch('/api/ips/history')
    ]);
    const s=await sR.json(),bl=await bR.json(),rl=await rR.json(),q=await qR.json(),al=await aR.json(),hist=await hR.json();
    document.getElementById('kBl').textContent=s.blocked_ips||bl.length||0;
    document.getElementById('kRL').textContent=s.rate_limited_ips||rl.length||0;
    document.getElementById('kQ').textContent=s.quarantined_ips||q.length||0;
    document.getElementById('kAl').textContent=al.length;
    document.getElementById('kEv').textContent=s.total_events||hist.length||0;
    const badge=document.getElementById('st');
    if(s.running===false){badge.textContent='NOT RUNNING';badge.style.color='var(--red)';}
    else{badge.textContent='Active';badge.style.color='var(--green)';}
    drawGauge(s.blocked_ips||bl.length||0,s.total_events||hist.length||0);
    drawActions(s.by_action||{});
    // Blocklist
    const bEl=document.getElementById('bl');
    if(!bl.length){bEl.innerHTML='<div class="empty">No blocked IPs</div>';}
    else{bEl.innerHTML=bl.map(b=>'<div class="ip-tile"><span>'+b.ip+'</span><span style="color:var(--dim);font-size:.7rem">'+b.hit_count+' hits</span></div>').join('');}
    // Rate limits
    const rEl=document.getElementById('rl');
    if(!rl.length){rEl.innerHTML='<div class="empty">No rate limits</div>';}
    else{rEl.innerHTML='<table><tr><th>IP</th><th>Max RPS</th><th>Tokens</th></tr>'+rl.map(r=>'<tr><td style="font-family:monospace">'+r.ip+'</td><td>'+r.max_rps+'</td><td>'+r.tokens_remaining+'</td></tr>').join('')+'</table>';}
    // History
    const hEl=document.getElementById('hist');
    if(!hist.length){hEl.innerHTML='<div class="empty">No events</div>';}
    else{hEl.innerHTML='<table><tr><th>Time</th><th>IP</th><th>Action</th><th>Reason</th></tr>'+hist.slice(-30).reverse().map(e=>'<tr><td style="color:var(--dim)">'+new Date(e.timestamp).toLocaleTimeString()+'</td><td style="font-family:monospace">'+e.target_ip+'</td><td><span class="pill sev-'+(e.action==='block'?'critical':'medium')+'">'+e.action+'</span></td><td style="color:var(--dim)">'+e.reason+'</td></tr>').join('')+'</table>';}
    document.getElementById('ts').textContent=new Date().toLocaleTimeString()+' | Auto 3s';
  }catch(e){console.error(e);}
}
load();setInterval(load,3000);
</script></body></html>"""
)

# ── WIFI PAGE ──────────────────────────────────────────────────────
WIFI_HTML = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1">'
    '<title>WiFi Scanner - Network Guardian</title>'
    '<style nonce="{{NONCE}}">' + _SHARED_CSS + """
.wifi-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px;display:flex;gap:14px;align-items:center;transition:.2s}
.wifi-card:hover{border-color:var(--blue);transform:translateY(-2px)}
.wifi-info{flex:1}
.wifi-info .ssid{font-weight:600;font-size:.95rem}
.wifi-info .meta{color:var(--dim);font-size:.75rem;margin-top:2px}
.signal-bar{height:6px;border-radius:3px;background:var(--border);margin-top:6px;overflow:hidden}
.signal-bar .fill{height:100%;border-radius:3px;transition:width .4s}
.conn-tag{background:var(--green);color:#000;font-size:.65rem;font-weight:700;padding:2px 8px;border-radius:8px}
</style></head><body>
<div class="wrap">
  <div class="banner">
    <h1>&#128225; WiFi Scanner</h1>
    <span id="st" class="badge" style="background:rgba(88,166,255,.15);color:var(--blue)">Scanning</span>
    <span id="ts" style="margin-left:auto;color:var(--dim);font-size:.85rem"></span>
  </div>
  <div class="kpi-row">
    <div class="kpi"><div class="v" id="kN">-</div><div class="l">Networks</div></div>
    <div class="kpi"><div class="v" id="kC">-</div><div class="l">Connected To</div></div>
    <div class="kpi"><div class="v" id="kS">-</div><div class="l">Signal</div></div>
    <div class="kpi"><div class="v" id="kCh">-</div><div class="l">Channel</div></div>
    <div class="kpi"><div class="v" id="kSec">-</div><div class="l">Security Types</div></div>
    <div class="kpi"><div class="v" id="kSc">-</div><div class="l">Scans</div></div>
  </div>
""" + NAV("/wifi") + """
  <div class="grid g2">
    <div class="card"><h2>&#128225; Signal Strength</h2><canvas id="sigChart" height="200"></canvas></div>
    <div class="card"><h2>&#128274; Security Breakdown</h2><canvas id="secChart" height="200"></canvas></div>
    <div class="card"><h2>&#128246; Frequency Bands</h2><canvas id="freqChart" height="180"></canvas></div>
    <div class="card"><h2>&#128752; Connected Network</h2><div id="connInfo" class="empty">Scanning...</div></div>
    <div class="card" style="grid-column:1/-1"><h2>&#128225; Discovered Networks</h2><div id="netList" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px"></div></div>
  </div>
</div>
<script nonce="{{NONCE}}">
function sigColor(s){return s>=-50?'#3fb950':s>=-65?'#58a6ff':s>=-75?'#d29922':'#f85149';}
function secColor(s){if(!s||s==='Open')return'#f85149';if(s.includes('WPA3'))return'#3fb950';if(s.includes('WPA2'))return'#58a6ff';if(s.includes('WPA'))return'#d29922';return'#db6d28';}
function drawSig(nets){
  const c=document.getElementById('sigChart'),ctx=c.getContext('2d');
  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;
  ctx.clearRect(0,0,W,H);
  if(!nets.length){ctx.fillStyle='#8b949e';ctx.textAlign='center';ctx.fillText('No networks',W/2,H/2);return;}
  const sorted=[...nets].sort((a,b)=>b.signal-a.signal);
  const bw=Math.min(40,Math.max(12,(W-20)/sorted.length-4));
  sorted.forEach((n,i)=>{
    const x=10+i*(bw+4), pct=(n.signal+100)/100, h=pct*(H-40), col=sigColor(n.signal);
    const g=ctx.createLinearGradient(x,H-20-h,x,H-20);g.addColorStop(0,col);g.addColorStop(1,col+'44');
    ctx.fillStyle=g;ctx.beginPath();ctx.roundRect(x,H-20-h,bw,h,4);ctx.fill();
    ctx.fillStyle='#c9d1d9';ctx.font='bold 9px sans-serif';ctx.textAlign='center';ctx.fillText(n.signal+'dBm',x+bw/2,H-24-h);
    ctx.save();ctx.translate(x+bw/2,H-8);ctx.rotate(-0.5);ctx.fillStyle='#8b949e';ctx.font='8px sans-serif';ctx.textAlign='right';
    ctx.fillText((n.ssid||'Hidden').slice(0,12),0,0);ctx.restore();
  });
}
function drawSec(nets){
  const c=document.getElementById('secChart'),ctx=c.getContext('2d');
  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;
  ctx.clearRect(0,0,W,H);
  const types={};
  nets.forEach(n=>{const s=n.security||'Open';const k=s.includes('WPA3')?'WPA3':s.includes('WPA2')?'WPA2':s.includes('WPA')?'WPA':s.includes('WEP')?'WEP':'Open';types[k]=(types[k]||0)+1;});
  const entries=Object.entries(types).sort((a,b)=>b[1]-a[1]);
  if(!entries.length){ctx.fillStyle='#8b949e';ctx.textAlign='center';ctx.fillText('No data',W/2,H/2);return;}
  const total=nets.length,cx=90,cy=H/2,r=70;
  const colors={WPA3:'#3fb950',WPA2:'#58a6ff',WPA:'#d29922',WEP:'#db6d28',Open:'#f85149'};
  let angle=-Math.PI/2;
  entries.forEach(([k,v])=>{const sl=v/total*Math.PI*2;ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,r,angle,angle+sl);ctx.closePath();ctx.fillStyle=colors[k]||'#bc8cff';ctx.fill();angle+=sl;});
  ctx.beginPath();ctx.arc(cx,cy,40,0,Math.PI*2);ctx.fillStyle='#161b22';ctx.fill();
  ctx.fillStyle='#c9d1d9';ctx.font='bold 14px sans-serif';ctx.textAlign='center';ctx.fillText(total,cx,cy+5);
  let ly=20;entries.forEach(([k,v])=>{ctx.fillStyle=colors[k]||'#bc8cff';ctx.fillRect(W-160,ly,10,10);ctx.fillStyle='#c9d1d9';ctx.font='12px sans-serif';ctx.textAlign='left';ctx.fillText(k+' ('+v+')',W-144,ly+9);ly+=20;});
}
function drawFreq(nets){
  const c=document.getElementById('freqChart'),ctx=c.getContext('2d');
  const W=c.width=c.parentElement.clientWidth-40,H=c.height=180;
  ctx.clearRect(0,0,W,H);
  let b24=0,b5=0;nets.forEach(n=>{const ch=n.channel||0;if(ch<=14)b24++;else b5++;});
  const data=[['2.4 GHz',b24,'#58a6ff'],['5 GHz',b5,'#bc8cff']];
  const total=Math.max(1,b24+b5),barH=36,gap=20,sy=(H-2*barH-gap)/2;
  data.forEach(([label,count,col],i)=>{
    const y=sy+i*(barH+gap),w=Math.max(4,(count/total)*(W-140));
    ctx.fillStyle='#30363d';ctx.beginPath();ctx.roundRect(120,y,W-140,barH,6);ctx.fill();
    const g=ctx.createLinearGradient(120,y,120+w,y);g.addColorStop(0,col);g.addColorStop(1,col+'66');
    ctx.fillStyle=g;ctx.beginPath();ctx.roundRect(120,y,w,barH,6);ctx.fill();
    ctx.fillStyle='#c9d1d9';ctx.font='bold 13px sans-serif';ctx.textAlign='right';ctx.fillText(label,108,y+barH/2+4);
    ctx.fillStyle='#fff';ctx.font='bold 13px sans-serif';ctx.textAlign='left';ctx.fillText(count+' ('+(count/total*100|0)+'%)',w>50?124:126+w,y+barH/2+4);
  });
}
async function load(){
  try{
    const [wR,sR]=await Promise.all([fetch('/api/wifi/networks'),fetch('/api/wifi/status')]);
    const nets=await wR.json(),st=await sR.json();
    document.getElementById('kN').textContent=nets.length;
    document.getElementById('kSc').textContent=st.scans||0;
    const conn=st.connected;
    document.getElementById('kC').textContent=conn?conn.ssid||'-':'-';
    document.getElementById('kS').textContent=conn?(conn.signal+' dBm'):'-';
    document.getElementById('kCh').textContent=conn?(conn.channel||'-'):'-';
    document.getElementById('kSec').textContent=new Set(nets.map(n=>n.security||'Open')).size;
    document.getElementById('st').textContent=nets.length?nets.length+' Networks':'Idle';
    document.getElementById('st').style.color=nets.length?'var(--green)':'var(--blue)';
    if(conn){document.getElementById('connInfo').innerHTML='<div style="display:flex;align-items:center;gap:12px"><span style="font-size:2rem">&#128225;</span><div><div style="font-size:1.1rem;font-weight:700">'+(conn.ssid||'Hidden')+' <span class="conn-tag">CONNECTED</span></div><div style="color:var(--dim);font-size:.82rem;margin-top:4px">BSSID: '+(conn.bssid||'-')+' | Ch '+(conn.channel||'-')+' | Signal: <span style="color:'+sigColor(conn.signal||0)+'">'+(conn.signal||'-')+' dBm</span> | '+(conn.security||'-')+'</div></div></div>';}
    else{document.getElementById('connInfo').innerHTML='<div class="empty">Not connected</div>';}
    drawSig(nets);drawSec(nets);drawFreq(nets);
    // Network list
    const el=document.getElementById('netList');
    if(!nets.length){el.innerHTML='<div class="empty">No networks</div>';}
    else{el.innerHTML=[...nets].sort((a,b)=>b.signal-a.signal).map(n=>{
      const pct=Math.max(0,Math.min(100,(n.signal+100))),col=sigColor(n.signal),isC=conn&&n.ssid===conn.ssid;
      return '<div class="wifi-card'+(isC?' style="border-color:var(--green)"':'')+'"><span style="font-size:1.6rem">'+(n.hidden?'&#128683;':'&#128225;')+'</span><div class="wifi-info"><div class="ssid">'+(n.ssid||'[Hidden]')+(isC?' <span class="conn-tag">CONNECTED</span>':'')+'</div><div class="meta">BSSID: '+(n.bssid||'-')+' | Ch '+(n.channel||'-')+' | '+(n.frequency||'-')+'</div><div class="signal-bar"><div class="fill" style="width:'+pct+'%;background:'+col+'"></div></div><div style="display:flex;justify-content:space-between;margin-top:4px;font-size:.7rem"><span style="color:'+col+'">'+n.signal+' dBm ('+pct+'%)</span><span style="padding:2px 6px;border-radius:6px;font-size:.65rem;background:'+secColor(n.security)+'22;color:'+secColor(n.security)+'">'+(n.security||'Open')+'</span></div></div></div>';
    }).join('');}
    document.getElementById('ts').textContent=new Date().toLocaleTimeString()+' | Auto 5s';
  }catch(e){console.error(e);}
}
load();setInterval(load,5000);
</script></body></html>"""
)

# ── CLOAKING PAGE ──────────────────────────────────────────────────
CLOAKING_HTML = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1">'
    '<title>IP Cloaking - Network Guardian</title>'
    '<style nonce="{{NONCE}}">' + _SHARED_CSS + """
.mode-row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}
.mode-chip{padding:10px 20px;border-radius:10px;border:2px solid var(--border);background:var(--card);text-align:center;min-width:100px;transition:.2s}
.mode-chip.active{border-color:var(--green);background:rgba(63,185,80,.1);box-shadow:0 0 12px rgba(63,185,80,.2)}
.mode-chip .ic{font-size:1.4rem}
.mode-chip .lb{font-size:.75rem;text-transform:uppercase;letter-spacing:.5px}
.id-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;transition:.2s}
.id-card.active{border-color:var(--cyan);box-shadow:0 0 12px rgba(57,210,224,.15)}
.id-card .nm{font-weight:700;font-size:1rem;margin-bottom:6px}
.id-card .dt{color:var(--dim);font-size:.78rem;line-height:1.6}
.proxy-hop{display:flex;align-items:center;gap:12px;padding:10px;border:1px solid var(--border);border-radius:8px;margin-bottom:6px}
</style></head><body>
<div class="wrap">
  <div class="banner">
    <h1>&#128373; IP Cloaking</h1>
    <span id="ml" class="badge" style="background:rgba(188,140,255,.15);color:var(--purple)">-</span>
    <span id="ts" style="margin-left:auto;color:var(--dim);font-size:.85rem"></span>
  </div>
  <div class="kpi-row">
    <div class="kpi"><div class="v" id="kMode">-</div><div class="l">Mode</div></div>
    <div class="kpi"><div class="v" id="kMask">0</div><div class="l">IPs Masked</div></div>
    <div class="kpi"><div class="v" id="kRot">0</div><div class="l">Rotated</div></div>
    <div class="kpi"><div class="v" id="kDec">0</div><div class="l">Decoys</div></div>
    <div class="kpi"><div class="v" id="kPrx">0</div><div class="l">Proxy Hops</div></div>
    <div class="kpi"><div class="v" id="kId">0</div><div class="l">Identities</div></div>
  </div>
""" + NAV("/cloaking") + """
  <div id="modes" class="mode-row"></div>
  <div class="grid g2">
    <div class="card"><h2>&#128200; Activity</h2><canvas id="actChart" height="200"></canvas></div>
    <div class="card"><h2>&#128279; Proxy Chain</h2><div id="proxies"><div class="empty">No proxies</div></div></div>
    <div class="card" style="grid-column:1/-1"><h2>&#128100; Identities</h2><div id="ids" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px"></div></div>
    <div class="card"><h2>&#127760; Source Pool</h2><div id="pool"></div></div>
    <div class="card"><h2>&#128736; Masker Stats</h2><div id="masker"></div></div>
  </div>
</div>
<script nonce="{{NONCE}}">
const MODES=['disabled','mask','rotate','proxy','decoy','full'];
const ICONS={disabled:'&#128683;',mask:'&#127917;',rotate:'&#128260;',proxy:'&#128279;',decoy:'&#128038;',full:'&#128737;'};
const MCOL={disabled:'var(--dim)',mask:'var(--blue)',rotate:'var(--cyan)',proxy:'var(--purple)',decoy:'var(--orange)',full:'var(--green)'};
let hist=[];
function drawAct(d){
  hist.push({m:d.masked_ips||0,r:d.rotated_sources||0,d:d.decoys_generated||0});
  if(hist.length>30)hist=hist.slice(-30);
  const c=document.getElementById('actChart'),ctx=c.getContext('2d');
  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;
  ctx.clearRect(0,0,W,H);
  if(hist.length<2){ctx.fillStyle='#8b949e';ctx.textAlign='center';ctx.fillText('Collecting...',W/2,H/2);return;}
  const pad=40,series=[{k:'m',c:'#58a6ff',l:'Masked'},{k:'r',c:'#39d2e0',l:'Rotated'},{k:'d',c:'#db6d28',l:'Decoys'}];
  const max=Math.max(1,...hist.flatMap(h=>series.map(s=>h[s.k])));
  series.forEach(s=>{
    ctx.beginPath();ctx.strokeStyle=s.c;ctx.lineWidth=2;
    hist.forEach((h,i)=>{const x=pad+i*(W-pad-10)/(hist.length-1),y=H-pad-(h[s.k]/max)*(H-pad*2);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});
    ctx.stroke();
  });
  let lx=pad;series.forEach(s=>{ctx.fillStyle=s.c;ctx.fillRect(lx,H-12,8,8);ctx.fillStyle='#c9d1d9';ctx.font='10px sans-serif';ctx.textAlign='left';ctx.fillText(s.l,lx+12,H-4);lx+=70;});
}
async function load(){
  try{
    const r=await fetch('/api/cloaking/status');const d=await r.json();
    const mode=d.mode||'disabled';
    document.getElementById('kMode').textContent=mode.toUpperCase();document.getElementById('kMode').style.color=MCOL[mode]||'var(--dim)';
    document.getElementById('kMask').textContent=d.masked_ips||0;document.getElementById('kRot').textContent=d.rotated_sources||0;
    document.getElementById('kDec').textContent=d.decoys_generated||0;document.getElementById('kPrx').textContent=d.proxy_chain_length||0;
    document.getElementById('kId').textContent=d.identities_count||0;
    document.getElementById('ml').textContent=mode.toUpperCase();
    document.getElementById('modes').innerHTML=MODES.map(m=>'<div class="mode-chip '+(m===mode?'active':'')+'"><div class="ic">'+ICONS[m]+'</div><div class="lb" style="color:'+(m===mode?MCOL[m]:'var(--dim)')+'">'+m+'</div></div>').join('');
    drawAct(d);
    // Proxies
    const pEl=document.getElementById('proxies');
    const chain=d.proxy_chain||[];
    if(!chain.length){pEl.innerHTML='<div class="empty">No proxy chain</div>';}
    else{pEl.innerHTML=chain.map((p,i)=>'<div class="proxy-hop"><span style="width:10px;height:10px;border-radius:50%;background:'+(p.is_alive?'var(--green)':'var(--red)')+'"></span><span style="color:var(--dim);font-size:.75rem">Hop '+(i+1)+'</span><span style="font-family:monospace;font-size:.85rem">'+p.host+':'+p.port+'</span><span style="font-size:.7rem;padding:2px 6px;border-radius:4px;background:rgba(88,166,255,.15);color:var(--blue)">'+p.protocol+'</span></div>').join('');}
    // Identities
    const iEl=document.getElementById('ids');
    const ids=d.identities||[];
    if(!ids.length){iEl.innerHTML='<div class="empty">No identities</div>';}
    else{iEl.innerHTML=ids.map(id=>'<div class="id-card '+(id.name===d.active_identity?'active':'')+'"><div class="nm">'+(id.name===d.active_identity?'&#9733; ':'')+id.name+'</div><div class="dt">Mode: <span style="color:'+(MCOL[id.mode]||'var(--dim)')+'">'+id.mode+'</span><br>Sources: '+(id.source_ips?id.source_ips.length:0)+' IPs<br>Proxies: '+(id.proxy_chain?id.proxy_chain.length:0)+' hops</div></div>').join('');}
    // Source pool
    const pool=d.source_pool||[];
    document.getElementById('pool').innerHTML=pool.length?pool.map(ip=>'<span style="display:inline-block;padding:4px 10px;margin:3px;border-radius:6px;background:rgba(57,210,224,.1);border:1px solid var(--border);font-family:monospace;font-size:.82rem">'+ip+'</span>').join(''):'<div class="empty">Empty pool</div>';
    // Masker
    document.getElementById('masker').innerHTML='<div style="display:grid;gap:8px"><div style="display:flex;justify-content:space-between"><span style="color:var(--dim)">Mappings</span><span>'+(d.mapping_count||0)+'</span></div><div style="display:flex;justify-content:space-between"><span style="color:var(--dim)">Masked</span><span style="color:var(--blue)">'+(d.masked_ips||0)+'</span></div><div style="display:flex;justify-content:space-between"><span style="color:var(--dim)">Rotated</span><span style="color:var(--cyan)">'+(d.rotated_sources||0)+'</span></div><div style="display:flex;justify-content:space-between"><span style="color:var(--dim)">Decoys</span><span style="color:var(--orange)">'+(d.decoys_generated||0)+'</span></div></div>';
    document.getElementById('ts').textContent=new Date().toLocaleTimeString()+' | Auto 4s';
  }catch(e){console.error(e);}
}
load();setInterval(load,4000);
</script></body></html>"""
)

# ── EXPLORER PAGE ──────────────────────────────────────────────────
EXPLORER_HTML = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1">'
    '<title>Network Explorer - Network Guardian</title>'
    '<style nonce="{{NONCE}}">' + _SHARED_CSS + """
.host-node{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px;transition:.2s}
.host-node:hover{border-color:var(--blue);transform:translateY(-2px)}
.host-node .ip{font-family:monospace;font-weight:700;font-size:1rem;margin-bottom:4px}
.host-node .info{color:var(--dim);font-size:.78rem;line-height:1.6}
.port-tag{padding:2px 6px;border-radius:4px;font-size:.65rem;font-family:monospace;background:rgba(88,166,255,.1);color:var(--blue);border:1px solid rgba(88,166,255,.2);display:inline-block;margin:2px}
</style></head><body>
<div class="wrap">
  <div class="banner">
    <h1>&#127760; Network Explorer</h1>
    <span id="st" class="badge" style="background:rgba(88,166,255,.15);color:var(--blue)">Idle</span>
    <span id="ts" style="margin-left:auto;color:var(--dim);font-size:.85rem"></span>
  </div>
  <div class="kpi-row">
    <div class="kpi"><div class="v" id="kH">0</div><div class="l">Hosts</div></div>
    <div class="kpi"><div class="v" id="kP">0</div><div class="l">Open Ports</div></div>
    <div class="kpi"><div class="v" id="kO">0</div><div class="l">OS Types</div></div>
    <div class="kpi"><div class="v" id="kE">0</div><div class="l">Connections</div></div>
  </div>
""" + NAV("/explorer") + """
  <div class="grid g2">
    <div class="card" style="grid-column:1/-1"><h2>&#127760; Topology</h2><canvas id="topo" height="350"></canvas></div>
    <div class="card" style="grid-column:1/-1"><h2>&#128187; Hosts</h2><div id="hosts" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px"></div></div>
    <div class="card"><h2>&#128202; Port Distribution</h2><canvas id="portChart" height="220"></canvas></div>
    <div class="card"><h2>&#128268; Edges</h2><div id="edges" style="max-height:250px;overflow-y:auto"></div></div>
  </div>
</div>
<script nonce="{{NONCE}}">
function drawTopo(hosts,topo){
  const c=document.getElementById('topo'),ctx=c.getContext('2d');
  const W=c.width=c.parentElement.clientWidth-40,H=c.height=350;
  ctx.clearRect(0,0,W,H);
  const ips=Object.keys(hosts);
  if(!ips.length){ctx.fillStyle='#8b949e';ctx.textAlign='center';ctx.font='14px sans-serif';ctx.fillText('No hosts - run explore to populate',W/2,H/2);return;}
  const cx=W/2,cy=H/2,r=Math.min(W,H)/2-60;
  const pos={};
  ips.forEach((ip,i)=>{const ang=(i/ips.length)*Math.PI*2-Math.PI/2;pos[ip]={x:cx+r*Math.cos(ang),y:cy+r*Math.sin(ang)};});
  if(topo){Object.entries(topo).forEach(([from,tos])=>{(tos||[]).forEach(to=>{if(pos[from]&&pos[to]){ctx.beginPath();ctx.moveTo(pos[from].x,pos[from].y);ctx.lineTo(pos[to].x,pos[to].y);ctx.strokeStyle='rgba(88,166,255,.3)';ctx.lineWidth=1.5;ctx.stroke();}});});}
  ips.forEach(ip=>{
    const p=pos[ip];
    const g=ctx.createRadialGradient(p.x,p.y,0,p.x,p.y,24);g.addColorStop(0,'rgba(88,166,255,.3)');g.addColorStop(1,'transparent');ctx.fillStyle=g;ctx.fillRect(p.x-24,p.y-24,48,48);
    ctx.beginPath();ctx.arc(p.x,p.y,14,0,Math.PI*2);ctx.fillStyle='#161b22';ctx.fill();ctx.strokeStyle='#58a6ff';ctx.lineWidth=2;ctx.stroke();
    ctx.fillStyle='#c9d1d9';ctx.font='10px monospace';ctx.textAlign='center';ctx.fillText(ip,p.x,p.y+28);
  });
}
function drawPorts(hosts){
  const c=document.getElementById('portChart'),ctx=c.getContext('2d');
  const W=c.width=c.parentElement.clientWidth-40,H=c.height=220;
  ctx.clearRect(0,0,W,H);
  const pc={};Object.values(hosts).forEach(h=>{(h.open_ports||[]).forEach(p=>{pc[p]=(pc[p]||0)+1;});});
  const entries=Object.entries(pc).sort((a,b)=>b[1]-a[1]).slice(0,12);
  if(!entries.length){ctx.fillStyle='#8b949e';ctx.textAlign='center';ctx.fillText('No port data',W/2,H/2);return;}
  const max=Math.max(...entries.map(e=>e[1])),bh=14;
  entries.forEach(([port,count],i)=>{
    const y=16+i*(bh+4),w=(count/max)*(W-100);
    ctx.fillStyle='#8b949e';ctx.font='10px monospace';ctx.textAlign='right';ctx.fillText(port,70,y+bh/2+3);
    const g=ctx.createLinearGradient(80,y,80+w,y);g.addColorStop(0,'#58a6ff');g.addColorStop(1,'#58a6ff44');
    ctx.fillStyle=g;ctx.beginPath();ctx.roundRect(80,y,w,bh,3);ctx.fill();
    ctx.fillStyle='#c9d1d9';ctx.font='9px sans-serif';ctx.textAlign='left';ctx.fillText(count,84+w,y+bh/2+3);
  });
}
async function load(){
  try{
    const [hR,tR]=await Promise.all([fetch('/api/hosts'),fetch('/api/explorer/topology')]);
    const hosts=await hR.json(),topo=await tR.json();
    const ips=Object.keys(hosts);let tp=0;const oSet=new Set();
    ips.forEach(ip=>{const h=hosts[ip];tp+=(h.open_ports||[]).length;if(h.os)oSet.add(h.os);});
    let ec=0;if(topo)Object.values(topo).forEach(v=>{ec+=(v||[]).length;});
    document.getElementById('kH').textContent=ips.length;document.getElementById('kP').textContent=tp;
    document.getElementById('kO').textContent=oSet.size;document.getElementById('kE').textContent=ec;
    document.getElementById('st').textContent=ips.length?ips.length+' Hosts':'Idle';document.getElementById('st').style.color=ips.length?'var(--green)':'var(--blue)';
    drawTopo(hosts,topo);drawPorts(hosts);
    const hEl=document.getElementById('hosts');
    if(!ips.length){hEl.innerHTML='<div class="empty">No hosts discovered</div>';}
    else{hEl.innerHTML=ips.map(ip=>{const h=hosts[ip];const ports=(h.open_ports||[]).slice(0,10);return '<div class="host-node"><div class="ip">'+ip+'</div><div class="info">'+(h.hostname?'Host: '+h.hostname+'<br>':'')+(h.os?'OS: '+h.os+'<br>':'')+'Ports: '+(h.open_ports||[]).length+' open</div><div>'+ports.map(p=>'<span class="port-tag">'+p+'</span>').join('')+'</div></div>';}).join('');}
    const eEl=document.getElementById('edges');
    if(!topo||!Object.keys(topo).length){eEl.innerHTML='<div class="empty">No topology</div>';}
    else{let html='';Object.entries(topo).forEach(([from,tos])=>{(tos||[]).forEach(to=>{html+='<div style="display:flex;align-items:center;gap:8px;padding:6px;font-size:.82rem;border-bottom:1px solid rgba(48,54,61,.4)"><span style="font-family:monospace;color:var(--blue)">'+from+'</span><span style="color:var(--dim)">&#8594;</span><span style="font-family:monospace;color:var(--cyan)">'+to+'</span></div>';});});eEl.innerHTML=html;}
    document.getElementById('ts').textContent=new Date().toLocaleTimeString()+' | Auto 5s';
  }catch(e){console.error(e);}
}
load();setInterval(load,5000);
</script></body></html>"""
)

# ── AUDITOR PAGE ───────────────────────────────────────────────────
AUDITOR_HTML = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1">'
    '<title>Security Auditor - Network Guardian</title>'
    '<style nonce="{{NONCE}}">' + _SHARED_CSS + """
.finding{display:flex;gap:12px;padding:12px;border:1px solid var(--border);border-radius:10px;margin-bottom:8px;border-left:4px solid var(--border);transition:.2s}
.finding:hover{background:rgba(88,166,255,.03)}
.finding.fc{border-left-color:var(--red)}
.finding.fh{border-left-color:var(--orange)}
.finding.fm{border-left-color:var(--yellow)}
.finding.fl{border-left-color:var(--green)}
.finding .body{flex:1}
.finding .title{font-weight:600;font-size:.9rem;margin-bottom:3px}
.finding .desc{color:var(--dim);font-size:.78rem;line-height:1.5}
</style></head><body>
<div class="wrap">
  <div class="banner">
    <h1>&#128270; Security Auditor</h1>
    <span id="st" class="badge" style="background:rgba(63,185,80,.15);color:var(--green)">Clean</span>
    <span id="ts" style="margin-left:auto;color:var(--dim);font-size:.85rem"></span>
  </div>
  <div class="kpi-row">
    <div class="kpi"><div class="v" id="kT">0</div><div class="l">Total</div></div>
    <div class="kpi"><div class="v" id="kC" style="color:var(--red)">0</div><div class="l">Critical</div></div>
    <div class="kpi"><div class="v" id="kH" style="color:var(--orange)">0</div><div class="l">High</div></div>
    <div class="kpi"><div class="v" id="kM" style="color:var(--yellow)">0</div><div class="l">Medium</div></div>
    <div class="kpi"><div class="v" id="kL" style="color:var(--green)">0</div><div class="l">Low</div></div>
  </div>
""" + NAV("/auditor") + """
  <div class="grid g2">
    <div class="card"><h2>&#128202; Severity</h2><canvas id="sevChart" height="200"></canvas></div>
    <div class="card"><h2>&#127919; Risk Score</h2><canvas id="riskGauge" height="200"></canvas></div>
    <div class="card" style="grid-column:1/-1"><h2>&#128196; Findings</h2><div id="finds"></div></div>
  </div>
</div>
<script nonce="{{NONCE}}">
function drawSev(findings){
  const c=document.getElementById('sevChart'),ctx=c.getContext('2d');
  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;
  ctx.clearRect(0,0,W,H);
  const cnt={critical:0,high:0,medium:0,low:0,info:0};
  findings.forEach(f=>{const s=(f.severity||'info').toLowerCase();if(cnt[s]!==undefined)cnt[s]++;});
  const total=findings.length;
  if(!total){ctx.fillStyle='#8b949e';ctx.textAlign='center';ctx.fillText('No findings',W/2,H/2);return;}
  const cols={critical:'#f85149',high:'#db6d28',medium:'#d29922',low:'#3fb950',info:'#58a6ff'};
  const cx=90,cy=H/2,r=75;let angle=-Math.PI/2;
  Object.entries(cnt).filter(e=>e[1]>0).forEach(([k,v])=>{const sl=v/total*Math.PI*2;ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,r,angle,angle+sl);ctx.closePath();ctx.fillStyle=cols[k];ctx.fill();angle+=sl;});
  ctx.beginPath();ctx.arc(cx,cy,45,0,Math.PI*2);ctx.fillStyle='#161b22';ctx.fill();
  ctx.fillStyle='#c9d1d9';ctx.font='bold 20px sans-serif';ctx.textAlign='center';ctx.fillText(total,cx,cy+7);
  let ly=20;Object.entries(cnt).forEach(([k,v])=>{ctx.fillStyle=cols[k];ctx.fillRect(W-150,ly,10,10);ctx.fillStyle='#c9d1d9';ctx.font='12px sans-serif';ctx.textAlign='left';ctx.fillText(k+' ('+v+')',W-134,ly+9);ly+=22;});
}
function drawRisk(findings){
  const c=document.getElementById('riskGauge'),ctx=c.getContext('2d');
  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;
  ctx.clearRect(0,0,W,H);
  const wt={critical:10,high:5,medium:2,low:1,info:0};
  let score=0;findings.forEach(f=>{score+=wt[(f.severity||'info').toLowerCase()]||0;});
  const pct=Math.min(1,score/100);
  const cx=W/2,cy=H-30,r=80;
  ctx.beginPath();ctx.arc(cx,cy,r,-Math.PI,0);ctx.strokeStyle='#30363d';ctx.lineWidth=20;ctx.lineCap='round';ctx.stroke();
  const col=pct<0.3?'#3fb950':pct<0.6?'#d29922':pct<0.8?'#db6d28':'#f85149';
  if(pct>0){ctx.beginPath();ctx.arc(cx,cy,r,-Math.PI,-Math.PI+pct*Math.PI);ctx.strokeStyle=col;ctx.lineWidth=20;ctx.lineCap='round';ctx.stroke();}
  ctx.fillStyle='#c9d1d9';ctx.font='bold 28px sans-serif';ctx.textAlign='center';ctx.fillText(score,cx,cy-10);
  ctx.fillStyle='#8b949e';ctx.font='12px sans-serif';ctx.fillText('Risk Score',cx,cy+10);
}
async function load(){
  try{
    const r=await fetch('/api/findings');const findings=await r.json();
    const cnt={critical:0,high:0,medium:0,low:0,info:0};
    findings.forEach(f=>{const s=(f.severity||'info').toLowerCase();if(cnt[s]!==undefined)cnt[s]++;});
    document.getElementById('kT').textContent=findings.length;
    document.getElementById('kC').textContent=cnt.critical;document.getElementById('kH').textContent=cnt.high;
    document.getElementById('kM').textContent=cnt.medium;document.getElementById('kL').textContent=cnt.low;
    const badge=document.getElementById('st');
    if(cnt.critical>0){badge.textContent='CRITICAL';badge.style.background='rgba(248,81,73,.15)';badge.style.color='var(--red)';}
    else if(cnt.high>0){badge.textContent='AT RISK';badge.style.background='rgba(219,109,40,.15)';badge.style.color='var(--orange)';}
    else if(findings.length>0){badge.textContent='WARNINGS';badge.style.background='rgba(210,153,34,.15)';badge.style.color='var(--yellow)';}
    else{badge.textContent='CLEAN';badge.style.background='rgba(63,185,80,.15)';badge.style.color='var(--green)';}
    drawSev(findings);drawRisk(findings);
    const fEl=document.getElementById('finds');
    if(!findings.length){fEl.innerHTML='<div class="empty">No findings - system clean</div>';}
    else{const sevC={critical:'fc',high:'fh',medium:'fm',low:'fl'};fEl.innerHTML=findings.map(f=>{const s=(f.severity||'info').toLowerCase();return '<div class="finding '+(sevC[s]||'')+'"><div style="font-size:1.4rem;min-width:30px;text-align:center">'+(s==='critical'?'&#128680;':s==='high'?'&#9888;':'&#128313;')+'</div><div class="body"><div class="title">'+(f.title||f.description||'Finding')+'</div><div class="desc">'+(f.target?'Target: <b>'+f.target+'</b> | ':'')+'Severity: <span class="pill sev-'+s+'">'+s.toUpperCase()+'</span></div></div></div>';}).join('');}
    document.getElementById('ts').textContent=new Date().toLocaleTimeString()+' | Auto 5s';
  }catch(e){console.error(e);}
}
load();setInterval(load,5000);
</script></body></html>"""
)

# ── AI PAGE ────────────────────────────────────────────────────────
AI_HTML = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1">'
    '<title>AI Engine - Network Guardian</title>'
    '<style nonce="{{NONCE}}">' + _SHARED_CSS + """
.ai-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center;transition:.2s}
.ai-card:hover{border-color:var(--purple);transform:translateY(-2px)}
.ai-card .icon{font-size:2rem;margin-bottom:8px}
.ai-card .name{font-weight:700;font-size:.9rem;margin-bottom:4px}
.ai-card .desc{color:var(--dim);font-size:.75rem}
.metric-row{display:flex;gap:8px;align-items:center;padding:8px 0;border-bottom:1px solid rgba(48,54,61,.4);font-size:.85rem}
.metric-row:last-child{border-bottom:none}
.metric-row .label{color:var(--dim);flex:1}
.metric-row .val{font-weight:600;font-family:monospace}
</style></head><body>
<div class="wrap">
  <div class="banner">
    <h1>&#129302; AI Engine</h1>
    <span class="badge" style="background:rgba(188,140,255,.15);color:var(--purple)">Active</span>
    <span id="ts" style="margin-left:auto;color:var(--dim);font-size:.85rem"></span>
  </div>
  <div class="kpi-row">
    <div class="kpi"><div class="v" id="kAn" style="color:var(--red)">0</div><div class="l">Anomalies</div></div>
    <div class="kpi"><div class="v" id="kPr" style="color:var(--purple)">0</div><div class="l">Predictions</div></div>
    <div class="kpi"><div class="v" id="kMe" style="color:var(--blue)">0</div><div class="l">Metrics</div></div>
    <div class="kpi"><div class="v" id="kEv" style="color:var(--cyan)">0</div><div class="l">AI Events</div></div>
  </div>
""" + NAV("/ai") + """
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px;margin-bottom:18px">
    <div class="ai-card"><div class="icon">&#128024;</div><div class="name">Isolation Forest</div><div class="desc">Unsupervised anomaly detection</div></div>
    <div class="ai-card"><div class="icon">&#127919;</div><div class="name">One-Class SVM</div><div class="desc">RBF kernel density</div></div>
    <div class="ai-card"><div class="icon">&#129704;</div><div class="name">Ensemble Detector</div><div class="desc">Multi-model averaging</div></div>
    <div class="ai-card"><div class="icon">&#128200;</div><div class="name">ARIMA</div><div class="desc">Time series forecasting</div></div>
    <div class="ai-card"><div class="icon">&#127777;</div><div class="name">Holt-Winters</div><div class="desc">Exponential smoothing</div></div>
    <div class="ai-card"><div class="icon">&#128172;</div><div class="name">NLP Engine</div><div class="desc">Command + log analysis</div></div>
  </div>
  <div class="grid g2">
    <div class="card"><h2>&#128200; Anomaly Timeline</h2><canvas id="anomChart" height="200"></canvas></div>
    <div class="card"><h2>&#128202; System Metrics</h2><canvas id="metChart" height="200"></canvas></div>
    <div class="card"><h2>&#128161; Metric Values</h2><div id="metList" style="max-height:260px;overflow-y:auto"></div></div>
    <div class="card"><h2>&#9889; AI Events</h2><div id="aiEvts" style="max-height:260px;overflow-y:auto"></div></div>
  </div>
</div>
<script nonce="{{NONCE}}">
let aHist=[];
function drawAnom(){
  const c=document.getElementById('anomChart'),ctx=c.getContext('2d');
  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;
  ctx.clearRect(0,0,W,H);
  if(aHist.length<2){ctx.fillStyle='#8b949e';ctx.textAlign='center';ctx.fillText('Collecting...',W/2,H/2);return;}
  const pad=40,max=Math.max(1,...aHist.map(a=>a.s));
  const thY=H-pad-(0.7/max)*(H-pad*2);
  ctx.setLineDash([5,5]);ctx.strokeStyle='rgba(248,81,73,.5)';ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(pad,thY);ctx.lineTo(W-10,thY);ctx.stroke();ctx.setLineDash([]);
  ctx.beginPath();aHist.forEach((a,i)=>{const x=pad+i*(W-pad-10)/(aHist.length-1),y=H-pad-(a.s/max)*(H-pad*2);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});
  ctx.strokeStyle='#bc8cff';ctx.lineWidth=2;ctx.stroke();
  const last=aHist.length-1;ctx.lineTo(pad+last*(W-pad-10)/last,H-pad);ctx.lineTo(pad,H-pad);ctx.closePath();ctx.fillStyle='rgba(188,140,255,.1)';ctx.fill();
}
function drawMet(metrics){
  const c=document.getElementById('metChart'),ctx=c.getContext('2d');
  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;
  ctx.clearRect(0,0,W,H);
  const names=Object.keys(metrics||{});
  if(!names.length){ctx.fillStyle='#8b949e';ctx.textAlign='center';ctx.fillText('No metrics',W/2,H/2);return;}
  const colors=['#58a6ff','#3fb950','#d29922','#bc8cff','#39d2e0','#f85149'];
  const pad=40,allV=names.flatMap(n=>(metrics[n]||[]).slice(-20)),max=Math.max(1,...allV);
  names.slice(0,6).forEach((name,ni)=>{
    const vals=(metrics[name]||[]).slice(-20);if(vals.length<2)return;
    ctx.beginPath();ctx.strokeStyle=colors[ni%6];ctx.lineWidth=1.5;
    vals.forEach((v,i)=>{const x=pad+i*(W-pad-10)/(vals.length-1),y=H-pad-(v/max)*(H-pad*2);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});ctx.stroke();
  });
  let lx=pad;names.slice(0,6).forEach((n,i)=>{ctx.fillStyle=colors[i%6];ctx.fillRect(lx,H-12,8,8);ctx.fillStyle='#c9d1d9';ctx.font='9px sans-serif';ctx.textAlign='left';ctx.fillText(n.slice(0,15),lx+12,H-4);lx+=W/6.5;});
}
async function load(){
  try{
    const [mR,eR]=await Promise.all([fetch('/api/ai/metrics'),fetch('/api/events')]);
    const md=await mR.json(),events=await eR.json();
    const met=md.metrics||{};
    aHist.push({s:md.latest_anomaly_score||0});if(aHist.length>30)aHist=aHist.slice(-30);
    document.getElementById('kAn').textContent=md.anomaly_count||0;
    document.getElementById('kPr').textContent=md.prediction_count||0;
    document.getElementById('kMe').textContent=Object.keys(met).length;
    const aiE=(events||[]).filter(e=>e.topic&&(e.topic.startsWith('ai.')||e.topic.startsWith('monitor.')));
    document.getElementById('kEv').textContent=aiE.length;
    drawAnom();drawMet(met);
    const mEl=document.getElementById('metList');
    const names=Object.keys(met);
    if(!names.length){mEl.innerHTML='<div class="empty">No metrics</div>';}
    else{mEl.innerHTML=names.map(n=>{const v=met[n]||[];const last=v.length?v[v.length-1]:'-';const avg=v.length?(v.reduce((a,b)=>a+b,0)/v.length).toFixed(2):'-';return '<div class="metric-row"><span class="label">'+n+'</span><span class="val" style="color:var(--blue)">'+(typeof last==='number'?last.toFixed(2):last)+'</span><span style="color:var(--dim);font-size:.7rem;margin-left:8px">avg:'+avg+'</span></div>';}).join('');}
    const aEl=document.getElementById('aiEvts');
    if(!aiE.length){aEl.innerHTML='<div class="empty">No AI events</div>';}
    else{aEl.innerHTML=aiE.slice(-20).reverse().map(e=>'<div style="display:flex;gap:10px;padding:8px;border-bottom:1px solid rgba(48,54,61,.3);font-size:.82rem"><span style="color:var(--dim);font-size:.75rem;min-width:80px">'+new Date(e.timestamp).toLocaleTimeString()+'</span><span style="color:var(--purple);font-family:monospace;font-size:.75rem">'+e.topic+'</span></div>').join('');}
    document.getElementById('ts').textContent=new Date().toLocaleTimeString()+' | Auto 4s';
  }catch(e){console.error(e);}
}
load();setInterval(load,4000);
</script></body></html>"""
)

# ── Now build template constants string ────────────────────────────
TEMPLATE_BLOCK = (
    '\n\n# ---------------------------------------------------------------------------\n'
    '# HTML page templates (module-level constants — avoids f-string brace issues)\n'
    '# ---------------------------------------------------------------------------\n\n'
    '_TMPL_INDEX = ' + repr(INDEX_HTML) + '\n\n'
    '_TMPL_IDS = ' + repr(IDS_HTML) + '\n\n'
    '_TMPL_IPS = ' + repr(IPS_HTML) + '\n\n'
    '_TMPL_WIFI = ' + repr(WIFI_HTML) + '\n\n'
    '_TMPL_CLOAKING = ' + repr(CLOAKING_HTML) + '\n\n'
    '_TMPL_EXPLORER = ' + repr(EXPLORER_HTML) + '\n\n'
    '_TMPL_AUDITOR = ' + repr(AUDITOR_HTML) + '\n\n'
    '_TMPL_AI = ' + repr(AI_HTML) + '\n'
)

# Insert template constants after _CONTENT_TEXT definition
src = src.replace(TEMPLATES_INSERT_MARKER, TEMPLATES_INSERT_MARKER + "\n" + TEMPLATE_BLOCK)

# ── 5) Remove the old _page_index method using HTML page marker → Response helpers ─
old_page_section_start = "    # -- HTML page"
old_page_section_end = "    # -- Response helpers"
idx_start = src.find(old_page_section_start)
idx_end = src.find(old_page_section_end)
if idx_start != -1 and idx_end != -1:
    src = src[:idx_start] + src[idx_end:]

# ── Write ──────────────────────────────────────────────────────────
with open(DASHBOARD, "w") as f:
    f.write(src)

# ── Syntax check ───────────────────────────────────────────────────
import py_compile
try:
    py_compile.compile(DASHBOARD, doraise=True)
    print("Syntax: OK")
except py_compile.PyCompileError as e:
    print(f"Syntax ERROR: {e}")
    sys.exit(1)

import re
methods = re.findall(r'def (_page_\w+|_api_\w+)', src)
print(f"Pages: {sum(1 for m in methods if m.startswith('_page_'))}")
print(f"APIs:  {sum(1 for m in methods if m.startswith('_api_'))}")
print(f"Lines: {len(src.splitlines())}")
print("Done! Pages: / /ids /ips /wifi /cloaking /explorer /auditor /ai")
