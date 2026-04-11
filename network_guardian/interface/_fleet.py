"""
Fleet Manager — Base Station Agent Registry & Dashboard

Manages deployed field agents (probes), accepting reports, tracking
status, and displaying a fleet overview dashboard page.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("network_guardian.fleet")


# ---------------------------------------------------------------------------
# Fleet store  (~/.network_guardian/fleet.json)
# ---------------------------------------------------------------------------

class FleetStore:
    """Persists registered agents and their latest reports."""

    def __init__(self, data_dir: Path) -> None:
        self._path = data_dir / "fleet.json"
        self._data: dict[str, Any] = {"agents": {}, "fleet_key": ""}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                with open(self._path, "r") as f:
                    self._data = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.error("Failed to load fleet file: %s", e)
                self._data = {"agents": {}, "fleet_key": ""}
        if not self._data.get("fleet_key"):
            self._data["fleet_key"] = secrets.token_urlsafe(32)
            self._save()

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(self._data, f, indent=2)
        tmp.replace(self._path)

    @property
    def fleet_key(self) -> str:
        return self._data["fleet_key"]

    def register_agent(self, agent_id: str, identity: dict) -> None:
        now = int(time.time())
        existing = self._data.setdefault("agents", {}).get(agent_id, {})
        self._data["agents"][agent_id] = {
            "identity": identity,
            "registered_at": existing.get("registered_at", now),
            "last_seen": now,
            "status": "online",
            "report_count": existing.get("report_count", 0),
            "last_report": existing.get("last_report"),
            "label": existing.get("label", identity.get("hostname", agent_id)),
        }
        self._save()
        logger.info("Agent registered: %s (%s)", agent_id,
                     identity.get("hostname", "?"))

    def accept_report(self, agent_id: str, report: dict) -> bool:
        agents = self._data.setdefault("agents", {})
        if agent_id not in agents:
            return False
        agents[agent_id]["last_seen"] = int(time.time())
        agents[agent_id]["status"] = "online"
        agents[agent_id]["report_count"] = agents[agent_id].get("report_count", 0) + 1
        agents[agent_id]["last_report"] = report
        self._save()
        return True

    def remove_agent(self, agent_id: str) -> bool:
        if agent_id in self._data.get("agents", {}):
            del self._data["agents"][agent_id]
            self._save()
            return True
        return False

    def set_label(self, agent_id: str, label: str) -> bool:
        agent = self._data.get("agents", {}).get(agent_id)
        if agent:
            agent["label"] = label
            self._save()
            return True
        return False

    def list_agents(self) -> list[dict]:
        """Return summary of all agents (with staleness check)."""
        now = int(time.time())
        result = []
        for aid, a in self._data.get("agents", {}).items():
            age = now - a.get("last_seen", 0)
            if age > 300:
                status = "offline"
            elif age > 120:
                status = "stale"
            else:
                status = "online"
            report = a.get("last_report") or {}
            result.append({
                "agent_id": aid,
                "label": a.get("label", aid),
                "hostname": a.get("identity", {}).get("hostname", "?"),
                "platform": a.get("identity", {}).get("platform_os", "?"),
                "local_ip": report.get("local_ip", ""),
                "subnet": report.get("subnet", ""),
                "status": status,
                "last_seen": a.get("last_seen", 0),
                "seconds_ago": age,
                "report_count": a.get("report_count", 0),
                "wifi_count": len(report.get("wifi_networks", [])),
                "host_count": len(report.get("discovered_hosts", [])),
            })
        return result

    def get_agent_report(self, agent_id: str) -> dict | None:
        agent = self._data.get("agents", {}).get(agent_id)
        if agent:
            return agent.get("last_report")
        return None

    def verify_signature(self, payload: bytes, signature: str) -> bool:
        """Verify an agent's HMAC-SHA256 signature."""
        expected = hmac.new(
            self.fleet_key.encode(), payload, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# Fleet dashboard page template
# ---------------------------------------------------------------------------

_TMPL_FLEET = '''<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Fleet Command — Network Guardian</title>
<style nonce="{{NONCE}}">
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
.kpi-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}
.kpi{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 20px;min-width:130px;flex:1}
.kpi .v{font-size:1.6rem;font-weight:700;color:var(--blue)}
.kpi .l{font-size:.7rem;color:var(--dim);text-transform:uppercase;letter-spacing:.5px}
.empty{color:var(--dim);font-style:italic;padding:20px;text-align:center}
table{width:100%;border-collapse:collapse;font-size:.82rem}
th{text-align:left;color:var(--dim);text-transform:uppercase;font-size:.7rem;letter-spacing:.8px;padding:8px 6px;border-bottom:1px solid var(--border)}
td{padding:8px 6px;border-bottom:1px solid rgba(48,54,61,.4)}

.agent-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px;transition:.2s;cursor:pointer}
.agent-card:hover{border-color:var(--blue);transform:translateY(-2px)}
.agent-card.online{border-left:4px solid var(--green)}
.agent-card.stale{border-left:4px solid var(--yellow)}
.agent-card.offline{border-left:4px solid var(--red)}
.agent-card .hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.agent-card .name{font-weight:700;font-size:1rem}
.agent-card .id{font-family:monospace;font-size:.75rem;color:var(--dim)}
.agent-card .stats{display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:.78rem;color:var(--dim)}
.agent-card .stats span{color:var(--text);font-weight:600}
.status-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.status-dot.online{background:var(--green);box-shadow:0 0 6px var(--green)}
.status-dot.stale{background:var(--yellow);box-shadow:0 0 6px var(--yellow)}
.status-dot.offline{background:var(--red);box-shadow:0 0 6px var(--red)}
.key-box{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px;font-family:monospace;font-size:.82rem;word-break:break-all;user-select:all;margin-top:8px}
.detail-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.7);z-index:100;align-items:center;justify-content:center}
.detail-overlay.show{display:flex}
.detail-box{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:24px;max-width:800px;width:90%;max-height:85vh;overflow-y:auto}
.detail-box h3{font-size:1.1rem;margin-bottom:16px;color:var(--blue)}
.close-btn{float:right;background:none;border:1px solid var(--border);color:var(--text);padding:4px 12px;border-radius:6px;cursor:pointer;font-size:.85rem}
.close-btn:hover{background:var(--border)}
.wifi-mini{display:inline-block;padding:3px 8px;margin:2px;border-radius:6px;font-size:.72rem;background:rgba(88,166,255,.1);border:1px solid rgba(88,166,255,.2);color:var(--blue)}
.host-mini{display:inline-block;padding:3px 8px;margin:2px;border-radius:6px;font-size:.72rem;background:rgba(63,185,80,.1);border:1px solid rgba(63,185,80,.2);color:var(--green);font-family:monospace}
</style></head><body>
<div class="wrap">
  <div class="banner">
    <h1>&#128752; Fleet Command</h1>
    <span id="count" class="badge" style="background:rgba(88,166,255,.15);color:var(--blue)">0 Agents</span>
    <span id="ts" style="margin-left:auto;color:var(--dim);font-size:.85rem"></span>
  </div>
  <div class="kpi-row">
    <div class="kpi"><div class="v" id="kT">0</div><div class="l">Total Agents</div></div>
    <div class="kpi"><div class="v" id="kOn" style="color:var(--green)">0</div><div class="l">Online</div></div>
    <div class="kpi"><div class="v" id="kSt" style="color:var(--yellow)">0</div><div class="l">Stale</div></div>
    <div class="kpi"><div class="v" id="kOf" style="color:var(--red)">0</div><div class="l">Offline</div></div>
    <div class="kpi"><div class="v" id="kWi" style="color:var(--cyan)">0</div><div class="l">Total WiFi Nets</div></div>
    <div class="kpi"><div class="v" id="kHo" style="color:var(--purple)">0</div><div class="l">Total Hosts</div></div>
  </div>
  <div class="nav">
    <a href="/">Dashboard</a><a href="/ids">IDS</a><a href="/ips">IPS</a><a href="/wifi">WiFi</a>
    <a href="/cloaking">Cloaking</a><a href="/explorer">Explorer</a><a href="/auditor">Auditor</a>
    <a href="/ai">AI Engine</a><a href="/fleet" class="active">Fleet</a>
  </div>
  <div class="card" style="margin-bottom:16px">
    <h2>&#128273; Agent Deployment Key</h2>
    <div style="font-size:.82rem;color:var(--dim);margin-bottom:6px">
      Give this key to field agents. Run:
      <code style="color:var(--cyan)">python probe.py --base http://YOUR_IP:8080 --key FLEET_KEY</code>
    </div>
    <div class="key-box" id="fleetKey">Loading...</div>
  </div>
  <div id="agents" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px;margin-bottom:20px"></div>
  <div class="card"><h2>&#128200; Fleet Map</h2><canvas id="fleetMap" height="300"></canvas></div>
</div>

<div class="detail-overlay" id="overlay">
  <div class="detail-box" id="detailBox">
    <button class="close-btn" onclick="closeDetail()">&#10005; Close</button>
    <div id="detailContent"></div>
  </div>
</div>

<script nonce="{{NONCE}}">
function closeDetail(){document.getElementById('overlay').classList.remove('show');}
document.getElementById('overlay').addEventListener('click',function(e){if(e.target===this)closeDetail();});

function showAgent(aid){
  fetch('/api/fleet/agent/'+aid).then(r=>r.json()).then(function(d){
    if(!d||!d.identity){return;}
    var r=d;var id=r.identity||{};var m=r.system_metrics||{};
    var html='<h3>'+id.hostname+' ('+r.agent_id+')</h3>';
    html+='<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">';
    html+='<div><b style="color:var(--dim);font-size:.75rem">PLATFORM</b><br>'+id.platform_os+'</div>';
    html+='<div><b style="color:var(--dim);font-size:.75rem">LOCAL IP</b><br><span style="font-family:monospace">'+(r.local_ip||'-')+'</span></div>';
    html+='<div><b style="color:var(--dim);font-size:.75rem">SUBNET</b><br><span style="font-family:monospace">'+(r.subnet||'-')+'</span></div>';
    html+='<div><b style="color:var(--dim);font-size:.75rem">GATEWAY</b><br><span style="font-family:monospace">'+(r.gateway||'-')+'</span></div>';
    html+='<div><b style="color:var(--dim);font-size:.75rem">CPU LOAD</b><br>'+(m.cpu_load_1m||'-')+'</div>';
    html+='<div><b style="color:var(--dim);font-size:.75rem">MEMORY</b><br>'+(m.mem_pct?m.mem_pct+'%':'-')+'</div>';
    html+='<div><b style="color:var(--dim);font-size:.75rem">DISK</b><br>'+(m.disk_pct?m.disk_pct+'%':'-')+'</div>';
    html+='<div><b style="color:var(--dim);font-size:.75rem">UPTIME</b><br>'+(m.uptime_hours?m.uptime_hours+'h':'-')+'</div>';
    html+='</div>';
    var nets=r.wifi_networks||[];
    html+='<h3 style="font-size:.9rem;margin:12px 0 8px">&#128225; WiFi Networks ('+nets.length+')</h3>';
    if(nets.length){html+='<div>';nets.forEach(function(n){html+='<span class="wifi-mini">'+(n.ssid||'Hidden')+' ('+n.signal+'dBm)</span>';});html+='</div>';}
    else{html+='<div class="empty">No networks</div>';}
    var hosts=r.discovered_hosts||[];
    html+='<h3 style="font-size:.9rem;margin:12px 0 8px">&#128187; Discovered Hosts ('+hosts.length+')</h3>';
    if(hosts.length){html+='<div>';hosts.forEach(function(h){html+='<span class="host-mini">'+h.ip+(h.hostname?' ('+h.hostname+')':'')+'</span>';});html+='</div>';}
    else{html+='<div class="empty">No hosts</div>';}
    document.getElementById('detailContent').innerHTML=html;
    document.getElementById('overlay').classList.add('show');
  });
}

function drawMap(agents){
  var c=document.getElementById('fleetMap'),ctx=c.getContext('2d');
  var W=c.width=c.parentElement.clientWidth-40,H=c.height=300;
  ctx.clearRect(0,0,W,H);
  if(!agents.length){ctx.fillStyle='#8b949e';ctx.textAlign='center';ctx.font='14px sans-serif';ctx.fillText('No agents deployed',W/2,H/2);return;}
  var cx=W/2,cy=H/2,r=Math.min(W,H)/2-50;
  // Base station center
  ctx.beginPath();ctx.arc(cx,cy,18,0,Math.PI*2);ctx.fillStyle='rgba(88,166,255,.2)';ctx.fill();
  ctx.beginPath();ctx.arc(cx,cy,10,0,Math.PI*2);ctx.fillStyle='#58a6ff';ctx.fill();
  ctx.fillStyle='#fff';ctx.font='bold 8px sans-serif';ctx.textAlign='center';ctx.fillText('BASE',cx,cy+3);
  agents.forEach(function(a,i){
    var ang=(i/agents.length)*Math.PI*2-Math.PI/2;
    var x=cx+r*Math.cos(ang),y=cy+r*Math.sin(ang);
    var col=a.status==='online'?'#3fb950':a.status==='stale'?'#d29922':'#f85149';
    // Line to base
    ctx.beginPath();ctx.moveTo(cx,cy);ctx.lineTo(x,y);
    ctx.strokeStyle=col+'66';ctx.lineWidth=1.5;ctx.setLineDash([4,4]);ctx.stroke();ctx.setLineDash([]);
    // Node
    ctx.beginPath();ctx.arc(x,y,14,0,Math.PI*2);ctx.fillStyle=a.status==='online'?'rgba(63,185,80,.15)':'rgba(248,81,73,.1)';ctx.fill();
    ctx.beginPath();ctx.arc(x,y,8,0,Math.PI*2);ctx.fillStyle=col;ctx.fill();
    // Label
    ctx.fillStyle='#c9d1d9';ctx.font='10px sans-serif';ctx.textAlign='center';
    ctx.fillText(a.label||a.agent_id,x,y+22);
    ctx.fillStyle='#8b949e';ctx.font='9px monospace';
    ctx.fillText(a.local_ip||'',x,y+33);
  });
}

async function load(){
  try{
    var r=await fetch('/api/fleet/list');var agents=await r.json();
    var kr=await fetch('/api/fleet/key');var kd=await kr.json();
    document.getElementById('fleetKey').textContent=kd.key||'N/A';
    document.getElementById('kT').textContent=agents.length;
    var on=0,st=0,of=0,tw=0,th=0;
    agents.forEach(function(a){
      if(a.status==='online')on++;else if(a.status==='stale')st++;else of++;
      tw+=a.wifi_count||0;th+=a.host_count||0;
    });
    document.getElementById('kOn').textContent=on;
    document.getElementById('kSt').textContent=st;
    document.getElementById('kOf').textContent=of;
    document.getElementById('kWi').textContent=tw;
    document.getElementById('kHo').textContent=th;
    document.getElementById('count').textContent=agents.length+' Agent'+(agents.length!==1?'s':'');
    var el=document.getElementById('agents');
    if(!agents.length){el.innerHTML='<div class="empty" style="grid-column:1/-1">No agents deployed. Deploy a probe to get started.</div>';}
    else{
      el.innerHTML=agents.map(function(a){
        var ago=a.seconds_ago<60?a.seconds_ago+'s ago':a.seconds_ago<3600?Math.floor(a.seconds_ago/60)+'m ago':Math.floor(a.seconds_ago/3600)+'h ago';
        return '<div class="agent-card '+a.status+'" onclick="showAgent(&apos;'+a.agent_id+'&apos;)">'+
          '<div class="hdr"><div class="name"><span class="status-dot '+a.status+'"></span>'+a.label+'</div>'+
          '<span style="font-size:.72rem;padding:2px 8px;border-radius:8px;background:rgba('+(a.status==='online'?'63,185,80':a.status==='stale'?'210,153,34':'248,81,73')+',.15);color:var(--'+(a.status==='online'?'green':a.status==='stale'?'yellow':'red')+')">'+a.status.toUpperCase()+'</span></div>'+
          '<div class="id">'+a.agent_id+'</div>'+
          '<div class="stats" style="margin-top:8px">'+
            '<div>IP: <span>'+(a.local_ip||'-')+'</span></div>'+
            '<div>Subnet: <span>'+(a.subnet||'-')+'</span></div>'+
            '<div>WiFi: <span>'+a.wifi_count+'</span></div>'+
            '<div>Hosts: <span>'+a.host_count+'</span></div>'+
            '<div>Reports: <span>'+a.report_count+'</span></div>'+
            '<div>Seen: <span>'+ago+'</span></div>'+
          '</div></div>';
      }).join('');
    }
    drawMap(agents);
    document.getElementById('ts').textContent=new Date().toLocaleTimeString()+' | Auto 5s';
  }catch(e){console.error(e);}
}
load();setInterval(load,5000);
</script></body></html>'''


def get_fleet_page(nonce: str) -> str:
    """Return the fleet dashboard HTML with nonce substituted."""
    return _TMPL_FLEET.replace("{{NONCE}}", nonce)
