# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Dashboard — web-based interface for network visualisation.

Provides a lightweight async HTTP dashboard for:
- Real-time network topology visualisation
- System health monitoring
- Finding / alert browsing
- Task management

Built on aiohttp for minimal dependencies. In production, front this
with a proper reverse proxy (nginx / caddy).
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

from network_guardian.core.events import Event, EventBus
from network_guardian.interface._controls import inject_controls
from network_guardian.interface._security import (
    TeamStore, create_session_token, verify_session_token,
    sanitize_data, get_login_page,
)
from network_guardian.interface._fleet import FleetStore, get_fleet_page
from network_guardian.interface._wolfpak_store import WolfpakClientStore
from network_guardian.ai.ethics import transparency_meta as _ethics_transparency_meta, check_confidence as _ethics_check_confidence

import ipaddress
import os

if TYPE_CHECKING:
    from network_guardian.core.engine import Engine

logger = logging.getLogger("network_guardian.interface.dashboard")

_CONTENT_TEXT = "text/plain"


# ---------------------------------------------------------------------------
# HTML page templates (module-level constants — avoids f-string brace issues)
# ---------------------------------------------------------------------------

_TMPL_INDEX = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet"><title>Network Guardian</title><style nonce="{{NONCE}}">\n:root{--bg:#000810;--bg2:#010d1a;--card:rgba(0,18,36,0.92);--border:rgba(0,200,255,0.15);--text:#cce8ff;\n  --dim:#3d7a9a;--blue:#0094d4;--green:#00ff88;--yellow:#ffcc00;\n  --orange:#ff8c00;--red:#ff2244;--purple:#aa44ff;--cyan:#00d4ff;--pink:#ff00aa}\n@keyframes scan-h{0%{left:-100%;opacity:0}50%{opacity:1}100%{left:100%;opacity:0}}\n@keyframes pulse-glow{0%,100%{opacity:.5}50%{opacity:1}}\n@keyframes hud-boot{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}\n@keyframes spin{to{transform:rotate(360deg)}}\n*{margin:0;padding:0;box-sizing:border-box}\nbody{background:var(--bg);background-image:radial-gradient(ellipse at 20% 50%,rgba(0,212,255,.04) 0%,transparent 50%),radial-gradient(ellipse at 80% 20%,rgba(0,100,255,.05) 0%,transparent 50%),linear-gradient(rgba(0,200,255,.015) 1px,transparent 1px),linear-gradient(90deg,rgba(0,200,255,.015) 1px,transparent 1px);background-size:auto,auto,50px 50px,50px 50px;color:var(--text);font-family:\'Rajdhani\',\'Segoe UI\',sans-serif;overflow-x:hidden}\n.wrap{max-width:1400px;margin:0 auto;padding:20px}\n.banner{display:flex;align-items:center;gap:16px;padding:16px 24px;background:linear-gradient(135deg,rgba(0,20,40,.97),rgba(0,8,20,.99));border:1px solid rgba(0,200,255,.22);border-radius:4px;margin-bottom:20px;flex-wrap:wrap;position:relative;overflow:hidden}\n.banner::before{content:\'\';position:absolute;top:0;left:-100%;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan-h 5s ease-in-out infinite}\n.banner h1{font-size:1.4rem;white-space:nowrap;font-family:\'Orbitron\',sans-serif;letter-spacing:3px;color:var(--cyan);text-shadow:0 0 20px rgba(0,212,255,.5)}\n.badge{padding:4px 12px;clip-path:polygon(6px 0%,100% 0%,calc(100% - 6px) 100%,0% 100%);border-radius:0;font-size:.75rem;font-weight:700;letter-spacing:.5px;font-family:\'Share Tech Mono\',monospace}\n.nav{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}\n.nav a{padding:8px 18px;clip-path:polygon(8px 0%,100% 0%,calc(100% - 8px) 100%,0% 100%);border-radius:0;border:1px solid rgba(0,200,255,.2);background:rgba(0,15,30,.7);color:var(--cyan);text-decoration:none;font-size:.72rem;font-family:\'Orbitron\',sans-serif;letter-spacing:1.5px;text-transform:uppercase;cursor:pointer;transition:.2s}\n.nav a:hover{background:rgba(0,212,255,.15);box-shadow:0 0 15px rgba(0,212,255,.25);color:#fff}\n.nav a.active{background:rgba(0,212,255,.18);border-color:var(--cyan);box-shadow:0 0 20px rgba(0,212,255,.3);color:var(--cyan)}\n.grid{display:grid;gap:16px}\n.g2{grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}\n.card{background:linear-gradient(135deg,rgba(0,22,44,.9),rgba(0,8,22,.95));border:1px solid rgba(0,200,255,.15);border-radius:4px;padding:20px;position:relative;box-shadow:0 0 25px rgba(0,212,255,.04),inset 0 1px 0 rgba(0,212,255,.08)}\n.card::before{content:\'\';position:absolute;top:-1px;left:-1px;width:18px;height:18px;border-top:2px solid var(--cyan);border-left:2px solid var(--cyan);box-shadow:-2px -2px 8px rgba(0,212,255,.3)}\n.card::after{content:\'\';position:absolute;bottom:-1px;right:-1px;width:18px;height:18px;border-bottom:2px solid var(--cyan);border-right:2px solid var(--cyan);box-shadow:2px 2px 8px rgba(0,212,255,.3)}\n.card h2{font-size:.85rem;font-family:\'Orbitron\',sans-serif;color:var(--cyan);text-transform:uppercase;letter-spacing:2px;margin-bottom:14px;text-shadow:0 0 15px rgba(0,212,255,.4)}\ntable{width:100%;border-collapse:collapse;font-size:.82rem}\nth{text-align:left;font-family:\'Share Tech Mono\',monospace;color:var(--cyan);text-transform:uppercase;font-size:.68rem;letter-spacing:1.2px;padding:8px 6px;background:rgba(0,212,255,.05);border-bottom:1px solid rgba(0,200,255,.25)}\ntd{font-family:\'Share Tech Mono\',monospace;font-size:.8rem;padding:8px 6px;border-bottom:1px solid rgba(0,200,255,.06)}\ntr:hover td{background:rgba(0,212,255,.04)}\ncanvas{display:block}\n.kpi-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}\n.kpi{background:linear-gradient(135deg,rgba(0,20,40,.8),rgba(0,10,25,.85));border:1px solid rgba(0,200,255,.15);border-radius:4px;padding:14px 20px;min-width:130px;flex:1;position:relative;overflow:hidden}\n.kpi::after{content:\'\';position:absolute;bottom:0;left:-100%;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan-h 4s ease-in-out infinite alternate}\n.kpi .v{font-size:1.8rem;font-weight:700;font-family:\'Orbitron\',sans-serif;color:var(--cyan);text-shadow:0 0 15px rgba(0,212,255,.5)}\n.kpi .l{font-size:.65rem;font-family:\'Share Tech Mono\',monospace;color:var(--dim);text-transform:uppercase;letter-spacing:1px}\n.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.7rem;font-weight:600}\n.sev-critical{background:rgba(255,34,68,.15);color:var(--red);box-shadow:0 0 8px rgba(255,34,68,.2)}\n.sev-high{background:rgba(255,140,0,.15);color:var(--orange);box-shadow:0 0 8px rgba(255,140,0,.2)}\n.sev-medium{background:rgba(255,204,0,.15);color:var(--yellow)}\n.sev-low{background:rgba(0,255,136,.15);color:var(--green);box-shadow:0 0 8px rgba(0,255,136,.2)}\n.empty{color:var(--dim);font-style:normal;font-family:\'Share Tech Mono\',monospace;letter-spacing:1px;padding:20px;text-align:center}\n\n.radar-wrap{position:relative;width:120px;height:120px;margin-right:20px}\n.cap-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}\n.cap-tile{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px;position:relative;transition:.2s}\n.cap-tile:hover{border-color:var(--blue);transform:translateY(-2px)}\n.cap-tile .icon{font-size:1.6rem;margin-bottom:6px}\n.cap-tile .name{font-weight:700;font-size:.9rem}\n.cap-tile .sub{color:var(--dim);font-size:.75rem;margin-top:2px}\n.cap-tile .led{position:absolute;top:10px;right:10px;width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green)}\n.cap-tile .bar{height:4px;border-radius:2px;margin-top:8px;background:var(--border);overflow:hidden}\n.cap-tile .bar .fill{height:100%;border-radius:2px;transition:width .5s}\n.evt{display:flex;gap:8px;padding:6px 0;border-bottom:1px solid rgba(48,54,61,.3);font-size:.8rem}\n.evt:last-child{border-bottom:none}\n.evt .time{color:var(--dim);min-width:80px}\n.evt .topic{color:var(--blue);font-family:monospace;font-size:.75rem}\n</style></head><body>\n<div class="wrap">\n  <div class="banner">\n    <canvas id="radar" width="100" height="100" style="border-radius:50%"></canvas>\n    <h1>&#128737; Network Guardian</h1>\n    <span id="engSt" style="margin-left:12px"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green);margin-right:6px"></span>Engine Active</span>\n    <span id="threat" class="badge" style="background:rgba(63,185,80,.15);color:var(--green)">Threat: LOW</span>\n    <span id="clock" style="margin-left:auto;color:var(--dim);font-size:.85rem"></span>\n  </div>\n  <div class="kpi-row">\n    <div class="kpi"><div class="v" id="kH">0</div><div class="l">Hosts</div></div>\n    <div class="kpi"><div class="v" id="kA">0</div><div class="l">IDS Alerts</div></div>\n    <div class="kpi"><div class="v" id="kB">0</div><div class="l">IPS Blocks</div></div>\n    <div class="kpi"><div class="v" id="kF">0</div><div class="l">Findings</div></div>\n    <div class="kpi"><div class="v" id="kR">0</div><div class="l">IDS Rules</div></div>\n    <div class="kpi"><div class="v" id="kE">0</div><div class="l">Events</div></div>\n  </div>\n<div class="nav"><a href="/" class="active">Dashboard</a><a href="/ids">IDS</a><a href="/ips">IPS</a><a href="/wifi">WiFi</a><a href="/cloaking">Cloaking</a><a href="/explorer">Explorer</a><a href="/auditor">Auditor</a><a href="/ai">AI Engine</a><a href="/fleet">Fleet</a><a href="/reports">Reports</a><a href="/incidents">Incidents</a></div>\n  <div class="grid g2">\n    <div class="card" style="grid-column:1/-1">\n      <h2>&#9889; Active Capabilities</h2>\n      <div id="caps" class="cap-grid"></div>\n    </div>\n    <div class="card"><h2>&#9889; Live Event Stream</h2><div id="evts" style="max-height:300px;overflow-y:auto"></div></div>\n    <div class="card"><h2>&#128270; Security Findings</h2><div id="finds"></div></div>\n  </div>\n</div>\n<script nonce="{{NONCE}}">\n// Radar animation\n(function(){\n  const c=document.getElementById(\'radar\'),ctx=c.getContext(\'2d\');\n  let angle=0;\n  function draw(){\n    const W=c.width,H=c.height,cx=W/2,cy=H/2,r=W/2-4;\n    ctx.clearRect(0,0,W,H);\n    ctx.beginPath();ctx.arc(cx,cy,r,0,Math.PI*2);ctx.fillStyle=\'#000810\';ctx.fill();\n    ctx.strokeStyle=\'rgba(0,200,255,0.12)\';ctx.lineWidth=1;\n    [.33,.66,1].forEach(f=>{ctx.beginPath();ctx.arc(cx,cy,r*f,0,Math.PI*2);ctx.stroke();});\n    ctx.beginPath();ctx.moveTo(cx,cy-r);ctx.lineTo(cx,cy+r);ctx.stroke();\n    ctx.beginPath();ctx.moveTo(cx-r,cy);ctx.lineTo(cx+r,cy);ctx.stroke();\n    const grd=ctx.createConicalGradient?null:null;\n    ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,r,angle-0.5,angle);ctx.closePath();\n    const g=ctx.createRadialGradient(cx,cy,0,cx,cy,r);\n    g.addColorStop(0,\'rgba(0,255,136,.5)\');g.addColorStop(1,\'transparent\');\n    ctx.fillStyle=g;ctx.fill();\n    ctx.beginPath();ctx.moveTo(cx,cy);\n    ctx.lineTo(cx+r*Math.cos(angle),cy+r*Math.sin(angle));\n    ctx.shadowBlur=8;ctx.shadowColor=\'#00ff88\';\n    ctx.strokeStyle=\'#00ff88\';ctx.lineWidth=2;ctx.stroke();ctx.shadowBlur=0;\n    angle+=0.03;\n    requestAnimationFrame(draw);\n  }\n  draw();\n})();\n\nasync function load(){\n  try{\n    const [stR,evR,fR,hR,idR,ipR]=await Promise.all([\n      fetch(\'/api/status\'),fetch(\'/api/events\'),fetch(\'/api/findings\'),\n      fetch(\'/api/hosts\'),fetch(\'/api/ids/stats\'),fetch(\'/api/ips/stats\')\n    ]);\n    const st=await stR.json(),ev=await evR.json(),fi=await fR.json(),\n          ho=await hR.json(),ids=await idR.json(),ips=await ipR.json();\n    const hc=Object.keys(ho).length;\n    document.getElementById(\'kH\').textContent=hc;\n    document.getElementById(\'kA\').textContent=ids.total_alerts||0;\n    document.getElementById(\'kB\').textContent=ips.blocked_ips||0;\n    document.getElementById(\'kF\').textContent=fi.length;\n    document.getElementById(\'kR\').textContent=ids.rules_loaded||0;\n    document.getElementById(\'kE\').textContent=ev.length;\n    document.getElementById(\'clock\').textContent=new Date().toLocaleTimeString();\n    // Threat level\n    const t=document.getElementById(\'threat\');\n    const al=ids.total_alerts||0;\n    if((ids.by_severity||{}).critical){t.textContent=\'Threat: CRITICAL\';t.style.background=\'rgba(248,81,73,.15)\';t.style.color=\'var(--red)\';}\n    else if((ids.by_severity||{}).high){t.textContent=\'Threat: HIGH\';t.style.background=\'rgba(219,109,40,.15)\';t.style.color=\'var(--orange)\';}\n    else if(al>0){t.textContent=\'Threat: MEDIUM\';t.style.background=\'rgba(210,153,34,.15)\';t.style.color=\'var(--yellow)\';}\n    else{t.textContent=\'Threat: LOW\';t.style.background=\'rgba(63,185,80,.15)\';t.style.color=\'var(--green)\';}\n    // Capabilities\n    const caps=[\n      {icon:\'&#128272;\',name:\'Intrusion Detection\',sub:(ids.rules_loaded||0)+\' rules, \'+(ids.total_alerts||0)+\' alerts\',pct:ids.rules_loaded?100:30,color:\'var(--blue)\'},\n      {icon:\'&#128737;\',name:\'Intrusion Prevention\',sub:ips.running===false?\'Standby\':\'Active\',pct:ips.running===false?20:100,color:\'var(--red)\'},\n      {icon:\'&#128225;\',name:\'WiFi Scanner\',sub:\'system_profiler SPAirPort\',pct:80,color:\'var(--green)\'},\n      {icon:\'&#129302;\',name:\'AI / Anomaly\',sub:\'ML + NLP + Forecasting\',pct:70,color:\'var(--purple)\'},\n      {icon:\'&#128270;\',name:\'Auditor\',sub:\'CVSS / OWASP scanning\',pct:60,color:\'var(--orange)\'},\n      {icon:\'&#127760;\',name:\'Network Explorer\',sub:hc+\' hosts discovered\',pct:hc?100:40,color:\'var(--cyan)\'}\n    ];\n    document.getElementById(\'caps\').innerHTML=caps.map(c=>\n      \'<div class="cap-tile"><div class="led"></div><div class="icon">\'+c.icon+\'</div><div class="name">\'+c.name+\'</div><div class="sub">\'+c.sub+\'</div><div class="bar"><div class="fill" style="width:\'+c.pct+\'%;background:\'+c.color+\'"></div></div></div>\'\n    ).join(\'\');\n    // Events\n    const eEl=document.getElementById(\'evts\');\n    if(!ev.length){eEl.innerHTML=\'<div class="empty">No events yet</div>\';}\n    else{eEl.innerHTML=ev.slice(-20).reverse().map(e=>\'<div class="evt"><span class="time">\'+new Date(e.timestamp).toLocaleTimeString()+\'</span><span class="topic">\'+e.topic+\'</span></div>\').join(\'\');}\n    // Findings\n    const fEl=document.getElementById(\'finds\');\n    if(!fi.length){fEl.innerHTML=\'<div class="empty">No findings - system clean</div>\';}\n    else{fEl.innerHTML=fi.slice(-10).map(f=>\'<div style="padding:6px 0;border-bottom:1px solid rgba(48,54,61,.3);font-size:.82rem">\'+(f.title||f.description||\'Finding\')+\'</div>\').join(\'\');}\n  }catch(e){console.error(e);}\n}\nload();setInterval(load,5000);\n</script></body></html>'

_TMPL_IDS = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet"><title>IDS Monitor - Network Guardian</title><style nonce="{{NONCE}}">\n:root{--bg:#000810;--bg2:#010d1a;--card:rgba(0,18,36,0.92);--border:rgba(0,200,255,0.15);--text:#cce8ff;\n  --dim:#3d7a9a;--blue:#0094d4;--green:#00ff88;--yellow:#ffcc00;\n  --orange:#ff8c00;--red:#ff2244;--purple:#aa44ff;--cyan:#00d4ff;--pink:#ff00aa}\n@keyframes scan-h{0%{left:-100%;opacity:0}50%{opacity:1}100%{left:100%;opacity:0}}\n@keyframes pulse-glow{0%,100%{opacity:.5}50%{opacity:1}}\n@keyframes hud-boot{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}\n@keyframes spin{to{transform:rotate(360deg)}}\n*{margin:0;padding:0;box-sizing:border-box}\nbody{background:var(--bg);background-image:radial-gradient(ellipse at 20% 50%,rgba(0,212,255,.04) 0%,transparent 50%),radial-gradient(ellipse at 80% 20%,rgba(0,100,255,.05) 0%,transparent 50%),linear-gradient(rgba(0,200,255,.015) 1px,transparent 1px),linear-gradient(90deg,rgba(0,200,255,.015) 1px,transparent 1px);background-size:auto,auto,50px 50px,50px 50px;color:var(--text);font-family:\'Rajdhani\',\'Segoe UI\',sans-serif;overflow-x:hidden}\n.wrap{max-width:1400px;margin:0 auto;padding:20px}\n.banner{display:flex;align-items:center;gap:16px;padding:16px 24px;background:linear-gradient(135deg,rgba(0,20,40,.97),rgba(0,8,20,.99));border:1px solid rgba(0,200,255,.22);border-radius:4px;margin-bottom:20px;flex-wrap:wrap;position:relative;overflow:hidden}\n.banner::before{content:\'\';position:absolute;top:0;left:-100%;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan-h 5s ease-in-out infinite}\n.banner h1{font-size:1.4rem;white-space:nowrap;font-family:\'Orbitron\',sans-serif;letter-spacing:3px;color:var(--cyan);text-shadow:0 0 20px rgba(0,212,255,.5)}\n.badge{padding:4px 12px;clip-path:polygon(6px 0%,100% 0%,calc(100% - 6px) 100%,0% 100%);border-radius:0;font-size:.75rem;font-weight:700;letter-spacing:.5px;font-family:\'Share Tech Mono\',monospace}\n.nav{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}\n.nav a{padding:8px 18px;clip-path:polygon(8px 0%,100% 0%,calc(100% - 8px) 100%,0% 100%);border-radius:0;border:1px solid rgba(0,200,255,.2);background:rgba(0,15,30,.7);color:var(--cyan);text-decoration:none;font-size:.72rem;font-family:\'Orbitron\',sans-serif;letter-spacing:1.5px;text-transform:uppercase;cursor:pointer;transition:.2s}\n.nav a:hover{background:rgba(0,212,255,.15);box-shadow:0 0 15px rgba(0,212,255,.25);color:#fff}\n.nav a.active{background:rgba(0,212,255,.18);border-color:var(--cyan);box-shadow:0 0 20px rgba(0,212,255,.3);color:var(--cyan)}\n.grid{display:grid;gap:16px}\n.g2{grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}\n.card{background:linear-gradient(135deg,rgba(0,22,44,.9),rgba(0,8,22,.95));border:1px solid rgba(0,200,255,.15);border-radius:4px;padding:20px;position:relative;box-shadow:0 0 25px rgba(0,212,255,.04),inset 0 1px 0 rgba(0,212,255,.08)}\n.card::before{content:\'\';position:absolute;top:-1px;left:-1px;width:18px;height:18px;border-top:2px solid var(--cyan);border-left:2px solid var(--cyan);box-shadow:-2px -2px 8px rgba(0,212,255,.3)}\n.card::after{content:\'\';position:absolute;bottom:-1px;right:-1px;width:18px;height:18px;border-bottom:2px solid var(--cyan);border-right:2px solid var(--cyan);box-shadow:2px 2px 8px rgba(0,212,255,.3)}\n.card h2{font-size:.85rem;font-family:\'Orbitron\',sans-serif;color:var(--cyan);text-transform:uppercase;letter-spacing:2px;margin-bottom:14px;text-shadow:0 0 15px rgba(0,212,255,.4)}\ntable{width:100%;border-collapse:collapse;font-size:.82rem}\nth{text-align:left;font-family:\'Share Tech Mono\',monospace;color:var(--cyan);text-transform:uppercase;font-size:.68rem;letter-spacing:1.2px;padding:8px 6px;background:rgba(0,212,255,.05);border-bottom:1px solid rgba(0,200,255,.25)}\ntd{font-family:\'Share Tech Mono\',monospace;font-size:.8rem;padding:8px 6px;border-bottom:1px solid rgba(0,200,255,.06)}\ntr:hover td{background:rgba(0,212,255,.04)}\ncanvas{display:block}\n.kpi-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}\n.kpi{background:linear-gradient(135deg,rgba(0,20,40,.8),rgba(0,10,25,.85));border:1px solid rgba(0,200,255,.15);border-radius:4px;padding:14px 20px;min-width:130px;flex:1;position:relative;overflow:hidden}\n.kpi::after{content:\'\';position:absolute;bottom:0;left:-100%;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan-h 4s ease-in-out infinite alternate}\n.kpi .v{font-size:1.8rem;font-weight:700;font-family:\'Orbitron\',sans-serif;color:var(--cyan);text-shadow:0 0 15px rgba(0,212,255,.5)}\n.kpi .l{font-size:.65rem;font-family:\'Share Tech Mono\',monospace;color:var(--dim);text-transform:uppercase;letter-spacing:1px}\n.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.7rem;font-weight:600}\n.sev-critical{background:rgba(255,34,68,.15);color:var(--red);box-shadow:0 0 8px rgba(255,34,68,.2)}\n.sev-high{background:rgba(255,140,0,.15);color:var(--orange);box-shadow:0 0 8px rgba(255,140,0,.2)}\n.sev-medium{background:rgba(255,204,0,.15);color:var(--yellow)}\n.sev-low{background:rgba(0,255,136,.15);color:var(--green);box-shadow:0 0 8px rgba(0,255,136,.2)}\n.empty{color:var(--dim);font-style:normal;font-family:\'Share Tech Mono\',monospace;letter-spacing:1px;padding:20px;text-align:center}\n\n.sev-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:4px}\n.rule-row{display:flex;align-items:center;gap:10px;padding:8px;border-bottom:1px solid rgba(48,54,61,.3);font-size:.82rem}\n.alert-row{display:flex;gap:8px;padding:10px;border-left:3px solid var(--border);margin-bottom:6px;font-size:.82rem;background:rgba(22,27,34,.5);border-radius:0 8px 8px 0}\n.alert-row.sev-critical{border-left-color:var(--red)}\n.alert-row.sev-high{border-left-color:var(--orange)}\n.alert-row.sev-medium{border-left-color:var(--yellow)}\n.alert-row.sev-low{border-left-color:var(--green)}\n</style></head><body>\n<div class="wrap">\n  <div class="banner">\n    <h1>&#128272; IDS Monitor</h1>\n    <span id="st" class="badge" style="background:rgba(88,166,255,.15);color:var(--blue)">Loading</span>\n    <span id="ts" style="margin-left:auto;color:var(--dim);font-size:.85rem"></span>\n  </div>\n  <div class="kpi-row">\n    <div class="kpi"><div class="v" id="kA">0</div><div class="l">Total Alerts</div></div>\n    <div class="kpi"><div class="v" id="kC" style="color:var(--red)">0</div><div class="l">Critical</div></div>\n    <div class="kpi"><div class="v" id="kH" style="color:var(--orange)">0</div><div class="l">High</div></div>\n    <div class="kpi"><div class="v" id="kM" style="color:var(--yellow)">0</div><div class="l">Medium</div></div>\n    <div class="kpi"><div class="v" id="kR">0</div><div class="l">Rules Loaded</div></div>\n  </div>\n<div class="nav"><a href="/">Dashboard</a><a href="/ids" class="active">IDS</a><a href="/ips">IPS</a><a href="/wifi">WiFi</a><a href="/cloaking">Cloaking</a><a href="/explorer">Explorer</a><a href="/auditor">Auditor</a><a href="/ai">AI Engine</a><a href="/fleet">Fleet</a><a href="/reports">Reports</a><a href="/incidents">Incidents</a></div>\n  <div class="grid g2">\n    <div class="card"><h2>&#128200; Severity Distribution</h2><canvas id="sevChart" height="200"></canvas></div>\n    <div class="card"><h2>&#128202; Detection Methods</h2><canvas id="methChart" height="200"></canvas></div>\n    <div class="card" style="grid-column:1/-1"><h2>&#128196; Signature Rules</h2><div id="rules" style="max-height:300px;overflow-y:auto"></div></div>\n    <div class="card" style="grid-column:1/-1"><h2>&#9888; Alert Feed</h2><div id="alerts"></div></div>\n  </div>\n</div>\n<script nonce="{{NONCE}}">\nfunction drawDonut(vals,colors,labels){\n  const c=document.getElementById(\'sevChart\'),ctx=c.getContext(\'2d\');\n  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;\n  ctx.clearRect(0,0,W,H);\n  const total=Object.values(vals).reduce((a,b)=>a+b,0);\n  if(!total){ctx.fillStyle=\'#8b949e\';ctx.textAlign=\'center\';ctx.fillText(\'No alerts\',W/2,H/2);return;}\n  const cx=90,cy=H/2,r=75;\n  let angle=-Math.PI/2;\n  const entries=Object.entries(vals).filter(e=>e[1]>0);\n  entries.forEach(([k,v])=>{\n    const slice=v/total*Math.PI*2;\n    ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,r,angle,angle+slice);ctx.closePath();\n    ctx.fillStyle=colors[k]||\'#8b949e\';ctx.fill();\n    angle+=slice;\n  });\n  ctx.beginPath();ctx.arc(cx,cy,45,0,Math.PI*2);ctx.fillStyle=\'#161b22\';ctx.fill();\n  ctx.fillStyle=\'#c9d1d9\';ctx.font=\'bold 18px sans-serif\';ctx.textAlign=\'center\';ctx.fillText(total,cx,cy+6);\n  let ly=20;\n  entries.forEach(([k,v])=>{\n    ctx.fillStyle=colors[k]||\'#8b949e\';ctx.fillRect(W-150,ly,10,10);\n    ctx.fillStyle=\'#c9d1d9\';ctx.font=\'12px sans-serif\';ctx.textAlign=\'left\';\n    ctx.fillText(k+\' (\'+v+\')\',W-134,ly+9);ly+=20;\n  });\n}\nfunction drawMethods(vals){\n  const c=document.getElementById(\'methChart\'),ctx=c.getContext(\'2d\');\n  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;\n  ctx.clearRect(0,0,W,H);\n  const entries=Object.entries(vals||{});\n  if(!entries.length){ctx.fillStyle=\'#8b949e\';ctx.textAlign=\'center\';ctx.fillText(\'No data\',W/2,H/2);return;}\n  const max=Math.max(...entries.map(e=>e[1]));\n  const barH=Math.min(30,(H-20)/entries.length-8);\n  const colors={\'signature\':\'#58a6ff\',\'anomaly\':\'#bc8cff\',\'heuristic\':\'#d29922\',\'correlation\':\'#39d2e0\'};\n  entries.forEach(([k,v],i)=>{\n    const y=20+i*(barH+8);\n    const w=(v/max)*(W-140);\n    ctx.fillStyle=\'#8b949e\';ctx.font=\'11px sans-serif\';ctx.textAlign=\'right\';ctx.fillText(k,100,y+barH/2+4);\n    const grd=ctx.createLinearGradient(110,y,110+w,y);\n    grd.addColorStop(0,colors[k]||\'#58a6ff\');grd.addColorStop(1,(colors[k]||\'#58a6ff\')+\'44\');\n    ctx.fillStyle=grd;ctx.beginPath();ctx.roundRect(110,y,w,barH,4);ctx.fill();\n    ctx.fillStyle=\'#c9d1d9\';ctx.font=\'bold 11px sans-serif\';ctx.textAlign=\'left\';ctx.fillText(v,114+w,y+barH/2+4);\n  });\n}\nasync function load(){\n  try{\n    const [sR,aR,rR]=await Promise.all([fetch(\'/api/ids/stats\'),fetch(\'/api/ids/alerts\'),fetch(\'/api/ids/rules\')]);\n    const s=await sR.json(),alerts=await aR.json(),rules=await rR.json();\n    document.getElementById(\'kA\').textContent=s.total_alerts||0;\n    document.getElementById(\'kC\').textContent=(s.by_severity||{}).critical||0;\n    document.getElementById(\'kH\').textContent=(s.by_severity||{}).high||0;\n    document.getElementById(\'kM\').textContent=(s.by_severity||{}).medium||0;\n    document.getElementById(\'kR\').textContent=s.rules_loaded||0;\n    const badge=document.getElementById(\'st\');\n    if(s.running===false){badge.textContent=\'NOT RUNNING\';badge.style.color=\'var(--red)\';}\n    else{badge.textContent=(s.total_alerts||0)+\' Alerts\';badge.style.color=s.total_alerts?\'var(--orange)\':\'var(--green)\';}\n    const sevC={critical:\'#f85149\',high:\'#db6d28\',medium:\'#d29922\',low:\'#3fb950\',info:\'#58a6ff\'};\n    drawDonut(s.by_severity||{},sevC);\n    drawMethods(s.by_method||{});\n    // Rules\n    const rEl=document.getElementById(\'rules\');\n    if(!rules.length){rEl.innerHTML=\'<div class="empty">No rules loaded</div>\';}\n    else{rEl.innerHTML=rules.map(r=>\'<div class="rule-row"><span class="sev-dot" style="background:\'+(sevC[r.severity]||\'#8b949e\')+\'"></span><span style="font-family:monospace;min-width:50px;color:var(--dim)">\'+r.sid+\'</span><span style="flex:1;font-weight:600">\'+r.name+\'</span><span class="pill sev-\'+r.severity+\'">\'+r.severity.toUpperCase()+\'</span><span style="color:var(--dim);font-size:.75rem;min-width:80px">\'+r.category+\'</span></div>\').join(\'\');}\n    // Alerts\n    const aEl=document.getElementById(\'alerts\');\n    if(!alerts.length){aEl.innerHTML=\'<div class="empty">No alerts</div>\';}\n    else{aEl.innerHTML=alerts.slice(-30).reverse().map(a=>\'<div class="alert-row sev-\'+(a.severity||\'info\')+\'"><span style="min-width:80px;color:var(--dim);font-size:.75rem">\'+new Date(a.timestamp).toLocaleTimeString()+\'</span><span style="font-weight:600;min-width:140px">\'+a.rule_name+\'</span><span class="pill sev-\'+(a.severity||\'info\')+\'">\'+(a.severity||\'info\').toUpperCase()+\'</span><span style="color:var(--dim);flex:1">\'+(a.description||\'\')+\'</span></div>\').join(\'\');}\n    document.getElementById(\'ts\').textContent=new Date().toLocaleTimeString()+\' | Auto 3s\';\n  }catch(e){console.error(e);}\n}\nload();setInterval(load,3000);\n</script></body></html>'

_TMPL_IPS = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet"><title>IPS Monitor - Network Guardian</title><style nonce="{{NONCE}}">\n:root{--bg:#000810;--bg2:#010d1a;--card:rgba(0,18,36,0.92);--border:rgba(0,200,255,0.15);--text:#cce8ff;\n  --dim:#3d7a9a;--blue:#0094d4;--green:#00ff88;--yellow:#ffcc00;\n  --orange:#ff8c00;--red:#ff2244;--purple:#aa44ff;--cyan:#00d4ff;--pink:#ff00aa}\n@keyframes scan-h{0%{left:-100%;opacity:0}50%{opacity:1}100%{left:100%;opacity:0}}\n@keyframes pulse-glow{0%,100%{opacity:.5}50%{opacity:1}}\n@keyframes hud-boot{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}\n@keyframes spin{to{transform:rotate(360deg)}}\n*{margin:0;padding:0;box-sizing:border-box}\nbody{background:var(--bg);background-image:radial-gradient(ellipse at 20% 50%,rgba(0,212,255,.04) 0%,transparent 50%),radial-gradient(ellipse at 80% 20%,rgba(0,100,255,.05) 0%,transparent 50%),linear-gradient(rgba(0,200,255,.015) 1px,transparent 1px),linear-gradient(90deg,rgba(0,200,255,.015) 1px,transparent 1px);background-size:auto,auto,50px 50px,50px 50px;color:var(--text);font-family:\'Rajdhani\',\'Segoe UI\',sans-serif;overflow-x:hidden}\n.wrap{max-width:1400px;margin:0 auto;padding:20px}\n.banner{display:flex;align-items:center;gap:16px;padding:16px 24px;background:linear-gradient(135deg,rgba(0,20,40,.97),rgba(0,8,20,.99));border:1px solid rgba(0,200,255,.22);border-radius:4px;margin-bottom:20px;flex-wrap:wrap;position:relative;overflow:hidden}\n.banner::before{content:\'\';position:absolute;top:0;left:-100%;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan-h 5s ease-in-out infinite}\n.banner h1{font-size:1.4rem;white-space:nowrap;font-family:\'Orbitron\',sans-serif;letter-spacing:3px;color:var(--cyan);text-shadow:0 0 20px rgba(0,212,255,.5)}\n.badge{padding:4px 12px;clip-path:polygon(6px 0%,100% 0%,calc(100% - 6px) 100%,0% 100%);border-radius:0;font-size:.75rem;font-weight:700;letter-spacing:.5px;font-family:\'Share Tech Mono\',monospace}\n.nav{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}\n.nav a{padding:8px 18px;clip-path:polygon(8px 0%,100% 0%,calc(100% - 8px) 100%,0% 100%);border-radius:0;border:1px solid rgba(0,200,255,.2);background:rgba(0,15,30,.7);color:var(--cyan);text-decoration:none;font-size:.72rem;font-family:\'Orbitron\',sans-serif;letter-spacing:1.5px;text-transform:uppercase;cursor:pointer;transition:.2s}\n.nav a:hover{background:rgba(0,212,255,.15);box-shadow:0 0 15px rgba(0,212,255,.25);color:#fff}\n.nav a.active{background:rgba(0,212,255,.18);border-color:var(--cyan);box-shadow:0 0 20px rgba(0,212,255,.3);color:var(--cyan)}\n.grid{display:grid;gap:16px}\n.g2{grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}\n.card{background:linear-gradient(135deg,rgba(0,22,44,.9),rgba(0,8,22,.95));border:1px solid rgba(0,200,255,.15);border-radius:4px;padding:20px;position:relative;box-shadow:0 0 25px rgba(0,212,255,.04),inset 0 1px 0 rgba(0,212,255,.08)}\n.card::before{content:\'\';position:absolute;top:-1px;left:-1px;width:18px;height:18px;border-top:2px solid var(--cyan);border-left:2px solid var(--cyan);box-shadow:-2px -2px 8px rgba(0,212,255,.3)}\n.card::after{content:\'\';position:absolute;bottom:-1px;right:-1px;width:18px;height:18px;border-bottom:2px solid var(--cyan);border-right:2px solid var(--cyan);box-shadow:2px 2px 8px rgba(0,212,255,.3)}\n.card h2{font-size:.85rem;font-family:\'Orbitron\',sans-serif;color:var(--cyan);text-transform:uppercase;letter-spacing:2px;margin-bottom:14px;text-shadow:0 0 15px rgba(0,212,255,.4)}\ntable{width:100%;border-collapse:collapse;font-size:.82rem}\nth{text-align:left;font-family:\'Share Tech Mono\',monospace;color:var(--cyan);text-transform:uppercase;font-size:.68rem;letter-spacing:1.2px;padding:8px 6px;background:rgba(0,212,255,.05);border-bottom:1px solid rgba(0,200,255,.25)}\ntd{font-family:\'Share Tech Mono\',monospace;font-size:.8rem;padding:8px 6px;border-bottom:1px solid rgba(0,200,255,.06)}\ntr:hover td{background:rgba(0,212,255,.04)}\ncanvas{display:block}\n.kpi-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}\n.kpi{background:linear-gradient(135deg,rgba(0,20,40,.8),rgba(0,10,25,.85));border:1px solid rgba(0,200,255,.15);border-radius:4px;padding:14px 20px;min-width:130px;flex:1;position:relative;overflow:hidden}\n.kpi::after{content:\'\';position:absolute;bottom:0;left:-100%;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan-h 4s ease-in-out infinite alternate}\n.kpi .v{font-size:1.8rem;font-weight:700;font-family:\'Orbitron\',sans-serif;color:var(--cyan);text-shadow:0 0 15px rgba(0,212,255,.5)}\n.kpi .l{font-size:.65rem;font-family:\'Share Tech Mono\',monospace;color:var(--dim);text-transform:uppercase;letter-spacing:1px}\n.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.7rem;font-weight:600}\n.sev-critical{background:rgba(255,34,68,.15);color:var(--red);box-shadow:0 0 8px rgba(255,34,68,.2)}\n.sev-high{background:rgba(255,140,0,.15);color:var(--orange);box-shadow:0 0 8px rgba(255,140,0,.2)}\n.sev-medium{background:rgba(255,204,0,.15);color:var(--yellow)}\n.sev-low{background:rgba(0,255,136,.15);color:var(--green);box-shadow:0 0 8px rgba(0,255,136,.2)}\n.empty{color:var(--dim);font-style:normal;font-family:\'Share Tech Mono\',monospace;letter-spacing:1px;padding:20px;text-align:center}\n\n.ip-tile{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:10px;font-family:monospace;font-size:.85rem;display:flex;justify-content:space-between;align-items:center}\n</style></head><body>\n<div class="wrap">\n  <div class="banner">\n    <h1>&#128737; IPS Monitor</h1>\n    <span id="st" class="badge" style="background:rgba(88,166,255,.15);color:var(--blue)">Loading</span>\n    <span id="ts" style="margin-left:auto;color:var(--dim);font-size:.85rem"></span>\n  </div>\n  <div class="kpi-row">\n    <div class="kpi"><div class="v" id="kBl" style="color:var(--red)">0</div><div class="l">Blocked IPs</div></div>\n    <div class="kpi"><div class="v" id="kRL" style="color:var(--yellow)">0</div><div class="l">Rate-Limited</div></div>\n    <div class="kpi"><div class="v" id="kQ" style="color:var(--purple)">0</div><div class="l">Quarantined</div></div>\n    <div class="kpi"><div class="v" id="kAl" style="color:var(--green)">0</div><div class="l">Allowlisted</div></div>\n    <div class="kpi"><div class="v" id="kEv" style="color:var(--blue)">0</div><div class="l">Total Events</div></div>\n  </div>\n<div class="nav"><a href="/">Dashboard</a><a href="/ids">IDS</a><a href="/ips" class="active">IPS</a><a href="/wifi">WiFi</a><a href="/cloaking">Cloaking</a><a href="/explorer">Explorer</a><a href="/auditor">Auditor</a><a href="/ai">AI Engine</a><a href="/fleet">Fleet</a><a href="/reports">Reports</a><a href="/incidents">Incidents</a></div>\n  <div class="grid g2">\n    <div class="card"><h2>&#128202; Actions Breakdown</h2><canvas id="actChart" height="200"></canvas></div>\n    <div class="card"><h2>&#128683; Protection Gauge</h2><canvas id="gauge" height="200"></canvas></div>\n    <div class="card"><h2>&#128683; Blocklist</h2><div id="bl" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:6px"></div></div>\n    <div class="card"><h2>&#128337; Rate Limits</h2><div id="rl"></div></div>\n    <div class="card" style="grid-column:1/-1"><h2>&#128196; Event History</h2><div id="hist" style="max-height:300px;overflow-y:auto"></div></div>\n  </div>\n</div>\n<script nonce="{{NONCE}}">\nfunction drawGauge(blocked,total){\n  const c=document.getElementById(\'gauge\'),ctx=c.getContext(\'2d\');\n  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;\n  ctx.clearRect(0,0,W,H);\n  const cx=W/2,cy=H-20,r=80;\n  ctx.beginPath();ctx.arc(cx,cy,r,-Math.PI,0);ctx.strokeStyle=\'#30363d\';ctx.lineWidth=20;ctx.lineCap=\'round\';ctx.stroke();\n  const pct=total?Math.min(1,blocked/Math.max(1,total)):0;\n  const col=pct<0.3?\'#3fb950\':pct<0.6?\'#d29922\':\'#f85149\';\n  if(pct>0){ctx.beginPath();ctx.arc(cx,cy,r,-Math.PI,-Math.PI+pct*Math.PI);ctx.strokeStyle=col;ctx.lineWidth=20;ctx.lineCap=\'round\';ctx.stroke();}\n  ctx.fillStyle=\'#c9d1d9\';ctx.font=\'bold 24px sans-serif\';ctx.textAlign=\'center\';ctx.fillText(blocked,cx,cy-10);\n  ctx.fillStyle=\'#8b949e\';ctx.font=\'11px sans-serif\';ctx.fillText(\'Blocked / \'+total+\' events\',cx,cy+8);\n}\nfunction drawActions(byAction){\n  const c=document.getElementById(\'actChart\'),ctx=c.getContext(\'2d\');\n  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;\n  ctx.clearRect(0,0,W,H);\n  const entries=Object.entries(byAction||{});\n  if(!entries.length){ctx.fillStyle=\'#8b949e\';ctx.textAlign=\'center\';ctx.fillText(\'No data\',W/2,H/2);return;}\n  const max=Math.max(...entries.map(e=>e[1]));\n  const barW=Math.min(50,(W-40)/entries.length-10);\n  const colors={block:\'#f85149\',rate_limit:\'#d29922\',quarantine:\'#bc8cff\',allow:\'#3fb950\',unblock:\'#58a6ff\'};\n  entries.forEach(([k,v],i)=>{\n    const x=30+i*(barW+10);\n    const h=(v/max)*(H-50);\n    const col=colors[k]||\'#58a6ff\';\n    const grd=ctx.createLinearGradient(x,H-30-h,x,H-30);\n    grd.addColorStop(0,col);grd.addColorStop(1,col+\'44\');\n    ctx.fillStyle=grd;ctx.beginPath();ctx.roundRect(x,H-30-h,barW,h,4);ctx.fill();\n    ctx.fillStyle=\'#c9d1d9\';ctx.font=\'bold 10px sans-serif\';ctx.textAlign=\'center\';ctx.fillText(v,x+barW/2,H-34-h);\n    ctx.fillStyle=\'#8b949e\';ctx.font=\'9px sans-serif\';ctx.fillText(k,x+barW/2,H-16);\n  });\n}\nasync function load(){\n  try{\n    const [sR,bR,rR,qR,aR,hR]=await Promise.all([\n      fetch(\'/api/ips/stats\'),fetch(\'/api/ips/blocklist\'),fetch(\'/api/ips/ratelimits\'),\n      fetch(\'/api/ips/quarantine\'),fetch(\'/api/ips/allowlist\'),fetch(\'/api/ips/history\')\n    ]);\n    const s=await sR.json(),bl=await bR.json(),rl=await rR.json(),q=await qR.json(),al=await aR.json(),hist=await hR.json();\n    document.getElementById(\'kBl\').textContent=s.blocked_ips||bl.length||0;\n    document.getElementById(\'kRL\').textContent=s.rate_limited_ips||rl.length||0;\n    document.getElementById(\'kQ\').textContent=s.quarantined_ips||q.length||0;\n    document.getElementById(\'kAl\').textContent=al.length;\n    document.getElementById(\'kEv\').textContent=s.total_events||hist.length||0;\n    const badge=document.getElementById(\'st\');\n    if(s.running===false){badge.textContent=\'NOT RUNNING\';badge.style.color=\'var(--red)\';}\n    else{badge.textContent=\'Active\';badge.style.color=\'var(--green)\';}\n    drawGauge(s.blocked_ips||bl.length||0,s.total_events||hist.length||0);\n    drawActions(s.by_action||{});\n    // Blocklist\n    const bEl=document.getElementById(\'bl\');\n    if(!bl.length){bEl.innerHTML=\'<div class="empty">No blocked IPs</div>\';}\n    else{bEl.innerHTML=bl.map(b=>\'<div class="ip-tile"><span>\'+b.ip+\'</span><span style="color:var(--dim);font-size:.7rem">\'+b.hit_count+\' hits</span></div>\').join(\'\');}\n    // Rate limits\n    const rEl=document.getElementById(\'rl\');\n    if(!rl.length){rEl.innerHTML=\'<div class="empty">No rate limits</div>\';}\n    else{rEl.innerHTML=\'<table><tr><th>IP</th><th>Max RPS</th><th>Tokens</th></tr>\'+rl.map(r=>\'<tr><td style="font-family:monospace">\'+r.ip+\'</td><td>\'+r.max_rps+\'</td><td>\'+r.tokens_remaining+\'</td></tr>\').join(\'\')+\'</table>\';}\n    // History\n    const hEl=document.getElementById(\'hist\');\n    if(!hist.length){hEl.innerHTML=\'<div class="empty">No events</div>\';}\n    else{hEl.innerHTML=\'<table><tr><th>Time</th><th>IP</th><th>Action</th><th>Reason</th></tr>\'+hist.slice(-30).reverse().map(e=>\'<tr><td style="color:var(--dim)">\'+new Date(e.timestamp).toLocaleTimeString()+\'</td><td style="font-family:monospace">\'+e.target_ip+\'</td><td><span class="pill sev-\'+(e.action===\'block\'?\'critical\':\'medium\')+\'">\'+e.action+\'</span></td><td style="color:var(--dim)">\'+e.reason+\'</td></tr>\').join(\'\')+\'</table>\';}\n    document.getElementById(\'ts\').textContent=new Date().toLocaleTimeString()+\' | Auto 3s\';\n  }catch(e){console.error(e);}\n}\nload();setInterval(load,3000);\n</script></body></html>'

_TMPL_WIFI = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet"><title>WiFi Scanner - Network Guardian</title><style nonce="{{NONCE}}">\n:root{--bg:#000810;--bg2:#010d1a;--card:rgba(0,18,36,0.92);--border:rgba(0,200,255,0.15);--text:#cce8ff;\n  --dim:#3d7a9a;--blue:#0094d4;--green:#00ff88;--yellow:#ffcc00;\n  --orange:#ff8c00;--red:#ff2244;--purple:#aa44ff;--cyan:#00d4ff;--pink:#ff00aa}\n@keyframes scan-h{0%{left:-100%;opacity:0}50%{opacity:1}100%{left:100%;opacity:0}}\n@keyframes pulse-glow{0%,100%{opacity:.5}50%{opacity:1}}\n@keyframes hud-boot{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}\n@keyframes spin{to{transform:rotate(360deg)}}\n*{margin:0;padding:0;box-sizing:border-box}\nbody{background:var(--bg);background-image:radial-gradient(ellipse at 20% 50%,rgba(0,212,255,.04) 0%,transparent 50%),radial-gradient(ellipse at 80% 20%,rgba(0,100,255,.05) 0%,transparent 50%),linear-gradient(rgba(0,200,255,.015) 1px,transparent 1px),linear-gradient(90deg,rgba(0,200,255,.015) 1px,transparent 1px);background-size:auto,auto,50px 50px,50px 50px;color:var(--text);font-family:\'Rajdhani\',\'Segoe UI\',sans-serif;overflow-x:hidden}\n.wrap{max-width:1400px;margin:0 auto;padding:20px}\n.banner{display:flex;align-items:center;gap:16px;padding:16px 24px;background:linear-gradient(135deg,rgba(0,20,40,.97),rgba(0,8,20,.99));border:1px solid rgba(0,200,255,.22);border-radius:4px;margin-bottom:20px;flex-wrap:wrap;position:relative;overflow:hidden}\n.banner::before{content:\'\';position:absolute;top:0;left:-100%;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan-h 5s ease-in-out infinite}\n.banner h1{font-size:1.4rem;white-space:nowrap;font-family:\'Orbitron\',sans-serif;letter-spacing:3px;color:var(--cyan);text-shadow:0 0 20px rgba(0,212,255,.5)}\n.badge{padding:4px 12px;clip-path:polygon(6px 0%,100% 0%,calc(100% - 6px) 100%,0% 100%);border-radius:0;font-size:.75rem;font-weight:700;letter-spacing:.5px;font-family:\'Share Tech Mono\',monospace}\n.nav{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}\n.nav a{padding:8px 18px;clip-path:polygon(8px 0%,100% 0%,calc(100% - 8px) 100%,0% 100%);border-radius:0;border:1px solid rgba(0,200,255,.2);background:rgba(0,15,30,.7);color:var(--cyan);text-decoration:none;font-size:.72rem;font-family:\'Orbitron\',sans-serif;letter-spacing:1.5px;text-transform:uppercase;cursor:pointer;transition:.2s}\n.nav a:hover{background:rgba(0,212,255,.15);box-shadow:0 0 15px rgba(0,212,255,.25);color:#fff}\n.nav a.active{background:rgba(0,212,255,.18);border-color:var(--cyan);box-shadow:0 0 20px rgba(0,212,255,.3);color:var(--cyan)}\n.grid{display:grid;gap:16px}\n.g2{grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}\n.card{background:linear-gradient(135deg,rgba(0,22,44,.9),rgba(0,8,22,.95));border:1px solid rgba(0,200,255,.15);border-radius:4px;padding:20px;position:relative;box-shadow:0 0 25px rgba(0,212,255,.04),inset 0 1px 0 rgba(0,212,255,.08)}\n.card::before{content:\'\';position:absolute;top:-1px;left:-1px;width:18px;height:18px;border-top:2px solid var(--cyan);border-left:2px solid var(--cyan);box-shadow:-2px -2px 8px rgba(0,212,255,.3)}\n.card::after{content:\'\';position:absolute;bottom:-1px;right:-1px;width:18px;height:18px;border-bottom:2px solid var(--cyan);border-right:2px solid var(--cyan);box-shadow:2px 2px 8px rgba(0,212,255,.3)}\n.card h2{font-size:.85rem;font-family:\'Orbitron\',sans-serif;color:var(--cyan);text-transform:uppercase;letter-spacing:2px;margin-bottom:14px;text-shadow:0 0 15px rgba(0,212,255,.4)}\ntable{width:100%;border-collapse:collapse;font-size:.82rem}\nth{text-align:left;font-family:\'Share Tech Mono\',monospace;color:var(--cyan);text-transform:uppercase;font-size:.68rem;letter-spacing:1.2px;padding:8px 6px;background:rgba(0,212,255,.05);border-bottom:1px solid rgba(0,200,255,.25)}\ntd{font-family:\'Share Tech Mono\',monospace;font-size:.8rem;padding:8px 6px;border-bottom:1px solid rgba(0,200,255,.06)}\ntr:hover td{background:rgba(0,212,255,.04)}\ncanvas{display:block}\n.kpi-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}\n.kpi{background:linear-gradient(135deg,rgba(0,20,40,.8),rgba(0,10,25,.85));border:1px solid rgba(0,200,255,.15);border-radius:4px;padding:14px 20px;min-width:130px;flex:1;position:relative;overflow:hidden}\n.kpi::after{content:\'\';position:absolute;bottom:0;left:-100%;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan-h 4s ease-in-out infinite alternate}\n.kpi .v{font-size:1.8rem;font-weight:700;font-family:\'Orbitron\',sans-serif;color:var(--cyan);text-shadow:0 0 15px rgba(0,212,255,.5)}\n.kpi .l{font-size:.65rem;font-family:\'Share Tech Mono\',monospace;color:var(--dim);text-transform:uppercase;letter-spacing:1px}\n.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.7rem;font-weight:600}\n.sev-critical{background:rgba(255,34,68,.15);color:var(--red);box-shadow:0 0 8px rgba(255,34,68,.2)}\n.sev-high{background:rgba(255,140,0,.15);color:var(--orange);box-shadow:0 0 8px rgba(255,140,0,.2)}\n.sev-medium{background:rgba(255,204,0,.15);color:var(--yellow)}\n.sev-low{background:rgba(0,255,136,.15);color:var(--green);box-shadow:0 0 8px rgba(0,255,136,.2)}\n.empty{color:var(--dim);font-style:normal;font-family:\'Share Tech Mono\',monospace;letter-spacing:1px;padding:20px;text-align:center}\n\n.wifi-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px;display:flex;gap:14px;align-items:center;transition:.2s}\n.wifi-card:hover{border-color:var(--blue);transform:translateY(-2px)}\n.wifi-info{flex:1}\n.wifi-info .ssid{font-weight:600;font-size:.95rem}\n.wifi-info .meta{color:var(--dim);font-size:.75rem;margin-top:2px}\n.signal-bar{height:6px;border-radius:3px;background:var(--border);margin-top:6px;overflow:hidden}\n.signal-bar .fill{height:100%;border-radius:3px;transition:width .4s}\n.conn-tag{background:var(--green);color:#000;font-size:.65rem;font-weight:700;padding:2px 8px;border-radius:8px}\n</style></head><body>\n<div class="wrap">\n  <div class="banner">\n    <h1>&#128225; WiFi Scanner</h1>\n    <span id="st" class="badge" style="background:rgba(88,166,255,.15);color:var(--blue)">Scanning</span>\n    <span id="ts" style="margin-left:auto;color:var(--dim);font-size:.85rem"></span>\n  </div>\n  <div class="kpi-row">\n    <div class="kpi"><div class="v" id="kN">-</div><div class="l">Networks</div></div>\n    <div class="kpi"><div class="v" id="kC">-</div><div class="l">Connected To</div></div>\n    <div class="kpi"><div class="v" id="kS">-</div><div class="l">Signal</div></div>\n    <div class="kpi"><div class="v" id="kCh">-</div><div class="l">Channel</div></div>\n    <div class="kpi"><div class="v" id="kSec">-</div><div class="l">Security Types</div></div>\n    <div class="kpi"><div class="v" id="kSc">-</div><div class="l">Scans</div></div>\n  </div>\n<div class="nav"><a href="/">Dashboard</a><a href="/ids">IDS</a><a href="/ips">IPS</a><a href="/wifi" class="active">WiFi</a><a href="/cloaking">Cloaking</a><a href="/explorer">Explorer</a><a href="/auditor">Auditor</a><a href="/ai">AI Engine</a><a href="/fleet">Fleet</a><a href="/reports">Reports</a><a href="/incidents">Incidents</a></div>\n  <div class="grid g2">\n    <div class="card"><h2>&#128225; Signal Strength</h2><canvas id="sigChart" height="200"></canvas></div>\n    <div class="card"><h2>&#128274; Security Breakdown</h2><canvas id="secChart" height="200"></canvas></div>\n    <div class="card"><h2>&#128246; Frequency Bands</h2><canvas id="freqChart" height="180"></canvas></div>\n    <div class="card"><h2>&#128752; Connected Network</h2><div id="connInfo" class="empty">Scanning...</div></div>\n    <div class="card" style="grid-column:1/-1"><h2>&#128225; Discovered Networks</h2><div id="netList" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px"></div></div>\n  </div>\n</div>\n<script nonce="{{NONCE}}">\nfunction sigColor(s){return s>=-50?\'#3fb950\':s>=-65?\'#58a6ff\':s>=-75?\'#d29922\':\'#f85149\';}\nfunction secColor(s){if(!s||s===\'Open\')return\'#f85149\';if(s.includes(\'WPA3\'))return\'#3fb950\';if(s.includes(\'WPA2\'))return\'#58a6ff\';if(s.includes(\'WPA\'))return\'#d29922\';return\'#db6d28\';}\nfunction drawSig(nets){\n  const c=document.getElementById(\'sigChart\'),ctx=c.getContext(\'2d\');\n  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;\n  ctx.clearRect(0,0,W,H);\n  if(!nets.length){ctx.fillStyle=\'#8b949e\';ctx.textAlign=\'center\';ctx.fillText(\'No networks\',W/2,H/2);return;}\n  const sorted=[...nets].sort((a,b)=>b.signal-a.signal);\n  const bw=Math.min(40,Math.max(12,(W-20)/sorted.length-4));\n  sorted.forEach((n,i)=>{\n    const x=10+i*(bw+4), pct=(n.signal+100)/100, h=pct*(H-40), col=sigColor(n.signal);\n    const g=ctx.createLinearGradient(x,H-20-h,x,H-20);g.addColorStop(0,col);g.addColorStop(1,col+\'44\');\n    ctx.fillStyle=g;ctx.beginPath();ctx.roundRect(x,H-20-h,bw,h,4);ctx.fill();\n    ctx.fillStyle=\'#c9d1d9\';ctx.font=\'bold 9px sans-serif\';ctx.textAlign=\'center\';ctx.fillText(n.signal+\'dBm\',x+bw/2,H-24-h);\n    ctx.save();ctx.translate(x+bw/2,H-8);ctx.rotate(-0.5);ctx.fillStyle=\'#8b949e\';ctx.font=\'8px sans-serif\';ctx.textAlign=\'right\';\n    ctx.fillText((n.ssid||\'Hidden\').slice(0,12),0,0);ctx.restore();\n  });\n}\nfunction drawSec(nets){\n  const c=document.getElementById(\'secChart\'),ctx=c.getContext(\'2d\');\n  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;\n  ctx.clearRect(0,0,W,H);\n  const types={};\n  nets.forEach(n=>{const s=n.security||\'Open\';const k=s.includes(\'WPA3\')?\'WPA3\':s.includes(\'WPA2\')?\'WPA2\':s.includes(\'WPA\')?\'WPA\':s.includes(\'WEP\')?\'WEP\':\'Open\';types[k]=(types[k]||0)+1;});\n  const entries=Object.entries(types).sort((a,b)=>b[1]-a[1]);\n  if(!entries.length){ctx.fillStyle=\'#8b949e\';ctx.textAlign=\'center\';ctx.fillText(\'No data\',W/2,H/2);return;}\n  const total=nets.length,cx=90,cy=H/2,r=70;\n  const colors={WPA3:\'#3fb950\',WPA2:\'#58a6ff\',WPA:\'#d29922\',WEP:\'#db6d28\',Open:\'#f85149\'};\n  let angle=-Math.PI/2;\n  entries.forEach(([k,v])=>{const sl=v/total*Math.PI*2;ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,r,angle,angle+sl);ctx.closePath();ctx.fillStyle=colors[k]||\'#bc8cff\';ctx.fill();angle+=sl;});\n  ctx.beginPath();ctx.arc(cx,cy,40,0,Math.PI*2);ctx.fillStyle=\'#161b22\';ctx.fill();\n  ctx.fillStyle=\'#c9d1d9\';ctx.font=\'bold 14px sans-serif\';ctx.textAlign=\'center\';ctx.fillText(total,cx,cy+5);\n  let ly=20;entries.forEach(([k,v])=>{ctx.fillStyle=colors[k]||\'#bc8cff\';ctx.fillRect(W-160,ly,10,10);ctx.fillStyle=\'#c9d1d9\';ctx.font=\'12px sans-serif\';ctx.textAlign=\'left\';ctx.fillText(k+\' (\'+v+\')\',W-144,ly+9);ly+=20;});\n}\nfunction drawFreq(nets){\n  const c=document.getElementById(\'freqChart\'),ctx=c.getContext(\'2d\');\n  const W=c.width=c.parentElement.clientWidth-40,H=c.height=180;\n  ctx.clearRect(0,0,W,H);\n  let b24=0,b5=0;nets.forEach(n=>{const ch=n.channel||0;if(ch<=14)b24++;else b5++;});\n  const data=[[\'2.4 GHz\',b24,\'#58a6ff\'],[\'5 GHz\',b5,\'#bc8cff\']];\n  const total=Math.max(1,b24+b5),barH=36,gap=20,sy=(H-2*barH-gap)/2;\n  data.forEach(([label,count,col],i)=>{\n    const y=sy+i*(barH+gap),w=Math.max(4,(count/total)*(W-140));\n    ctx.fillStyle=\'#30363d\';ctx.beginPath();ctx.roundRect(120,y,W-140,barH,6);ctx.fill();\n    const g=ctx.createLinearGradient(120,y,120+w,y);g.addColorStop(0,col);g.addColorStop(1,col+\'66\');\n    ctx.fillStyle=g;ctx.beginPath();ctx.roundRect(120,y,w,barH,6);ctx.fill();\n    ctx.fillStyle=\'#c9d1d9\';ctx.font=\'bold 13px sans-serif\';ctx.textAlign=\'right\';ctx.fillText(label,108,y+barH/2+4);\n    ctx.fillStyle=\'#fff\';ctx.font=\'bold 13px sans-serif\';ctx.textAlign=\'left\';ctx.fillText(count+\' (\'+(count/total*100|0)+\'%)\',w>50?124:126+w,y+barH/2+4);\n  });\n}\nasync function load(){\n  try{\n    const [wR,sR]=await Promise.all([fetch(\'/api/wifi/networks\'),fetch(\'/api/wifi/status\')]);\n    const nets=await wR.json(),st=await sR.json();\n    document.getElementById(\'kN\').textContent=nets.length;\n    document.getElementById(\'kSc\').textContent=st.scans||0;\n    const conn=st.connected;\n    const _ssid=conn?(conn.ssid||\'-\'):\'-\';const _ssidShort=_ssid.length>12?_ssid.slice(0,11)+\'…\':_ssid;document.getElementById(\'kC\').textContent=_ssidShort;document.getElementById(\'kC\').style.fontSize=_ssid.length>8?\'1rem\':\'1.6rem\';\n    document.getElementById(\'kS\').textContent=conn?(conn.signal+\' dBm\'):\'-\';\n    document.getElementById(\'kCh\').textContent=conn?(conn.channel||\'-\'):\'-\';\n    document.getElementById(\'kSec\').textContent=new Set(nets.map(n=>n.security||\'Open\')).size;\n    document.getElementById(\'st\').textContent=nets.length?nets.length+\' Networks\':\'Idle\';\n    document.getElementById(\'st\').style.color=nets.length?\'var(--green)\':\'var(--blue)\';\n    if(conn){document.getElementById(\'connInfo\').innerHTML=\'<div style="display:flex;align-items:center;gap:12px"><span style="font-size:2rem">&#128225;</span><div><div style="font-size:1.1rem;font-weight:700">\'+(conn.ssid||\'Hidden\')+\' <span class="conn-tag">CONNECTED</span></div><div style="color:var(--dim);font-size:.82rem;margin-top:4px">BSSID: \'+(conn.bssid||\'-\')+\' | Ch \'+(conn.channel||\'-\')+\' | Signal: <span style="color:\'+sigColor(conn.signal||0)+\'">\'+(conn.signal||\'-\')+\' dBm</span> | \'+(conn.security||\'-\')+\'</div></div></div>\';}\n    else{document.getElementById(\'connInfo\').innerHTML=\'<div class="empty">Not connected</div>\';}\n    drawSig(nets);drawSec(nets);drawFreq(nets);\n    // Network list\n    const el=document.getElementById(\'netList\');\n    if(!nets.length){el.innerHTML=\'<div class="empty">No networks</div>\';}\n    else{el.innerHTML=[...nets].sort((a,b)=>b.signal-a.signal).map(n=>{\n      const pct=Math.max(0,Math.min(100,(n.signal+100))),col=sigColor(n.signal),isC=conn&&n.ssid===conn.ssid;\n      return \'<div class="wifi-card\'+(isC?\' style="border-color:var(--green)"\':\'\')+\'"><span style="font-size:1.6rem">\'+(n.hidden?\'&#128683;\':\'&#128225;\')+\'</span><div class="wifi-info"><div class="ssid">\'+(n.ssid||\'[Hidden]\')+(isC?\' <span class="conn-tag">CONNECTED</span>\':\'\')+\'</div><div class="meta">BSSID: \'+(n.bssid||\'-\')+\' | Ch \'+(n.channel||\'-\')+\' | \'+(n.frequency||\'-\')+\'</div><div class="signal-bar"><div class="fill" style="width:\'+pct+\'%;background:\'+col+\'"></div></div><div style="display:flex;justify-content:space-between;margin-top:4px;font-size:.7rem"><span style="color:\'+col+\'">\'+n.signal+\' dBm (\'+pct+\'%)</span><span style="padding:2px 6px;border-radius:6px;font-size:.65rem;background:\'+secColor(n.security)+\'22;color:\'+secColor(n.security)+\'">\'+(n.security||\'Open\')+\'</span></div></div></div>\';\n    }).join(\'\');}\n    document.getElementById(\'ts\').textContent=new Date().toLocaleTimeString()+\' | Auto 5s\';\n  }catch(e){console.error(e);}\n}\nload();setInterval(load,5000);\n</script></body></html>'

_TMPL_CLOAKING = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet"><title>IP Cloaking - Network Guardian</title><style nonce="{{NONCE}}">\n:root{--bg:#000810;--bg2:#010d1a;--card:rgba(0,18,36,0.92);--border:rgba(0,200,255,0.15);--text:#cce8ff;\n  --dim:#3d7a9a;--blue:#0094d4;--green:#00ff88;--yellow:#ffcc00;\n  --orange:#ff8c00;--red:#ff2244;--purple:#aa44ff;--cyan:#00d4ff;--pink:#ff00aa}\n@keyframes scan-h{0%{left:-100%;opacity:0}50%{opacity:1}100%{left:100%;opacity:0}}\n@keyframes pulse-glow{0%,100%{opacity:.5}50%{opacity:1}}\n@keyframes hud-boot{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}\n@keyframes spin{to{transform:rotate(360deg)}}\n*{margin:0;padding:0;box-sizing:border-box}\nbody{background:var(--bg);background-image:radial-gradient(ellipse at 20% 50%,rgba(0,212,255,.04) 0%,transparent 50%),radial-gradient(ellipse at 80% 20%,rgba(0,100,255,.05) 0%,transparent 50%),linear-gradient(rgba(0,200,255,.015) 1px,transparent 1px),linear-gradient(90deg,rgba(0,200,255,.015) 1px,transparent 1px);background-size:auto,auto,50px 50px,50px 50px;color:var(--text);font-family:\'Rajdhani\',\'Segoe UI\',sans-serif;overflow-x:hidden}\n.wrap{max-width:1400px;margin:0 auto;padding:20px}\n.banner{display:flex;align-items:center;gap:16px;padding:16px 24px;background:linear-gradient(135deg,rgba(0,20,40,.97),rgba(0,8,20,.99));border:1px solid rgba(0,200,255,.22);border-radius:4px;margin-bottom:20px;flex-wrap:wrap;position:relative;overflow:hidden}\n.banner::before{content:\'\';position:absolute;top:0;left:-100%;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan-h 5s ease-in-out infinite}\n.banner h1{font-size:1.4rem;white-space:nowrap;font-family:\'Orbitron\',sans-serif;letter-spacing:3px;color:var(--cyan);text-shadow:0 0 20px rgba(0,212,255,.5)}\n.badge{padding:4px 12px;clip-path:polygon(6px 0%,100% 0%,calc(100% - 6px) 100%,0% 100%);border-radius:0;font-size:.75rem;font-weight:700;letter-spacing:.5px;font-family:\'Share Tech Mono\',monospace}\n.nav{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}\n.nav a{padding:8px 18px;clip-path:polygon(8px 0%,100% 0%,calc(100% - 8px) 100%,0% 100%);border-radius:0;border:1px solid rgba(0,200,255,.2);background:rgba(0,15,30,.7);color:var(--cyan);text-decoration:none;font-size:.72rem;font-family:\'Orbitron\',sans-serif;letter-spacing:1.5px;text-transform:uppercase;cursor:pointer;transition:.2s}\n.nav a:hover{background:rgba(0,212,255,.15);box-shadow:0 0 15px rgba(0,212,255,.25);color:#fff}\n.nav a.active{background:rgba(0,212,255,.18);border-color:var(--cyan);box-shadow:0 0 20px rgba(0,212,255,.3);color:var(--cyan)}\n.grid{display:grid;gap:16px}\n.g2{grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}\n.card{background:linear-gradient(135deg,rgba(0,22,44,.9),rgba(0,8,22,.95));border:1px solid rgba(0,200,255,.15);border-radius:4px;padding:20px;position:relative;box-shadow:0 0 25px rgba(0,212,255,.04),inset 0 1px 0 rgba(0,212,255,.08)}\n.card::before{content:\'\';position:absolute;top:-1px;left:-1px;width:18px;height:18px;border-top:2px solid var(--cyan);border-left:2px solid var(--cyan);box-shadow:-2px -2px 8px rgba(0,212,255,.3)}\n.card::after{content:\'\';position:absolute;bottom:-1px;right:-1px;width:18px;height:18px;border-bottom:2px solid var(--cyan);border-right:2px solid var(--cyan);box-shadow:2px 2px 8px rgba(0,212,255,.3)}\n.card h2{font-size:.85rem;font-family:\'Orbitron\',sans-serif;color:var(--cyan);text-transform:uppercase;letter-spacing:2px;margin-bottom:14px;text-shadow:0 0 15px rgba(0,212,255,.4)}\ntable{width:100%;border-collapse:collapse;font-size:.82rem}\nth{text-align:left;font-family:\'Share Tech Mono\',monospace;color:var(--cyan);text-transform:uppercase;font-size:.68rem;letter-spacing:1.2px;padding:8px 6px;background:rgba(0,212,255,.05);border-bottom:1px solid rgba(0,200,255,.25)}\ntd{font-family:\'Share Tech Mono\',monospace;font-size:.8rem;padding:8px 6px;border-bottom:1px solid rgba(0,200,255,.06)}\ntr:hover td{background:rgba(0,212,255,.04)}\ncanvas{display:block}\n.kpi-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}\n.kpi{background:linear-gradient(135deg,rgba(0,20,40,.8),rgba(0,10,25,.85));border:1px solid rgba(0,200,255,.15);border-radius:4px;padding:14px 20px;min-width:130px;flex:1;position:relative;overflow:hidden}\n.kpi::after{content:\'\';position:absolute;bottom:0;left:-100%;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan-h 4s ease-in-out infinite alternate}\n.kpi .v{font-size:1.8rem;font-weight:700;font-family:\'Orbitron\',sans-serif;color:var(--cyan);text-shadow:0 0 15px rgba(0,212,255,.5)}\n.kpi .l{font-size:.65rem;font-family:\'Share Tech Mono\',monospace;color:var(--dim);text-transform:uppercase;letter-spacing:1px}\n.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.7rem;font-weight:600}\n.sev-critical{background:rgba(255,34,68,.15);color:var(--red);box-shadow:0 0 8px rgba(255,34,68,.2)}\n.sev-high{background:rgba(255,140,0,.15);color:var(--orange);box-shadow:0 0 8px rgba(255,140,0,.2)}\n.sev-medium{background:rgba(255,204,0,.15);color:var(--yellow)}\n.sev-low{background:rgba(0,255,136,.15);color:var(--green);box-shadow:0 0 8px rgba(0,255,136,.2)}\n.empty{color:var(--dim);font-style:normal;font-family:\'Share Tech Mono\',monospace;letter-spacing:1px;padding:20px;text-align:center}\n\n.mode-row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}\n.mode-chip{padding:10px 20px;border-radius:10px;border:2px solid var(--border);background:var(--card);text-align:center;min-width:100px;transition:.2s}\n.mode-chip.active{border-color:var(--green);background:rgba(63,185,80,.1);box-shadow:0 0 12px rgba(63,185,80,.2)}\n.mode-chip .ic{font-size:1.4rem}\n.mode-chip .lb{font-size:.75rem;text-transform:uppercase;letter-spacing:.5px}\n.id-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;transition:.2s}\n.id-card.active{border-color:var(--cyan);box-shadow:0 0 12px rgba(57,210,224,.15)}\n.id-card .nm{font-weight:700;font-size:1rem;margin-bottom:6px}\n.id-card .dt{color:var(--dim);font-size:.78rem;line-height:1.6}\n.proxy-hop{display:flex;align-items:center;gap:12px;padding:10px;border:1px solid var(--border);border-radius:8px;margin-bottom:6px}\n</style></head><body>\n<div class="wrap">\n  <div class="banner">\n    <h1>&#128373; IP Cloaking</h1>\n    <span id="ml" class="badge" style="background:rgba(188,140,255,.15);color:var(--purple)">-</span>\n    <span id="ts" style="margin-left:auto;color:var(--dim);font-size:.85rem"></span>\n  </div>\n  <div class="kpi-row">\n    <div class="kpi"><div class="v" id="kMode">-</div><div class="l">Mode</div></div>\n    <div class="kpi"><div class="v" id="kMask">0</div><div class="l">IPs Masked</div></div>\n    <div class="kpi"><div class="v" id="kRot">0</div><div class="l">Rotated</div></div>\n    <div class="kpi"><div class="v" id="kDec">0</div><div class="l">Decoys</div></div>\n    <div class="kpi"><div class="v" id="kPrx">0</div><div class="l">Proxy Hops</div></div>\n    <div class="kpi"><div class="v" id="kId">0</div><div class="l">Identities</div></div>\n  </div>\n<div class="nav"><a href="/">Dashboard</a><a href="/ids">IDS</a><a href="/ips">IPS</a><a href="/wifi">WiFi</a><a href="/cloaking" class="active">Cloaking</a><a href="/explorer">Explorer</a><a href="/auditor">Auditor</a><a href="/ai">AI Engine</a><a href="/fleet">Fleet</a><a href="/reports">Reports</a><a href="/incidents">Incidents</a></div>\n  <div id="modes" class="mode-row"></div>\n  <div class="grid g2">\n    <div class="card"><h2>&#128200; Activity</h2><canvas id="actChart" height="200"></canvas></div>\n    <div class="card"><h2>&#128279; Proxy Chain (Live Hops)</h2><div id="proxies"><div class="empty">Starting agent...</div></div></div>\n    <div class="card" style="grid-column:1/-1"><h2>&#129504; ReAct Agent Log</h2><div id="react" style="max-height:260px;overflow-y:auto;font-size:.8rem"></div></div>\n    <div class="card"><h2>&#127760; Network Intelligence</h2><div id="netinfo"></div></div>\n    <div class="card"><h2>&#128218; Learned Networks</h2><div id="learned"></div></div>\n    <div class="card" style="grid-column:1/-1"><h2>&#128100; Identities</h2><div id="ids" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px"></div></div>\n    <div class="card"><h2>&#127760; Source Pool</h2><div id="pool"></div></div>\n    <div class="card"><h2>&#128736; Masker Stats</h2><div id="masker"></div></div>\n  </div>\n</div>\n<script nonce="{{NONCE}}">\nconst MODES=[\'disabled\',\'mask\',\'rotate\',\'proxy\',\'decoy\',\'full\'];\nconst ICONS={disabled:\'&#128683;\',mask:\'&#127917;\',rotate:\'&#128260;\',proxy:\'&#128279;\',decoy:\'&#128038;\',full:\'&#128737;\'};\nconst MCOL={disabled:\'var(--dim)\',mask:\'var(--blue)\',rotate:\'var(--cyan)\',proxy:\'var(--purple)\',decoy:\'var(--orange)\',full:\'var(--green)\'};\nlet hist=[];\nfunction drawAct(d){\n  hist.push({m:d.masked_ips||0,r:d.rotated_sources||0,d:d.decoys_generated||0});\n  if(hist.length>30)hist=hist.slice(-30);\n  const c=document.getElementById(\'actChart\'),ctx=c.getContext(\'2d\');\n  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;\n  ctx.clearRect(0,0,W,H);\n  if(hist.length<2){ctx.fillStyle=\'#8b949e\';ctx.textAlign=\'center\';ctx.fillText(\'Collecting...\',W/2,H/2);return;}\n  const pad=40,series=[{k:\'m\',c:\'#58a6ff\',l:\'Masked\'},{k:\'r\',c:\'#39d2e0\',l:\'Rotated\'},{k:\'d\',c:\'#db6d28\',l:\'Decoys\'}];\n  const max=Math.max(1,...hist.flatMap(h=>series.map(s=>h[s.k])));\n  series.forEach(s=>{\n    ctx.beginPath();ctx.strokeStyle=s.c;ctx.lineWidth=2;\n    hist.forEach((h,i)=>{const x=pad+i*(W-pad-10)/(hist.length-1),y=H-pad-(h[s.k]/max)*(H-pad*2);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});\n    ctx.stroke();\n  });\n  let lx=pad;series.forEach(s=>{ctx.fillStyle=s.c;ctx.fillRect(lx,H-12,8,8);ctx.fillStyle=\'#c9d1d9\';ctx.font=\'10px sans-serif\';ctx.textAlign=\'left\';ctx.fillText(s.l,lx+12,H-4);lx+=70;});\n}\nasync function setMode(m){\n  try{\n    const r=await fetch(\'/api/control/cloaking/mode\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\',\'X-Requested-With\':\'XMLHttpRequest\'},body:JSON.stringify({mode:m})});\n    if(m!==\'disabled\'){await fetch(\'/api/control/cloaking/start\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\',\'X-Requested-With\':\'XMLHttpRequest\'},body:\'{}\'});}\n    else{await fetch(\'/api/control/cloaking/stop\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\',\'X-Requested-With\':\'XMLHttpRequest\'},body:\'{}\'});}\n    load();\n  }catch(e){console.error(e);}\n}\nasync function activateId(name){\n  try{\n    await fetch(\'/api/control/cloaking/activate\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\',\'X-Requested-With\':\'XMLHttpRequest\'},body:JSON.stringify({name:name})});\n    load();\n  }catch(e){console.error(e);}\n}\nasync function load(){\n  try{\n    const r=await fetch(\'/api/cloaking/status\');const d=await r.json();\n    const mode=d.mode||\'disabled\';\n    document.getElementById(\'kMode\').textContent=mode.toUpperCase();document.getElementById(\'kMode\').style.color=MCOL[mode]||\'var(--dim)\';\n    document.getElementById(\'kMask\').textContent=d.masked_ips||0;document.getElementById(\'kRot\').textContent=d.rotated_sources||0;\n    document.getElementById(\'kDec\').textContent=d.decoys_generated||0;document.getElementById(\'kPrx\').textContent=d.proxy_chain_length||0;\n    document.getElementById(\'kId\').textContent=d.identities_count||0;\n    document.getElementById(\'ml\').textContent=mode.toUpperCase();\n    document.getElementById(\'modes\').innerHTML=MODES.map(m=>\'<div class="mode-chip \'+(m===mode?\'active\':\'\')+\'" onclick="setMode(\\x27\'+m+\'\\x27)" style="cursor:pointer"><div class="ic">\'+ICONS[m]+\'</div><div class="lb" style="color:\'+(m===mode?MCOL[m]:\'var(--dim)\')+\'">\'+m+\'</div></div>\').join(\'\');\n    drawAct(d);\n    // Proxies\n    const pEl=document.getElementById(\'proxies\');\n    const chain=d.proxy_chain||[];\n    if(!chain.length){pEl.innerHTML=\'<div class="empty">No proxy chain</div>\';}\n    else{pEl.innerHTML=chain.map((p,i)=>\'<div class="proxy-hop"><span style="width:10px;height:10px;border-radius:50%;background:\'+(p.is_alive?\'var(--green)\':\'var(--red)\')+\'"></span><span style="color:var(--dim);font-size:.75rem">Hop \'+(i+1)+\'</span><span style="font-family:monospace;font-size:.85rem">\'+p.host+\':\'+p.port+\'</span><span style="font-size:.7rem;padding:2px 6px;border-radius:4px;background:rgba(88,166,255,.15);color:var(--blue)">\'+p.protocol+\'</span></div>\').join(\'\');}\n    // Identities\n    const iEl=document.getElementById(\'ids\');\n    const ids=d.identities||[];\n    if(!ids.length){iEl.innerHTML=\'<div class="empty">No identities</div>\';}\n    else{iEl.innerHTML=ids.map(id=>\'<div class="id-card \'+(id.name===d.active_identity?\'active\':\'\')+\'" onclick="activateId(\\x27\'+id.name+\'\\x27)" style="cursor:pointer"><div class="nm">\'+(id.name===d.active_identity?\'&#9733; \':\'\')+id.name+\'</div><div class="dt">Mode: <span style="color:\'+(MCOL[id.mode]||\'var(--dim)\')+\'">\'+id.mode+\'</span><br>Sources: \'+(id.source_ips?id.source_ips.length:0)+\' IPs<br>Proxies: \'+(id.proxy_chain?id.proxy_chain.length:0)+\' hops</div></div>\').join(\'\');}\n    // Source pool\n    const pool=d.source_pool||[];\n    document.getElementById(\'pool\').innerHTML=pool.length?pool.map(ip=>\'<span style="display:inline-block;padding:4px 10px;margin:3px;border-radius:6px;background:rgba(57,210,224,.1);border:1px solid var(--border);font-family:monospace;font-size:.82rem">\'+ip+\'</span>\').join(\'\'):\'<div class="empty">Empty pool</div>\';\n    // Masker\n    document.getElementById(\'masker\').innerHTML=\'<div style="display:grid;gap:8px"><div style="display:flex;justify-content:space-between"><span style="color:var(--dim)">Mappings</span><span>\'+(d.mapping_count||0)+\'</span></div><div style="display:flex;justify-content:space-between"><span style="color:var(--dim)">Masked</span><span style="color:var(--blue)">\'+(d.masked_ips||0)+\'</span></div><div style="display:flex;justify-content:space-between"><span style="color:var(--dim)">Rotated</span><span style="color:var(--cyan)">\'+(d.rotated_sources||0)+\'</span></div><div style="display:flex;justify-content:space-between"><span style="color:var(--dim)">Decoys</span><span style="color:var(--orange)">\'+(d.decoys_generated||0)+\'</span></div></div>\';\n    // ReAct agent data\n    const ra=d.react_agent||{};\n    const obs=ra.last_observation;\n    if(obs){\n      document.getElementById(\'netinfo\').innerHTML=\'<div style="display:grid;gap:6px;font-size:.82rem"><div style="display:flex;justify-content:space-between"><span style="color:var(--dim)">Local IP</span><span style="font-family:monospace">\'+obs.local_ip+\'</span></div><div style="display:flex;justify-content:space-between"><span style="color:var(--dim)">Gateway</span><span style="font-family:monospace">\'+obs.gateway_ip+\'</span></div><div style="display:flex;justify-content:space-between"><span style="color:var(--dim)">Public IP</span><span style="font-family:monospace">\'+obs.public_ip+\'</span></div><div style="display:flex;justify-content:space-between"><span style="color:var(--dim)">SSID</span><span style="color:var(--green)">\'+obs.ssid+\'</span></div><div style="display:flex;justify-content:space-between"><span style="color:var(--dim)">Network Type</span><span style="color:var(--cyan);text-transform:uppercase;font-weight:700;font-size:.75rem">\'+obs.network_type+\'</span></div><div style="display:flex;justify-content:space-between"><span style="color:var(--dim)">Interface</span><span>\'+obs.interface+\'</span></div><div style="display:flex;justify-content:space-between"><span style="color:var(--dim)">Gateway Latency</span><span>\'+(obs.latency_gateway_ms>=0?obs.latency_gateway_ms+\' ms\':\'N/A\')+\'</span></div><div style="display:flex;justify-content:space-between"><span style="color:var(--dim)">Internet Latency</span><span>\'+(obs.latency_internet_ms>=0?obs.latency_internet_ms+\' ms\':\'N/A\')+\'</span></div><div style="display:flex;justify-content:space-between"><span style="color:var(--dim)">Live Hops</span><span style="color:var(--blue)">\'+obs.hop_count+\'</span></div><div style="display:flex;justify-content:space-between"><span style="color:var(--dim)">DNS</span><span style="font-family:monospace;font-size:.75rem">\'+(obs.dns_servers||[]).join(\', \')+\'</span></div></div>\';\n    }else{\n      document.getElementById(\'netinfo\').innerHTML=\'<div class="empty">Agent not started — click a mode above</div>\';\n    }\n    // Fetch ReAct log\n    try{\n      const rr=await fetch(\'/api/cloaking/react\');const rd=await rr.json();\n      const log=rd.log||[];\n      const PCOL={observe:\'var(--blue)\',reason:\'var(--yellow)\',act:\'var(--green)\',learn:\'var(--purple)\'};\n      const PICON={observe:\'&#128065;\',reason:\'&#129504;\',act:\'&#9889;\',learn:\'&#128218;\'};\n      if(log.length){\n        document.getElementById(\'react\').innerHTML=log.slice(-15).reverse().map(s=>\'<div style="padding:6px 10px;border-left:3px solid \'+(PCOL[s.phase]||\'var(--dim)\')+\';margin-bottom:4px;background:rgba(22,27,34,.8);border-radius:0 6px 6px 0"><span style="font-size:.7rem;color:\'+(PCOL[s.phase]||\'var(--dim)\')+\';font-weight:700;text-transform:uppercase">\'+PICON[s.phase]+\' \'+s.phase+\'</span><span style="color:var(--dim);font-size:.65rem;margin-left:8px">\'+s.timestamp.slice(11,19)+\'</span><div style="margin-top:2px;color:var(--text)">\'+s.thought+\'</div></div>\').join(\'\');\n      }else{\n        document.getElementById(\'react\').innerHTML=\'<div class="empty">No ReAct steps yet</div>\';\n      }\n      // Learned networks\n      const nr=await fetch(\'/api/cloaking/networks\');const nd=await nr.json();\n      const profiles=nd.profiles||[];\n      if(profiles.length){\n        document.getElementById(\'learned\').innerHTML=profiles.map(p=>\'<div style="padding:8px;border:1px solid var(--border);border-radius:8px;margin-bottom:6px"><div style="display:flex;justify-content:space-between;align-items:center"><span style="font-weight:700;color:var(--cyan)">\'+p.network_type.toUpperCase()+\'</span><span class="pill" style="background:rgba(\'+(p.threat_score>.5?\'248,81,73\':p.threat_score>.3?\'210,153,34\':\'63,185,80\')+",.15);color:"+(p.threat_score>.5?"var(--red)":p.threat_score>.3?"var(--yellow)":"var(--green)")+\'">Threat: \'+(p.threat_score*100).toFixed(0)+\'%</span></div><div style="color:var(--dim);font-size:.75rem;margin-top:4px">Seen \'+p.times_connected+\'x | \'+p.avg_hop_count+\' avg hops | GW: \'+p.avg_gateway_latency+\'ms | Net: \'+p.avg_internet_latency+\'ms</div><div style="color:var(--dim);font-size:.7rem;margin-top:2px;font-style:italic">\'+((p.notes&&p.notes.length)?p.notes[p.notes.length-1]:\'\')+\'</div></div>\').join(\'\');\n      }else{\n        document.getElementById(\'learned\').innerHTML=\'<div class="empty">No networks learned yet</div>\';\n      }\n    }catch(re){console.error(re);}\n    document.getElementById(\'ts\').textContent=new Date().toLocaleTimeString()+\' | Auto 4s\';\n  }catch(e){console.error(e);}\n}\nload();setInterval(load,4000);\n</script></body></html>'

_TMPL_EXPLORER = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet"><title>Network Explorer - Network Guardian</title><style nonce="{{NONCE}}">\n:root{--bg:#000810;--bg2:#010d1a;--card:rgba(0,18,36,0.92);--border:rgba(0,200,255,0.15);--text:#cce8ff;\n  --dim:#3d7a9a;--blue:#0094d4;--green:#00ff88;--yellow:#ffcc00;\n  --orange:#ff8c00;--red:#ff2244;--purple:#aa44ff;--cyan:#00d4ff;--pink:#ff00aa}\n@keyframes scan-h{0%{left:-100%;opacity:0}50%{opacity:1}100%{left:100%;opacity:0}}\n@keyframes pulse-glow{0%,100%{opacity:.5}50%{opacity:1}}\n@keyframes hud-boot{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}\n@keyframes spin{to{transform:rotate(360deg)}}\n*{margin:0;padding:0;box-sizing:border-box}\nbody{background:var(--bg);background-image:radial-gradient(ellipse at 20% 50%,rgba(0,212,255,.04) 0%,transparent 50%),radial-gradient(ellipse at 80% 20%,rgba(0,100,255,.05) 0%,transparent 50%),linear-gradient(rgba(0,200,255,.015) 1px,transparent 1px),linear-gradient(90deg,rgba(0,200,255,.015) 1px,transparent 1px);background-size:auto,auto,50px 50px,50px 50px;color:var(--text);font-family:\'Rajdhani\',\'Segoe UI\',sans-serif;overflow-x:hidden}\n.wrap{max-width:1400px;margin:0 auto;padding:20px}\n.banner{display:flex;align-items:center;gap:16px;padding:16px 24px;background:linear-gradient(135deg,rgba(0,20,40,.97),rgba(0,8,20,.99));border:1px solid rgba(0,200,255,.22);border-radius:4px;margin-bottom:20px;flex-wrap:wrap;position:relative;overflow:hidden}\n.banner::before{content:\'\';position:absolute;top:0;left:-100%;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan-h 5s ease-in-out infinite}\n.banner h1{font-size:1.4rem;white-space:nowrap;font-family:\'Orbitron\',sans-serif;letter-spacing:3px;color:var(--cyan);text-shadow:0 0 20px rgba(0,212,255,.5)}\n.badge{padding:4px 12px;clip-path:polygon(6px 0%,100% 0%,calc(100% - 6px) 100%,0% 100%);border-radius:0;font-size:.75rem;font-weight:700;letter-spacing:.5px;font-family:\'Share Tech Mono\',monospace}\n.nav{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}\n.nav a{padding:8px 18px;clip-path:polygon(8px 0%,100% 0%,calc(100% - 8px) 100%,0% 100%);border-radius:0;border:1px solid rgba(0,200,255,.2);background:rgba(0,15,30,.7);color:var(--cyan);text-decoration:none;font-size:.72rem;font-family:\'Orbitron\',sans-serif;letter-spacing:1.5px;text-transform:uppercase;cursor:pointer;transition:.2s}\n.nav a:hover{background:rgba(0,212,255,.15);box-shadow:0 0 15px rgba(0,212,255,.25);color:#fff}\n.nav a.active{background:rgba(0,212,255,.18);border-color:var(--cyan);box-shadow:0 0 20px rgba(0,212,255,.3);color:var(--cyan)}\n.grid{display:grid;gap:16px}\n.g2{grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}\n.card{background:linear-gradient(135deg,rgba(0,22,44,.9),rgba(0,8,22,.95));border:1px solid rgba(0,200,255,.15);border-radius:4px;padding:20px;position:relative;box-shadow:0 0 25px rgba(0,212,255,.04),inset 0 1px 0 rgba(0,212,255,.08)}\n.card::before{content:\'\';position:absolute;top:-1px;left:-1px;width:18px;height:18px;border-top:2px solid var(--cyan);border-left:2px solid var(--cyan);box-shadow:-2px -2px 8px rgba(0,212,255,.3)}\n.card::after{content:\'\';position:absolute;bottom:-1px;right:-1px;width:18px;height:18px;border-bottom:2px solid var(--cyan);border-right:2px solid var(--cyan);box-shadow:2px 2px 8px rgba(0,212,255,.3)}\n.card h2{font-size:.85rem;font-family:\'Orbitron\',sans-serif;color:var(--cyan);text-transform:uppercase;letter-spacing:2px;margin-bottom:14px;text-shadow:0 0 15px rgba(0,212,255,.4)}\ntable{width:100%;border-collapse:collapse;font-size:.82rem}\nth{text-align:left;font-family:\'Share Tech Mono\',monospace;color:var(--cyan);text-transform:uppercase;font-size:.68rem;letter-spacing:1.2px;padding:8px 6px;background:rgba(0,212,255,.05);border-bottom:1px solid rgba(0,200,255,.25)}\ntd{font-family:\'Share Tech Mono\',monospace;font-size:.8rem;padding:8px 6px;border-bottom:1px solid rgba(0,200,255,.06)}\ntr:hover td{background:rgba(0,212,255,.04)}\ncanvas{display:block}\n.kpi-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}\n.kpi{background:linear-gradient(135deg,rgba(0,20,40,.8),rgba(0,10,25,.85));border:1px solid rgba(0,200,255,.15);border-radius:4px;padding:14px 20px;min-width:130px;flex:1;position:relative;overflow:hidden}\n.kpi::after{content:\'\';position:absolute;bottom:0;left:-100%;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan-h 4s ease-in-out infinite alternate}\n.kpi .v{font-size:1.8rem;font-weight:700;font-family:\'Orbitron\',sans-serif;color:var(--cyan);text-shadow:0 0 15px rgba(0,212,255,.5)}\n.kpi .l{font-size:.65rem;font-family:\'Share Tech Mono\',monospace;color:var(--dim);text-transform:uppercase;letter-spacing:1px}\n.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.7rem;font-weight:600}\n.sev-critical{background:rgba(255,34,68,.15);color:var(--red);box-shadow:0 0 8px rgba(255,34,68,.2)}\n.sev-high{background:rgba(255,140,0,.15);color:var(--orange);box-shadow:0 0 8px rgba(255,140,0,.2)}\n.sev-medium{background:rgba(255,204,0,.15);color:var(--yellow)}\n.sev-low{background:rgba(0,255,136,.15);color:var(--green);box-shadow:0 0 8px rgba(0,255,136,.2)}\n.empty{color:var(--dim);font-style:normal;font-family:\'Share Tech Mono\',monospace;letter-spacing:1px;padding:20px;text-align:center}\n\n.host-node{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px;transition:.2s}\n.host-node:hover{border-color:var(--blue);transform:translateY(-2px)}\n.host-node .ip{font-family:monospace;font-weight:700;font-size:1rem;margin-bottom:4px}\n.host-node .info{color:var(--dim);font-size:.78rem;line-height:1.6}\n.port-tag{padding:2px 6px;border-radius:4px;font-size:.65rem;font-family:monospace;background:rgba(88,166,255,.1);color:var(--blue);border:1px solid rgba(88,166,255,.2);display:inline-block;margin:2px}\n</style></head><body>\n<div class="wrap">\n  <div class="banner">\n    <h1>&#127760; Network Explorer</h1>\n    <span id="st" class="badge" style="background:rgba(88,166,255,.15);color:var(--blue)">Idle</span>\n    <span id="ts" style="margin-left:auto;color:var(--dim);font-size:.85rem"></span>\n  </div>\n  <div class="kpi-row">\n    <div class="kpi"><div class="v" id="kH">0</div><div class="l">Hosts</div></div>\n    <div class="kpi"><div class="v" id="kP">0</div><div class="l">Open Ports</div></div>\n    <div class="kpi"><div class="v" id="kO">0</div><div class="l">OS Types</div></div>\n    <div class="kpi"><div class="v" id="kE">0</div><div class="l">Connections</div></div>\n  </div>\n<div class="nav"><a href="/">Dashboard</a><a href="/ids">IDS</a><a href="/ips">IPS</a><a href="/wifi">WiFi</a><a href="/cloaking">Cloaking</a><a href="/explorer" class="active">Explorer</a><a href="/auditor">Auditor</a><a href="/ai">AI Engine</a><a href="/fleet">Fleet</a><a href="/reports">Reports</a><a href="/incidents">Incidents</a></div>\n  <div class="grid g2">\n    <div class="card" style="grid-column:1/-1"><h2>&#127760; Topology</h2><canvas id="topo" height="350"></canvas></div>\n    <div class="card" style="grid-column:1/-1"><h2>&#128187; Hosts</h2><div id="hosts" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px"></div></div>\n    <div class="card"><h2>&#128202; Port Distribution</h2><canvas id="portChart" height="220"></canvas></div>\n    <div class="card"><h2>&#128268; Edges</h2><div id="edges" style="max-height:250px;overflow-y:auto"></div></div>\n  </div>\n</div>\n<script nonce="{{NONCE}}">\nfunction drawTopo(hosts,topo){\n  const c=document.getElementById(\'topo\'),ctx=c.getContext(\'2d\');\n  const W=c.width=c.parentElement.clientWidth-40,H=c.height=350;\n  ctx.clearRect(0,0,W,H);\n  const ips=Object.keys(hosts);\n  if(!ips.length){ctx.fillStyle=\'#8b949e\';ctx.textAlign=\'center\';ctx.font=\'14px sans-serif\';ctx.fillText(\'No hosts - run explore to populate\',W/2,H/2);return;}\n  const cx=W/2,cy=H/2,r=Math.min(W,H)/2-60;\n  const pos={};\n  ips.forEach((ip,i)=>{const ang=(i/ips.length)*Math.PI*2-Math.PI/2;pos[ip]={x:cx+r*Math.cos(ang),y:cy+r*Math.sin(ang)};});\n  if(topo){Object.entries(topo).forEach(([from,tos])=>{(tos||[]).forEach(to=>{if(pos[from]&&pos[to]){ctx.beginPath();ctx.moveTo(pos[from].x,pos[from].y);ctx.lineTo(pos[to].x,pos[to].y);ctx.strokeStyle=\'rgba(88,166,255,.3)\';ctx.lineWidth=1.5;ctx.stroke();}});});}\n  ips.forEach(ip=>{\n    const p=pos[ip];\n    const g=ctx.createRadialGradient(p.x,p.y,0,p.x,p.y,24);g.addColorStop(0,\'rgba(88,166,255,.3)\');g.addColorStop(1,\'transparent\');ctx.fillStyle=g;ctx.fillRect(p.x-24,p.y-24,48,48);\n    ctx.beginPath();ctx.arc(p.x,p.y,14,0,Math.PI*2);ctx.fillStyle=\'#161b22\';ctx.fill();ctx.strokeStyle=\'#58a6ff\';ctx.lineWidth=2;ctx.stroke();\n    ctx.fillStyle=\'#c9d1d9\';ctx.font=\'10px monospace\';ctx.textAlign=\'center\';ctx.fillText(ip,p.x,p.y+28);\n  });\n}\nfunction drawPorts(hosts){\n  const c=document.getElementById(\'portChart\'),ctx=c.getContext(\'2d\');\n  const W=c.width=c.parentElement.clientWidth-40,H=c.height=220;\n  ctx.clearRect(0,0,W,H);\n  const pc={};Object.values(hosts).forEach(h=>{(h.open_ports||[]).forEach(p=>{pc[p]=(pc[p]||0)+1;});});\n  const entries=Object.entries(pc).sort((a,b)=>b[1]-a[1]).slice(0,12);\n  if(!entries.length){ctx.fillStyle=\'#8b949e\';ctx.textAlign=\'center\';ctx.fillText(\'No port data\',W/2,H/2);return;}\n  const max=Math.max(...entries.map(e=>e[1])),bh=14;\n  entries.forEach(([port,count],i)=>{\n    const y=16+i*(bh+4),w=(count/max)*(W-100);\n    ctx.fillStyle=\'#8b949e\';ctx.font=\'10px monospace\';ctx.textAlign=\'right\';ctx.fillText(port,70,y+bh/2+3);\n    const g=ctx.createLinearGradient(80,y,80+w,y);g.addColorStop(0,\'#58a6ff\');g.addColorStop(1,\'#58a6ff44\');\n    ctx.fillStyle=g;ctx.beginPath();ctx.roundRect(80,y,w,bh,3);ctx.fill();\n    ctx.fillStyle=\'#c9d1d9\';ctx.font=\'9px sans-serif\';ctx.textAlign=\'left\';ctx.fillText(count,84+w,y+bh/2+3);\n  });\n}\nasync function load(){\n  try{\n    const [hR,tR]=await Promise.all([fetch(\'/api/hosts\'),fetch(\'/api/explorer/topology\')]);\n    const hosts=await hR.json(),topo=await tR.json();\n    const ips=Object.keys(hosts);let tp=0;const oSet=new Set();\n    ips.forEach(ip=>{const h=hosts[ip];tp+=(h.open_ports||[]).length;if(h.os)oSet.add(h.os);});\n    let ec=0;if(topo)Object.values(topo).forEach(v=>{ec+=(v||[]).length;});\n    document.getElementById(\'kH\').textContent=ips.length;document.getElementById(\'kP\').textContent=tp;\n    document.getElementById(\'kO\').textContent=oSet.size;document.getElementById(\'kE\').textContent=ec;\n    document.getElementById(\'st\').textContent=ips.length?ips.length+\' Hosts\':\'Idle\';document.getElementById(\'st\').style.color=ips.length?\'var(--green)\':\'var(--blue)\';\n    drawTopo(hosts,topo);drawPorts(hosts);\n    const hEl=document.getElementById(\'hosts\');\n    if(!ips.length){hEl.innerHTML=\'<div class="empty">No hosts discovered</div>\';}\n    else{hEl.innerHTML=ips.map(ip=>{const h=hosts[ip];const ports=(h.open_ports||[]).slice(0,10);return \'<div class="host-node"><div class="ip">\'+ip+\'</div><div class="info">\'+(h.hostname?\'Host: \'+h.hostname+\'<br>\':\'\')+(h.os?\'OS: \'+h.os+\'<br>\':\'\')+\'Ports: \'+(h.open_ports||[]).length+\' open</div><div>\'+ports.map(p=>\'<span class="port-tag">\'+p+\'</span>\').join(\'\')+\'</div></div>\';}).join(\'\');}\n    const eEl=document.getElementById(\'edges\');\n    if(!topo||!Object.keys(topo).length){eEl.innerHTML=\'<div class="empty">No topology</div>\';}\n    else{let html=\'\';Object.entries(topo).forEach(([from,tos])=>{(tos||[]).forEach(to=>{html+=\'<div style="display:flex;align-items:center;gap:8px;padding:6px;font-size:.82rem;border-bottom:1px solid rgba(48,54,61,.4)"><span style="font-family:monospace;color:var(--blue)">\'+from+\'</span><span style="color:var(--dim)">&#8594;</span><span style="font-family:monospace;color:var(--cyan)">\'+to+\'</span></div>\';});});eEl.innerHTML=html;}\n    document.getElementById(\'ts\').textContent=new Date().toLocaleTimeString()+\' | Auto 5s\';\n  }catch(e){console.error(e);}\n}\nload();setInterval(load,5000);\n</script></body></html>'

_TMPL_AUDITOR = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet"><title>Security Auditor - Network Guardian</title><style nonce="{{NONCE}}">\n:root{--bg:#000810;--bg2:#010d1a;--card:rgba(0,18,36,0.92);--border:rgba(0,200,255,0.15);--text:#cce8ff;\n  --dim:#3d7a9a;--blue:#0094d4;--green:#00ff88;--yellow:#ffcc00;\n  --orange:#ff8c00;--red:#ff2244;--purple:#aa44ff;--cyan:#00d4ff;--pink:#ff00aa}\n@keyframes scan-h{0%{left:-100%;opacity:0}50%{opacity:1}100%{left:100%;opacity:0}}\n@keyframes pulse-glow{0%,100%{opacity:.5}50%{opacity:1}}\n@keyframes hud-boot{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}\n@keyframes spin{to{transform:rotate(360deg)}}\n*{margin:0;padding:0;box-sizing:border-box}\nbody{background:var(--bg);background-image:radial-gradient(ellipse at 20% 50%,rgba(0,212,255,.04) 0%,transparent 50%),radial-gradient(ellipse at 80% 20%,rgba(0,100,255,.05) 0%,transparent 50%),linear-gradient(rgba(0,200,255,.015) 1px,transparent 1px),linear-gradient(90deg,rgba(0,200,255,.015) 1px,transparent 1px);background-size:auto,auto,50px 50px,50px 50px;color:var(--text);font-family:\'Rajdhani\',\'Segoe UI\',sans-serif;overflow-x:hidden}\n.wrap{max-width:1400px;margin:0 auto;padding:20px}\n.banner{display:flex;align-items:center;gap:16px;padding:16px 24px;background:linear-gradient(135deg,rgba(0,20,40,.97),rgba(0,8,20,.99));border:1px solid rgba(0,200,255,.22);border-radius:4px;margin-bottom:20px;flex-wrap:wrap;position:relative;overflow:hidden}\n.banner::before{content:\'\';position:absolute;top:0;left:-100%;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan-h 5s ease-in-out infinite}\n.banner h1{font-size:1.4rem;white-space:nowrap;font-family:\'Orbitron\',sans-serif;letter-spacing:3px;color:var(--cyan);text-shadow:0 0 20px rgba(0,212,255,.5)}\n.badge{padding:4px 12px;clip-path:polygon(6px 0%,100% 0%,calc(100% - 6px) 100%,0% 100%);border-radius:0;font-size:.75rem;font-weight:700;letter-spacing:.5px;font-family:\'Share Tech Mono\',monospace}\n.nav{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}\n.nav a{padding:8px 18px;clip-path:polygon(8px 0%,100% 0%,calc(100% - 8px) 100%,0% 100%);border-radius:0;border:1px solid rgba(0,200,255,.2);background:rgba(0,15,30,.7);color:var(--cyan);text-decoration:none;font-size:.72rem;font-family:\'Orbitron\',sans-serif;letter-spacing:1.5px;text-transform:uppercase;cursor:pointer;transition:.2s}\n.nav a:hover{background:rgba(0,212,255,.15);box-shadow:0 0 15px rgba(0,212,255,.25);color:#fff}\n.nav a.active{background:rgba(0,212,255,.18);border-color:var(--cyan);box-shadow:0 0 20px rgba(0,212,255,.3);color:var(--cyan)}\n.grid{display:grid;gap:16px}\n.g2{grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}\n.card{background:linear-gradient(135deg,rgba(0,22,44,.9),rgba(0,8,22,.95));border:1px solid rgba(0,200,255,.15);border-radius:4px;padding:20px;position:relative;box-shadow:0 0 25px rgba(0,212,255,.04),inset 0 1px 0 rgba(0,212,255,.08)}\n.card::before{content:\'\';position:absolute;top:-1px;left:-1px;width:18px;height:18px;border-top:2px solid var(--cyan);border-left:2px solid var(--cyan);box-shadow:-2px -2px 8px rgba(0,212,255,.3)}\n.card::after{content:\'\';position:absolute;bottom:-1px;right:-1px;width:18px;height:18px;border-bottom:2px solid var(--cyan);border-right:2px solid var(--cyan);box-shadow:2px 2px 8px rgba(0,212,255,.3)}\n.card h2{font-size:.85rem;font-family:\'Orbitron\',sans-serif;color:var(--cyan);text-transform:uppercase;letter-spacing:2px;margin-bottom:14px;text-shadow:0 0 15px rgba(0,212,255,.4)}\ntable{width:100%;border-collapse:collapse;font-size:.82rem}\nth{text-align:left;font-family:\'Share Tech Mono\',monospace;color:var(--cyan);text-transform:uppercase;font-size:.68rem;letter-spacing:1.2px;padding:8px 6px;background:rgba(0,212,255,.05);border-bottom:1px solid rgba(0,200,255,.25)}\ntd{font-family:\'Share Tech Mono\',monospace;font-size:.8rem;padding:8px 6px;border-bottom:1px solid rgba(0,200,255,.06)}\ntr:hover td{background:rgba(0,212,255,.04)}\ncanvas{display:block}\n.kpi-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}\n.kpi{background:linear-gradient(135deg,rgba(0,20,40,.8),rgba(0,10,25,.85));border:1px solid rgba(0,200,255,.15);border-radius:4px;padding:14px 20px;min-width:130px;flex:1;position:relative;overflow:hidden}\n.kpi::after{content:\'\';position:absolute;bottom:0;left:-100%;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan-h 4s ease-in-out infinite alternate}\n.kpi .v{font-size:1.8rem;font-weight:700;font-family:\'Orbitron\',sans-serif;color:var(--cyan);text-shadow:0 0 15px rgba(0,212,255,.5)}\n.kpi .l{font-size:.65rem;font-family:\'Share Tech Mono\',monospace;color:var(--dim);text-transform:uppercase;letter-spacing:1px}\n.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.7rem;font-weight:600}\n.sev-critical{background:rgba(255,34,68,.15);color:var(--red);box-shadow:0 0 8px rgba(255,34,68,.2)}\n.sev-high{background:rgba(255,140,0,.15);color:var(--orange);box-shadow:0 0 8px rgba(255,140,0,.2)}\n.sev-medium{background:rgba(255,204,0,.15);color:var(--yellow)}\n.sev-low{background:rgba(0,255,136,.15);color:var(--green);box-shadow:0 0 8px rgba(0,255,136,.2)}\n.empty{color:var(--dim);font-style:normal;font-family:\'Share Tech Mono\',monospace;letter-spacing:1px;padding:20px;text-align:center}\n\n.finding{display:flex;gap:12px;padding:12px;border:1px solid var(--border);border-radius:10px;margin-bottom:8px;border-left:4px solid var(--border);transition:.2s}\n.finding:hover{background:rgba(88,166,255,.03)}\n.finding.fc{border-left-color:var(--red)}\n.finding.fh{border-left-color:var(--orange)}\n.finding.fm{border-left-color:var(--yellow)}\n.finding.fl{border-left-color:var(--green)}\n.finding .body{flex:1}\n.finding .title{font-weight:600;font-size:.9rem;margin-bottom:3px}\n.finding .desc{color:var(--dim);font-size:.78rem;line-height:1.5}\n</style></head><body>\n<div class="wrap">\n  <div class="banner">\n    <h1>&#128270; Security Auditor</h1>\n    <span id="st" class="badge" style="background:rgba(63,185,80,.15);color:var(--green)">Clean</span>\n    <span id="ts" style="margin-left:auto;color:var(--dim);font-size:.85rem"></span>\n  </div>\n  <div class="kpi-row">\n    <div class="kpi"><div class="v" id="kT">0</div><div class="l">Total</div></div>\n    <div class="kpi"><div class="v" id="kC" style="color:var(--red)">0</div><div class="l">Critical</div></div>\n    <div class="kpi"><div class="v" id="kH" style="color:var(--orange)">0</div><div class="l">High</div></div>\n    <div class="kpi"><div class="v" id="kM" style="color:var(--yellow)">0</div><div class="l">Medium</div></div>\n    <div class="kpi"><div class="v" id="kL" style="color:var(--green)">0</div><div class="l">Low</div></div>\n  </div>\n<div class="nav"><a href="/">Dashboard</a><a href="/ids">IDS</a><a href="/ips">IPS</a><a href="/wifi">WiFi</a><a href="/cloaking">Cloaking</a><a href="/explorer">Explorer</a><a href="/auditor" class="active">Auditor</a><a href="/ai">AI Engine</a><a href="/fleet">Fleet</a><a href="/reports">Reports</a><a href="/incidents">Incidents</a></div>\n  <div class="grid g2">\n    <div class="card"><h2>&#128202; Severity</h2><canvas id="sevChart" height="200"></canvas></div>\n    <div class="card"><h2>&#127919; Risk Score</h2><canvas id="riskGauge" height="200"></canvas></div>\n    <div class="card" style="grid-column:1/-1"><h2>&#128196; Findings</h2><div id="finds"></div></div>\n  </div>\n</div>\n<script nonce="{{NONCE}}">\nfunction drawSev(findings){\n  const c=document.getElementById(\'sevChart\'),ctx=c.getContext(\'2d\');\n  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;\n  ctx.clearRect(0,0,W,H);\n  const cnt={critical:0,high:0,medium:0,low:0,info:0};\n  findings.forEach(f=>{const s=(f.severity||\'info\').toLowerCase();if(cnt[s]!==undefined)cnt[s]++;});\n  const total=findings.length;\n  if(!total){ctx.fillStyle=\'#8b949e\';ctx.textAlign=\'center\';ctx.fillText(\'No findings\',W/2,H/2);return;}\n  const cols={critical:\'#f85149\',high:\'#db6d28\',medium:\'#d29922\',low:\'#3fb950\',info:\'#58a6ff\'};\n  const cx=90,cy=H/2,r=75;let angle=-Math.PI/2;\n  Object.entries(cnt).filter(e=>e[1]>0).forEach(([k,v])=>{const sl=v/total*Math.PI*2;ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,r,angle,angle+sl);ctx.closePath();ctx.fillStyle=cols[k];ctx.fill();angle+=sl;});\n  ctx.beginPath();ctx.arc(cx,cy,45,0,Math.PI*2);ctx.fillStyle=\'#161b22\';ctx.fill();\n  ctx.fillStyle=\'#c9d1d9\';ctx.font=\'bold 20px sans-serif\';ctx.textAlign=\'center\';ctx.fillText(total,cx,cy+7);\n  let ly=20;Object.entries(cnt).forEach(([k,v])=>{ctx.fillStyle=cols[k];ctx.fillRect(W-150,ly,10,10);ctx.fillStyle=\'#c9d1d9\';ctx.font=\'12px sans-serif\';ctx.textAlign=\'left\';ctx.fillText(k+\' (\'+v+\')\',W-134,ly+9);ly+=22;});\n}\nfunction drawRisk(findings){\n  const c=document.getElementById(\'riskGauge\'),ctx=c.getContext(\'2d\');\n  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;\n  ctx.clearRect(0,0,W,H);\n  const wt={critical:10,high:5,medium:2,low:1,info:0};\n  let score=0;findings.forEach(f=>{score+=wt[(f.severity||\'info\').toLowerCase()]||0;});\n  const pct=Math.min(1,score/100);\n  const cx=W/2,cy=H-30,r=80;\n  ctx.beginPath();ctx.arc(cx,cy,r,-Math.PI,0);ctx.strokeStyle=\'#30363d\';ctx.lineWidth=20;ctx.lineCap=\'round\';ctx.stroke();\n  const col=pct<0.3?\'#3fb950\':pct<0.6?\'#d29922\':pct<0.8?\'#db6d28\':\'#f85149\';\n  if(pct>0){ctx.beginPath();ctx.arc(cx,cy,r,-Math.PI,-Math.PI+pct*Math.PI);ctx.strokeStyle=col;ctx.lineWidth=20;ctx.lineCap=\'round\';ctx.stroke();}\n  ctx.fillStyle=\'#c9d1d9\';ctx.font=\'bold 28px sans-serif\';ctx.textAlign=\'center\';ctx.fillText(score,cx,cy-10);\n  ctx.fillStyle=\'#8b949e\';ctx.font=\'12px sans-serif\';ctx.fillText(\'Risk Score\',cx,cy+10);\n}\nasync function load(){\n  try{\n    const r=await fetch(\'/api/findings\');const findings=await r.json();\n    const cnt={critical:0,high:0,medium:0,low:0,info:0};\n    findings.forEach(f=>{const s=(f.severity||\'info\').toLowerCase();if(cnt[s]!==undefined)cnt[s]++;});\n    document.getElementById(\'kT\').textContent=findings.length;\n    document.getElementById(\'kC\').textContent=cnt.critical;document.getElementById(\'kH\').textContent=cnt.high;\n    document.getElementById(\'kM\').textContent=cnt.medium;document.getElementById(\'kL\').textContent=cnt.low;\n    const badge=document.getElementById(\'st\');\n    if(cnt.critical>0){badge.textContent=\'CRITICAL\';badge.style.background=\'rgba(248,81,73,.15)\';badge.style.color=\'var(--red)\';}\n    else if(cnt.high>0){badge.textContent=\'AT RISK\';badge.style.background=\'rgba(219,109,40,.15)\';badge.style.color=\'var(--orange)\';}\n    else if(findings.length>0){badge.textContent=\'WARNINGS\';badge.style.background=\'rgba(210,153,34,.15)\';badge.style.color=\'var(--yellow)\';}\n    else{badge.textContent=\'CLEAN\';badge.style.background=\'rgba(63,185,80,.15)\';badge.style.color=\'var(--green)\';}\n    drawSev(findings);drawRisk(findings);\n    const fEl=document.getElementById(\'finds\');\n    if(!findings.length){fEl.innerHTML=\'<div class="empty">No findings - system clean</div>\';}\n    else{const sevC={critical:\'fc\',high:\'fh\',medium:\'fm\',low:\'fl\'};fEl.innerHTML=findings.map(f=>{const s=(f.severity||\'info\').toLowerCase();return \'<div class="finding \'+(sevC[s]||\'\')+\'"><div style="font-size:1.4rem;min-width:30px;text-align:center">\'+(s===\'critical\'?\'&#128680;\':s===\'high\'?\'&#9888;\':\'&#128313;\')+\'</div><div class="body"><div class="title">\'+(f.title||f.description||\'Finding\')+\'</div><div class="desc">\'+(f.target?\'Target: <b>\'+f.target+\'</b> | \':\'\')+\'Severity: <span class="pill sev-\'+s+\'">\'+s.toUpperCase()+\'</span></div></div></div>\';}).join(\'\');}\n    document.getElementById(\'ts\').textContent=new Date().toLocaleTimeString()+\' | Auto 5s\';\n  }catch(e){console.error(e);}\n}\nload();setInterval(load,5000);\n</script></body></html>'

_TMPL_AI = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet"><title>AI Engine - Network Guardian</title><style nonce="{{NONCE}}">\n:root{--bg:#000810;--bg2:#010d1a;--card:rgba(0,18,36,0.92);--border:rgba(0,200,255,0.15);--text:#cce8ff;\n  --dim:#3d7a9a;--blue:#0094d4;--green:#00ff88;--yellow:#ffcc00;\n  --orange:#ff8c00;--red:#ff2244;--purple:#aa44ff;--cyan:#00d4ff;--pink:#ff00aa}\n@keyframes scan-h{0%{left:-100%;opacity:0}50%{opacity:1}100%{left:100%;opacity:0}}\n@keyframes pulse-glow{0%,100%{opacity:.5}50%{opacity:1}}\n@keyframes hud-boot{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}\n@keyframes spin{to{transform:rotate(360deg)}}\n*{margin:0;padding:0;box-sizing:border-box}\nbody{background:var(--bg);background-image:radial-gradient(ellipse at 20% 50%,rgba(0,212,255,.04) 0%,transparent 50%),radial-gradient(ellipse at 80% 20%,rgba(0,100,255,.05) 0%,transparent 50%),linear-gradient(rgba(0,200,255,.015) 1px,transparent 1px),linear-gradient(90deg,rgba(0,200,255,.015) 1px,transparent 1px);background-size:auto,auto,50px 50px,50px 50px;color:var(--text);font-family:\'Rajdhani\',\'Segoe UI\',sans-serif;overflow-x:hidden}\n.wrap{max-width:1400px;margin:0 auto;padding:20px}\n.banner{display:flex;align-items:center;gap:16px;padding:16px 24px;background:linear-gradient(135deg,rgba(0,20,40,.97),rgba(0,8,20,.99));border:1px solid rgba(0,200,255,.22);border-radius:4px;margin-bottom:20px;flex-wrap:wrap;position:relative;overflow:hidden}\n.banner::before{content:\'\';position:absolute;top:0;left:-100%;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan-h 5s ease-in-out infinite}\n.banner h1{font-size:1.4rem;white-space:nowrap;font-family:\'Orbitron\',sans-serif;letter-spacing:3px;color:var(--cyan);text-shadow:0 0 20px rgba(0,212,255,.5)}\n.badge{padding:4px 12px;clip-path:polygon(6px 0%,100% 0%,calc(100% - 6px) 100%,0% 100%);border-radius:0;font-size:.75rem;font-weight:700;letter-spacing:.5px;font-family:\'Share Tech Mono\',monospace}\n.nav{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}\n.nav a{padding:8px 18px;clip-path:polygon(8px 0%,100% 0%,calc(100% - 8px) 100%,0% 100%);border-radius:0;border:1px solid rgba(0,200,255,.2);background:rgba(0,15,30,.7);color:var(--cyan);text-decoration:none;font-size:.72rem;font-family:\'Orbitron\',sans-serif;letter-spacing:1.5px;text-transform:uppercase;cursor:pointer;transition:.2s}\n.nav a:hover{background:rgba(0,212,255,.15);box-shadow:0 0 15px rgba(0,212,255,.25);color:#fff}\n.nav a.active{background:rgba(0,212,255,.18);border-color:var(--cyan);box-shadow:0 0 20px rgba(0,212,255,.3);color:var(--cyan)}\n.grid{display:grid;gap:16px}\n.g2{grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}\n.card{background:linear-gradient(135deg,rgba(0,22,44,.9),rgba(0,8,22,.95));border:1px solid rgba(0,200,255,.15);border-radius:4px;padding:20px;position:relative;box-shadow:0 0 25px rgba(0,212,255,.04),inset 0 1px 0 rgba(0,212,255,.08)}\n.card::before{content:\'\';position:absolute;top:-1px;left:-1px;width:18px;height:18px;border-top:2px solid var(--cyan);border-left:2px solid var(--cyan);box-shadow:-2px -2px 8px rgba(0,212,255,.3)}\n.card::after{content:\'\';position:absolute;bottom:-1px;right:-1px;width:18px;height:18px;border-bottom:2px solid var(--cyan);border-right:2px solid var(--cyan);box-shadow:2px 2px 8px rgba(0,212,255,.3)}\n.card h2{font-size:.85rem;font-family:\'Orbitron\',sans-serif;color:var(--cyan);text-transform:uppercase;letter-spacing:2px;margin-bottom:14px;text-shadow:0 0 15px rgba(0,212,255,.4)}\ntable{width:100%;border-collapse:collapse;font-size:.82rem}\nth{text-align:left;font-family:\'Share Tech Mono\',monospace;color:var(--cyan);text-transform:uppercase;font-size:.68rem;letter-spacing:1.2px;padding:8px 6px;background:rgba(0,212,255,.05);border-bottom:1px solid rgba(0,200,255,.25)}\ntd{font-family:\'Share Tech Mono\',monospace;font-size:.8rem;padding:8px 6px;border-bottom:1px solid rgba(0,200,255,.06)}\ntr:hover td{background:rgba(0,212,255,.04)}\ncanvas{display:block}\n.kpi-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}\n.kpi{background:linear-gradient(135deg,rgba(0,20,40,.8),rgba(0,10,25,.85));border:1px solid rgba(0,200,255,.15);border-radius:4px;padding:14px 20px;min-width:130px;flex:1;position:relative;overflow:hidden}\n.kpi::after{content:\'\';position:absolute;bottom:0;left:-100%;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan-h 4s ease-in-out infinite alternate}\n.kpi .v{font-size:1.8rem;font-weight:700;font-family:\'Orbitron\',sans-serif;color:var(--cyan);text-shadow:0 0 15px rgba(0,212,255,.5)}\n.kpi .l{font-size:.65rem;font-family:\'Share Tech Mono\',monospace;color:var(--dim);text-transform:uppercase;letter-spacing:1px}\n.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.7rem;font-weight:600}\n.sev-critical{background:rgba(255,34,68,.15);color:var(--red);box-shadow:0 0 8px rgba(255,34,68,.2)}\n.sev-high{background:rgba(255,140,0,.15);color:var(--orange);box-shadow:0 0 8px rgba(255,140,0,.2)}\n.sev-medium{background:rgba(255,204,0,.15);color:var(--yellow)}\n.sev-low{background:rgba(0,255,136,.15);color:var(--green);box-shadow:0 0 8px rgba(0,255,136,.2)}\n.empty{color:var(--dim);font-style:normal;font-family:\'Share Tech Mono\',monospace;letter-spacing:1px;padding:20px;text-align:center}\n\n.ai-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center;transition:.2s}\n.ai-card:hover{border-color:var(--purple);transform:translateY(-2px)}\n.ai-card .icon{font-size:2rem;margin-bottom:8px}\n.ai-card .name{font-weight:700;font-size:.9rem;margin-bottom:4px}\n.ai-card .desc{color:var(--dim);font-size:.75rem}\n.metric-row{display:flex;gap:8px;align-items:center;padding:8px 0;border-bottom:1px solid rgba(48,54,61,.4);font-size:.85rem}\n.metric-row:last-child{border-bottom:none}\n.metric-row .label{color:var(--dim);flex:1}\n.metric-row .val{font-weight:600;font-family:monospace}\n</style></head><body>\n<div class="wrap">\n  <div class="banner">\n    <h1>&#129302; AI Engine</h1>\n    <span class="badge" style="background:rgba(188,140,255,.15);color:var(--purple)">Active</span>\n    <span id="ts" style="margin-left:auto;color:var(--dim);font-size:.85rem"></span>\n  </div>\n  <div class="kpi-row">\n    <div class="kpi"><div class="v" id="kAn" style="color:var(--red)">0</div><div class="l">Anomalies</div></div>\n    <div class="kpi"><div class="v" id="kPr" style="color:var(--purple)">0</div><div class="l">Predictions</div></div>\n    <div class="kpi"><div class="v" id="kMe" style="color:var(--blue)">0</div><div class="l">Metrics</div></div>\n    <div class="kpi"><div class="v" id="kEv" style="color:var(--cyan)">0</div><div class="l">AI Events</div></div>\n  </div>\n<div class="nav"><a href="/">Dashboard</a><a href="/ids">IDS</a><a href="/ips">IPS</a><a href="/wifi">WiFi</a><a href="/cloaking">Cloaking</a><a href="/explorer">Explorer</a><a href="/auditor">Auditor</a><a href="/ai" class="active">AI Engine</a></div>\n  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px;margin-bottom:18px">\n    <div class="ai-card"><div class="icon">&#128024;</div><div class="name">Isolation Forest</div><div class="desc">Unsupervised anomaly detection</div></div>\n    <div class="ai-card"><div class="icon">&#127919;</div><div class="name">One-Class SVM</div><div class="desc">RBF kernel density</div></div>\n    <div class="ai-card"><div class="icon">&#129704;</div><div class="name">Ensemble Detector</div><div class="desc">Multi-model averaging</div></div>\n    <div class="ai-card"><div class="icon">&#128200;</div><div class="name">ARIMA</div><div class="desc">Time series forecasting</div></div>\n    <div class="ai-card"><div class="icon">&#127777;</div><div class="name">Holt-Winters</div><div class="desc">Exponential smoothing</div></div>\n    <div class="ai-card"><div class="icon">&#128172;</div><div class="name">NLP Engine</div><div class="desc">Command + log analysis</div></div>\n  </div>\n  <div class="grid g2">\n    <div class="card"><h2>&#128200; Anomaly Timeline</h2><canvas id="anomChart" height="200"></canvas></div>\n    <div class="card"><h2>&#128202; System Metrics</h2><canvas id="metChart" height="200"></canvas></div>\n    <div class="card"><h2>&#128161; Metric Values</h2><div id="metList" style="max-height:260px;overflow-y:auto"></div></div>\n    <div class="card"><h2>&#9889; AI Events</h2><div id="aiEvts" style="max-height:260px;overflow-y:auto"></div></div>\n  </div>\n</div>\n<script nonce="{{NONCE}}">\nlet aHist=[];\nfunction drawAnom(){\n  const c=document.getElementById(\'anomChart\'),ctx=c.getContext(\'2d\');\n  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;\n  ctx.clearRect(0,0,W,H);\n  if(aHist.length<2){ctx.fillStyle=\'#8b949e\';ctx.textAlign=\'center\';ctx.fillText(\'Collecting...\',W/2,H/2);return;}\n  const pad=40,max=Math.max(1,...aHist.map(a=>a.s));\n  const thY=H-pad-(0.7/max)*(H-pad*2);\n  ctx.setLineDash([5,5]);ctx.strokeStyle=\'rgba(248,81,73,.5)\';ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(pad,thY);ctx.lineTo(W-10,thY);ctx.stroke();ctx.setLineDash([]);\n  ctx.beginPath();aHist.forEach((a,i)=>{const x=pad+i*(W-pad-10)/(aHist.length-1),y=H-pad-(a.s/max)*(H-pad*2);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});\n  ctx.strokeStyle=\'#bc8cff\';ctx.lineWidth=2;ctx.stroke();\n  const last=aHist.length-1;ctx.lineTo(pad+last*(W-pad-10)/last,H-pad);ctx.lineTo(pad,H-pad);ctx.closePath();ctx.fillStyle=\'rgba(188,140,255,.1)\';ctx.fill();\n}\nfunction drawMet(metrics){\n  const c=document.getElementById(\'metChart\'),ctx=c.getContext(\'2d\');\n  const W=c.width=c.parentElement.clientWidth-40,H=c.height=200;\n  ctx.clearRect(0,0,W,H);\n  const names=Object.keys(metrics||{});\n  if(!names.length){ctx.fillStyle=\'#8b949e\';ctx.textAlign=\'center\';ctx.fillText(\'No metrics\',W/2,H/2);return;}\n  const colors=[\'#58a6ff\',\'#3fb950\',\'#d29922\',\'#bc8cff\',\'#39d2e0\',\'#f85149\'];\n  const pad=40,allV=names.flatMap(n=>(metrics[n]||[]).slice(-20)),max=Math.max(1,...allV);\n  names.slice(0,6).forEach((name,ni)=>{\n    const vals=(metrics[name]||[]).slice(-20);if(vals.length<2)return;\n    ctx.beginPath();ctx.strokeStyle=colors[ni%6];ctx.lineWidth=1.5;\n    vals.forEach((v,i)=>{const x=pad+i*(W-pad-10)/(vals.length-1),y=H-pad-(v/max)*(H-pad*2);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});ctx.stroke();\n  });\n  let lx=pad;names.slice(0,6).forEach((n,i)=>{ctx.fillStyle=colors[i%6];ctx.fillRect(lx,H-12,8,8);ctx.fillStyle=\'#c9d1d9\';ctx.font=\'9px sans-serif\';ctx.textAlign=\'left\';ctx.fillText(n.slice(0,15),lx+12,H-4);lx+=W/6.5;});\n}\nasync function load(){\n  try{\n    const [mR,eR]=await Promise.all([fetch(\'/api/ai/metrics\'),fetch(\'/api/events\')]);\n    const md=await mR.json(),events=await eR.json();\n    const met=md.metrics||{};\n    aHist.push({s:md.latest_anomaly_score||0});if(aHist.length>30)aHist=aHist.slice(-30);\n    document.getElementById(\'kAn\').textContent=md.anomaly_count||0;\n    document.getElementById(\'kPr\').textContent=md.prediction_count||0;\n    document.getElementById(\'kMe\').textContent=Object.keys(met).length;\n    const aiE=(md.ai_events&&md.ai_events.length)?md.ai_events:(events||[]).filter(e=>e.topic&&(e.topic.startsWith(\'ai.\')||e.topic.startsWith(\'monitor.\')));\n    document.getElementById(\'kEv\').textContent=aiE.length;\n    drawAnom();drawMet(met);\n    const mEl=document.getElementById(\'metList\');\n    const names=Object.keys(met);\n    if(!names.length){mEl.innerHTML=\'<div class="empty">No metrics</div>\';}\n    else{mEl.innerHTML=names.map(n=>{const v=met[n]||[];const last=v.length?v[v.length-1]:\'-\';const avg=v.length?(v.reduce((a,b)=>a+b,0)/v.length).toFixed(2):\'-\';return \'<div class="metric-row"><span class="label">\'+n+\'</span><span class="val" style="color:var(--blue)">\'+(typeof last===\'number\'?last.toFixed(2):last)+\'</span><span style="color:var(--dim);font-size:.7rem;margin-left:8px">avg:\'+avg+\'</span></div>\';}).join(\'\');}\n    const aEl=document.getElementById(\'aiEvts\');\n    if(!aiE.length){aEl.innerHTML=\'<div class="empty">No AI events</div>\';}\n    else{aEl.innerHTML=aiE.slice(0,20).map(e=>{const d=e.data||{};const detail=d.title||(d.risk?\'Risk: \'+d.risk:\'\');return\'<div style="display:flex;gap:10px;padding:8px;border-bottom:1px solid rgba(48,54,61,.3);font-size:.82rem;align-items:center"><span style="color:var(--dim);font-size:.75rem;min-width:80px">\'+new Date(e.timestamp).toLocaleTimeString()+\'</span><span style="color:var(--purple);font-family:monospace;font-size:.75rem;min-width:160px">\'+e.topic+\'</span><span style="color:var(--text);font-size:.75rem">\'+detail+\'</span></div>\';}).join(\'\');}\n    document.getElementById(\'ts\').textContent=new Date().toLocaleTimeString()+\' | Auto 4s\';\n  }catch(e){console.error(e);}\n}\nfunction applyData(md){\n  const met=md.metrics||{};\n  aHist.push({s:md.latest_anomaly_score||0});if(aHist.length>60)aHist=aHist.slice(-60);\n  document.getElementById(\'kAn\').textContent=md.anomaly_count||0;\n  document.getElementById(\'kPr\').textContent=md.prediction_count||0;\n  document.getElementById(\'kMe\').textContent=Object.keys(met).length;\n  const aiE=md.ai_events||[];\n  document.getElementById(\'kEv\').textContent=aiE.length;\n  drawAnom();drawMet(met);\n  const mEl=document.getElementById(\'metList\');\n  const names=Object.keys(met);\n  if(!names.length){mEl.innerHTML=\'<div class="empty">No metrics yet</div>\';}\n  else{mEl.innerHTML=names.map(n=>{const v=met[n]||[];const last=v.length?v[v.length-1]:\'-\';const avg=v.length?(v.reduce((a,b)=>a+b,0)/v.length).toFixed(2):\'-\';return\'<div class="metric-row"><span class="label">\'+n+\'</span><span class="val" style="color:var(--blue)">\'+(typeof last===\'number\'?last.toFixed(2):last)+\'</span><span style="color:var(--dim);font-size:.7rem;margin-left:8px">avg:\'+avg+\'</span></div>\';}).join(\'\');}\n  const aEl=document.getElementById(\'aiEvts\');\n  if(!aiE.length){aEl.innerHTML=\'<div class="empty">No AI events yet</div>\';}\n  else{aEl.innerHTML=aiE.slice(0,30).map(e=>{const d=e.data||{};const detail=d.title||(d.risk?\'Risk: \'+d.risk:\'\');return\'<div style="display:flex;gap:10px;padding:8px;border-bottom:1px solid rgba(48,54,61,.3);font-size:.82rem;align-items:center"><span style="color:var(--dim);font-size:.75rem;min-width:80px">\'+new Date(e.timestamp).toLocaleTimeString()+\'</span><span style="color:var(--purple);font-family:monospace;font-size:.75rem;min-width:160px">\'+e.topic+\'</span><span style="color:var(--text);font-size:.75rem">\'+detail+\'</span></div>\';}).join(\'\');}\n  const st=md.monitor_status||\'active\',ag=md.agents_monitored||0,cyc=md.uptime_cycles||0;\n  document.getElementById(\'ts\').textContent=new Date().toLocaleTimeString()+\' | \'+st.toUpperCase()+\' | Agents: \'+ag+\' | Cycles: \'+cyc;\n}\nasync function load(){try{const r=await fetch(\'/api/ai/metrics\');applyData(await r.json());}catch(e){console.error(e);}}\nload();\nlet _sse=null,_sseFails=0;\nfunction connectSSE(){\n  _sse=new EventSource(\'/api/ai/live\');\n  _sse.onopen=function(){_sseFails=0;};\n  _sse.onmessage=function(ev){try{applyData(JSON.parse(ev.data));}catch(err){}};\n  _sse.onerror=function(){\n    _sse.close();\n    _sseFails++;\n    setTimeout(connectSSE,Math.min(5000*Math.pow(2,_sseFails-1),30000));\n    load();\n  };\n}\nconnectSSE();\n</script></body></html>'



# ---------------------------------------------------------------------------
# Threat Detection page template
# ---------------------------------------------------------------------------

_TMPL_SECURITY = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet">'
    '<title>Threat Detection &#8212; Network Guardian</title>'
    '<style nonce="{{NONCE}}">'
    ':root{--bg:#000810;--bg2:#010d1a;--card:rgba(0,18,36,0.92);--border:rgba(0,200,255,0.15);--text:#cce8ff;'
    '--dim:#3d7a9a;--blue:#0094d4;--green:#00ff88;--yellow:#ffcc00;'
    '--orange:#ff8c00;--red:#ff2244;--purple:#aa44ff;--cyan:#00d4ff;--pink:#ff00aa}'
    '@keyframes scan-h{0%{left:-100%;opacity:0}50%{opacity:1}100%{left:100%;opacity:0}}'
    '@keyframes pulse-glow{0%,100%{opacity:.5}50%{opacity:1}}'
    '@keyframes hud-boot{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}'
    '@keyframes spin{to{transform:rotate(360deg)}}'
    '*{margin:0;padding:0;box-sizing:border-box}'
    'body{background:var(--bg);background-image:radial-gradient(ellipse at 20% 50%,rgba(0,212,255,.04) 0%,transparent 50%),radial-gradient(ellipse at 80% 20%,rgba(0,100,255,.05) 0%,transparent 50%),linear-gradient(rgba(0,200,255,.015) 1px,transparent 1px),linear-gradient(90deg,rgba(0,200,255,.015) 1px,transparent 1px);background-size:auto,auto,50px 50px,50px 50px;color:var(--text);font-family:\'Rajdhani\',\'Segoe UI\',sans-serif;overflow-x:hidden}'
    '.wrap{max-width:1400px;margin:0 auto;padding:20px}'
    '.banner{display:flex;align-items:center;gap:16px;padding:16px 24px;background:linear-gradient(135deg,rgba(0,20,40,.97),rgba(0,8,20,.99));border:1px solid rgba(0,200,255,.22);border-radius:4px;margin-bottom:20px;flex-wrap:wrap;position:relative;overflow:hidden}'
    '.banner::before{content:\'\';position:absolute;top:0;left:-100%;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan-h 5s ease-in-out infinite}'
    '.banner h1{font-size:1.4rem;white-space:nowrap;font-family:\'Orbitron\',sans-serif;letter-spacing:3px;color:var(--cyan);text-shadow:0 0 20px rgba(0,212,255,.5)}'
    '.badge{padding:4px 12px;clip-path:polygon(6px 0%,100% 0%,calc(100% - 6px) 100%,0% 100%);border-radius:0;font-size:.75rem;font-weight:700;letter-spacing:.5px;font-family:\'Share Tech Mono\',monospace}'
    '.nav{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}'
    '.nav a{padding:8px 18px;clip-path:polygon(8px 0%,100% 0%,calc(100% - 8px) 100%,0% 100%);border-radius:0;border:1px solid rgba(0,200,255,.2);background:rgba(0,15,30,.7);color:var(--cyan);text-decoration:none;font-size:.72rem;font-family:\'Orbitron\',sans-serif;letter-spacing:1.5px;text-transform:uppercase;cursor:pointer;transition:.2s}'
    '.nav a:hover{background:rgba(0,212,255,.15);box-shadow:0 0 15px rgba(0,212,255,.25);color:#fff}.nav a.active{background:rgba(0,212,255,.18);border-color:var(--cyan);box-shadow:0 0 20px rgba(0,212,255,.3);color:var(--cyan)}'
    '.grid{display:grid;gap:16px}.g2{grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}'
    '.card{background:linear-gradient(135deg,rgba(0,22,44,.9),rgba(0,8,22,.95));border:1px solid rgba(0,200,255,.15);border-radius:4px;padding:20px;position:relative;box-shadow:0 0 25px rgba(0,212,255,.04),inset 0 1px 0 rgba(0,212,255,.08)}'
    '.card::before{content:\'\';position:absolute;top:-1px;left:-1px;width:18px;height:18px;border-top:2px solid var(--cyan);border-left:2px solid var(--cyan);box-shadow:-2px -2px 8px rgba(0,212,255,.3)}'
    '.card::after{content:\'\';position:absolute;bottom:-1px;right:-1px;width:18px;height:18px;border-bottom:2px solid var(--cyan);border-right:2px solid var(--cyan);box-shadow:2px 2px 8px rgba(0,212,255,.3)}'
    '.card h2{font-size:.85rem;font-family:\'Orbitron\',sans-serif;color:var(--cyan);text-transform:uppercase;letter-spacing:2px;margin-bottom:14px;text-shadow:0 0 15px rgba(0,212,255,.4)}'
    'table{width:100%;border-collapse:collapse;font-size:.82rem}'
    'th{text-align:left;font-family:\'Share Tech Mono\',monospace;color:var(--cyan);text-transform:uppercase;font-size:.68rem;letter-spacing:1.2px;padding:8px 6px;background:rgba(0,212,255,.05);border-bottom:1px solid rgba(0,200,255,.25)}'
    'td{font-family:\'Share Tech Mono\',monospace;font-size:.8rem;padding:8px 6px;border-bottom:1px solid rgba(0,200,255,.06)}'
    'tr:hover td{background:rgba(0,212,255,.04)}'
    '.kpi-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}'
    '.kpi{background:linear-gradient(135deg,rgba(0,20,40,.8),rgba(0,10,25,.85));border:1px solid rgba(0,200,255,.15);border-radius:4px;padding:14px 20px;min-width:130px;flex:1;position:relative;overflow:hidden}'
    '.kpi::after{content:\'\';position:absolute;bottom:0;left:-100%;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan-h 4s ease-in-out infinite alternate}'
    '.kpi .v{font-size:1.8rem;font-weight:700;font-family:\'Orbitron\',sans-serif;color:var(--cyan);text-shadow:0 0 15px rgba(0,212,255,.5)}.kpi .l{font-size:.65rem;font-family:\'Share Tech Mono\',monospace;color:var(--dim);text-transform:uppercase;letter-spacing:1px}'
    '.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.7rem;font-weight:600}'
    '.sev-critical{background:rgba(255,34,68,.15);color:var(--red);box-shadow:0 0 8px rgba(255,34,68,.2)}.sev-high{background:rgba(255,140,0,.15);color:var(--orange);box-shadow:0 0 8px rgba(255,140,0,.2)}'
    '.sev-medium{background:rgba(255,204,0,.15);color:var(--yellow)}.sev-low{background:rgba(0,255,136,.15);color:var(--green);box-shadow:0 0 8px rgba(0,255,136,.2)}'
    '.empty{color:var(--dim);font-style:normal;font-family:\'Share Tech Mono\',monospace;letter-spacing:1px;padding:20px;text-align:center}'
    '.scan-btn{display:inline-flex;align-items:center;gap:8px;padding:10px 20px;clip-path:polygon(8px 0%,100% 0%,calc(100% - 8px) 100%,0% 100%);border-radius:0;border:1px solid var(--green);background:rgba(0,255,136,.08);color:var(--green);font-size:.75rem;font-family:\'Orbitron\',sans-serif;letter-spacing:1px;cursor:pointer;transition:.2s;box-shadow:0 0 12px rgba(0,255,136,.1)}'
    '.scan-btn:hover{background:rgba(0,255,136,.18);box-shadow:0 0 20px rgba(0,255,136,.3)}.scan-btn:disabled{opacity:.4;cursor:not-allowed}'
    '.scan-btn.danger{border-color:var(--red);background:rgba(255,34,68,.08);color:var(--red);box-shadow:0 0 12px rgba(255,34,68,.1)}'
    '.scan-btn.danger:hover{background:rgba(255,34,68,.18);box-shadow:0 0 20px rgba(255,34,68,.3)}'
    '.spin{display:inline-block;width:14px;height:14px;border:2px solid rgba(63,185,80,.3);border-top-color:var(--green);border-radius:50%;animation:spin .7s linear infinite}'
    '@keyframes spin{to{transform:rotate(360deg)}}'
    '.alert-row{display:flex;gap:8px;padding:10px;border-bottom:1px solid rgba(48,54,61,.3);font-size:.82rem;align-items:flex-start}'
    '.alert-row:last-child{border-bottom:none}'
    '.alert-time{color:var(--dim);font-size:.75rem;min-width:80px;padding-top:2px;white-space:nowrap}'
    '</style></head><body>'
    '<div class="wrap">'
    '<div class="banner"><h1>&#128737; Threat Detection</h1>'
    '<span id="overallBadge" class="badge" style="background:rgba(63,185,80,.15);color:var(--green)">&#10003; All Clear</span>'
    '<span id="ts" style="margin-left:auto;color:var(--dim);font-size:.85rem"></span></div>'
    '<div class="kpi-row">'
    '<div class="kpi"><div class="v" id="kProcs" style="color:var(--blue)">&#8212;</div><div class="l">Processes Checked</div></div>'
    '<div class="kpi"><div class="v" id="kSusp" style="color:var(--red)">&#8212;</div><div class="l">Suspicious</div></div>'
    '<div class="kpi"><div class="v" id="kAlerts" style="color:var(--orange)">0</div><div class="l">Ransomware Alerts</div></div>'
    '<div class="kpi"><div class="v" id="kMon" style="color:var(--dim)">STOPPED</div><div class="l">Monitor Status</div></div>'
    '</div>'
    '<div class="nav"><a href="/">Dashboard</a><a href="/ids">IDS</a><a href="/ips">IPS</a>'
    '<a href="/wifi">WiFi</a><a href="/cloaking">Cloaking</a><a href="/explorer">Explorer</a>'
    '<a href="/auditor">Auditor</a><a href="/ai">AI Engine</a><a href="/fleet">Fleet</a>'
    '<a href="/reports">Reports</a><a href="/incidents">Incidents</a>'
    '<a href="/security" class="active">&#128737; Threats</a></div>'
    '<div class="grid g2">'
    '<div class="card"><h2>&#128030; Malware Process Scanner</h2>'
    '<p style="color:var(--dim);font-size:.83rem;margin-bottom:16px">'
    'Scans all running processes for suspicious names, paths, and behaviour indicators.</p>'
    '<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap">'
    '<button class="scan-btn" id="btnScan">&#9654; Run ReAct Scan</button>'
    '<span id="lastScan" style="color:var(--dim);font-size:.78rem"></span></div>'
    '<div id="scanResults"><div class="empty">Press &ldquo;Run Scan&rdquo; to check running processes</div></div></div>'
    '<div class="card"><h2>&#128274; Ransomware Monitor</h2>'
    '<p style="color:var(--dim);font-size:.83rem;margin-bottom:16px">'
    'Watches the filesystem in real time for ransomware-style burst activity and suspicious extensions.</p>'
    '<div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap">'
    '<button class="scan-btn" id="btnMon">&#9654; Start ReAct Monitor</button>'
    '<span id="monStatus" class="badge" style="background:rgba(139,148,158,.15);color:var(--dim)">STOPPED</span></div>'
    '<div style="font-size:.82rem;color:var(--dim);margin-bottom:12px">'
    'Watch folder: <span id="watchFolder" style="color:var(--text);font-family:monospace;font-size:.8rem">&#8212;</span></div>'
    '<div id="ransomAlerts"><div class="empty">No ransomware alerts</div></div></div>'
    '</div></div>'
    '<script nonce="{{NONCE}}">'
    'var _scanning=false,_monRunning=false,_alertTotal=0;'
    'function esc(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}'
    'function sevColor(s){'
    '  if(s==="critical")return "var(--red)";'
    '  if(s==="high")return "#f56e30";'
    '  if(s==="low")return "var(--green)";'
    '  return "var(--orange)";'
    '}'
    'function runScan(){'
    '  if(_scanning)return;'
    '  _scanning=true;'
    '  var btn=document.getElementById("btnScan");'
    '  btn.disabled=true;'
    '  btn.innerHTML=\'<span class="spin"></span> Running ReAct...\';'
    '  fetch("/api/control/malware/scan",{method:"POST",'
    '    headers:{"Content-Type":"application/json","X-Requested-With":"XMLHttpRequest"},'
    '    body:"{}"})'
    '  .then(function(r){'
    '    if(!r.ok){'
    '      if(r.status===401){window.location.href="/login?next=/security";}'
    '      throw new Error("HTTP "+r.status);'
    '    }'
    '    return r.json();'
    '  })'
    '  .then(function(d){'
    '    _scanning=false;btn.disabled=false;btn.innerHTML="&#9654; Run ReAct Scan";'
    '    renderMalwareResults(d);'
    '  })'
    '  .catch(function(e){'
    '    _scanning=false;btn.disabled=false;btn.innerHTML="&#9654; Run ReAct Scan";'
    '    document.getElementById("scanResults").innerHTML='
    '      \'<div class="empty" style="color:var(--red)">Scan error: \'+esc(e.message)+\'</div>\';'
    '  });'
    '}'
    'function renderMalwareResults(d){'
    '  var el=document.getElementById("scanResults");'
    '  var sc=d.scanned||0,fi=d.findings||[],er=d.errors||0;'
    '  var rl=d.risk_level||"low",ts=d.threat_score||0,steps=d.react_steps||0;'
    '  document.getElementById("kProcs").textContent=sc;'
    '  document.getElementById("kSusp").textContent=fi.length;'
    '  document.getElementById("lastScan").textContent='
    '    "Last ReAct: "+new Date().toLocaleTimeString()+'
    '    " | Risk: "+rl.toUpperCase()+" | Score: "+ts+"/100 | Steps: "+steps;'
    '  updateOverallBadge();'
    '  var pdfHtml="";'
    '  if(d.pdf_file){'
    '    pdfHtml=\'<div style="margin-top:10px">\''
    '      +\'<a href="/api/reports/pdf/\'+encodeURIComponent(d.pdf_file)+\'" target="_blank"\''
    '      +\' style="display:inline-flex;align-items:center;gap:6px;padding:7px 14px;\''
    '      +\'background:rgba(30,120,222,.15);border:1px solid rgba(30,120,222,.4);\''
    '      +\'border-radius:6px;color:var(--blue);text-decoration:none;font-size:.82rem">\''
    '      +\'&#128196; Download ReAct PDF Report</a></div>\';'
    '  }'
    '  if(!fi.length){'
    '    el.innerHTML='
    '      \'<div style="display:flex;align-items:center;gap:10px;padding:14px;\''
    '      +\'background:rgba(63,185,80,.08);border:1px solid rgba(63,185,80,.3);border-radius:8px">\''
    '      +\'<span style="font-size:1.5rem">&#10003;</span>\''
    '      +\'<div><div style="color:var(--green);font-weight:700">All Clear &mdash; ReAct Cycle Complete</div>\''
    '      +\'<div style="color:var(--dim);font-size:.78rem">\'+sc+\' processes scanned\''
    '      +(er?\' &mdash; \'+er+\' errors\':\'\')+'
    '      \'</div></div></div>\'+pdfHtml;'
    '    return;'
    '  }'
    '  var rows=fi.map(function(f){'
    '    var sc2=sevColor(f.severity||"medium");'
    '    return \'<tr>\''
    '      +\'<td><code style="font-size:.78rem">\'+esc(f.pid||"")+\'</code></td>\''
    '      +\'<td><span style="color:var(--orange);font-weight:600">\'+esc(f.name||"?")+\'</span></td>\''
    '      +\'<td><code style="font-size:.72rem;color:var(--dim)">\'+esc((f.exe||"").slice(0,55))+\'</code></td>\''
    '      +\'<td><span style="color:\'+sc2+\';font-size:.75rem;font-weight:700">\''
    '        +esc((f.severity||"medium").toUpperCase())+\'</span></td>\''
    '      +\'<td><span class="pill sev-high">\'+esc(f.matched_reason||"suspicious")+\'</span></td>\''
    '      +\'</tr>\';'
    '  }).join("");'
    '  el.innerHTML='
    '    \'<div style="color:var(--red);font-weight:700;margin-bottom:10px">\''
    '    +\'&#9888; \'+fi.length+\' Suspicious Process\'+(fi.length!==1?"es":"")+\' Found\''
    '    +\' &mdash; Risk: <span style="color:\'+sevColor(rl)+\'">\'+rl.toUpperCase()+\'</span></div>\''
    '    +\'<div style="overflow-x:auto"><table>\''
    '    +\'<thead><tr><th>PID</th><th>Process</th><th>Executable</th><th>Sev</th><th>Reason</th></tr></thead>\''
    '    +\'<tbody>\'+rows+\'</tbody></table></div>\''
    '    +pdfHtml;'
    '}'
    'function toggleMonitor(){'
    '  var url=_monRunning?"/api/control/ransomware/stop":"/api/control/ransomware/start";'
    '  var btn=document.getElementById("btnMon");'
    '  btn.disabled=true;'
    '  fetch(url,{method:"POST",'
    '    headers:{"Content-Type":"application/json","X-Requested-With":"XMLHttpRequest"},'
    '    body:"{}"})'
    '  .then(function(r){'
    '    if(!r.ok){'
    '      if(r.status===401){window.location.href="/login?next=/security";}'
    '      throw new Error("HTTP "+r.status);'
    '    }'
    '    return r.json();'
    '  })'
    '  .then(function(d){btn.disabled=false;setTimeout(loadStatus,400);})'
    '  .catch(function(e){'
    '    btn.disabled=false;'
    '    document.getElementById("ransomAlerts").innerHTML='
    '      \'<div class="empty" style="color:var(--red)">Monitor error: \'+esc(String(e))+\'</div>\';'
    '  });'
    '}'
    'function loadStatus(){'
    '  fetch("/api/ransomware/status")'
    '  .then(function(r){'
    '    if(r.status===401){window.location.href="/login?next=/security";throw new Error("401");}'
    '    if(!r.ok){throw new Error("HTTP "+r.status);}'
    '    return r.json();'
    '  })'
    '  .then(function(d){'
    '    _monRunning=d.running||false;'
    '    _alertTotal=d.alert_count||0;'
    '    document.getElementById("kAlerts").textContent=_alertTotal;'
    '    document.getElementById("kMon").textContent=_monRunning?"RUNNING":"STOPPED";'
    '    document.getElementById("kMon").style.color=_monRunning?"var(--green)":"var(--dim)";'
    '    var badge=document.getElementById("monStatus");'
    '    badge.textContent=_monRunning?"RUNNING":"STOPPED";'
    '    badge.style.background=_monRunning?"rgba(63,185,80,.15)":"rgba(139,148,158,.15)";'
    '    badge.style.color=_monRunning?"var(--green)":"var(--dim)";'
    '    var btn=document.getElementById("btnMon");'
    '    btn.innerHTML=_monRunning?"&#9632; Stop ReAct Monitor":"&#9654; Start ReAct Monitor";'
    '    btn.className=_monRunning?"scan-btn danger":"scan-btn";'
    '    document.getElementById("watchFolder").textContent=d.watch_folder||"&#8212;";'
    '    renderAlerts(d.recent_alerts||[],d.last_pdf||null);'
    '    document.getElementById("ts").textContent=new Date().toLocaleTimeString()+" | Auto 3s";'
    '    updateOverallBadge();'
    '  })'
    '  .catch(function(e){});'
    '}'
    'function renderAlerts(alerts,lastPdf){'
    '  var el=document.getElementById("ransomAlerts");'
    '  var pdfHtml="";'
    '  if(lastPdf){'
    '    pdfHtml=\'<div style="margin-bottom:10px">\''
    '      +\'<a href="/api/reports/pdf/\'+encodeURIComponent(lastPdf)+\'" target="_blank"\''
    '      +\' style="display:inline-flex;align-items:center;gap:6px;padding:7px 14px;\''
    '      +\'background:rgba(30,120,222,.15);border:1px solid rgba(30,120,222,.4);\''
    '      +\'border-radius:6px;color:var(--blue);text-decoration:none;font-size:.82rem">\''
    '      +\'&#128196; Download Latest ReAct PDF Report</a></div>\';'
    '  }'
    '  if(!alerts.length){'
    '    el.innerHTML=pdfHtml+\'<div class="empty">No ransomware alerts</div>\';'
    '    return;'
    '  }'
    '  el.innerHTML=pdfHtml+alerts.slice(0,20).map(function(a){'
    '    var k=a.kind==="extension"?"Ransomware Extension Detected":"Burst File Activity";'
    '    return \'<div class="alert-row">\''
    '      +\'<span class="alert-time">\'+new Date(a.timestamp*1000).toLocaleTimeString()+\'</span>\''
    '      +\'<div><div style="color:var(--red);font-weight:600">&#9888; \'+k+\'</div>\''
    '      +\'<div style="color:var(--dim);font-size:.78rem">\'+esc(a.detail||"")+\'</div></div></div>\';'
    '  }).join("");'
    '}'
    'function updateOverallBadge(){'
    '  var susp=parseInt(document.getElementById("kSusp").textContent)||0;'
    '  var badge=document.getElementById("overallBadge");'
    '  if(susp>0||_alertTotal>0){'
    '    badge.innerHTML="&#9888; Threats Detected";'
    '    badge.style.background="rgba(248,81,73,.15)";'
    '    badge.style.color="var(--red)";'
    '  } else if(document.getElementById("kProcs").textContent!=="&#8212;"){'
    '    badge.innerHTML="&#10003; All Clear";'
    '    badge.style.background="rgba(63,185,80,.15)";'
    '    badge.style.color="var(--green)";'
    '  }'
    '}'
    'document.getElementById("btnScan").addEventListener("click",runScan);'
    'document.getElementById("btnMon").addEventListener("click",toggleMonitor);'
    'loadStatus();'
    'setInterval(loadStatus,3000);'
    '</script></body></html>'
)


# ---------------------------------------------------------------------------
# Data serialisation helpers
# ---------------------------------------------------------------------------


def _serialise(obj: Any) -> Any:
    """Make dataclass / datetime JSON-serialisable."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _serialise(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _serialise(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_serialise(v) for v in obj]
    if hasattr(obj, "value"):  # Enum
        return obj.value
    return obj


# ---------------------------------------------------------------------------
# Dashboard server
# ---------------------------------------------------------------------------


class Dashboard:
    """Lightweight async HTTP dashboard.

    Uses only the stdlib ``http.server``-style pattern over raw asyncio
    sockets so we have zero extra dependencies for the foundation layer.
    A production build should swap this for aiohttp or FastAPI.
    """

    # Security: max header bytes to read before rejecting (8 KB)
    MAX_HEADER_BYTES = 8192
    # Security: request read timeout in seconds
    REQUEST_TIMEOUT = 10.0
    # Security: rate-limit window (seconds) and max requests per IP
    RATE_LIMIT_WINDOW = 60.0
    RATE_LIMIT_MAX = 200

    # CSP nonce is regenerated each startup
    _csp_nonce: str = ""

    def __init__(self, engine: Engine, host: str = "127.0.0.1", port: int | None = None) -> None:
        self.engine = engine
        self.host = host
        self.port = port or int(os.environ.get("NG_DASHBOARD_PORT", "8080"))
        self._server: asyncio.Server | None = None
        self._recent_events: list[dict[str, Any]] = []
        self._api_key: str | None = None
        # Rate limiting: {ip: [timestamps]}
        self._rate_tracker: dict[str, list[float]] = {}

        import secrets
        Dashboard._csp_nonce = secrets.token_urlsafe(16)

        # Team-based authentication
        from pathlib import Path
        data_dir = Path.home() / ".network_guardian"
        self._team = TeamStore(data_dir)

        # If no team members exist, prompt admin to create one via CLI
        if not self._team.has_members():
            self._team.add_member("admin", "Admin", "<password>", role="admin")
            logger.warning(
                "\n" + "=" * 60 + "\n"
                "  WOLFPAK TEAM ACCOUNTS\n"
                "  Default admin created:\n"
                "    Username: admin\n"
                "    Password: <password>\n\n"
                "  CHANGE THIS PASSWORD IMMEDIATELY after login!\n"
                "  Team data: %s\n"
                + "=" * 60,
                data_dir / "wolfpak_team.json",
            )
        else:
            members = self._team.list_members()
            logger.info(
                "Loaded %d Wolfpak team members. Expired: %d",
                len(members),
                sum(1 for m in members if m["expired"]),
            )

        # Keep api_key as the server secret for sessions
        self._api_key = self._team.server_secret

        # Fleet agent registry
        self._fleet = FleetStore(data_dir)
        logger.info("Fleet key: %s", self._fleet.fleet_key[:8] + "...")

        # Wolfpak admin client registry
        self._wolfpak = WolfpakClientStore()

        # ReAct cloaking agent
        from network_guardian.cloaking.react_agent import CloakingAgent
        self._cloak_agent = CloakingAgent(data_dir)

        # Brute-force protection tracker
        self._login_attempts: dict[str, list[float]] = {}

        # 24/7 AI monitor state — rolling time-series + live events
        self._ai_state: dict[str, Any] = {
            "metrics": {
                "threat_score": [],
                "connections": [],
                "external_conns": [],
                "net_drift_%": [],
                "proc_drift_%": [],
                "processes": [],
                "listening_ports": [],
            },
            "anomaly_count": 0,
            "assessment_count": 0,
            "latest_score": 0.0,
            "ai_events": [],          # newest-first, capped at 500
            "last_tick": "",
            "uptime_cycles": 0,
            "agents_monitored": 0,
            "status": "starting",
        }
        self._ai_monitor_task: asyncio.Task | None = None

        # Threat detection module state
        self._ransomware_monitor: Any = None   # RansomwareReActAgent when started
        self._malware_react_agent: Any = None   # MalwareReActAgent singleton
        self._last_malware_scan: dict = {}

        # Subscribe to key events for the live feed
        for topic in ("audit.finding", "monitor.anomaly", "ai.anomaly_detected",
                       "explorer.discovery_complete", "automator.task_complete",
                       "ips.block", "ips.unblock", "ips.rate_limit",
                       "ips.quarantine", "ips.quarantine_release", "ips.started",
                       "ids.alert", "ids.started", "ids.correlation",
                       "ransomware.alert"):
            engine.event_bus.subscribe(topic, self._capture_event)

    def _capture_event(self, event: Event) -> None:
        entry = {"topic": event.topic, "data": _serialise(event.data),
                 "timestamp": event.timestamp.isoformat()}
        self._recent_events.append(entry)
        # Keep only last 200 events in memory
        if len(self._recent_events) > 200:
            self._recent_events = self._recent_events[-200:]

    # -- HTTP handling --------------------------------------------------

    def _check_rate_limit(self, client_ip: str) -> bool:
        """Return True if the request should be rejected (rate exceeded)."""
        import time as _time
        now = _time.monotonic()
        window = self.RATE_LIMIT_WINDOW
        timestamps = self._rate_tracker.get(client_ip, [])
        # Prune old entries for this IP
        timestamps = [t for t in timestamps if now - t < window]
        timestamps.append(now)
        self._rate_tracker[client_ip] = timestamps
        # Evict stale IPs to prevent unbounded memory growth
        if len(self._rate_tracker) > 200:
            self._rate_tracker = {
                ip: ts for ip, ts in self._rate_tracker.items()
                if ts and now - ts[-1] < window
            }
        return len(timestamps) > self.RATE_LIMIT_MAX

    def _check_auth(self, headers: dict[str, str], return_data: bool = False) -> bool | dict:
        """Return True if authenticated via session cookie.

        If return_data=True, returns a dict with session info on success
        or an empty dict on failure (for extracting username etc.).
        """
        if not self._api_key:
            return {} if return_data else False  # Fail-closed: no secret = no access
        # Session cookie
        for part in headers.get("cookie", "").split(";"):
            part = part.strip()
            if part.startswith("ng_session="):
                token = part[len("ng_session="):]
                username = verify_session_token(
                    token, self._api_key, self._csp_nonce, self._team
                )
                if username:
                    return {"username": username} if return_data else True
        return {} if return_data else False

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        client_ip = "unknown"
        try:
            peername = writer.get_extra_info("peername")
            if peername:
                client_ip = peername[0]

            # Rate limiting
            if self._check_rate_limit(client_ip):
                writer.write(self._http_response(429, _CONTENT_TEXT, "Too Many Requests").encode())
                await writer.drain()
                logger.warning("Rate limit exceeded for %s", client_ip)
                return

            # Read request line with timeout
            request_line = await asyncio.wait_for(
                reader.readline(), timeout=self.REQUEST_TIMEOUT
            )
            parts = request_line.decode(errors="replace").strip().split()
            if len(parts) < 2:
                writer.close()
                return

            method, raw_path = parts[0], parts[1]
            # Strip query string for routing (keep clean path only)
            path = raw_path.split("?", 1)[0] if "?" in raw_path else raw_path

            # Consume headers (with size limit)
            headers: dict[str, str] = {}
            total_header_bytes = len(request_line)
            while True:
                header_line = await asyncio.wait_for(
                    reader.readline(), timeout=self.REQUEST_TIMEOUT
                )
                total_header_bytes += len(header_line)
                if total_header_bytes > self.MAX_HEADER_BYTES:
                    writer.write(
                        self._http_response(431, _CONTENT_TEXT,
                                            "Request Header Fields Too Large").encode()
                    )
                    await writer.drain()
                    return
                if header_line in (b"\r\n", b"\n", b""):
                    break
                decoded = header_line.decode(errors="replace").strip()
                if ":" in decoded:
                    k, v = decoded.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            # POST handling with CSRF + Content-Type validation
            body = b""
            if method.upper() == "POST":
                if path not in ("/api/auth/login", "/api/auth/change-password") \
                   and not path.startswith("/api/control/") \
                   and not path.startswith("/api/team/") \
                   and not path.startswith("/api/fleet/report") \
                   and not path.startswith("/api/fleet/register") \
                   and not path.startswith("/api/fleet/auth"):
                    writer.write(self._http_response(405, _CONTENT_TEXT, "Method Not Allowed").encode())
                    await writer.drain()
                    return
                # CSRF: require custom header (blocks cross-origin form posts)
                if headers.get("x-requested-with") != "XMLHttpRequest":
                    writer.write(self._http_response(403, _CONTENT_TEXT, "Forbidden").encode())
                    await writer.drain()
                    return
                # Content-Type must be JSON
                if not headers.get("content-type", "").startswith("application/json"):
                    writer.write(self._http_response(415, _CONTENT_TEXT, "Unsupported Media Type").encode())
                    await writer.drain()
                    return
                try:
                    content_length = int(headers.get("content-length", "0"))
                except ValueError:
                    writer.write(self._http_response(400, _CONTENT_TEXT, "Bad Request").encode())
                    await writer.drain()
                    return
                # Agent reports can be larger than normal payloads
                max_body = 262144 if path.startswith("/api/fleet/") else 4096
                if content_length > max_body:
                    writer.write(self._http_response(413, _CONTENT_TEXT, "Payload Too Large").encode())
                    await writer.drain()
                    return
                if content_length > 0:
                    body = await asyncio.wait_for(
                        reader.read(content_length), timeout=self.REQUEST_TIMEOUT
                    )
            elif method.upper() not in ("GET", "HEAD"):
                writer.write(self._http_response(405, _CONTENT_TEXT, "Method Not Allowed").encode())
                await writer.drain()
                return

            # Agent endpoints use HMAC auth instead of session auth
            _AGENT_PATHS = ("/api/fleet/report", "/api/fleet/register", "/api/fleet/auth")

            # Authentication gate — all routes except login & agent endpoints
            if path not in ("/login", "/api/auth/login", "/api/auth/change-password") \
               and not path.startswith(tuple(_AGENT_PATHS)) \
               and not self._check_auth(headers):
                if path.startswith("/api/"):
                    writer.write(self._http_response(401, _CONTENT_TEXT, "Unauthorized").encode())
                else:
                    writer.write(self._http_response(
                        302, _CONTENT_TEXT, "Redirecting",
                        extra_headers=f"Location: /login?next={path}\r\n").encode())
                await writer.drain()
                logger.warning("Unauthenticated request from %s: %s %s", client_ip, method, path)
                return

            # Record wolfpak admin client if headers present (runs after auth gate)
            wp_tag    = headers.get("x-wp-tag", "").strip()
            wp_client = headers.get("x-wp-client", "").strip()
            wp_host   = headers.get("x-wp-host", "").strip()
            if wp_tag and wp_client and path not in ("/api/auth/login", "/api/auth/change-password"):
                session_data = self._check_auth(headers, return_data=True)
                wp_user = (session_data or {}).get("username", "")
                self._wolfpak.record(wp_tag, wp_host, wp_client, wp_user, path, client_ip)

            # Route to handler
            if path == "/api/auth/login":
                response = await self._auth_login(body, client_ip, headers)
            elif path == "/api/auth/change-password":
                response = await self._auth_change_password(body, client_ip)
            elif path.startswith("/api/team/"):
                response = await self._team_route(path, body, headers)
            elif path.startswith("/api/control/"):
                response = await self._control_route(path, body)
            elif path == "/api/fleet/report":
                response = self._fleet_report(body, headers)
            elif path == "/api/fleet/register":
                response = self._fleet_register(body, headers)
            elif path == "/api/fleet/auth":
                response = self._fleet_auth(body, headers)
            elif path == "/api/fleet/key":
                # Fleet key is sensitive — admin role required
                _session = self._check_auth(headers, return_data=True)
                _user = ((_session or {}).get("username", ""))
                _member = self._team.members.get(_user) if _user else None
                if not _member or _member.get("role") != "admin":
                    response = self._http_response(403, _CONTENT_TEXT, "Admin access required")
                else:
                    response = self._route(path)
            elif path == "/api/ai/live":
                # SSE — takes over the connection; returns without writing a response
                await self._sse_ai_live(writer)
                return
            else:
                response = self._route(path)
            # Handle binary PDF responses
            if isinstance(response, str) and response.startswith("__PDF__"):
                await self._api_serve_pdf(response[len("__PDF__"):], writer)
                return
            writer.write(response.encode())
            await writer.drain()
            logger.debug("Request from %s: %s %s", client_ip, method, path)
        except asyncio.TimeoutError:
            logger.debug("Request timeout for %s", client_ip)
        except Exception:
            logger.debug("Dashboard client error from %s", client_ip, exc_info=True)
        finally:
            writer.close()

    def _route(self, path: str) -> str:
        routes: dict[str, Any] = {
            "/login": self._page_login,
            "/logout": self._page_logout,
            "/": self._page_index,
            "/ids": self._page_ids,
            "/ips": self._page_ips,
            "/wifi": self._page_wifi,
            "/cloaking": self._page_cloaking,
            "/explorer": self._page_explorer,
            "/auditor": self._page_auditor,
            "/ai": self._page_ai,
            "/reports": self._page_reports,
            "/incidents": self._page_incidents,
            "/api/fleet/incidents": self._api_fleet_all_incidents,
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
            "/api/cloaking/react": self._api_cloaking_react,
            "/api/cloaking/networks": self._api_cloaking_networks,
            "/api/explorer/topology": self._api_explorer_topology,
            "/api/ai/metrics": self._api_ai_metrics,
            "/fleet": self._page_fleet,
            "/api/fleet/list": self._api_fleet_list,
            "/api/fleet/key": self._api_fleet_key,
            "/api/fleet/threats": self._api_fleet_threats,
            "/api/fleet/reports": self._api_fleet_all_reports,
            "/api/wolfpak/clients": self._api_wolfpak_clients,
            "/security": self._page_security,
            "/api/malware/results": self._api_malware_results,
            "/api/ransomware/status": self._api_ransomware_status,
        }

        # PDF download (dynamic path)
        if path.startswith("/api/reports/pdf/"):
            return "__PDF__" + path   # sentinel — handled in _handle_client

        # Dynamic fleet routes
        if path.startswith("/api/fleet/agent/") and "/diagnostics" in path:
            return self._api_fleet_agent_diagnostics(path)
        if path.startswith("/api/fleet/agent/") and "/threats" in path:
            return self._api_fleet_agent_threats(path)
        if path.startswith("/api/fleet/agent/") and "/reports" in path:
            return self._api_fleet_agent_reports(path)
        if path.startswith("/api/fleet/agent/") and "/incidents" in path:
            return self._api_fleet_agent_incidents(path)
        if path.startswith("/api/fleet/agent/") and "/sentinel" in path:
            return self._api_fleet_agent_sentinel(path)
        if path.startswith("/api/fleet/agent/"):
            return self._api_fleet_agent(path)

        handler = routes.get(path)
        if handler is None:
            return self._http_response(404, _CONTENT_TEXT, "Not Found")
        return handler()

    # -- API endpoints --------------------------------------------------

    def _api_status(self) -> str:
        data = {
            "engine_running": self.engine.is_running,
            "data_dir": str(self.engine.config.data_dir),
            "subsystems": {
                "auditor": self.engine._auditor is not None,
                "monitor": self.engine._monitor is not None,
                "explorer": self.engine._explorer is not None,
                "automator": self.engine._automator is not None,
            },
        }
        return self._json_response(data)

    def _api_findings(self) -> str:
        findings = self.engine.auditor.findings if self.engine._auditor else []
        return self._json_response([_serialise(f) for f in findings])

    def _api_events(self) -> str:
        return self._json_response(self._recent_events[-50:])

    def _api_hosts(self) -> str:
        hosts = self.engine.explorer.hosts if self.engine._explorer else {}
        if not hosts:
            # Fall back to aggregated fleet agent discovery data
            merged: dict[str, dict] = {}
            for aid, agent in self._fleet._data.get("agents", {}).items():
                report = agent.get("last_report") or {}
                for h in report.get("discovered_hosts", []):
                    ip = h.get("ip", "")
                    if ip and ip not in merged:
                        merged[ip] = h
            return self._json_response(merged)
        return self._json_response({ip: _serialise(h) for ip, h in hosts.items()})

    def _api_tasks(self) -> str:
        tasks = self.engine.automator.list_tasks() if self.engine._automator else []
        history = self.engine.automator.history if self.engine._automator else []
        return self._json_response({
            "registered": [{"name": t.name, "description": t.description} for t in tasks],
            "history": [_serialise(r) for r in history[-20:]],
        })

    def _api_health(self) -> str:
        return self._json_response({"status": "ok", "engine_running": self.engine.is_running})


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

    def _fleet_wifi_networks(self) -> list[dict]:
        """Aggregate WiFi networks from all fleet agent reports."""
        seen: dict[str, dict] = {}
        for aid, agent in self._fleet._data.get("agents", {}).items():
            report = agent.get("last_report") or {}
            for net in report.get("wifi_networks", []):
                ssid = net.get("ssid") or net.get("SSID") or ""
                key = ssid or net.get("bssid") or net.get("BSSID") or str(net)
                if key not in seen:
                    seen[key] = net
        return list(seen.values())

    def _api_wifi_networks(self) -> str:
        ws = self.engine.wifi_stealth
        scanner = ws._scanner if hasattr(ws, '_scanner') else None
        nets = getattr(scanner, '_last_scan', None) if scanner else None
        if not nets:
            # Fall back to fleet agent data
            fleet_nets = self._fleet_wifi_networks()
            return self._json_response(fleet_nets)
        return self._json_response([n.as_dict if hasattr(n, 'as_dict') else _serialise(n) for n in nets])

    def _api_wifi_status(self) -> str:
        ws = self.engine.wifi_stealth
        scanner = ws._scanner if hasattr(ws, '_scanner') else None
        connected = getattr(scanner, '_last_connected', None) if scanner else None
        # If no cached connected info yet, fetch it synchronously
        if connected is None and scanner and hasattr(scanner, '_connected_sync'):
            try:
                connected = scanner._connected_sync()
                if connected:
                    scanner._last_connected = connected
            except Exception:
                pass
        # Fall back to most recent fleet agent report for connected network
        if connected is None:
            for aid, agent in self._fleet._data.get("agents", {}).items():
                report = agent.get("last_report") or {}
                nets = report.get("wifi_networks", [])
                for net in nets:
                    if net.get("connected") or net.get("is_connected"):
                        connected = net
                        break
                if connected:
                    break
        fleet_nets = self._fleet_wifi_networks()
        scans_total = sum(
            a.get("report_count", 0)
            for a in self._fleet._data.get("agents", {}).values()
        ) if not getattr(ws, '_stats_scans', 0) else getattr(ws, '_stats_scans', 0)
        return self._json_response({
            "scans": scans_total,
            "connected": connected.as_dict if connected and hasattr(connected, 'as_dict') else (connected if isinstance(connected, dict) else None),
            "stealth_active": getattr(ws, '_stealth_active', False),
            "home_ssid": getattr(ws, '_home_ssid', None),
        })

    # -- Cloaking API endpoints -------------------------------------------

    def _api_cloaking_status(self) -> str:
        ip_system = self.engine.cloaking
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
            "react_agent": self._cloak_agent.status,
        })

    def _api_cloaking_react(self) -> str:
        """Return the ReAct reasoning log."""
        return self._json_response({
            "log": self._cloak_agent.react_log,
            "observation": self._cloak_agent.current_observation,
            "status": self._cloak_agent.status,
        })

    def _api_cloaking_networks(self) -> str:
        """Return learned network profiles."""
        return self._json_response({
            "profiles": self._cloak_agent.learned_profiles,
            "total": len(self._cloak_agent.learned_profiles),
        })

    # -- Explorer API endpoints -------------------------------------------

    def _api_explorer_topology(self) -> str:
        explorer = self.engine._explorer
        if explorer is not None:
            topo = getattr(explorer, '_topology', None) or {}
            if topo:
                return self._json_response({k: list(v) if isinstance(v, (set, frozenset)) else v for k, v in topo.items()})
        # Build topology from fleet agent reports (gateway → hosts)
        topo: dict[str, list[str]] = {}
        for aid, agent in self._fleet._data.get("agents", {}).items():
            report = agent.get("last_report") or {}
            gateway = report.get("gateway", "")
            hosts = [h.get("ip", "") for h in report.get("discovered_hosts", []) if h.get("ip")]
            if gateway and hosts:
                bucket = topo.setdefault(gateway, [])
                for ip in hosts:
                    if ip not in bucket:
                        bucket.append(ip)
        return self._json_response(topo)

    # -- AI / Monitor API endpoints ---------------------------------------

    def _api_ai_metrics(self) -> str:
        """Serve live AI metrics from the 24/7 background monitor state."""
        state = self._ai_state
        score = state["latest_score"]
        confidence = _ethics_check_confidence(score)
        return self._json_response({
            "metrics":              state["metrics"],
            "anomaly_count":        state["anomaly_count"],
            "prediction_count":     state["assessment_count"],
            "latest_anomaly_score": score,
            "ai_events":            state["ai_events"][:100],
            "uptime_cycles":        state["uptime_cycles"],
            "agents_monitored":     state["agents_monitored"],
            "last_tick":            state["last_tick"],
            "monitor_status":       state["status"],
            # Pillar 5: Transparency — every AI response discloses origin and confidence
            "_ai_transparency": _ethics_transparency_meta(
                score=score,
                reasoning=(
                    f"monitor_status={state['status']}, "
                    f"agents={state['agents_monitored']}, "
                    f"cycles={state['uptime_cycles']}"
                ),
                engine="network_guardian_ai_monitor",
            ),
            # Pillar 4: Misinformation guard — surface confidence label so UI can warn operators
            "confidence_label":   confidence.label,
            "confidence_warning": confidence.warning or None,
        })

    # -- Control route handlers (POST /api/control/*) --------------------

    async def _control_route(self, path: str, body: bytes) -> str:
        """Dispatch POST control actions to subsystem methods."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            data = {}
        handlers = {
            "/api/control/ids/start": self._ctrl_ids_start,
            "/api/control/ids/stop": self._ctrl_ids_stop,
            "/api/control/ids/clear": self._ctrl_ids_clear,
            "/api/control/ips/start": self._ctrl_ips_start,
            "/api/control/ips/stop": self._ctrl_ips_stop,
            "/api/control/ips/auto-respond": self._ctrl_ips_auto,
            "/api/control/wifi/scan": self._ctrl_wifi_scan,
            "/api/control/cloaking/mode": self._ctrl_cloaking_mode,
            "/api/control/cloaking/start": self._ctrl_cloaking_start,
            "/api/control/cloaking/stop": self._ctrl_cloaking_stop,
            "/api/control/cloaking/activate": self._ctrl_cloaking_activate,
            "/api/control/explorer/discover": self._ctrl_explorer_discover,
            "/api/control/auditor/audit": self._ctrl_auditor_audit,
            "/api/control/malware/scan": self._ctrl_malware_scan,
            "/api/control/ransomware/start": self._ctrl_ransomware_start,
            "/api/control/ransomware/stop": self._ctrl_ransomware_stop,
        }
        handler = handlers.get(path)
        if handler is None:
            return self._http_response(404, _CONTENT_TEXT, "Not Found")
        try:
            return await handler(data)
        except Exception:
            logger.exception("Control action failed: %s", path)
            return self._json_response({"ok": False, "message": "Action failed"})

    async def _ctrl_ids_start(self, data: dict) -> str:
        await self.engine.ids.start()
        return self._json_response({"ok": True, "message": "IDS started"})

    async def _ctrl_ids_stop(self, data: dict) -> str:
        await self.engine.ids.stop()
        return self._json_response({"ok": True, "message": "IDS stopped"})

    async def _ctrl_ids_clear(self, data: dict) -> str:
        count = self.engine.ids.clear_alerts()
        return self._json_response({"ok": True, "message": f"{count} alerts cleared"})

    async def _ctrl_ips_start(self, data: dict) -> str:
        await self.engine.ips.start()
        return self._json_response({"ok": True, "message": "IPS started"})

    async def _ctrl_ips_stop(self, data: dict) -> str:
        await self.engine.ips.stop()
        return self._json_response({"ok": True, "message": "IPS stopped"})

    async def _ctrl_ips_auto(self, data: dict) -> str:
        enabled = data.get("enabled", True)
        self.engine.ips.set_auto_respond(enabled)
        state = "enabled" if enabled else "disabled"
        return self._json_response({"ok": True, "message": f"Auto-respond {state}"})

    async def _ctrl_wifi_scan(self, data: dict) -> str:
        nets = await self.engine.wifi_stealth.scan_networks()
        return self._json_response({"ok": True, "message": f"Scan complete: {len(nets)} networks found"})

    async def _ctrl_cloaking_mode(self, data: dict) -> str:
        from network_guardian.cloaking import CloakMode
        mode_str = data.get("mode", "disabled")
        try:
            mode = CloakMode(mode_str)
        except ValueError:
            return self._json_response({"ok": False, "message": f"Unknown mode: {mode_str}"})
        self.engine.cloaking.set_mode(mode)
        return self._json_response({"ok": True, "message": f"Cloaking mode: {mode_str}"})

    async def _ctrl_cloaking_start(self, data: dict) -> str:
        cloak = self.engine.cloaking
        await cloak.start()
        # Launch the ReAct agent — it will observe, reason, act, and learn
        await self._cloak_agent.start(cloak)
        return self._json_response({"ok": True, "message": "Cloaking started — ReAct agent observing network"})

    async def _ctrl_cloaking_stop(self, data: dict) -> str:
        await self._cloak_agent.stop()
        await self.engine.cloaking.stop()
        return self._json_response({"ok": True, "message": "Cloaking stopped"})

    async def _ctrl_cloaking_activate(self, data: dict) -> str:
        name = data.get("name", "")
        if not name:
            return self._json_response({"ok": False, "message": "Identity name required"})
        ok = self.engine.cloaking.activate_identity(name)
        if not ok:
            return self._json_response({"ok": False, "message": f"Unknown identity: {name}"})
        return self._json_response({"ok": True, "message": f"Identity activated: {name}"})

    async def _ctrl_explorer_discover(self, data: dict) -> str:
        subnet = data.get("subnet", "")
        if not subnet:
            return self._json_response({"ok": False, "message": "Subnet required"})
        try:
            ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            return self._json_response({"ok": False, "message": f"Invalid subnet: {subnet}"})
        hosts = await self.engine.explorer.discover(subnet)
        return self._json_response({"ok": True, "message": f"Discovered {len(hosts)} hosts"})

    async def _ctrl_auditor_audit(self, data: dict) -> str:
        targets = data.get("targets", [])
        if not targets or not isinstance(targets, list):
            return self._json_response({"ok": False, "message": "Targets required (list of IPs)"})
        for t in targets:
            try:
                ipaddress.ip_network(t, strict=False)
            except ValueError:
                return self._json_response({"ok": False, "message": f"Invalid target: {t}"})
        findings = await self.engine.auditor.run_audit(targets)
        return self._json_response({"ok": True, "message": f"Audit complete: {len(findings)} findings"})

    # -- Page renderers (with control injection) --------------------------

    @staticmethod
    def _inject_security_nav(html: str) -> str:
        """Inject the Threats nav link into any page with the standard nav bar."""
        _lnk = '<a href="/security">&#128737; Threats</a>'
        return (
            html
            .replace('<a href="/incidents">Incidents</a></div>',
                     f'<a href="/incidents">Incidents</a>{_lnk}</div>')
            .replace('<a href="/incidents" class="active">Incidents</a></div>',
                     f'<a href="/incidents" class="active">Incidents</a>{_lnk}</div>')
            .replace('<a href="/ai" class="active">AI Engine</a></div>',
                     f'<a href="/ai" class="active">AI Engine</a>{_lnk}</div>')
            .replace('<a href="/reports" class="active">Reports</a></div>',
                     f'<a href="/reports" class="active">Reports</a>{_lnk}</div>')
        )

    def _page_with_controls(self, tmpl: str, path: str) -> str:
        nonce = Dashboard._csp_nonce
        body = inject_controls(tmpl.replace("{{NONCE}}", nonce), path, nonce)
        body = Dashboard._inject_security_nav(body)
        return self._http_response(200, "text/html", body)

    def _page_index(self) -> str:
        body = Dashboard._inject_security_nav(
            _TMPL_INDEX.replace("{{NONCE}}", Dashboard._csp_nonce))
        return self._http_response(200, "text/html", body)

    def _page_ids(self) -> str:
        return self._page_with_controls(_TMPL_IDS, "/ids")

    def _page_ips(self) -> str:
        return self._page_with_controls(_TMPL_IPS, "/ips")

    def _page_wifi(self) -> str:
        return self._page_with_controls(_TMPL_WIFI, "/wifi")

    def _page_cloaking(self) -> str:
        return self._page_with_controls(_TMPL_CLOAKING, "/cloaking")

    def _page_explorer(self) -> str:
        return self._page_with_controls(_TMPL_EXPLORER, "/explorer")

    def _page_auditor(self) -> str:
        return self._page_with_controls(_TMPL_AUDITOR, "/auditor")

    def _page_ai(self) -> str:
        return self._page_with_controls(_TMPL_AI, "/ai")

    def _page_fleet(self) -> str:
        html = Dashboard._inject_security_nav(get_fleet_page(Dashboard._csp_nonce))
        return self._http_response(200, "text/html", html)

    # -- Fleet API (agent-facing, HMAC authenticated) -------------------

    def _verify_agent_sig(self, body: bytes, headers: dict[str, str]) -> bool:
        sig = headers.get("x-agent-signature", "")
        if not sig:
            return False
        return self._fleet.verify_signature(body, sig)

    def _fleet_register(self, body: bytes, headers: dict[str, str]) -> str:
        if not self._verify_agent_sig(body, headers):
            return self._http_response(403, _CONTENT_TEXT, "Invalid signature")
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return self._http_response(400, _CONTENT_TEXT, "Invalid JSON")
        agent_id = data.get("agent_id") or headers.get("x-agent-id", "")
        if not agent_id:
            return self._http_response(400, _CONTENT_TEXT, "Missing agent_id")
        self._fleet.register_agent(agent_id, data)
        return self._json_response({"ok": True, "agent_id": agent_id})

    def _fleet_report(self, body: bytes, headers: dict[str, str]) -> str:
        if not self._verify_agent_sig(body, headers):
            return self._http_response(403, _CONTENT_TEXT, "Invalid signature")
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return self._http_response(400, _CONTENT_TEXT, "Invalid JSON")
        agent_id = data.get("agent_id") or headers.get("x-agent-id", "")
        if not agent_id:
            return self._http_response(400, _CONTENT_TEXT, "Missing agent_id")
        if not self._fleet.accept_report(agent_id, data):
            # Auto-register if unknown
            self._fleet.register_agent(agent_id, data.get("identity", {}))
            self._fleet.accept_report(agent_id, data)
        
        # Process threat alerts from the agent
        threat_alerts = data.get("threat_alerts", [])
        if threat_alerts and self.engine and self.engine.ids:
            logger.info("Processing %d threat alert(s) from agent %s", len(threat_alerts), agent_id)
            for alert_data in threat_alerts:
                try:
                    # Convert bot threat alert to IDS alert format
                    threat_type = alert_data.get("threat_type", "unknown")
                    severity_map = {
                        "critical": "critical",
                        "high": "high",
                        "medium": "medium",
                        "low": "low",
                    }
                    severity_str = severity_map.get(alert_data.get("severity", "medium"), "medium")
                    
                    # Create payload string for signature matching
                    payload = f"{threat_type}: {alert_data.get('description', '')}. Items: {', '.join(alert_data.get('affected_items', [])[:3])}"
                    
                    # Analyze through IDS (will match generic rules)
                    import asyncio
                    asyncio.create_task(self.engine.ids.analyse_payload(
                        payload,
                        source_ip=alert_data.get("source_ip", agent_id),
                        destination_ip=alert_data.get("target_ip", ""),
                        destination_port=alert_data.get("target_port", 0),
                    ))
                    logger.debug("Threat from %s: %s", agent_id, alert_data.get("description"))
                except Exception as e:
                    logger.warning("Failed to process bot threat alert: %s", e)
        
        ack: dict = {"ok": True, "agent_id": agent_id}
        patch_cfg = self._fleet.pop_patch_config(agent_id)
        if patch_cfg:
            ack["patch_config"] = patch_cfg
            logger.info("Delivering patch config to agent %s: %s", agent_id, patch_cfg)
        return self._json_response(ack)

    def _fleet_auth(self, body: bytes, headers: dict[str, str]) -> str:
        """Authenticate a Wolfpak member for agent use. HMAC-signed request."""
        if not self._verify_agent_sig(body, headers):
            return self._http_response(403, _CONTENT_TEXT, "Invalid signature")
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return self._http_response(400, _CONTENT_TEXT, "Invalid JSON")
        username = data.get("username", "").strip().lower()
        password = data.get("password", "")
        if not username or not password:
            return self._http_response(403, _CONTENT_JSON,
                json.dumps({"ok": False, "message": "Credentials required"}))
        member = self._team.authenticate(username, password)
        if not member:
            logger.warning("Failed agent auth attempt for user: %s", username)
            return self._http_response(403, _CONTENT_JSON,
                json.dumps({"ok": False, "message": "Invalid credentials"}))
        # Generate a short-lived agent token
        agent_token = secrets.token_urlsafe(32)
        logger.info("Agent auth granted to Wolfpak member: %s", username)
        return self._json_response({
            "ok": True,
            "operator": member.get("display_name", username),
            "role": member.get("role", "operator"),
            "agent_token": agent_token,
        })

    # -- Fleet API (dashboard-facing, session authenticated) ------------

    def _api_fleet_list(self) -> str:
        return self._json_response(self._fleet.list_agents())

    def _api_fleet_key(self) -> str:
        return self._json_response({"key": self._fleet.fleet_key})

    def _api_fleet_agent(self, path: str) -> str:
        agent_id = path.split("/api/fleet/agent/", 1)[-1].split("/")[0]
        report = self._fleet.get_agent_report(agent_id)
        if report is None:
            return self._http_response(404, _CONTENT_TEXT, "Agent not found")
        return self._json_response(report)

    def _api_fleet_agent_diagnostics(self, path: str) -> str:
        """Return the latest ReAct diagnostics for a specific agent."""
        agent_id = path.split("/api/fleet/agent/", 1)[-1].split("/")[0]
        diag = self._fleet.get_agent_diagnostics(agent_id)
        if diag is None:
            return self._http_response(404, _CONTENT_TEXT, "No diagnostics")
        return self._json_response(diag)

    def _api_fleet_agent_threats(self, path: str) -> str:
        """Return threat history for a specific agent."""
        agent_id = path.split("/api/fleet/agent/", 1)[-1].split("/")[0]
        history = self._fleet.get_agent_threat_history(agent_id)
        return self._json_response({"agent_id": agent_id, "threats": history})

    def _api_fleet_agent_sentinel(self, path: str) -> str:
        """Return sentinel bot intelligence for a specific agent."""
        agent_id = path.split("/api/fleet/agent/", 1)[-1].split("/")[0]
        data = self._fleet.get_agent_sentinel(agent_id)
        if data is None:
            return self._http_response(404, _CONTENT_TEXT, "Not a sentinel agent")
        return self._json_response(data)

    def _api_fleet_threats(self) -> str:
        """Aggregate threat intelligence across all fleet agents."""
        summary = self._fleet.get_fleet_threat_summary()
        return self._json_response(summary)

    def _api_fleet_agent_reports(self, path: str) -> str:
        """Return detailed threat assessment reports for a specific agent."""
        agent_id = path.split("/api/fleet/agent/", 1)[-1].split("/")[0]
        reports = self._fleet.get_agent_threat_reports(agent_id)
        return self._json_response({"agent_id": agent_id, "reports": reports})

    def _api_fleet_all_reports(self) -> str:
        """Return all threat assessment reports across the fleet, newest first."""
        reports = self._fleet.get_all_threat_reports()
        return self._json_response({"reports": reports, "total": len(reports)})

    def _api_fleet_all_incidents(self) -> str:
        """Return all reports that have an attached incident_report_md, newest first."""
        all_reports = self._fleet.get_all_threat_reports()
        incidents = [r for r in all_reports if r.get("incident_report_md")]
        return self._json_response({"incidents": incidents, "total": len(incidents)})

    def _api_fleet_agent_incidents(self, path: str) -> str:
        """Return incident reports for a specific agent."""
        agent_id = path.split("/api/fleet/agent/", 1)[-1].split("/")[0]
        reports = self._fleet.get_agent_threat_reports(agent_id)
        incidents = [r for r in reports if r.get("incident_report_md")]
        return self._json_response({"agent_id": agent_id, "incidents": incidents})

    def _api_wolfpak_clients(self) -> str:
        """List all registered wolfpak admin client devices."""
        clients = self._wolfpak.list_clients()
        return self._json_response({
            "clients":      clients,
            "total":        self._wolfpak.total_count(),
            "active":       self._wolfpak.active_count(),
        })

    def _page_reports(self) -> str:
        nonce = Dashboard._csp_nonce
        nav = '<div class="nav"><a href="/">Dashboard</a><a href="/ids">IDS</a><a href="/ips">IPS</a><a href="/wifi">WiFi</a><a href="/cloaking">Cloaking</a><a href="/explorer">Explorer</a><a href="/auditor">Auditor</a><a href="/ai">AI Engine</a><a href="/fleet">Fleet</a><a href="/reports" class="active">Reports</a></div>'
        html = (
            '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet">'
            '<title>Threat Reports — Network Guardian</title>'
            '<style>'
            ':root{--bg:#000810;--bg2:#010d1a;--surface:rgba(0,18,36,0.92);--border:rgba(0,200,255,0.15);--text:#cce8ff;--dim:#3d7a9a;'
            '--red:#ff2244;--orange:#ff8c00;--yellow:#ffcc00;--green:#00ff88;--blue:#0094d4;--purple:#aa44ff;--cyan:#00d4ff}'
            '@keyframes scan-h{0%{left:-100%;opacity:0}50%{opacity:1}100%{left:100%;opacity:0}}'
            '@keyframes pulse-glow{0%,100%{opacity:.5}50%{opacity:1}}'
            '@keyframes hud-boot{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}'
            '@keyframes spin{to{transform:rotate(360deg)}}'
            '*{box-sizing:border-box;margin:0;padding:0}'
            'body{background:var(--bg);background-image:radial-gradient(ellipse at 20% 50%,rgba(0,212,255,.04) 0%,transparent 50%),radial-gradient(ellipse at 80% 20%,rgba(0,100,255,.05) 0%,transparent 50%),linear-gradient(rgba(0,200,255,.015) 1px,transparent 1px),linear-gradient(90deg,rgba(0,200,255,.015) 1px,transparent 1px);background-size:auto,auto,50px 50px,50px 50px;color:var(--text);font-family:\'Rajdhani\',\'Segoe UI\',sans-serif;font-size:.9rem}'
            '.wrap{max-width:1400px;margin:0 auto;padding:20px}'
            '.banner{display:flex;align-items:center;gap:12px;padding:16px 20px;background:linear-gradient(135deg,rgba(0,20,40,.97),rgba(0,8,20,.99));'
            'border:1px solid rgba(0,200,255,.22);border-radius:4px;margin-bottom:16px;position:relative;overflow:hidden}'
            '.banner::before{content:\'\';position:absolute;top:0;left:-100%;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan-h 5s ease-in-out infinite}'
            '.banner h1{font-size:1.3rem;font-weight:700;font-family:\'Orbitron\',sans-serif;letter-spacing:3px;color:var(--cyan);text-shadow:0 0 20px rgba(0,212,255,.5)}'
            '.badge{padding:4px 10px;clip-path:polygon(6px 0%,100% 0%,calc(100% - 6px) 100%,0% 100%);border-radius:0;font-size:.75rem;font-weight:600;font-family:\'Share Tech Mono\',monospace}'
            '.nav{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:20px}'
            '.nav a{padding:6px 14px;clip-path:polygon(8px 0%,100% 0%,calc(100% - 8px) 100%,0% 100%);border-radius:0;text-decoration:none;color:var(--cyan);'
            'background:rgba(0,15,30,.7);border:1px solid rgba(0,200,255,.2);font-size:.72rem;font-family:\'Orbitron\',sans-serif;letter-spacing:1.5px;text-transform:uppercase;transition:.15s}'
            '.nav a:hover,.nav a.active{background:rgba(0,212,255,.18);color:var(--cyan);border-color:var(--cyan);box-shadow:0 0 20px rgba(0,212,255,.3)}'
            '.card{background:linear-gradient(135deg,rgba(0,22,44,.9),rgba(0,8,22,.95));border:1px solid rgba(0,200,255,.15);border-radius:4px;'
            'padding:18px;margin-bottom:16px;position:relative;box-shadow:0 0 25px rgba(0,212,255,.04),inset 0 1px 0 rgba(0,212,255,.08)}'
            '.card::before{content:\'\';position:absolute;top:-1px;left:-1px;width:18px;height:18px;border-top:2px solid var(--cyan);border-left:2px solid var(--cyan);box-shadow:-2px -2px 8px rgba(0,212,255,.3)}'
            '.card::after{content:\'\';position:absolute;bottom:-1px;right:-1px;width:18px;height:18px;border-bottom:2px solid var(--cyan);border-right:2px solid var(--cyan);box-shadow:2px 2px 8px rgba(0,212,255,.3)}'
            '.card h2{font-size:.85rem;font-family:\'Orbitron\',sans-serif;font-weight:600;margin-bottom:14px;color:var(--cyan);text-shadow:0 0 15px rgba(0,212,255,.4)}'
            '.report-card{background:rgba(0,10,25,.8);border:1px solid rgba(0,200,255,.15);border-radius:4px;'
            'margin-bottom:12px;overflow:hidden}'
            '.report-header{display:flex;align-items:center;gap:12px;padding:14px 16px;cursor:pointer;'
            'user-select:none;border-bottom:1px solid rgba(0,200,255,.1)}'
            '.report-header:hover{background:rgba(0,212,255,.04)}'
            '.report-body{padding:16px;display:none}'
            '.report-body.open{display:block}'
            '.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.7rem;font-weight:600}'
            '.sev-critical{background:rgba(255,34,68,.15);color:var(--red);box-shadow:0 0 8px rgba(255,34,68,.2)}'
            '.sev-high{background:rgba(255,140,0,.15);color:var(--orange);box-shadow:0 0 8px rgba(255,140,0,.2)}'
            '.sev-medium{background:rgba(255,204,0,.15);color:var(--yellow)}'
            '.sev-low{background:rgba(0,255,136,.15);color:var(--green);box-shadow:0 0 8px rgba(0,255,136,.2)}'
            '.sev-info{background:rgba(0,148,212,.15);color:var(--blue)}'
            '.risk-critical{color:var(--red)}'
            '.risk-high{color:var(--orange)}'
            '.risk-medium{color:var(--yellow)}'
            '.risk-low{color:var(--green)}'
            '.threat-block{border-left:3px solid var(--border);padding:10px 14px;margin:8px 0;'
            'background:rgba(0,212,255,.02);border-radius:0 4px 4px 0}'
            '.threat-block.sev-critical{border-left-color:var(--red)}'
            '.threat-block.sev-high{border-left-color:var(--orange)}'
            '.threat-block.sev-medium{border-left-color:var(--yellow)}'
            '.threat-block.sev-low{border-left-color:var(--green)}'
            '.label{font-size:.7rem;font-weight:600;font-family:\'Share Tech Mono\',monospace;color:var(--dim);text-transform:uppercase;letter-spacing:.05em;margin-bottom:2px}'
            '.value{font-size:.85rem;line-height:1.5}'
            '.action-block{border-left:3px solid var(--cyan);padding:10px 14px;margin:8px 0;'
            'background:rgba(0,212,255,.04);border-radius:0 4px 4px 0}'
            '.narrative{background:rgba(0,148,212,.08);border:1px solid rgba(0,148,212,.25);border-radius:4px;'
            'padding:12px 14px;font-size:.85rem;line-height:1.6;color:var(--text);margin-bottom:14px}'
            '.obs-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:8px;margin:8px 0}'
            '.obs-item{background:rgba(0,212,255,.04);border-radius:4px;padding:8px 10px;text-align:center}'
            '.obs-item .n{font-size:1.3rem;font-weight:700;font-family:\'Orbitron\',sans-serif;color:var(--cyan)}'
            '.obs-item .l{font-size:.65rem;font-family:\'Share Tech Mono\',monospace;color:var(--dim);margin-top:2px}'
            '.empty{color:var(--dim);font-family:\'Share Tech Mono\',monospace;letter-spacing:1px;padding:30px;text-align:center}'
            '.filter-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}'
            '.filter-btn{padding:5px 12px;clip-path:polygon(6px 0%,100% 0%,calc(100% - 6px) 100%,0% 100%);border-radius:0;border:1px solid rgba(0,200,255,.2);'
            'background:rgba(0,15,30,.7);color:var(--dim);cursor:pointer;font-size:.78rem;font-family:\'Share Tech Mono\',monospace}'
            '.filter-btn.active{border-color:var(--cyan);color:var(--cyan);background:rgba(0,212,255,.1)}'
            '#ts{margin-left:auto;color:var(--dim);font-size:.85rem}'
            '</style></head><body>'
            '<div class="wrap">'
            '<div class="banner"><h1>&#128203; Threat Assessment Reports</h1>'
            '<span id="badge" class="badge" style="background:rgba(88,166,255,.15);color:var(--blue)">Loading</span>'
            '<span id="ts"></span></div>'
            + nav +
            '<div class="filter-row">'
            '<button class="filter-btn active" onclick="setFilter(\'all\',this)">All</button>'
            '<button class="filter-btn" onclick="setFilter(\'critical\',this)">Critical</button>'
            '<button class="filter-btn" onclick="setFilter(\'high\',this)">High</button>'
            '<button class="filter-btn" onclick="setFilter(\'medium\',this)">Medium</button>'
            '<button class="filter-btn" onclick="setFilter(\'low\',this)">Low / Clean</button>'
            '</div>'
            '<div id="reports"></div>'
            '</div>'
            f'<script nonce="{nonce}">'
            'let _filter="all";'
            'function setFilter(f,btn){'
            '  _filter=f;'
            '  document.querySelectorAll(".filter-btn").forEach(b=>b.classList.remove("active"));'
            '  btn.classList.add("active");'
            '  render(_lastData);'
            '}'
            'let _lastData=[];'
            'function sevIcon(s){return s==="critical"?"\\u{1F6A8}":s==="high"?"\\u26A0\\uFE0F":s==="medium"?"\\u{1F7E1}":s==="low"?"\\u2705":"\\u2139\\uFE0F";}'
            'function toggle(id){const b=document.getElementById("body_"+id);if(b)b.classList.toggle("open");}'
            'function render(reports){'
            '  _lastData=reports;'
            '  const el=document.getElementById("reports");'
            '  let filtered=reports;'
            '  if(_filter!=="all"){'
            '    if(_filter==="low") filtered=reports.filter(r=>r.risk_level==="low");'
            '    else filtered=reports.filter(r=>r.risk_level===_filter);'
            '  }'
            '  if(!filtered.length){el.innerHTML=\'<div class="empty">No reports match the selected filter.</div>\';return;}'
            '  el.innerHTML=filtered.map((r,i)=>{'
            '    const rid=r.report_id||("R"+i);'
            '    const ts=r.generated_at?new Date(r.generated_at).toLocaleString():"";'
            '    const risk=r.risk_level||"low";'
            '    const score=r.threat_score||0;'
            '    const tcount=(r.threats||[]).length;'
            '    const acount=(r.actions_taken||[]).filter(a=>a.success).length;'
            '    const sevIcon_=r=>sevIcon(r.risk_level||"low");'
            '    const threatBlocks=(r.threats||[]).map(t=>{'
            '      const sev=t.severity||"medium";'
            '      return `<div class="threat-block sev-${sev}">'
            '        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">'
            '          <span class="pill sev-${sev}">${sev.toUpperCase()}</span>'
            '          <span style="font-weight:600">${t.title||""}</span>'
            '          <span style="color:var(--dim);font-size:.75rem;margin-left:auto">${t.mitre_att_ck||""}</span>'
            '        </div>'
            '        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">'
            '          <div><div class="label">What It Is</div><div class="value">${t.what_it_is||""}</div></div>'
            '          <div><div class="label">Potential Impact</div><div class="value">${t.potential_impact||""}</div></div>'
            '          <div><div class="label">Why Triggered</div><div class="value">${t.why_triggered||""}</div></div>'
            '          <div><div class="label">CVSS Base Score</div><div class="value">${t.cvss_base_score||"-"}</div></div>'
            '          <div style="grid-column:1/-1"><div class="label">Technical Detail</div><div class="value" style="font-family:monospace;font-size:.8rem">${t.technical_detail||""}</div></div>'
            '        </div>'
            '        <div style="margin-top:10px"><div class="label">&#x2705; Action Taken</div>'
            '          <div class="value" style="color:var(--green)">${t.action_taken?t.action_taken.replace(/_/g," "):"No automated action"}</div>'
            '          <div class="value" style="color:var(--dim);margin-top:3px">${t.action_explanation||""}</div>'
            '        </div>'
            '      </div>`;'
            '    }).join("");'
            '    const actionBlocks=(r.actions_taken||[]).map(a=>{'
            '      return `<div class="action-block">'
            '        <div style="font-weight:600;margin-bottom:4px">&#128274; ${(a.action||"").replace(/_/g," ").toUpperCase()}</div>'
            '        <div class="value">${a.explanation||a.detail||""}</div>'
            '        <div style="font-size:.75rem;color:${a.success?"var(--green)":"var(--red)"};margin-top:3px">'
            '          ${a.success?"&#10003; Executed successfully":"&#10007; Action failed"}</div>'
            '      </div>`;'
            '    }).join("");'
            '    const obs=r.observations||{};'
            '    const recs=(r.recommendations||[]).map(rec=>`<li style="margin:4px 0;color:var(--yellow)">${rec}</li>`).join("");'
            '    return `<div class="report-card">'
            '      <div class="report-header" onclick="toggle(\'${rid}\')">'
            '        <span style="font-size:1.4rem">${sevIcon(risk)}</span>'
            '        <div>'
            '          <div style="font-weight:700">Report ${rid} &nbsp;<span class="pill sev-${risk}" style="text-transform:uppercase">${risk}</span>'
            '            &nbsp;<span style="color:var(--dim);font-size:.75rem">Score: ${score}/100</span></div>'
            '          <div style="color:var(--dim);font-size:.75rem;margin-top:2px">${ts} &nbsp;|&nbsp; Agent: ${r.agent_id||r.host||""} &nbsp;|&nbsp; ${tcount} threat(s) &nbsp;|&nbsp; ${acount} action(s) taken</div>'
            '        </div>'
            '        <span style="margin-left:auto;color:var(--dim);font-size:.9rem">&#9660;</span>'
            '      </div>'
            '      <div class="report-body" id="body_${rid}">'
            '        <div class="narrative">${r.narrative||""}</div>'
            '        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">'
            '          <div>'
            '            <div class="label" style="margin-bottom:8px">&#128202; Observations Snapshot</div>'
            '            <div class="obs-grid">'
            '              <div class="obs-item"><div class="n">${obs.connections||0}</div><div class="l">Connections</div></div>'
            '              <div class="obs-item"><div class="n">${obs.listening_ports||0}</div><div class="l">Listening Ports</div></div>'
            '              <div class="obs-item"><div class="n">${obs.external_connections||0}</div><div class="l">External Conns</div></div>'
            '              <div class="obs-item"><div class="n">${obs.active_processes||0}</div><div class="l">Processes</div></div>'
            '              <div class="obs-item"><div class="n">${(r.baselines||{}).network_drift_pct||0}%</div><div class="l">Net Drift</div></div>'
            '              <div class="obs-item"><div class="n">${(r.baselines||{}).cycle_count||0}</div><div class="l">Cycle #</div></div>'
            '            </div>'
            '          </div>'
            '          ${recs?`<div><div class="label" style="margin-bottom:8px">&#128680; Recommendations</div><ul style="padding-left:16px;list-style:disc">${recs}</ul></div>`:"<div></div>"}'
            '        </div>'
            '        ${tcount?`<div style="margin-top:14px"><div class="label" style="margin-bottom:8px">&#128273; Threat Detail</div>${threatBlocks}</div>`:"<div style=\'color:var(--green);margin-top:10px\'>&#10003; No threats detected in this cycle.</div>"}'
            '        ${acount?`<div style="margin-top:14px"><div class="label" style="margin-bottom:8px">&#128736; Automated Actions</div>${actionBlocks}</div>`:""}'
            '      </div>'
            '    </div>`;'
            '  }).join("");'
            '}'
            'async function load(){'
            '  try{'
            '    const r=await fetch("/api/fleet/reports");'
            '    const d=await r.json();'
            '    const reports=d.reports||[];'
            '    const badge=document.getElementById("badge");'
            '    const withThreats=reports.filter(r=>(r.threats||[]).length>0);'
            '    badge.textContent=reports.length+" Reports ("+(withThreats.length)+" with threats)";'
            '    document.getElementById("ts").textContent=new Date().toLocaleTimeString()+" | Auto 30s";'
            '    render(reports);'
            '  }catch(e){console.error(e);}'
            '}'
            'load();setInterval(load,30000);'
            '</script></body></html>'
        )
        html = Dashboard._inject_security_nav(html)
        return self._http_response(200, "text/html", html)

    def _page_incidents(self) -> str:
        nonce = Dashboard._csp_nonce
        nav = '<div class="nav"><a href="/">Dashboard</a><a href="/ids">IDS</a><a href="/ips">IPS</a><a href="/wifi">WiFi</a><a href="/cloaking">Cloaking</a><a href="/explorer">Explorer</a><a href="/auditor">Auditor</a><a href="/ai">AI Engine</a><a href="/fleet">Fleet</a><a href="/reports">Reports</a><a href="/incidents" class="active">Incidents</a></div>'
        html = (
            '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet">'
            '<title>Incident Reports — Network Guardian</title>'
            '<style>'
            ':root{--bg:#000810;--bg2:#010d1a;--surface:rgba(0,18,36,0.92);--border:rgba(0,200,255,0.15);--text:#cce8ff;--dim:#3d7a9a;'
            '--red:#ff2244;--orange:#ff8c00;--yellow:#ffcc00;--green:#00ff88;--blue:#0094d4;--purple:#aa44ff;--cyan:#00d4ff}'
            '@keyframes scan-h{0%{left:-100%;opacity:0}50%{opacity:1}100%{left:100%;opacity:0}}'
            '@keyframes pulse-glow{0%,100%{opacity:.5}50%{opacity:1}}'
            '@keyframes hud-boot{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}'
            '@keyframes spin{to{transform:rotate(360deg)}}'
            '*{box-sizing:border-box;margin:0;padding:0}'
            'body{background:var(--bg);background-image:radial-gradient(ellipse at 20% 50%,rgba(0,212,255,.04) 0%,transparent 50%),radial-gradient(ellipse at 80% 20%,rgba(0,100,255,.05) 0%,transparent 50%),linear-gradient(rgba(0,200,255,.015) 1px,transparent 1px),linear-gradient(90deg,rgba(0,200,255,.015) 1px,transparent 1px);background-size:auto,auto,50px 50px,50px 50px;color:var(--text);font-family:\'Rajdhani\',\'Segoe UI\',sans-serif;font-size:.9rem}'
            '.wrap{max-width:1400px;margin:0 auto;padding:20px}'
            '.banner{display:flex;align-items:center;gap:12px;padding:16px 20px;background:linear-gradient(135deg,rgba(0,20,40,.97),rgba(0,8,20,.99));'
            'border:1px solid rgba(0,200,255,.22);border-radius:4px;margin-bottom:16px;position:relative;overflow:hidden}'
            '.banner::before{content:\'\';position:absolute;top:0;left:-100%;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan-h 5s ease-in-out infinite}'
            '.banner h1{font-size:1.3rem;font-weight:700;font-family:\'Orbitron\',sans-serif;letter-spacing:3px;color:var(--cyan);text-shadow:0 0 20px rgba(0,212,255,.5)}'
            '.badge{padding:4px 10px;clip-path:polygon(6px 0%,100% 0%,calc(100% - 6px) 100%,0% 100%);border-radius:0;font-size:.75rem;font-weight:600;font-family:\'Share Tech Mono\',monospace}'
            '.nav{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:20px}'
            '.nav a{padding:6px 14px;clip-path:polygon(8px 0%,100% 0%,calc(100% - 8px) 100%,0% 100%);border-radius:0;text-decoration:none;color:var(--cyan);'
            'background:rgba(0,15,30,.7);border:1px solid rgba(0,200,255,.2);font-size:.72rem;font-family:\'Orbitron\',sans-serif;letter-spacing:1.5px;text-transform:uppercase;transition:.15s}'
            '.nav a:hover,.nav a.active{background:rgba(0,212,255,.18);color:var(--cyan);border-color:var(--cyan);box-shadow:0 0 20px rgba(0,212,255,.3)}'
            '.ir-card{background:linear-gradient(135deg,rgba(0,22,44,.9),rgba(0,8,22,.95));border:1px solid rgba(0,200,255,.15);border-radius:4px;'
            'margin-bottom:16px;overflow:hidden}'
            '.ir-header{display:flex;align-items:center;gap:12px;padding:14px 18px;cursor:pointer;'
            'border-bottom:1px solid rgba(0,200,255,.1)}'
            '.ir-header:hover{background:rgba(0,212,255,.04)}'
            '.ir-body{display:none;padding:0}'
            '.ir-body.open{display:block}'
            '.ir-md{padding:20px 24px;font-size:.85rem;line-height:1.7;'
            'font-family:\'Rajdhani\',\'Segoe UI\',sans-serif}'
            '.ir-md h1{font-size:1.15rem;font-weight:700;font-family:\'Orbitron\',sans-serif;color:var(--cyan);margin:0 0 12px;text-shadow:0 0 15px rgba(0,212,255,.4)}'
            '.ir-md h2{font-size:.95rem;font-weight:600;color:var(--text);margin:18px 0 8px;'
            'border-bottom:1px solid rgba(0,200,255,.15);padding-bottom:4px}'
            '.ir-md h3{font-size:.88rem;font-weight:600;color:var(--yellow);margin:12px 0 6px}'
            '.ir-md table{width:100%;border-collapse:collapse;margin:8px 0 12px;font-size:.83rem}'
            '.ir-md th,.ir-md td{padding:6px 10px;border:1px solid rgba(0,200,255,.15);text-align:left;font-family:\'Share Tech Mono\',monospace}'
            '.ir-md th{background:rgba(0,212,255,.05);font-weight:600;color:var(--cyan)}'
            '.ir-md code{background:rgba(0,212,255,.08);padding:1px 5px;border-radius:3px;'
            'font-family:\'Share Tech Mono\',monospace;font-size:.82rem;color:var(--cyan)}'
            '.ir-md hr{border:none;border-top:1px solid rgba(0,200,255,.15);margin:16px 0}'
            '.ir-md p{margin:6px 0}'
            '.ir-md ul,.ir-md ol{padding-left:20px;margin:6px 0}'
            '.ir-md li{margin:3px 0}'
            '.ir-md strong{color:var(--text);font-weight:600}'
            '.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.7rem;font-weight:600}'
            '.sev-critical{background:rgba(255,34,68,.15);color:var(--red);box-shadow:0 0 8px rgba(255,34,68,.2)}'
            '.sev-high{background:rgba(255,140,0,.15);color:var(--orange);box-shadow:0 0 8px rgba(255,140,0,.2)}'
            '.sev-medium{background:rgba(255,204,0,.15);color:var(--yellow)}'
            '.sev-low{background:rgba(0,255,136,.15);color:var(--green);box-shadow:0 0 8px rgba(0,255,136,.2)}'
            '.dl-btn{padding:5px 12px;clip-path:polygon(6px 0%,100% 0%,calc(100% - 6px) 100%,0% 100%);border-radius:0;border:1px solid rgba(0,200,255,.2);'
            'background:rgba(0,15,30,.7);color:var(--cyan);cursor:pointer;font-size:.78rem;font-family:\'Share Tech Mono\',monospace;margin-left:auto}'
            '.dl-btn:hover{background:rgba(0,212,255,.15);box-shadow:0 0 15px rgba(0,212,255,.25)}'
            '.empty{color:var(--dim);font-family:\'Share Tech Mono\',monospace;letter-spacing:1px;padding:30px;text-align:center}'
            '#ts{margin-left:auto;color:var(--dim);font-size:.85rem}'
            '</style></head><body>'
            '<div class="wrap">'
            '<div class="banner"><h1>&#128196; Incident Reports</h1>'
            '<span id="badge" class="badge" style="background:rgba(248,81,73,.15);color:var(--red)">Loading</span>'
            '<span id="ts"></span></div>'
            + nav +
            '<div id="incidents"></div>'
            '</div>'
            f'<script nonce="{nonce}">'
            # Minimal markdown-to-HTML renderer
            'function mdToHtml(md){'
            '  if(!md)return "";'
            '  let h=md'
            '    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")'
            '    .replace(/^# (.+)$/gm,"<h1>$1</h1>")'
            '    .replace(/^## (.+)$/gm,"<h2>$1</h2>")'
            '    .replace(/^### (.+)$/gm,"<h3>$1</h3>")'
            '    .replace(/^---$/gm,"<hr>")'
            '    .replace(/\\*\\*([^*]+)\\*\\*/g,"<strong>$1</strong>")'
            '    .replace(/`([^`]+)`/g,"<code>$1</code>")'
            '    .replace(/^\\| (.+) \\|$/gm,function(m,p1){'
            '      const cells=p1.split(" | ");'
            '      const isHead=/^[- ]+$/.test(cells[0]);'
            '      if(isHead)return "";'
            '      const tag=cells[0].includes("<strong>")||cells[0].includes("**")?"th":"td";'
            '      return "<tr>"+cells.map(c=>`<${tag}>${c}</${tag}>`).join("")+"</tr>";'
            '    })'
            '    .replace(/(<tr>.*<\\/tr>)/gs,function(m){return `<table>${m}</table>`;})'
            '    .replace(/^(\\d+\\. .+)$/gm,"<li>$1</li>")'
            '    .replace(/(<li>.*<\\/li>)/gs,"<ol>$1</ol>")'
            '    .replace(/\\n\\n/g,"</p><p>")'
            '    .replace(/\\n/g,"<br>");'
            '  return "<p>"+h+"</p>";'
            '}'
            'function downloadMd(id,md){'
            '  const b=new Blob([md],{type:"text/markdown"});'
            '  const a=document.createElement("a");'
            '  a.href=URL.createObjectURL(b);'
            '  a.download="INCIDENT_REPORT_"+id+".md";'
            '  a.click();'
            '}'
            'function toggle(id){const b=document.getElementById("ib_"+id);if(b)b.classList.toggle("open");}'
            'async function load(){'
            '  try{'
            '    const r=await fetch("/api/fleet/incidents");'
            '    const d=await r.json();'
            '    const incidents=d.incidents||[];'
            '    document.getElementById("badge").textContent=incidents.length+" Incident Report(s)";'
            '    document.getElementById("ts").textContent=new Date().toLocaleTimeString()+" | Auto 30s";'
            '    const el=document.getElementById("incidents");'
            '    if(!incidents.length){el.innerHTML=\'<div class="empty">No incident reports yet. They are generated automatically whenever a threat is detected.</div>\';return;}'
            '    el.innerHTML=incidents.map((r,i)=>{'
            '      const rid=r.report_id||("IR"+i);'
            '      const ts=r.generated_at?new Date(r.generated_at).toLocaleString():"";'
            '      const risk=r.risk_level||"low";'
            '      const sevMap={critical:"sev-critical",high:"sev-high",medium:"sev-medium",low:"sev-low"};'
            '      const sevClass=sevMap[risk]||"sev-low";'
            '      const tcount=(r.threats||[]).length;'
            '      const title=(r.threats||[]).map(t=>t.title).filter(Boolean).join(", ")||"Clean Assessment";'
            '      return `<div class="ir-card">'
            '        <div class="ir-header" onclick="toggle(\'${rid}\')">'
            '          <span style="font-size:1.3rem">${risk==="critical"?"\\u{1F6A8}":risk==="high"?"\\u26A0\\uFE0F":risk==="medium"?"\\u{1F7E1}":"\\u2705"}</span>'
            '          <div style="flex:1">'
            '            <div style="font-weight:700">IR-${r.generated_at?r.generated_at.slice(0,10):"?"}-${rid}'
            '              &nbsp;<span class="pill ${sevClass}">${risk.toUpperCase()}</span>'
            '              &nbsp;<span style="color:var(--dim);font-weight:400;font-size:.8rem">${title}</span></div>'
            '            <div style="color:var(--dim);font-size:.75rem;margin-top:2px">${ts} &nbsp;|&nbsp; Agent: ${r.agent_id||""} &nbsp;|&nbsp; ${tcount} threat(s) &nbsp;|&nbsp; Score: ${r.threat_score||0}/100</div>'
            '          </div>'
            '          <button class="dl-btn" onclick="event.stopPropagation();downloadMd(\'${rid}\',${JSON.stringify(r.incident_report_md||"")})">&#11015; .md</button>'
            '          <span style="color:var(--dim);font-size:.9rem;margin-left:8px">&#9660;</span>'
            '        </div>'
            '        <div class="ir-body" id="ib_${rid}">'
            '          <div class="ir-md">${mdToHtml(r.incident_report_md||"_No markdown content available._")}</div>'
            '        </div>'
            '      </div>`;'
            '    }).join("");'
            '  }catch(e){console.error(e);}'
            '}'
            'load();setInterval(load,30000);'
            '</script></body></html>'
        )
        html = Dashboard._inject_security_nav(html)
        return self._http_response(200, "text/html", html)

    def _page_login(self) -> str:
        return self._http_response(200, "text/html",
            get_login_page(Dashboard._csp_nonce))

    def _page_logout(self) -> str:
        return self._http_response(
            302, _CONTENT_TEXT, "Redirecting to login...",
            extra_headers=(
                "Location: /login\r\n"
                "Set-Cookie: ng_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0\r\n"
            ),
        )

    async def _auth_login(self, body: bytes, client_ip: str, headers: dict[str, str] | None = None) -> str:
        """Authenticate team member and issue a session cookie."""
        import time as _time
        now = _time.monotonic()
        # Brute-force protection: 5 attempts per 5 minutes
        attempts = self._login_attempts.get(client_ip, [])
        attempts = [t for t in attempts if now - t < 300]
        if len(attempts) >= 5:
            logger.warning("Login throttled for %s (%d attempts)", client_ip, len(attempts))
            return self._json_response({"ok": False, "message": "Too many attempts. Try again later."})
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            data = {}
        username = data.get("username", "").strip()
        password = data.get("password", "")
        if not username or not password:
            attempts.append(now)
            self._login_attempts[client_ip] = attempts
            return self._json_response({"ok": False, "message": "Username and password required"})

        member = self._team.authenticate(username, password)
        if not member:
            attempts.append(now)
            self._login_attempts[client_ip] = attempts
            logger.warning("Failed login from %s (user: %s)", client_ip, username)
            return self._json_response({"ok": False, "message": "Invalid credentials"})

        # Check password expiry (60-day rotation)
        if self._team.password_expired(username):
            logger.info("Expired password for %s", username)
            return self._json_response({
                "ok": False,
                "expired": True,
                "message": "Password expired. Please set a new password.",
            })

        # Success — create session
        self._login_attempts.pop(client_ip, None)
        session_token = create_session_token(username, self._api_key, self._csp_nonce)
        # Add Secure flag when served over HTTPS (Heroku sets X-Forwarded-Proto)
        _secure_flag = "; Secure" if (headers or {}).get("x-forwarded-proto") == "https" else ""
        cookie = f"Set-Cookie: ng_session={session_token}; HttpOnly{_secure_flag}; SameSite=Strict; Path=/; Max-Age=3600\r\n"

        # Warn if password expiring within 7 days
        days_left = self._team.days_until_expiry(username)
        warning = None
        if days_left <= 7:
            warning = f"Password expires in {days_left} day{'s' if days_left != 1 else ''}. Please update it."

        logger.info("Login success: %s from %s", username, client_ip)
        return self._http_response(
            200, "application/json",
            json.dumps({"ok": True, "message": "Authenticated",
                        "user": member.get("display_name", username),
                        "warning": warning}),
            extra_headers=cookie,
        )

    async def _auth_change_password(self, body: bytes, client_ip: str) -> str:
        """Change password for a team member (requires old password)."""
        import time as _time
        now = _time.monotonic()
        attempts = self._login_attempts.get(client_ip, [])
        attempts = [t for t in attempts if now - t < 300]
        if len(attempts) >= 5:
            return self._json_response({"ok": False, "message": "Too many attempts."})
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            data = {}
        username = data.get("username", "").strip()
        old_pw = data.get("old_password", "")
        new_pw = data.get("new_password", "")

        if not username or not old_pw or not new_pw:
            return self._json_response({"ok": False, "message": "All fields required"})

        # Verify old password
        member = self._team.authenticate(username, old_pw)
        if not member:
            attempts.append(now)
            self._login_attempts[client_ip] = attempts
            return self._json_response({"ok": False, "message": "Invalid credentials"})

        try:
            self._team.change_password(username, new_pw)
        except ValueError as e:
            return self._json_response({"ok": False, "message": str(e)})

        logger.info("Password changed for %s from %s", username, client_ip)
        return self._json_response({"ok": True, "message": "Password updated"})

    async def _team_route(self, path: str, body: bytes, headers: dict[str, str]) -> str:
        """Admin team management endpoints."""
        # Require authentication for all team routes
        if not self._check_auth(headers):
            return self._http_response(401, _CONTENT_TEXT, "Unauthorized")

        # Check admin role from session
        username = self._get_session_user(headers)
        if not username:
            return self._http_response(401, _CONTENT_TEXT, "Unauthorized")
        member = self._team.members.get(username)
        if not member or member.get("role") != "admin":
            return self._json_response({"ok": False, "message": "Admin access required"})

        if path == "/api/team/list":
            return self._json_response(self._team.list_members())

        if path == "/api/team/add":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                data = {}
            try:
                self._team.add_member(
                    username=data.get("username", ""),
                    display_name=data.get("display_name", ""),
                    password=data.get("password", ""),
                    role=data.get("role", "operator"),
                )
                return self._json_response({"ok": True, "message": "Member added"})
            except ValueError as e:
                return self._json_response({"ok": False, "message": str(e)})

        if path == "/api/team/remove":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                data = {}
            target = data.get("username", "").lower().strip()
            if target == username:
                return self._json_response({"ok": False, "message": "Cannot remove yourself"})
            if self._team.remove_member(target):
                return self._json_response({"ok": True, "message": "Member removed"})
            return self._json_response({"ok": False, "message": "Member not found"})

        if path == "/api/team/reset-password":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                data = {}
            target = data.get("username", "")
            new_pw = data.get("password", "")
            try:
                if self._team.change_password(target, new_pw):
                    return self._json_response({"ok": True, "message": "Password reset"})
                return self._json_response({"ok": False, "message": "Member not found"})
            except ValueError as e:
                return self._json_response({"ok": False, "message": str(e)})

        return self._http_response(404, _CONTENT_TEXT, "Not Found")

    def _get_session_user(self, headers: dict[str, str]) -> str | None:
        """Extract username from valid session cookie."""
        for part in headers.get("cookie", "").split(";"):
            part = part.strip()
            if part.startswith("ng_session="):
                token = part[len("ng_session="):]
                return verify_session_token(
                    token, self._api_key, self._csp_nonce, self._team
                )
        return None

    # -- Response helpers -----------------------------------------------

    # Security headers added to every response
    _SECURITY_HEADERS = (
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "X-XSS-Protection: 1; mode=block\r\n"
        "Referrer-Policy: strict-origin-when-cross-origin\r\n"
        "Permissions-Policy: geolocation=(), camera=(), microphone=()\r\n"
        "Cache-Control: no-store\r\n"
        "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\r\n"
    )

    @classmethod
    def _http_response(cls, status: int, content_type: str, body: str,
                       extra_headers: str = "") -> str:
        reason = {
            200: "OK", 302: "Found", 400: "Bad Request",
            401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
            405: "Method Not Allowed", 413: "Payload Too Large",
            415: "Unsupported Media Type",
            429: "Too Many Requests",
            431: "Request Header Fields Too Large",
            500: "Internal Server Error",
        }.get(status, "OK")
        csp = (
            f"Content-Security-Policy: default-src 'self'; "
            f"script-src 'nonce-{cls._csp_nonce}'; "
            f"style-src 'self' 'unsafe-inline'; "
            f"font-src fonts.googleapis.com fonts.gstatic.com; "
            f"img-src 'self' data:; connect-src 'self'\r\n"
        )
        return (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body.encode())}\r\n"
            f"Connection: close\r\n"
            f"{extra_headers}"
            f"{cls._SECURITY_HEADERS}"
            f"{csp}"
            f"\r\n"
            f"{body}"
        )

    @classmethod
    def _json_response(cls, data: Any) -> str:
        body = json.dumps(sanitize_data(data), default=str)
        return cls._http_response(200, "application/json", body)

    # -- SSE live stream -----------------------------------------------

    async def _sse_ai_live(self, writer: asyncio.StreamWriter) -> None:
        """Server-Sent Events endpoint for the AI Engine page.
        Streams the full _ai_state JSON every 5 seconds and sends a keepalive
        comment every 25 seconds so Heroku's 55-second idle timer never fires."""
        import json as _json
        headers = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "X-Accel-Buffering: no\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
        )
        try:
            writer.write(headers.encode())
            await writer.drain()
        except Exception:
            return

        tick = 0
        while True:
            await asyncio.sleep(5)
            tick += 1
            try:
                # Keepalive comment every 25 s (5 ticks)
                if tick % 5 == 0:
                    writer.write(b": ping\n\n")
                    await writer.drain()

                state = self._ai_state
                payload = {
                    "metrics":              state["metrics"],
                    "anomaly_count":        state["anomaly_count"],
                    "prediction_count":     state["assessment_count"],
                    "latest_anomaly_score": state["latest_score"],
                    "ai_events":            state["ai_events"][:50],
                    "uptime_cycles":        state["uptime_cycles"],
                    "agents_monitored":     state["agents_monitored"],
                    "last_tick":            state["last_tick"],
                    "monitor_status":       state["status"],
                }
                line = "data: " + _json.dumps(payload) + "\n\n"
                writer.write(line.encode())
                await writer.drain()
            except (ConnectionResetError, BrokenPipeError, OSError):
                break
            except Exception as exc:
                logger.debug("[SSE] stream error: %s", exc)
                break

    # -- 24/7 AI Monitor Loop ------------------------------------------

    async def _ai_monitor_loop(self) -> None:
        """Continuously ingest fleet agent data, build rolling AI metrics,
        detect anomalies, and emit AI events. Runs every 10 seconds forever."""
        logger.info("[AI-MONITOR] 24/7 AI monitoring loop started")
        self._ai_state["status"] = "active"

        while True:
            try:
                await self._ai_monitor_tick()
            except Exception as exc:  # pragma: no cover
                logger.warning("[AI-MONITOR] tick error: %s", exc)
            await asyncio.sleep(10)

    async def _ai_monitor_tick(self) -> None:
        """Single monitoring tick — ingest all fleet agents, update state."""
        from datetime import datetime, timezone
        now_iso = datetime.now(timezone.utc).isoformat()
        state = self._ai_state
        metrics = state["metrics"]

        agents = self._fleet._data.get("agents", {})
        active_agents = 0
        new_events: list[dict] = []

        for aid, agent in agents.items():
            diag = agent.get("last_diagnostics", {})
            last_report = agent.get("last_report", {})
            threat_reports = agent.get("threat_reports", [])

            # --- Live diagnostics (arrives every ~60s from probe) ---
            if diag:
                active_agents += 1
                score = diag.get("threat_score", 0)
                net_drift = diag.get("network_baseline_drift", 0)
                proc_drift = diag.get("process_baseline_drift", 0)
                conns = len(diag.get("network_connections", []))
                ext_conns = sum(1 for c in diag.get("network_connections", [])
                                if isinstance(c, dict) and c.get("remote", "").split(":")[0]
                                not in ("127.0.0.1", "", "0.0.0.0", "::1", "::"))
                procs = diag.get("active_processes", 0)
                listeners = len([c for c in diag.get("network_connections", [])
                                 if isinstance(c, dict) and c.get("state") == "LISTEN"])

                # Append to rolling time-series (keep last 100 points)
                metrics["threat_score"].append(round(score, 1))
                metrics["connections"].append(conns)
                metrics["external_conns"].append(ext_conns)
                metrics["net_drift_%"].append(round(net_drift, 1))
                metrics["proc_drift_%"].append(round(proc_drift, 1))
                metrics["processes"].append(procs)
                metrics["listening_ports"].append(listeners)

                state["latest_score"] = max(state["latest_score"], score)
                state["assessment_count"] += 1

                # Emit assessment event
                new_events.append({
                    "timestamp": now_iso,
                    "topic": "ai.assessment",
                    "data": {
                        "agent": aid,
                        "score": score,
                        "risk": diag.get("risk_level", "low"),
                        "connections": conns,
                        "processes": procs,
                    },
                })

                # --- Anomaly detection (threshold-based) ---
                if score >= 70:
                    state["anomaly_count"] += 1
                    new_events.append({
                        "timestamp": now_iso,
                        "topic": "ai.anomaly.critical_score",
                        "data": {
                            "agent": aid,
                            "score": score,
                            "title": f"Critical threat score {score:.0f}/100",
                        },
                    })
                elif score >= 40:
                    state["anomaly_count"] += 1
                    new_events.append({
                        "timestamp": now_iso,
                        "topic": "ai.anomaly.elevated_score",
                        "data": {
                            "agent": aid,
                            "score": score,
                            "title": f"Elevated threat score {score:.0f}/100",
                        },
                    })

                if net_drift > 30:
                    state["anomaly_count"] += 1
                    new_events.append({
                        "timestamp": now_iso,
                        "topic": "ai.anomaly.network_drift",
                        "data": {
                            "agent": aid,
                            "drift_pct": net_drift,
                            "title": f"Network baseline drift {net_drift:.0f}%",
                        },
                    })

                if proc_drift > 40:
                    state["anomaly_count"] += 1
                    new_events.append({
                        "timestamp": now_iso,
                        "topic": "ai.anomaly.process_drift",
                        "data": {
                            "agent": aid,
                            "drift_pct": proc_drift,
                            "title": f"Process baseline drift {proc_drift:.0f}%",
                        },
                    })

                # Spike detection: last value vs rolling average
                for key, series in metrics.items():
                    if len(series) >= 5:
                        recent = series[-5:]
                        avg = sum(recent[:-1]) / (len(recent) - 1)
                        last = recent[-1]
                        if avg > 0 and last > avg * 2.5 and last > 10:
                            new_events.append({
                                "timestamp": now_iso,
                                "topic": f"ai.spike.{key}",
                                "data": {
                                    "agent": aid,
                                    "metric": key,
                                    "value": last,
                                    "avg": round(avg, 1),
                                    "title": f"Spike: {key} = {last} (avg {avg:.0f})",
                                },
                            })

            # --- Per-threat events from threat_history ---
            for t in agent.get("threat_history", [])[-10:]:
                state["anomaly_count"] += 1
                new_events.append({
                    "timestamp": t.get("timestamp", now_iso),
                    "topic": f"ai.threat.{t.get('category', 'unknown')}",
                    "data": {
                        "agent": aid,
                        "title": t.get("title", ""),
                        "severity": t.get("severity", ""),
                        "action": t.get("action_taken", ""),
                    },
                })

        # Trim series to last 100 data points
        for key in metrics:
            if len(metrics[key]) > 100:
                metrics[key] = metrics[key][-100:]

        # Prepend new events (newest-first), cap at 500
        existing_events = state["ai_events"]
        merged = new_events + existing_events
        # Deduplicate by topic+timestamp
        seen: set[str] = set()
        deduped: list[dict] = []
        for ev in merged:
            key = ev.get("topic", "") + ev.get("timestamp", "")[:19]
            if key not in seen:
                seen.add(key)
                deduped.append(ev)
        state["ai_events"] = deduped[:500]

        state["last_tick"] = now_iso
        state["uptime_cycles"] = state.get("uptime_cycles", 0) + 1
        state["agents_monitored"] = active_agents
        state["status"] = "active"

        # Also push into _recent_events for the live feed
        for ev in new_events[:5]:
            self._recent_events.append(ev)
        if len(self._recent_events) > 200:
            self._recent_events = self._recent_events[-200:]

    # -- Server lifecycle -----------------------------------------------

    def _page_security(self) -> str:
        return self._http_response(200, "text/html",
            _TMPL_SECURITY.replace("{{NONCE}}", Dashboard._csp_nonce),
            extra_headers="Cache-Control: no-store, no-cache, must-revalidate\r\nPragma: no-cache\r\n")

    def _api_malware_results(self) -> str:
        return self._json_response(self._last_malware_scan)

    def _api_ransomware_status(self) -> str:
        mon = self._ransomware_monitor
        if mon is None:
            return self._json_response({
                "running": False,
                "watch_folder": None,
                "alert_count": 0,
                "recent_alerts": [],
                "last_pdf": None,
            })
        alerts = [
            {"kind": a.kind, "path": a.path, "detail": a.detail, "timestamp": a.timestamp}
            for a in mon.alerts[-20:]
        ]
        last_pdf = None
        if hasattr(mon, "last_report") and mon.last_report and mon.last_report.pdf_path:
            import os as _os
            last_pdf = _os.path.basename(mon.last_report.pdf_path)
        return self._json_response({
            "running": mon.is_running,
            "watch_folder": mon.watch_folder,
            "alert_count": len(mon.alerts),
            "recent_alerts": list(reversed(alerts)),
            "last_pdf": last_pdf,
        })

    async def _api_serve_pdf(self, path: str, writer: asyncio.StreamWriter) -> None:
        """Serve a PDF from the pdf_reports directory as a binary download."""
        import os as _os
        from pathlib import Path as _Path
        filename = _os.path.basename(path.split("/api/reports/pdf/")[-1])
        # Validate filename — only allow safe characters
        import re as _re
        if not _re.match(r'^[\w\-\.]+\.pdf$', filename, _re.IGNORECASE):
            writer.write(self._http_response(400, _CONTENT_TEXT, "Bad filename").encode())
            await writer.drain()
            return
        candidates = [
            _Path.home() / ".network_guardian" / "pdf_reports" / filename,
            _Path("pdf_reports") / filename,
        ]
        pdf_bytes: bytes | None = None
        for p in candidates:
            if p.exists():
                try:
                    pdf_bytes = p.read_bytes()
                except OSError:
                    pass
                break
        if pdf_bytes is None:
            writer.write(self._http_response(404, _CONTENT_TEXT, "PDF not found").encode())
            await writer.drain()
            return
        header = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: application/pdf\r\n"
            f"Content-Length: {len(pdf_bytes)}\r\n"
            f"Content-Disposition: attachment; filename=\"{filename}\"\r\n"
            f"Cache-Control: no-store\r\n"
            f"\r\n"
        )
        writer.write(header.encode() + pdf_bytes)
        await writer.drain()

    async def _ctrl_malware_scan(self, data: dict) -> str:
        from network_guardian.agent.malware_react_agent import MalwareReActAgent
        if self._malware_react_agent is None:
            self._malware_react_agent = MalwareReActAgent(
                auto_kill=False,
                generate_pdf="on_threat",
                event_bus=self.engine.event_bus,
            )
        report = await self._malware_react_agent.run_cycle()
        findings = [
            {"pid": t["pid"], "name": t["name"], "exe": t.get("exe"),
             "matched_reason": t.get("detail", ""), "severity": t.get("severity", "medium")}
            for t in report.threats
        ]
        pdf_filename = None
        if report.pdf_path:
            import os as _os
            pdf_filename = _os.path.basename(report.pdf_path)
        payload: dict = {
            "ok": True,
            "scanned": report.scanned,
            "findings": findings,
            "errors": 0,
            "clean": len(findings) == 0,
            "risk_level": report.risk_level,
            "threat_score": report.threat_score,
            "react_steps": len(report.react_steps),
            "pdf_file": pdf_filename,
        }
        self._last_malware_scan = payload
        return self._json_response(payload)

    async def _ctrl_ransomware_start(self, data: dict) -> str:
        if self._ransomware_monitor is None:
            from network_guardian.agent.ransomware_react_agent import RansomwareReActAgent
            self._ransomware_monitor = RansomwareReActAgent(
                auto_quarantine=False,
                generate_pdf="on_threat",
                event_bus=self.engine.event_bus,
            )
        if self._ransomware_monitor.is_running:
            return self._json_response({"ok": True, "message": "ReAct monitor already running"})
        self._ransomware_monitor.start()
        return self._json_response({
            "ok": True,
            "message": (
                f"Ransomware ReAct monitor started — "
                f"watching {self._ransomware_monitor.watch_folder}"
            ),
        })

    async def _ctrl_ransomware_stop(self, data: dict) -> str:
        if self._ransomware_monitor is None or not self._ransomware_monitor.is_running:
            return self._json_response({"ok": True, "message": "Monitor not running"})
        self._ransomware_monitor.stop()
        return self._json_response({"ok": True, "message": "Ransomware ReAct monitor stopped"})

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        logger.info("Dashboard listening on %s:%d", self.host, self.port)
        # Start the 24/7 AI monitoring loop as a background task
        self._ai_monitor_task = asyncio.create_task(self._ai_monitor_loop())
        logger.info("[AI-MONITOR] Background monitoring task created")

    async def stop(self) -> None:
        if self._ai_monitor_task:
            self._ai_monitor_task.cancel()
            try:
                await self._ai_monitor_task
            except asyncio.CancelledError:
                pass
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("Dashboard stopped.")
