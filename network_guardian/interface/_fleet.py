# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
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
import os
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
        # Always honour a pinned key from the environment (survives Heroku restarts)
        env_key = os.environ.get("FLEET_KEY", "").strip()
        if env_key and self._data.get("fleet_key") != env_key:
            self._data["fleet_key"] = env_key
            self._save()
        elif not self._data.get("fleet_key"):
            # No env var — generate and persist one
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
        # Track ReAct diagnostics separately for quick access
        diag = report.get("diagnostics", {})
        if diag:
            agents[agent_id]["last_diagnostics"] = diag
            # Accumulate threat history
            hist = agents[agent_id].setdefault("threat_history", [])
            for t in diag.get("threats_detected", []):
                hist.append(t)
            # Keep last 200
            agents[agent_id]["threat_history"] = hist[-200:]
        # Store detailed threat reports sent by the agent
        for rpt in report.get("threat_reports", []):
            rpt_store = agents[agent_id].setdefault("threat_reports", [])
            # Deduplicate by report_id
            existing_ids = {r.get("report_id") for r in rpt_store}
            if rpt.get("report_id") not in existing_ids:
                rpt_store.append(rpt)
            agents[agent_id]["threat_reports"] = rpt_store[-50:]
        # Track sentinel data (stay-behind bot intelligence)
        sentinel = report.get("sentinel", {})
        if sentinel:
            agents[agent_id]["sentinel"] = sentinel
            agents[agent_id]["is_sentinel"] = True
            # Accumulate WiFi changes
            wifi_log = agents[agent_id].setdefault("wifi_change_log", [])
            wifi_log.extend(sentinel.get("wifi_changes", []))
            agents[agent_id]["wifi_change_log"] = wifi_log[-200:]
            # Accumulate flow anomalies
            anomaly_log = agents[agent_id].setdefault("flow_anomaly_log", [])
            anomaly_log.extend(sentinel.get("flow_anomalies", []))
            agents[agent_id]["flow_anomaly_log"] = anomaly_log[-200:]
            # Track rogue AP history
            rogue_log = agents[agent_id].setdefault("rogue_ap_log", [])
            rogue_log.extend(sentinel.get("rogue_ap_alerts", []))
            agents[agent_id]["rogue_ap_log"] = rogue_log[-100:]
        # Track covert comms status (which proxy/Tor channel the agent is using)
        covert = report.get("covert_status") or {}
        if covert:
            agents[agent_id]["covert_status"] = covert
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
            diag = a.get("last_diagnostics", {})
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
                # ReAct diagnostics summary
                "threat_score": diag.get("threat_score", 0),
                "risk_level": diag.get("risk_level", "unknown"),
                "threats_count": len(diag.get("threats_detected", [])),
                "issues_count": len(diag.get("issues_found", [])),
                "actions_count": len(diag.get("actions_taken", [])),
                "react_active": bool(diag),
                # Sentinel bot fields
                "is_sentinel": a.get("is_sentinel", False),
                "sentinel_sensitivity": sentinel.get("sensitivity_level", "") if (sentinel := a.get("sentinel")) else "",
                "sentinel_active_flows": sentinel.get("active_flows", 0) if (sentinel := a.get("sentinel")) else 0,
                "sentinel_wifi_changes": len(a.get("wifi_change_log", [])),
                "sentinel_flow_anomalies": len(a.get("flow_anomaly_log", [])),
                "sentinel_rogue_alerts": len(a.get("rogue_ap_log", [])),
                "sentinel_uptime": sentinel.get("uptime_seconds", 0) if (sentinel := a.get("sentinel")) else 0,
                "sentinel_bandwidth": sentinel.get("bandwidth_pattern", "") if (sentinel := a.get("sentinel")) else "",
                # Covert comms status per agent
                "covert_proxy": (cs := a.get("covert_status", {})).get("proxy", ""),
                "covert_jitter": cs.get("jitter", "off"),
                "covert_decoys": cs.get("decoys", 0),
                "covert_ua": cs.get("user_agent_rotation", False),
                "covert_padding": cs.get("body_padding", False),
            })
        return result

    def get_agent_report(self, agent_id: str) -> dict | None:
        agent = self._data.get("agents", {}).get(agent_id)
        if agent:
            return agent.get("last_report")
        return None

    def get_agent_diagnostics(self, agent_id: str) -> dict | None:
        """Return the latest ReAct diagnostics for an agent."""
        agent = self._data.get("agents", {}).get(agent_id)
        if agent:
            return agent.get("last_diagnostics")
        return None

    def get_agent_threat_history(self, agent_id: str) -> list[dict]:
        """Return accumulated threat history for an agent."""
        agent = self._data.get("agents", {}).get(agent_id)
        if agent:
            return agent.get("threat_history", [])
        return []

    def get_agent_threat_reports(self, agent_id: str) -> list[dict]:
        """Return all detailed threat assessment reports for an agent."""
        agent = self._data.get("agents", {}).get(agent_id)
        if not agent:
            return []
        return agent.get("threat_reports", [])

    def get_all_threat_reports(self) -> list[dict]:
        """Aggregate threat reports across all agents, newest first."""
        all_reports = []
        for aid, agent in self._data.get("agents", {}).items():
            for r in agent.get("threat_reports", []):
                r_copy = dict(r)
                r_copy.setdefault("agent_id", aid)
                all_reports.append(r_copy)
        all_reports.sort(key=lambda r: r.get("generated_at", ""), reverse=True)
        return all_reports[:200]

    def set_patch_config(self, agent_id: str, config: dict) -> bool:
        """Queue a patch config to be delivered to a specific agent on next phone-home."""
        agent = self._data.get("agents", {}).get(agent_id)
        if not agent:
            return False
        agent["pending_patch_config"] = config
        self._save()
        logger.info("Patch config queued for agent %s: %s", agent_id, config)
        return True

    def pop_patch_config(self, agent_id: str) -> dict | None:
        """Return and clear any pending patch config for this agent."""
        agent = self._data.get("agents", {}).get(agent_id)
        if not agent:
            return None
        cfg = agent.pop("pending_patch_config", None)
        if cfg is not None:
            self._save()
        return cfg

    def get_agent_sentinel(self, agent_id: str) -> dict | None:
        """Return sentinel bot intelligence for an agent."""
        agent = self._data.get("agents", {}).get(agent_id)
        if not agent or not agent.get("is_sentinel"):
            return None
        return {
            "sentinel": agent.get("sentinel", {}),
            "wifi_change_log": agent.get("wifi_change_log", [])[-50:],
            "flow_anomaly_log": agent.get("flow_anomaly_log", [])[-50:],
            "rogue_ap_log": agent.get("rogue_ap_log", [])[-30:],
        }

    def get_fleet_threat_summary(self) -> dict:
        """Aggregate threat intelligence across all agents."""
        total_threats = 0
        critical_agents = []
        all_categories: dict[str, int] = {}
        now = int(time.time())

        for aid, a in self._data.get("agents", {}).items():
            diag = a.get("last_diagnostics", {})
            if not diag:
                continue
            score = diag.get("threat_score", 0)
            risk = diag.get("risk_level", "low")
            threats = diag.get("threats_detected", [])
            total_threats += len(threats)

            if risk in ("high", "critical"):
                age = now - a.get("last_seen", 0)
                if age < 600:  # Only recent agents
                    critical_agents.append({
                        "agent_id": aid,
                        "label": a.get("label", aid),
                        "threat_score": score,
                        "risk_level": risk,
                        "threats": len(threats),
                    })

            for t in threats:
                cat = t.get("category", "unknown")
                all_categories[cat] = all_categories.get(cat, 0) + 1

        return {
            "total_threats_detected": total_threats,
            "critical_agents": critical_agents,
            "threat_categories": all_categories,
            "fleet_agents_with_react": sum(
                1 for a in self._data.get("agents", {}).values()
                if a.get("last_diagnostics")),
        }

    def verify_signature(self, payload: bytes, signature: str) -> bool:
        """Verify an agent's HMAC-SHA256 signature.

        CovertComms pads the body (adds a ``_t`` field and compacts the JSON)
        after the probe computes the HMAC on the original, unpadded payload.
        We therefore try two forms:
          1. Exact match against the received bytes.
          2. Strip the ``_t`` field and re-serialise with default separators
             to recover the bytes the probe originally signed.
        """
        key = self.fleet_key.encode()
        expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, signature):
            return True
        # Attempt to recover original pre-padding payload
        try:
            data = json.loads(payload)
            if "_t" in data:
                original = {k: v for k, v in data.items() if k != "_t"}
                original_bytes = json.dumps(original).encode()
                exp2 = hmac.new(key, original_bytes, hashlib.sha256).hexdigest()
                if hmac.compare_digest(exp2, signature):
                    return True
        except Exception:
            pass
        return False


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
.detail-box{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:24px;max-width:900px;width:95%;max-height:90vh;overflow-y:auto}
.detail-box h3{font-size:1.1rem;margin-bottom:16px;color:var(--blue)}
.close-btn{float:right;background:none;border:1px solid var(--border);color:var(--text);padding:4px 12px;border-radius:6px;cursor:pointer;font-size:.85rem}
.close-btn:hover{background:var(--border)}
.wifi-mini{display:inline-block;padding:3px 8px;margin:2px;border-radius:6px;font-size:.72rem;background:rgba(88,166,255,.1);border:1px solid rgba(88,166,255,.2);color:var(--blue)}
.host-mini{display:inline-block;padding:3px 8px;margin:2px;border-radius:6px;font-size:.72rem;background:rgba(63,185,80,.1);border:1px solid rgba(63,185,80,.2);color:var(--green);font-family:monospace}
.threat-badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.7rem;font-weight:700;letter-spacing:.5px}
.threat-badge.low{background:rgba(63,185,80,.15);color:var(--green)}
.threat-badge.medium{background:rgba(210,153,34,.15);color:var(--yellow)}
.threat-badge.high{background:rgba(219,109,40,.15);color:var(--orange)}
.threat-badge.critical{background:rgba(248,81,73,.15);color:var(--red)}
.threat-badge.unknown{background:rgba(139,148,158,.15);color:var(--dim)}
.react-chip{display:inline-block;padding:2px 6px;border-radius:6px;font-size:.68rem;font-weight:700;margin-right:4px}
.react-chip.observe{background:rgba(88,166,255,.15);color:var(--blue)}
.react-chip.reason{background:rgba(210,153,34,.15);color:var(--yellow)}
.react-chip.act{background:rgba(63,185,80,.15);color:var(--green)}
.react-chip.learn{background:rgba(188,140,255,.15);color:var(--purple)}
.covert-chip{display:inline-block;padding:2px 8px;border-radius:6px;font-size:.7rem;font-weight:700;letter-spacing:.3px}
.covert-chip.tor{background:rgba(63,185,80,.12);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.covert-chip.proxy{background:rgba(88,166,255,.12);color:var(--blue);border:1px solid rgba(88,166,255,.3)}
.covert-chip.direct{background:rgba(139,148,158,.1);color:var(--dim);border:1px solid rgba(139,148,158,.2)}
.threat-entry{padding:8px 12px;border-radius:8px;margin-bottom:6px;font-size:.78rem;border-left:3px solid}
.threat-entry.info{border-color:var(--blue);background:rgba(88,166,255,.05)}
.threat-entry.low{border-color:var(--green);background:rgba(63,185,80,.05)}
.threat-entry.medium{border-color:var(--yellow);background:rgba(210,153,34,.05)}
.threat-entry.high{border-color:var(--orange);background:rgba(219,109,40,.05)}
.threat-entry.critical{border-color:var(--red);background:rgba(248,81,73,.05)}
</style></head><body>
<div class="wrap">
  <div class="banner">
    <h1>&#128752; Fleet Command</h1>
    <span id="count" class="badge" style="background:rgba(88,166,255,.15);color:var(--blue)">0 Agents</span>
    <span id="threatBadge" class="badge" style="background:rgba(63,185,80,.15);color:var(--green)">Fleet Secure</span>
    <span id="ts" style="margin-left:auto;color:var(--dim);font-size:.85rem"></span>
  </div>
  <div class="kpi-row">
    <div class="kpi"><div class="v" id="kT">0</div><div class="l">Total Agents</div></div>
    <div class="kpi"><div class="v" id="kOn" style="color:var(--green)">0</div><div class="l">Online</div></div>
    <div class="kpi"><div class="v" id="kSt" style="color:var(--yellow)">0</div><div class="l">Stale</div></div>
    <div class="kpi"><div class="v" id="kOf" style="color:var(--red)">0</div><div class="l">Offline</div></div>
    <div class="kpi"><div class="v" id="kTh" style="color:var(--orange)">0</div><div class="l">Threats</div></div>
    <div class="kpi"><div class="v" id="kRe" style="color:var(--cyan)">0</div><div class="l">ReAct Agents</div></div>
    <div class="kpi"><div class="v" id="kWi" style="color:var(--purple)">0</div><div class="l">WiFi Nets</div></div>
    <div class="kpi"><div class="v" id="kHo" style="color:var(--pink)">0</div><div class="l">Hosts</div></div>
    <div class="kpi"><div class="v" id="kCo" style="color:var(--green)">0</div><div class="l">&#128274; Covert</div></div>
  </div>
  <div class="nav">
    <a href="/">Dashboard</a><a href="/ids">IDS</a><a href="/ips">IPS</a><a href="/wifi">WiFi</a>
    <a href="/cloaking">Cloaking</a><a href="/explorer">Explorer</a><a href="/auditor">Auditor</a>
    <a href="/ai">AI Engine</a><a href="/fleet" class="active">Fleet</a><a href="/security">&#128737; Threats</a>
  </div>

  <!-- Fleet Threat Intelligence -->
  <div class="card" style="margin-bottom:16px" id="threatIntelCard">
    <h2>&#128680; Fleet Threat Intelligence</h2>
    <div id="threatIntel"><div class="empty">Waiting for agent diagnostics...</div></div>
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
  <div class="card" style="padding:0;overflow:hidden">
    <div style="padding:18px 22px 12px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border)">
      <h2 style="margin:0">&#128200; Fleet Map</h2>
      <span id="mapStatus" style="font-size:.75rem;color:var(--dim);font-family:monospace">&#9900; live</span>
    </div>
    <canvas id="fleetMap" style="display:block;width:100%"></canvas>
    <div id="mapLegend" style="padding:10px 22px 16px;display:flex;gap:18px;flex-wrap:wrap;font-size:.72rem;color:var(--dim);border-top:1px solid var(--border)"></div>
  </div>
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

var riskColor={low:'--green',medium:'--yellow',high:'--orange',critical:'--red',unknown:'--dim'};
var _agents=[];var _mapAnim=null;

function _isTorProxy(proxy){
  return proxy&&(proxy.indexOf('socks5')!==-1||proxy.indexOf('9050')!==-1||proxy.indexOf('9150')!==-1);
}

function showAgent(aid){
  var aInfo=_agents.find(function(a){return a.agent_id===aid;})||{};
  Promise.all([
    fetch('/api/fleet/agent/'+aid).then(r=>r.json()).catch(()=>({})),
    fetch('/api/fleet/agent/'+aid+'/diagnostics').then(r=>r.ok?r.json():null).catch(()=>null),
    fetch('/api/fleet/agent/'+aid+'/sentinel').then(r=>r.ok?r.json():null).catch(()=>null),
  ]).then(function(arr){
    var d=arr[0]||{};var diag=arr[1];var sent=arr[2];
    var id=d.identity||{};var m=d.system_metrics||{};
    var html='<h3>'+((id.hostname)||'Agent')+' ('+(d.agent_id||aid)+')</h3>';

    // Covert comms banner (top of detail — most important opsec info)
    var cov=aInfo.covert_proxy!==undefined?aInfo:{};
    if(cov.covert_proxy!==undefined){
      var ctIsTor=_isTorProxy(cov.covert_proxy);
      var ctIsProxy=cov.covert_proxy&&cov.covert_proxy!=='none';
      var ctColor=ctIsProxy?'var(--green)':'var(--red)';
      var ctLabel=ctIsTor?'TOR SOCKS5':ctIsProxy?'HTTP/SOCKS PROXY':'DIRECT (UNPROTECTED)';
      html+='<div style="padding:10px 14px;border-radius:10px;margin-bottom:14px;border:1px solid '+(ctIsProxy?'rgba(63,185,80,.3)':'rgba(248,81,73,.3)')+';background:'+(ctIsProxy?'rgba(63,185,80,.05)':'rgba(248,81,73,.05)')+'">';
      html+='<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">';
      html+='<span class="covert-chip '+(ctIsTor?'tor':ctIsProxy?'proxy':'direct')+'">&#128274; '+ctLabel+'</span>';
      if(ctIsProxy){
        html+='<span style="font-size:.78rem;color:var(--dim)">Jitter: <b style="color:var(--text)">'+(cov.covert_jitter||'off')+'</b></span>';
        html+='<span style="font-size:.78rem;color:var(--dim)">Decoys: <b style="color:var(--text)">'+(cov.covert_decoys||0)+'</b></span>';
        html+='<span style="font-size:.78rem;color:var(--dim)">UA Rotation: <b style="color:var(--text)">'+(cov.covert_ua?'on':'off')+'</b></span>';
        html+='<span style="font-size:.78rem;color:var(--dim)">Body Pad: <b style="color:var(--text)">'+(cov.covert_padding?'on':'off')+'</b></span>';
      }else{
        html+='<span style="font-size:.78rem;color:var(--red)">Base IP visible to network observers — use --tor or --proxy</span>';
      }
      html+='</div></div>';
    }

    // Diagnostics banner
    if(diag){
      var rc=riskColor[diag.risk_level]||'--dim';
      html+='<div style="padding:12px 16px;border-radius:10px;margin-bottom:16px;border:1px solid var('+rc+');background:rgba(0,0,0,.3)">';
      html+='<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">';
      html+='<span class="threat-badge '+diag.risk_level+'">'+diag.risk_level.toUpperCase()+' RISK</span>';
      html+='<span style="font-size:1.3rem;font-weight:700;color:var('+rc+')">'+Math.round(diag.threat_score)+'/100</span>';
      html+='<span style="color:var(--dim);font-size:.8rem">Threat Score</span>';
      html+='</div>';
      if(diag.recommendations&&diag.recommendations.length){
        html+='<div style="font-size:.78rem;color:var(--text);margin-top:6px">';
        diag.recommendations.forEach(function(r){html+='<div style="margin:3px 0">&#9888;&#65039; '+r+'</div>';});
        html+='</div>';
      }
      html+='</div>';
    }

    // Identity grid
    html+='<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">';
    html+='<div><b style="color:var(--dim);font-size:.75rem">PLATFORM</b><br>'+(id.platform_os||'-')+'</div>';
    html+='<div><b style="color:var(--dim);font-size:.75rem">LOCAL IP</b><br><span style="font-family:monospace">'+(d.local_ip||'-')+'</span></div>';
    html+='<div><b style="color:var(--dim);font-size:.75rem">SUBNET</b><br><span style="font-family:monospace">'+(d.subnet||'-')+'</span></div>';
    html+='<div><b style="color:var(--dim);font-size:.75rem">GATEWAY</b><br><span style="font-family:monospace">'+(d.gateway||'-')+'</span></div>';
    html+='<div><b style="color:var(--dim);font-size:.75rem">CPU LOAD</b><br>'+(m.cpu_load_1m||'-')+'</div>';
    html+='<div><b style="color:var(--dim);font-size:.75rem">MEMORY</b><br>'+(m.mem_pct?m.mem_pct+'%':'-')+'</div>';
    html+='<div><b style="color:var(--dim);font-size:.75rem">DISK</b><br>'+(m.disk_pct?m.disk_pct+'%':'-')+'</div>';
    html+='<div><b style="color:var(--dim);font-size:.75rem">UPTIME</b><br>'+(m.uptime_hours?m.uptime_hours+'h':'-')+'</div>';
    html+='</div>';

    // ReAct diagnostics section
    if(diag){
      // Threats
      var threats=diag.threats_detected||[];
      html+='<h3 style="font-size:.9rem;margin:16px 0 8px">&#128680; Threats Detected ('+threats.length+')</h3>';
      if(threats.length){
        threats.forEach(function(t){
          html+='<div class="threat-entry '+t.severity+'">';
          html+='<span class="threat-badge '+t.severity+'">'+t.severity.toUpperCase()+'</span> ';
          html+='<b>'+t.title+'</b><br>';
          html+='<span style="color:var(--dim);font-size:.72rem">'+t.detail+'</span>';
          if(t.action_taken){html+='<br><span style="color:var(--green);font-size:.72rem">Action: '+t.action_taken+'</span>';}
          html+='</div>';
        });
      }else{html+='<div style="color:var(--green);font-size:.82rem">&#9989; No threats detected</div>';}

      // Issues
      var issues=diag.issues_found||[];
      if(issues.length){
        html+='<h3 style="font-size:.9rem;margin:16px 0 8px">&#128295; Issues Found ('+issues.length+')</h3>';
        issues.forEach(function(iss){
          html+='<div style="padding:6px 10px;margin:4px 0;border-radius:6px;background:rgba(210,153,34,.08);font-size:.78rem">';
          html+='<b>'+iss.type+'</b>: '+(iss.recommendation||JSON.stringify(iss));
          html+='</div>';
        });
      }

      // Actions taken
      var actions=diag.actions_taken||[];
      if(actions.length){
        html+='<h3 style="font-size:.9rem;margin:16px 0 8px">&#9889; Actions Taken ('+actions.length+')</h3>';
        actions.forEach(function(a){
          var ok=a.success?'var(--green)':'var(--red)';
          html+='<div style="padding:4px 10px;margin:3px 0;border-radius:6px;background:rgba(63,185,80,.05);font-size:.78rem">';
          html+='<span style="color:'+ok+'">&#x2022;</span> '+a.action+': '+a.detail;
          html+='</div>';
        });
      }

      // ReAct log
      var log=diag.react_log||[];
      if(log.length){
        html+='<h3 style="font-size:.9rem;margin:16px 0 8px">&#129504; ReAct Agent Log</h3>';
        html+='<div style="max-height:200px;overflow-y:auto;background:var(--bg);border-radius:8px;padding:8px">';
        log.forEach(function(s){
          html+='<div style="margin:3px 0;font-size:.75rem">';
          html+='<span class="react-chip '+s.phase+'">'+s.phase.toUpperCase()+'</span>';
          html+=s.thought;
          html+='</div>';
        });
        html+='</div>';
      }

      // Baseline drift
      html+='<div style="display:flex;gap:16px;margin-top:14px">';
      html+='<div style="font-size:.78rem;color:var(--dim)">Network Drift: <b style="color:var(--text)">'+Math.round(diag.network_baseline_drift||0)+'%</b></div>';
      html+='<div style="font-size:.78rem;color:var(--dim)">Process Drift: <b style="color:var(--text)">'+Math.round(diag.process_baseline_drift||0)+'%</b></div>';
      html+='<div style="font-size:.78rem;color:var(--dim)">Active Processes: <b style="color:var(--text)">'+(diag.active_processes||0)+'</b></div>';
      html+='<div style="font-size:.78rem;color:var(--dim)">Listeners: <b style="color:var(--text)">'+(diag.listening_ports?diag.listening_ports.length:0)+'</b></div>';
      html+='</div>';
    }

    // Sentinel intelligence
    if(sent){
      var si=sent.sentinel||{};
      html+='<div style="margin-top:16px;padding:14px 16px;border-radius:10px;border:1px solid rgba(57,210,224,.3);background:rgba(57,210,224,.04)">';
      html+='<h3 style="font-size:.9rem;margin:0 0 10px;color:var(--cyan)">&#128737; Sentinel Intelligence</h3>';
      // Strategy bar
      html+='<div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:10px">';
      html+='<div style="font-size:.78rem">Sensitivity: <b style="color:var(--cyan)">'+(si.sensitivity_level||'normal').toUpperCase()+'</b></div>';
      html+='<div style="font-size:.78rem">Active Flows: <b style="color:var(--text)">'+(si.active_flows||0)+'</b></div>';
      html+='<div style="font-size:.78rem">Bandwidth: <b style="color:var(--text)">'+(si.bandwidth_pattern||'baseline')+'</b></div>';
      html+='<div style="font-size:.78rem">Adapt Count: <b style="color:var(--text)">'+(si.adapt_count||0)+'</b></div>';
      var upS=si.uptime_seconds||0;var upH=upS>3600?Math.floor(upS/3600)+'h '+Math.floor((upS%3600)/60)+'m':Math.floor(upS/60)+'m';
      html+='<div style="font-size:.78rem">Uptime: <b style="color:var(--text)">'+upH+'</b></div>';
      html+='</div>';
      // WiFi watcher
      var wch=sent.wifi_change_log||[];
      if(wch.length){
        html+='<div style="margin-bottom:8px"><b style="font-size:.78rem;color:var(--blue)">WiFi Changes ('+wch.length+')</b>';
        html+='<div style="max-height:120px;overflow-y:auto;background:var(--bg);border-radius:6px;padding:6px;margin-top:4px">';
        wch.slice(-20).reverse().forEach(function(c){
          var icon=c.type==='new_ap'?'&#128994;':c.type==='disappeared'?'&#128308;':c.type==='rogue_suspect'?'&#128721;':'&#128309;';
          html+='<div style="font-size:.72rem;margin:2px 0">'+icon+' '+c.type+': <b>'+(c.ssid||c.bssid||'')+'</b>'+(c.detail?' — '+c.detail:'')+'</div>';
        });
        html+='</div></div>';
      }
      // Flow anomalies
      var fan=sent.flow_anomaly_log||[];
      if(fan.length){
        html+='<div style="margin-bottom:8px"><b style="font-size:.78rem;color:var(--orange)">Flow Anomalies ('+fan.length+')</b>';
        html+='<div style="max-height:120px;overflow-y:auto;background:var(--bg);border-radius:6px;padding:6px;margin-top:4px">';
        fan.slice(-15).reverse().forEach(function(a){
          html+='<div style="font-size:.72rem;margin:2px 0">&#9888;&#65039; '+a.type+': '+(a.detail||JSON.stringify(a))+'</div>';
        });
        html+='</div></div>';
      }
      // Rogue AP alerts
      var rog=sent.rogue_ap_log||[];
      if(rog.length){
        html+='<div style="margin-bottom:8px"><b style="font-size:.78rem;color:var(--red)">&#128721; Rogue AP Alerts ('+rog.length+')</b>';
        html+='<div style="max-height:100px;overflow-y:auto;background:rgba(248,81,73,.05);border-radius:6px;padding:6px;margin-top:4px">';
        rog.slice(-10).reverse().forEach(function(r){
          html+='<div style="font-size:.72rem;margin:2px 0;color:var(--red)">SSID: <b>'+r.ssid+'</b> — '+r.bssid_count+' BSSIDs, signal spread: '+r.signal_spread+'dBm</div>';
        });
        html+='</div></div>';
      }
      html+='</div>';
    }

    // WiFi / Hosts
    var nets=d.wifi_networks||[];
    html+='<h3 style="font-size:.9rem;margin:16px 0 8px">&#128225; WiFi Networks ('+nets.length+')</h3>';
    if(nets.length){html+='<div>';nets.forEach(function(n){html+='<span class="wifi-mini">'+(n.ssid||'Hidden')+' ('+n.signal+'dBm)</span>';});html+='</div>';}
    else{html+='<div class="empty">No networks</div>';}
    var hosts=d.discovered_hosts||[];
    html+='<h3 style="font-size:.9rem;margin:16px 0 8px">&#128187; Discovered Hosts ('+hosts.length+')</h3>';
    if(hosts.length){html+='<div>';hosts.forEach(function(h){html+='<span class="host-mini">'+h.ip+(h.hostname?' ('+h.hostname+')':'')+'</span>';});html+='</div>';}
    else{html+='<div class="empty">No hosts</div>';}

    document.getElementById('detailContent').innerHTML=html;
    document.getElementById('overlay').classList.add('show');
  });
}

function _hex2rgb(h){return[parseInt(h.slice(1,3),16),parseInt(h.slice(3,5),16),parseInt(h.slice(5,7),16)];}
function drawMap(agents){
  var c=document.getElementById('fleetMap'),ctx=c.getContext('2d');
  if(_mapAnim){cancelAnimationFrame(_mapAnim);_mapAnim=null;}
  // Legend
  document.getElementById('mapLegend').innerHTML=
    '<span style="display:flex;align-items:center;gap:5px"><i style="width:9px;height:9px;border-radius:50%;background:#3fb950;display:inline-block;box-shadow:0 0 6px #3fb950"></i>Online</span>'+
    '<span style="display:flex;align-items:center;gap:5px"><i style="width:9px;height:9px;border-radius:50%;background:#d29922;display:inline-block"></i>Stale</span>'+
    '<span style="display:flex;align-items:center;gap:5px"><i style="width:9px;height:9px;border-radius:50%;background:#f85149;display:inline-block"></i>Offline</span>'+
    '<span style="display:flex;align-items:center;gap:5px"><i style="width:9px;height:9px;border-radius:50%;background:#bc8cff;display:inline-block"></i>ReAct</span>'+
    '<span style="display:flex;align-items:center;gap:5px"><i style="width:9px;height:9px;border-radius:50%;background:#39d2e0;display:inline-block"></i>Sentinel</span>'+
    '<span style="display:flex;align-items:center;gap:5px"><i style="width:9px;height:9px;border-radius:50%;background:#3fb950;display:inline-block"></i>Covert/Tor</span>'+
    '<span style="color:var(--dim)">Arc&#8202;=&#8202;threat score</span>';
  function frame(ts){
    var W=c.width=c.parentElement.clientWidth,H=c.height=440;
    ctx.clearRect(0,0,W,H);
    // Background gradient
    var bg=ctx.createLinearGradient(0,0,W,H);
    bg.addColorStop(0,'#0a0e14');bg.addColorStop(1,'#0d1117');
    ctx.fillStyle=bg;ctx.fillRect(0,0,W,H);
    // Grid
    ctx.save();ctx.strokeStyle='rgba(48,54,61,0.45)';ctx.lineWidth=0.5;
    var gs=38;
    for(var gx=0;gx<=W;gx+=gs){ctx.beginPath();ctx.moveTo(gx,0);ctx.lineTo(gx,H);ctx.stroke();}
    for(var gy=0;gy<=H;gy+=gs){ctx.beginPath();ctx.moveTo(0,gy);ctx.lineTo(W,gy);ctx.stroke();}
    ctx.restore();
    var cx=W/2,cy=H/2,r=Math.min(W*0.4,H*0.4);
    if(!agents.length){
      ctx.fillStyle='#8b949e';ctx.textAlign='center';ctx.textBaseline='middle';
      ctx.font='14px -apple-system,sans-serif';ctx.fillText('No agents deployed — deploy a probe to get started',W/2,H/2);
      _mapAnim=requestAnimationFrame(frame);return;
    }
    // Animated connection lines (drawn first, behind nodes)
    agents.forEach(function(a,i){
      var ang=(i/agents.length)*Math.PI*2-Math.PI/2;
      var x=cx+r*Math.cos(ang),y=cy+r*Math.sin(ang);
      var col=a.status==='online'?'#3fb950':a.status==='stale'?'#d29922':'#f85149';
      var rgb=_hex2rgb(col);
      var grad=ctx.createLinearGradient(cx,cy,x,y);
      grad.addColorStop(0,'rgba(88,166,255,0.6)');
      grad.addColorStop(1,'rgba('+rgb[0]+','+rgb[1]+','+rgb[2]+',0.3)');
      ctx.save();
      ctx.beginPath();ctx.moveTo(cx,cy);ctx.lineTo(x,y);
      ctx.strokeStyle=grad;ctx.lineWidth=1.5;
      ctx.setLineDash([7,7]);ctx.lineDashOffset=-(ts/55)%14;
      ctx.stroke();ctx.restore();
    });
    // Base station
    var pulse=(Math.sin(ts/750)+1)/2;
    ctx.beginPath();ctx.arc(cx,cy,32+pulse*10,0,Math.PI*2);
    ctx.strokeStyle='rgba(88,166,255,'+(0.1+pulse*0.12)+')';ctx.lineWidth=2;ctx.stroke();
    ctx.beginPath();ctx.arc(cx,cy,25,0,Math.PI*2);
    ctx.strokeStyle='rgba(88,166,255,0.28)';ctx.lineWidth=1.5;ctx.stroke();
    var bfg=ctx.createRadialGradient(cx,cy,0,cx,cy,22);
    bfg.addColorStop(0,'rgba(88,166,255,0.45)');bfg.addColorStop(1,'rgba(88,166,255,0.03)');
    ctx.beginPath();ctx.arc(cx,cy,22,0,Math.PI*2);ctx.fillStyle=bfg;ctx.fill();
    ctx.shadowBlur=22;ctx.shadowColor='#58a6ff';
    ctx.beginPath();ctx.arc(cx,cy,13,0,Math.PI*2);ctx.fillStyle='#58a6ff';ctx.fill();
    ctx.shadowBlur=0;
    ctx.fillStyle='#fff';ctx.font='bold 7px sans-serif';
    ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText('BASE',cx,cy);
    // Agent nodes
    agents.forEach(function(a,i){
      var ang=(i/agents.length)*Math.PI*2-Math.PI/2;
      var x=cx+r*Math.cos(ang),y=cy+r*Math.sin(ang);
      var col=a.status==='online'?'#3fb950':a.status==='stale'?'#d29922':'#f85149';
      var rgb=_hex2rgb(col);
      // Sentinel dashed orbit ring
      if(a.is_sentinel){
        ctx.save();ctx.beginPath();ctx.arc(x,y,27,0,Math.PI*2);
        ctx.strokeStyle='rgba(57,210,224,0.45)';ctx.lineWidth=1.5;
        ctx.setLineDash([4,6]);ctx.lineDashOffset=-(ts/80)%10;ctx.stroke();ctx.restore();
      }
      // Online pulse ring
      if(a.status==='online'){
        var p2=(Math.sin(ts/750+i*1.4)+1)/2;
        ctx.beginPath();ctx.arc(x,y,20+p2*9,0,Math.PI*2);
        ctx.strokeStyle='rgba('+rgb[0]+','+rgb[1]+','+rgb[2]+','+(0.07+p2*0.13)+')';ctx.lineWidth=1.5;ctx.stroke();
      }
      // Threat score arc ring (behind node fill)
      if(a.react_active){
        var rc=a.risk_level==='critical'?[248,81,73]:a.risk_level==='high'?[219,109,40]:a.risk_level==='medium'?[210,153,34]:[63,185,80];
        var score=Math.max(0,Math.min(100,a.threat_score||0));
        ctx.beginPath();ctx.arc(x,y,20,0,Math.PI*2);
        ctx.strokeStyle='rgba(24,30,38,0.9)';ctx.lineWidth=4;ctx.stroke();
        if(score>0){
          ctx.beginPath();ctx.arc(x,y,20,-Math.PI/2,-Math.PI/2+(score/100)*Math.PI*2);
          ctx.strokeStyle='rgba('+rc[0]+','+rc[1]+','+rc[2]+',0.95)';ctx.lineWidth=4;ctx.lineCap='round';ctx.stroke();ctx.lineCap='butt';
        }
      }
      // Node glow
      ctx.shadowBlur=18;ctx.shadowColor='rgba('+rgb[0]+','+rgb[1]+','+rgb[2]+',0.75)';
      var ng=ctx.createRadialGradient(x,y,0,x,y,16);
      ng.addColorStop(0,'rgba('+rgb[0]+','+rgb[1]+','+rgb[2]+',0.6)');
      ng.addColorStop(1,'rgba('+rgb[0]+','+rgb[1]+','+rgb[2]+',0.04)');
      ctx.beginPath();ctx.arc(x,y,16,0,Math.PI*2);ctx.fillStyle=ng;ctx.fill();
      ctx.shadowBlur=0;
      ctx.beginPath();ctx.arc(x,y,11,0,Math.PI*2);ctx.fillStyle=col;ctx.fill();
      // Icon letter
      ctx.fillStyle='rgba(0,0,0,0.55)';ctx.font='bold 9px sans-serif';
      ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText(a.is_sentinel?'S':'P',x,y);
      // ReAct dot (top-right, purple)
      if(a.react_active){
        ctx.shadowBlur=8;ctx.shadowColor='#bc8cff';
        ctx.beginPath();ctx.arc(x+13,y-13,4.5,0,Math.PI*2);ctx.fillStyle='#bc8cff';ctx.fill();
        ctx.shadowBlur=0;
      }
      // Sentinel dot (top-left, cyan)
      if(a.is_sentinel){
        ctx.shadowBlur=8;ctx.shadowColor='#39d2e0';
        ctx.beginPath();ctx.arc(x-13,y-13,4.5,0,Math.PI*2);ctx.fillStyle='#39d2e0';ctx.fill();
        ctx.shadowBlur=0;
      }
      // Covert dot (bottom-right)
      if(a.covert_proxy&&a.covert_proxy!=='none'){
        var lc=_isTorProxy(a.covert_proxy)?'#3fb950':'#58a6ff';
        ctx.shadowBlur=8;ctx.shadowColor=lc;
        ctx.beginPath();ctx.arc(x+13,y+13,4.5,0,Math.PI*2);ctx.fillStyle=lc;ctx.fill();
        ctx.shadowBlur=0;
      }
      // Labels
      ctx.textBaseline='top';
      ctx.fillStyle='#e6edf3';ctx.font='bold 10px -apple-system,BlinkMacSystemFont,sans-serif';
      ctx.textAlign='center';ctx.fillText((a.label||a.agent_id).substring(0,18),x,y+19);
      if(a.local_ip){
        ctx.fillStyle='#8b949e';ctx.font='8px monospace';
        ctx.fillText(a.local_ip,x,y+31);
      }
      if(a.react_active&&a.threat_score>0){
        var sc=a.risk_level==='critical'?'#f85149':a.risk_level==='high'?'#db6d28':a.risk_level==='medium'?'#d29922':'#8b949e';
        ctx.fillStyle=sc;ctx.font='bold 8px sans-serif';
        ctx.fillText(Math.round(a.threat_score)+'T',x,y+41);
      }
    });
    _mapAnim=requestAnimationFrame(frame);
  }
  _mapAnim=requestAnimationFrame(frame);
}

async function loadThreatIntel(){
  try{
    var r=await fetch('/api/fleet/threats');var d=await r.json();
    var el=document.getElementById('threatIntel');
    if(!d.fleet_agents_with_react){
      el.innerHTML='<div class="empty">No agents reporting ReAct diagnostics yet. Deploy agents with ReAct enabled.</div>';
      return;
    }
    var html='<div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px">';
    html+='<div style="font-size:.82rem">ReAct Agents: <b style="color:var(--cyan)">'+d.fleet_agents_with_react+'</b></div>';
    html+='<div style="font-size:.82rem">Total Threats: <b style="color:var(--orange)">'+d.total_threats_detected+'</b></div>';
    html+='</div>';
    var crit=d.critical_agents||[];
    if(crit.length){
      html+='<div style="margin-bottom:10px">';
      html+='<div style="font-size:.78rem;color:var(--red);font-weight:700;margin-bottom:6px">&#128680; AGENTS AT RISK</div>';
      crit.forEach(function(a){
        html+='<div class="threat-entry '+a.risk_level+'">';
        html+='<span class="threat-badge '+a.risk_level+'">'+a.risk_level.toUpperCase()+'</span> ';
        html+='<b>'+a.label+'</b> — Score: '+Math.round(a.threat_score)+'/100, '+a.threats+' threats';
        html+='</div>';
      });
      html+='</div>';
    }
    var cats=d.threat_categories||{};
    if(Object.keys(cats).length){
      html+='<div style="display:flex;gap:8px;flex-wrap:wrap">';
      Object.entries(cats).forEach(function(kv){
        html+='<span style="padding:4px 10px;border-radius:8px;font-size:.75rem;background:rgba(188,140,255,.1);color:var(--purple)">'+kv[0]+': '+kv[1]+'</span>';
      });
      html+='</div>';
    }
    el.innerHTML=html;
    // Update banner badge
    var bb=document.getElementById('threatBadge');
    if(crit.length){
      bb.textContent=crit.length+' Agent'+(crit.length>1?'s':'')+' At Risk';
      bb.style.background='rgba(248,81,73,.15)';bb.style.color='var(--red)';
    }else if(d.total_threats_detected>0){
      bb.textContent=d.total_threats_detected+' Threat'+(d.total_threats_detected>1?'s':'');
      bb.style.background='rgba(210,153,34,.15)';bb.style.color='var(--yellow)';
    }else{
      bb.textContent='Fleet Secure';
      bb.style.background='rgba(63,185,80,.15)';bb.style.color='var(--green)';
    }
    document.getElementById('kTh').textContent=d.total_threats_detected;
    document.getElementById('kRe').textContent=d.fleet_agents_with_react;
  }catch(e){console.error('Threat intel error',e);}
}

async function load(){
  try{
    var r=await fetch('/api/fleet/list');var agents=await r.json();
    var kr=await fetch('/api/fleet/key');var kd=await kr.json();
    document.getElementById('fleetKey').textContent=kd.key||'N/A';
    document.getElementById('kT').textContent=agents.length;
    var on=0,st=0,of=0,tw=0,th=0,co=0;
    agents.forEach(function(a){
      if(a.status==='online')on++;else if(a.status==='stale')st++;else of++;
      tw+=a.wifi_count||0;th+=a.host_count||0;
      if(a.covert_proxy&&a.covert_proxy!=='none')co++;
    });
    document.getElementById('kOn').textContent=on;
    document.getElementById('kSt').textContent=st;
    document.getElementById('kOf').textContent=of;
    document.getElementById('kWi').textContent=tw;
    document.getElementById('kHo').textContent=th;
    document.getElementById('kCo').textContent=co;
    document.getElementById('count').textContent=agents.length+' Agent'+(agents.length!==1?'s':'');
    _agents=agents;
    var el=document.getElementById('agents');
    if(!agents.length){el.innerHTML='<div class="empty" style="grid-column:1/-1">No agents deployed. Deploy a probe to get started.</div>';}
    else{
      el.innerHTML=agents.map(function(a){
        var ago=a.seconds_ago<60?a.seconds_ago+'s ago':a.seconds_ago<3600?Math.floor(a.seconds_ago/60)+'m ago':Math.floor(a.seconds_ago/3600)+'h ago';
        var riskHtml='';
        if(a.react_active){
          var rc=riskColor[a.risk_level]||'--dim';
          riskHtml='<div style="margin-top:6px;padding:6px 10px;border-radius:8px;background:rgba(0,0,0,.3);border:1px solid var('+rc+')">';
          riskHtml+='<span class="threat-badge '+a.risk_level+'">'+a.risk_level.toUpperCase()+'</span> ';
          riskHtml+='<span style="font-size:.78rem">Score: <b>'+Math.round(a.threat_score)+'</b>/100</span>';
          if(a.threats_count>0){riskHtml+=' <span style="font-size:.72rem;color:var(--orange)">'+a.threats_count+' threats</span>';}
          if(a.issues_count>0){riskHtml+=' <span style="font-size:.72rem;color:var(--yellow)">'+a.issues_count+' issues</span>';}
          riskHtml+='</div>';
        }
        var sentinelHtml='';
        if(a.is_sentinel){
          sentinelHtml='<div style="margin-top:6px;padding:6px 10px;border-radius:8px;background:rgba(57,210,224,.08);border:1px solid rgba(57,210,224,.25)">';
          sentinelHtml+='<span style="color:var(--cyan);font-weight:700;font-size:.72rem">&#128737; SENTINEL</span> ';
          sentinelHtml+='<span style="font-size:.72rem;color:var(--dim)">'+(a.sentinel_sensitivity||'normal').toUpperCase()+' | Flows: '+(a.sentinel_active_flows||0)+' | '+(a.sentinel_bandwidth||'baseline')+'</span>';
          if(a.sentinel_wifi_changes>0){sentinelHtml+=' <span style="font-size:.72rem;color:var(--blue)">'+(a.sentinel_wifi_changes)+' WiFi chg</span>';}
          if(a.sentinel_rogue_alerts>0){sentinelHtml+=' <span style="font-size:.72rem;color:var(--red)">'+(a.sentinel_rogue_alerts)+' rogues</span>';}
          sentinelHtml+='</div>';
        }
        var typeLabel=a.is_sentinel?' <span style="color:var(--cyan);font-size:.65rem">&#128737; Sentinel</span>':'';
        typeLabel+=a.react_active?' <span style="color:var(--purple);font-size:.65rem">&#129504; ReAct</span>':'';
        // Covert chip
        var covertHtml='';
        if(a.covert_proxy!==undefined&&a.covert_proxy!==null){
          var ctIsTor=_isTorProxy(a.covert_proxy);
          if(a.covert_proxy==='none'||!a.covert_proxy){
            covertHtml='<div style="margin-top:5px"><span class="covert-chip direct">&#128275; Direct</span></div>';
          }else{
            covertHtml='<div style="margin-top:5px"><span class="covert-chip '+(ctIsTor?'tor':'proxy')+'">&#128274; '+(ctIsTor?'Tor':'Proxy')+'</span>';
            if(a.covert_jitter&&a.covert_jitter!=='off'){covertHtml+=' <span style="font-size:.68rem;color:var(--dim)">jitter:'+a.covert_jitter+'</span>';}
            if(a.covert_decoys>0){covertHtml+=' <span style="font-size:.68rem;color:var(--dim)">'+a.covert_decoys+' decoys</span>';}
            covertHtml+='</div>';
            typeLabel+=' <span style="color:var(--green);font-size:.65rem">&#128274;</span>';
          }
        }
        return '<div class="agent-card '+a.status+'" onclick="showAgent(&apos;'+a.agent_id+'&apos;)">'+
          '<div class="hdr"><div class="name"><span class="status-dot '+a.status+'"></span>'+a.label+'</div>'+
          '<span style="font-size:.72rem;padding:2px 8px;border-radius:8px;background:rgba('+(a.status==='online'?'63,185,80':a.status==='stale'?'210,153,34':'248,81,73')+',.15);color:var(--'+(a.status==='online'?'green':a.status==='stale'?'yellow':'red')+')">'+a.status.toUpperCase()+'</span></div>'+
          '<div class="id">'+a.agent_id+typeLabel+'</div>'+
          '<div class="stats" style="margin-top:8px">'+
            '<div>IP: <span>'+(a.local_ip||'-')+'</span></div>'+
            '<div>Subnet: <span>'+(a.subnet||'-')+'</span></div>'+
            '<div>WiFi: <span>'+a.wifi_count+'</span></div>'+
            '<div>Hosts: <span>'+a.host_count+'</span></div>'+
            '<div>Reports: <span>'+a.report_count+'</span></div>'+
            '<div>Seen: <span>'+ago+'</span></div>'+
          '</div>'+riskHtml+sentinelHtml+covertHtml+'</div>';
      }).join('');
    }
    drawMap(agents);
    document.getElementById('ts').textContent=new Date().toLocaleTimeString()+' | Auto 5s';
  }catch(e){console.error(e);}
}
load();loadThreatIntel();setInterval(load,5000);setInterval(loadThreatIntel,10000);
</script></body></html>'''


def get_fleet_page(nonce: str) -> str:
    """Return the fleet dashboard HTML with nonce substituted."""
    return _TMPL_FLEET.replace("{{NONCE}}", nonce)
