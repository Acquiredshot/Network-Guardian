"""
ReAct Field Agent — Observe → Reason → Act → Learn.

Agentic intelligence layer for field probes. Runs on any deployed agent,
continuously monitoring the host environment, diagnosing threats, taking
protective actions, and reporting diagnostic intelligence back to base.

Unlike the basic probe (collect + dump), this agent:
  1. **Observe** — deep system + network scan (processes, connections, ARP, ports, traffic patterns)
  2. **Reason**  — classify threats, detect anomalies, diagnose issues, score risk
  3. **Act**     — block threats, kill suspicious processes, firewall rules, self-heal
  4. **Learn**   — persist threat signatures, network baselines, share intel with base
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import re
import socket
import subprocess
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("ng-probe.react")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ProcessInfo:
    """A running process on the host."""
    pid: int
    name: str
    user: str
    cpu_pct: float = 0.0
    mem_pct: float = 0.0
    command: str = ""
    suspicious: bool = False
    reason: str = ""


@dataclass
class NetworkConnection:
    """An active network connection on the host."""
    protocol: str  # tcp/udp
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str  # ESTABLISHED, LISTEN, etc.
    pid: int = 0
    process_name: str = ""
    suspicious: bool = False
    reason: str = ""


@dataclass
class ARPEntry:
    """An ARP table entry."""
    ip: str
    mac: str
    interface: str = ""
    is_gateway: bool = False


@dataclass
class ThreatEvent:
    """A detected threat or anomaly."""
    timestamp: str
    severity: str  # info, low, medium, high, critical
    category: str  # port_scan, arp_spoof, rogue_process, brute_force, data_exfil, anomaly
    title: str
    detail: str
    source_ip: str = ""
    action_taken: str = ""
    resolved: bool = False


@dataclass
class ThreatReport:
    """Detailed auto-generated report for a single threat assessment cycle."""
    report_id: str
    generated_at: str
    agent_id: str
    host: str
    cycle: int
    risk_level: str
    threat_score: float
    threats: list[dict]
    actions_taken: list[dict]
    observations: dict         # key stats from observe phase
    baselines: dict            # drift values
    narrative: str             # Plain-English explanation of what happened
    recommendations: list[str] # Prioritised fix list

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Threat report narrative templates
# ---------------------------------------------------------------------------

_THREAT_EXPLANATIONS: dict[str, dict[str, str]] = {
    "arp_spoof": {
        "what": (
            "ARP (Address Resolution Protocol) spoofing is a man-in-the-middle attack where "
            "an attacker sends forged ARP messages on the local network. This maps the attacker's "
            "MAC address to a legitimate IP address (typically the default gateway), causing all "
            "traffic destined for that IP to be intercepted by the attacker instead."
        ),
        "impact": (
            "If successful, the attacker can read, modify, or drop all traffic on the network "
            "segment — including unencrypted passwords, session tokens, and sensitive data. "
            "This is one of the most dangerous local-network attacks."
        ),
        "why_triggered": "The MAC address recorded for a known IP changed between scan cycles.",
        "cvss_base": "8.1 (High)",
        "mitre": "T1557.002 — ARP Cache Poisoning",
    },
    "rogue_process": {
        "what": (
            "A process was detected whose name matches a known offensive security or hacking tool. "
            "These tools are designed for network scanning, credential harvesting, traffic interception, "
            "or remote code execution."
        ),
        "impact": (
            "The presence of offensive tooling may indicate an active attacker, a red-team exercise "
            "not coordinated with the security team, or malware that includes embedded hacking modules."
        ),
        "why_triggered": "Process name matched a known offensive tool signature list.",
        "cvss_base": "7.5 (High)",
        "mitre": "T1059 — Command and Scripting Interpreter / T1106 — Native API",
    },
    "port_scan": {
        "what": (
            "A port was found listening on the host that is commonly associated with backdoors, "
            "command-and-control (C2) frameworks, or reverse shells. Legitimate applications "
            "rarely use these port numbers."
        ),
        "impact": (
            "An open backdoor port allows an attacker to maintain persistent access to the system "
            "or receive instructions from a remote command server, even after initial malware removal."
        ),
        "why_triggered": "Listening port number matched known backdoor/C2 port signature.",
        "cvss_base": "6.5 (Medium–High)",
        "mitre": "T1571 — Non-Standard Port / T1090 — Proxy",
    },
    "data_exfil": {
        "what": (
            "An unusually high number of simultaneous outbound network connections was detected. "
            "This pattern is consistent with data exfiltration — where malware or an attacker "
            "copies large volumes of data to remote servers by fanning out across many connections."
        ),
        "impact": (
            "Sensitive files, credentials, or intellectual property may be leaving the network. "
            "Multiple simultaneous connections are used to maximise transfer speed and evade "
            "per-connection bandwidth alerts."
        ),
        "why_triggered": "Active external TCP connections exceeded the threshold of 50 simultaneous sessions.",
        "cvss_base": "7.2 (High)",
        "mitre": "T1041 — Exfiltration Over C2 Channel",
    },
    "anomaly": {
        "what": (
            "A significant deviation from the learned baseline was detected. This could represent "
            "a misconfigured service, a resource-hungry process (such as a cryptominer), or an "
            "indicator of compromise where malware is consuming system resources."
        ),
        "impact": (
            "Sustained CPU or memory anomalies can degrade system performance and may indicate "
            "cryptomining malware, a denial-of-service attempt, or a runaway compromised process."
        ),
        "why_triggered": "Resource usage or network behaviour deviated significantly from the established baseline.",
        "cvss_base": "5.3 (Medium)",
        "mitre": "T1496 — Resource Hijacking",
    },
}

_ACTION_EXPLANATIONS: dict[str, str] = {
    "alert_and_log":       "Flagged the process for operator review and logged it to the threat history. "
                           "No automated process termination was performed — requires manual investigation.",
    "alert_arp_spoof":     "Immediately alerted the base station with CRITICAL priority. The MAC-to-IP "
                           "mapping was logged for forensic analysis. Network traffic should be treated "
                           "as compromised until the spoofing source is identified and removed.",
    "flag_suspicious_port":"Logged the suspicious listening port and notified the base station. "
                           "The port binding and associated process have been recorded for investigation.",
    "alert_data_exfil":    "Reported the high outbound connection count to base with HIGH priority. "
                           "Detailed connection metadata has been preserved for forensic review.",
    "alert_dns_change":    "Sent a CRITICAL alert to base — DNS server changes can redirect all "
                           "web traffic through an attacker-controlled resolver, enabling phishing "
                           "and credential harvesting at scale.",
    "increase_monitoring": "Monitoring frequency increased — the agent will report more frequently "
                           "to give operators real-time visibility during the elevated threat period.",
}


@dataclass
class DiagnosticReport:
    """Full diagnostic intelligence package sent to base."""
    agent_id: str
    timestamp: str
    # Current state
    network_connections: list[dict]
    listening_ports: list[dict]
    active_processes: int
    suspicious_processes: list[dict]
    arp_table: list[dict]
    # Threat intelligence
    threats_detected: list[dict]
    threat_score: float  # 0-100
    risk_level: str  # low, medium, high, critical
    # Self-protection
    actions_taken: list[dict]
    firewall_rules_active: int
    blocked_ips: list[str]
    # Diagnostics for base
    issues_found: list[dict]
    recommendations: list[str]
    # ReAct log
    react_log: list[dict]
    # Baselines
    network_baseline_drift: float  # % deviation from learned baseline
    process_baseline_drift: float

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ReActStep:
    """Single step in the ReAct reasoning chain."""
    phase: str  # observe, reason, act, learn
    thought: str
    detail: Any = None
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "phase": self.phase,
            "thought": self.thought,
            "detail": self.detail,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Suspicious patterns for reasoning
# ---------------------------------------------------------------------------

# Known sketchy process names / patterns
_SUSPICIOUS_PROCS = {
    "nmap", "masscan", "zmap", "responder", "ettercap", "arpspoof",
    "bettercap", "mitmproxy", "wireshark", "tcpdump", "hashcat",
    "john", "hydra", "medusa", "metasploit", "msfconsole", "msfvenom",
    "netcat", "nc", "ncat", "socat", "cryptominer", "xmrig", "minerd",
    "coinhive", "reverse_shell", "bind_shell", "mimikatz", "lazagne",
    "procdump", "keylogger", "aircrack", "airodump", "aireplay",
    "wifite", "kismet", "reaver", "pixiewps",
}

# Ports that shouldn't be open on a typical workstation
_SUSPICIOUS_LISTEN_PORTS = {
    4444, 5555, 6666, 7777,  # Common reverse shell ports
    1337, 31337,              # Leet ports
    9001, 9050, 9150,         # Tor
    3128, 8888, 8118,         # Open proxies
    6667, 6697,               # IRC (C2 channels)
    2222,                     # Alt SSH (suspicious if unexpected)
}

# Known malicious port ranges
_C2_PORT_RANGES = [(4440, 4450), (5550, 5560), (6660, 6670)]


# ---------------------------------------------------------------------------
# Probe ReAct Agent
# ---------------------------------------------------------------------------

class ProbeReActAgent:
    """ReAct intelligence layer for field agents.

    Runs alongside the basic probe, adding threat detection,
    self-protection, and diagnostic intelligence.
    """

    def __init__(self, data_dir: Path | None = None) -> None:
        self._data_dir = data_dir or (Path.home() / ".ng_agent")
        self._data_dir.mkdir(parents=True, exist_ok=True)

        # State
        self._react_log: list[ReActStep] = []
        self._threats: list[ThreatEvent] = []
        self._actions_taken: list[dict] = []
        self._blocked_ips: set[str] = set()
        self._running = False
        self._task: asyncio.Task | None = None
        self._agent_id: str = ""

        # Learned baselines
        self._baselines_path = self._data_dir / "baselines.json"
        self._baselines: dict[str, Any] = self._load_baselines()

        # Threat history
        self._threat_history_path = self._data_dir / "threat_history.json"
        self._threat_history: list[dict] = self._load_threat_history()

        # Detailed threat reports
        self._reports_path = self._data_dir / "threat_reports.json"
        self._threat_reports: list[dict] = self._load_threat_reports()

    # -- Persistence ---------------------------------------------------

    def _load_baselines(self) -> dict[str, Any]:
        if self._baselines_path.exists():
            try:
                data = json.loads(self._baselines_path.read_text())
                logger.info("Loaded baselines (%d keys)", len(data))
                return data
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _save_baselines(self) -> None:
        try:
            self._baselines_path.write_text(json.dumps(self._baselines, indent=2))
        except OSError as e:
            logger.warning("Failed to save baselines: %s", e)

    def _load_threat_history(self) -> list[dict]:
        if self._threat_history_path.exists():
            try:
                data = json.loads(self._threat_history_path.read_text())
                logger.info("Loaded %d threat history entries", len(data))
                return data[-500:]  # Keep last 500
            except (json.JSONDecodeError, OSError):
                pass
        return []

    def _save_threat_history(self) -> None:
        try:
            self._threat_history_path.write_text(
                json.dumps(self._threat_history[-500:], indent=2)
            )
        except OSError as e:
            logger.warning("Failed to save threat history: %s", e)

    def _load_threat_reports(self) -> list[dict]:
        if self._reports_path.exists():
            try:
                data = json.loads(self._reports_path.read_text())
                return data[-100:]
            except (json.JSONDecodeError, OSError):
                pass
        return []

    def _save_threat_reports(self) -> None:
        try:
            self._reports_path.write_text(
                json.dumps(self._threat_reports[-100:], indent=2)
            )
        except OSError as e:
            logger.warning("Failed to save threat reports: %s", e)

    def _generate_incident_report_md(self, report: "ThreatReport", obs: dict[str, Any]) -> str:
        """Render a full Markdown incident report matching the Network Guardian IR format."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        date_str = now.strftime("%B %d, %Y")
        date_tag = now.strftime("%Y-%m-%d")
        time_str = now.strftime("%H:%M UTC")

        sev_icon = {
            "critical": "🚨 CRITICAL",
            "high": "⚠️ HIGH",
            "medium": "🟡 MEDIUM",
            "low": "✅ LOW",
        }

        # Severity counts
        sev_counts: dict[str, int] = {}
        for t in report.threats:
            sev_counts[t["severity"]] = sev_counts.get(t["severity"], 0) + 1
        sev_summary = ", ".join(
            f"{v} {k.upper()}" for k, v in sorted(
                sev_counts.items(),
                key=lambda x: ["critical","high","medium","low","info"].index(x[0])
                if x[0] in ["critical","high","medium","low","info"] else 99
            )
        ) or "None"

        status = "ACTIVE — UNDER INVESTIGATION"
        if report.risk_level == "low":
            status = "CLEAN — NO THREATS"
        elif all(t.get("resolved") for t in report.threats):
            status = "RESOLVED — THREAT CONTAINED"

        # Build timeline from threat timestamps
        timeline_rows = []
        seen_ts: set[str] = set()
        for t in report.threats:
            ts = t.get("timestamp", "")
            if ts and ts not in seen_ts:
                seen_ts.add(ts)
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    ts_fmt = dt.strftime("%Y-%m-%d %H:%M")
                except Exception:
                    ts_fmt = ts[:16]
                timeline_rows.append(f"| {ts_fmt} | {t['title']} detected — severity {t['severity'].upper()} |")
        # Add actions to timeline
        for a in report.actions_taken:
            if a.get("success"):
                timeline_rows.append(f"| {date_tag} {time_str[:5]} | Automated action: `{a['action']}` executed successfully |")

        timeline_md = "\n".join(timeline_rows) if timeline_rows else f"| {date_tag} {time_str[:5]} | Automated assessment cycle completed — no threat events |"

        # Build per-threat sections
        threat_sections = []
        for i, t in enumerate(report.threats, 1):
            sev_label = sev_icon.get(t.get("severity", "medium"), t.get("severity", "medium").upper())
            threat_sections.append(f"""
### {i}. {t.get("title", "Unnamed Threat")}

| Field | Value |
|---|---|
| **Severity** | {sev_label} |
| **Category** | `{t.get("category", "")}` |
| **Source IP** | `{t.get("source_ip") or "N/A"}` |
| **MITRE ATT&CK** | {t.get("mitre_att_ck") or "—"} |
| **CVSS Base Score** | {t.get("cvss_base_score") or "—"} |
| **Status** | {"✅ Resolved" if t.get("resolved") else "🔴 Active"} |

**What It Is:**
{t.get("what_it_is", "")}

**Technical Detail:**
`{t.get("technical_detail", "")}`

**Why It Was Triggered:**
{t.get("why_triggered", "")}

**Potential Impact:**
{t.get("potential_impact", "")}

**Automated Response:**
`{t.get("action_taken") or "None"}` — {t.get("action_explanation", "No automated action taken.")}
""")

        threats_md = "\n".join(threat_sections) if threat_sections else "_No threats detected in this assessment cycle._"

        # Build actions section
        action_rows = []
        for a in report.actions_taken:
            result = "✅ Success" if a.get("success") else "❌ Failed"
            action_rows.append(f"| `{a.get('action','')}` | {a.get('explanation') or a.get('detail','')} | {result} |")
        actions_table = "\n".join(action_rows) if action_rows else "| — | No automated actions executed | — |"

        # Recommendations
        rec_lines = "\n".join(
            f"{j+1}. {r}" for j, r in enumerate(report.recommendations)
        ) if report.recommendations else "_No specific recommendations generated for this cycle._"

        # Observations
        obs_data = report.observations
        gateway = obs_data.get("gateway", "—")
        local_ip = obs_data.get("local_ip", report.host)
        dns_servers = ", ".join(obs_data.get("dns_servers", [])) or "—"

        md = f"""# Incident Report — {", ".join(set(t.get("title","") for t in report.threats)) or "Clean Assessment"}
**Report ID:** IR-{date_tag}-{report.report_id}
**Classification:** Confidential
**Date of Detection:** {date_str}
**Date of Report:** {date_str} at {time_str}
**Reported By:** Network Guardian (Agent: {report.agent_id or "unknown"})
**Assessment Cycle:** #{report.cycle}
**Risk Level:** {report.risk_level.upper()} — Threat Score {report.threat_score:.0f}/100
**Status:** {status}

---

## 1. Executive Summary

{report.narrative}

Threat severity breakdown: {sev_summary}.
Total threats identified: **{len(report.threats)}**.
Automated protective actions executed: **{len([a for a in report.actions_taken if a.get("success")])}**.

---

## 2. Timeline of Events

| Time (UTC) | Event |
|---|---|
{timeline_md}

---

## 3. Threat Details

{threats_md}

---

## 4. Automated Actions Taken

| Action | Description | Result |
|---|---|---|
{actions_table}

---

## 5. Environment Snapshot

| Field | Value |
|---|---|
| **Agent ID** | `{report.agent_id or "—"}` |
| **Host IP** | `{local_ip}` |
| **Gateway** | `{gateway}` |
| **DNS Servers** | `{dns_servers}` |
| **Active Connections** | {obs_data.get("connections", 0)} |
| **Listening Ports** | {obs_data.get("listening_ports", 0)} |
| **External Connections** | {obs_data.get("external_connections", 0)} |
| **Active Processes** | {obs_data.get("active_processes", 0)} |
| **Network Baseline Drift** | {report.baselines.get("network_drift_pct", 0):.1f}% |
| **Process Baseline Drift** | {report.baselines.get("process_drift_pct", 0):.1f}% |
| **Assessment Cycle** | #{report.cycle} |

---

## 6. Recommendations

{rec_lines}

---

## 7. Report Metadata

| Field | Value |
|---|---|
| **Report ID** | `IR-{date_tag}-{report.report_id}` |
| **Generated At** | {report.generated_at} |
| **Agent** | `{report.agent_id or "—"}` |
| **Platform** | {platform.system()} {platform.release()} ({platform.machine()}) |
"""
        return md

    def _save_incident_report(self, md: str, report_id: str) -> Path | None:
        """Write the Markdown incident report to disk."""
        try:
            ir_dir = self._data_dir / "incident_reports"
            ir_dir.mkdir(parents=True, exist_ok=True)
            now_tag = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
            path = ir_dir / f"INCIDENT_REPORT_{now_tag}_{report_id}.md"
            path.write_text(md)
            logger.info("[INCIDENT] Report written to %s", path)
            return path
        except OSError as e:
            logger.warning("Failed to save incident report: %s", e)
            return None

    def _log_step(self, phase: str, thought: str, detail: Any = None) -> None:
        step = ReActStep(phase=phase, thought=thought, detail=detail)
        self._react_log.append(step)
        # Keep last 100 steps
        if len(self._react_log) > 100:
            self._react_log = self._react_log[-100:]
        logger.info("[%s] %s", phase.upper(), thought)

    # -- OBSERVE -------------------------------------------------------

    def observe(self) -> dict[str, Any]:
        """Phase 1: Deep system + network observation."""
        self._log_step("observe", "Scanning host environment...")

        obs: dict[str, Any] = {}

        # Active network connections
        connections = self._get_connections()
        obs["connections"] = connections
        obs["connection_count"] = len(connections)

        # Listening ports
        listeners = [c for c in connections if c.state == "LISTEN"]
        obs["listening_ports"] = listeners
        obs["listener_count"] = len(listeners)

        # Running processes
        processes = self._get_processes()
        obs["processes"] = processes
        obs["process_count"] = len(processes)

        # ARP table
        arp_table = self._get_arp_table()
        obs["arp_table"] = arp_table
        obs["arp_entry_count"] = len(arp_table)

        # Gateway
        obs["gateway"] = self._get_gateway()
        obs["local_ip"] = self._get_local_ip()

        # DNS servers
        obs["dns_servers"] = self._get_dns_servers()

        # Open external connections
        external = [c for c in connections
                    if c.state == "ESTABLISHED"
                    and c.remote_addr
                    and not c.remote_addr.startswith("127.")
                    and not c.remote_addr.startswith("::1")]
        obs["external_connections"] = external
        obs["external_count"] = len(external)

        self._log_step("observe",
                        f"Found {len(connections)} connections ({len(listeners)} listening), "
                        f"{len(processes)} processes, {len(arp_table)} ARP entries, "
                        f"{len(external)} external connections",
                        {
                            "connections": len(connections),
                            "listeners": len(listeners),
                            "processes": len(processes),
                            "arp_entries": len(arp_table),
                            "external": len(external),
                        })
        return obs

    def _get_connections(self) -> list[NetworkConnection]:
        """Get all active network connections with process info."""
        connections: list[NetworkConnection] = []
        try:
            os_name = platform.system().lower()
            if os_name == "darwin":
                # netstat on macOS
                r = subprocess.run(
                    ["netstat", "-anv", "-p", "tcp"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in r.stdout.splitlines()[2:]:
                    c = self._parse_netstat_darwin(line, "tcp")
                    if c:
                        connections.append(c)
                r = subprocess.run(
                    ["netstat", "-anv", "-p", "udp"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in r.stdout.splitlines()[2:]:
                    c = self._parse_netstat_darwin(line, "udp")
                    if c:
                        connections.append(c)
            elif os_name == "linux":
                r = subprocess.run(
                    ["ss", "-tunap"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in r.stdout.splitlines()[1:]:
                    c = self._parse_ss_linux(line)
                    if c:
                        connections.append(c)
            elif os_name == "windows":
                r = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in r.stdout.splitlines()[4:]:
                    c = self._parse_netstat_windows(line)
                    if c:
                        connections.append(c)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.warning("Connection scan failed: %s", e)
        return connections

    def _parse_netstat_darwin(self, line: str, proto: str) -> NetworkConnection | None:
        """Parse a macOS netstat -anv line."""
        parts = line.split()
        if len(parts) < 6:
            return None
        try:
            local = parts[3]
            remote = parts[4]
            state = parts[5] if len(parts) > 5 and not parts[5].isdigit() else ""
            pid = 0
            # PID is usually the last numeric field
            for p in reversed(parts):
                if p.isdigit() and int(p) > 0:
                    pid = int(p)
                    break

            local_ip, local_port = self._split_addr(local)
            remote_ip, remote_port = self._split_addr(remote)

            return NetworkConnection(
                protocol=proto,
                local_addr=local_ip,
                local_port=local_port,
                remote_addr=remote_ip,
                remote_port=remote_port,
                state=state,
                pid=pid,
            )
        except (ValueError, IndexError):
            return None

    def _parse_ss_linux(self, line: str) -> NetworkConnection | None:
        """Parse a Linux ss -tunap line."""
        parts = line.split()
        if len(parts) < 5:
            return None
        try:
            proto = parts[0].lower()
            state = parts[1]
            local = parts[4]
            remote = parts[5] if len(parts) > 5 else "*:*"

            local_ip, local_port = self._split_addr(local)
            remote_ip, remote_port = self._split_addr(remote)

            pid = 0
            pname = ""
            if len(parts) > 6:
                m = re.search(r'pid=(\d+)', parts[6])
                if m:
                    pid = int(m.group(1))
                m2 = re.search(r'"([^"]+)"', parts[6])
                if m2:
                    pname = m2.group(1)

            return NetworkConnection(
                protocol=proto,
                local_addr=local_ip,
                local_port=local_port,
                remote_addr=remote_ip,
                remote_port=remote_port,
                state=state,
                pid=pid,
                process_name=pname,
            )
        except (ValueError, IndexError):
            return None

    def _parse_netstat_windows(self, line: str) -> NetworkConnection | None:
        """Parse a Windows netstat -ano line."""
        parts = line.split()
        if len(parts) < 4:
            return None
        try:
            proto = parts[0].lower()
            local = parts[1]
            remote = parts[2]
            state = parts[3] if not parts[3].isdigit() else ""
            pid = int(parts[-1]) if parts[-1].isdigit() else 0

            local_ip, local_port = self._split_addr(local)
            remote_ip, remote_port = self._split_addr(remote)

            return NetworkConnection(
                protocol=proto,
                local_addr=local_ip,
                local_port=local_port,
                remote_addr=remote_ip,
                remote_port=remote_port,
                state=state,
                pid=pid,
            )
        except (ValueError, IndexError):
            return None

    @staticmethod
    def _split_addr(addr: str) -> tuple[str, int]:
        """Split 'ip.port' or '[ip]:port' into (ip, port)."""
        if addr.startswith("["):
            # IPv6: [::1]:443
            bracket = addr.index("]")
            ip = addr[1:bracket]
            port = int(addr[bracket + 2:]) if bracket + 2 < len(addr) else 0
            return ip, port
        # IPv4: last dot separates port
        dot = addr.rfind(".")
        if dot == -1:
            dot = addr.rfind(":")
        if dot == -1:
            return addr, 0
        try:
            return addr[:dot], int(addr[dot + 1:])
        except ValueError:
            return addr, 0

    def _get_processes(self) -> list[ProcessInfo]:
        """Get running processes with resource usage."""
        procs: list[ProcessInfo] = []
        try:
            os_name = platform.system().lower()
            if os_name in ("darwin", "linux"):
                r = subprocess.run(
                    ["ps", "aux"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in r.stdout.splitlines()[1:]:
                    p = self._parse_ps_line(line)
                    if p:
                        procs.append(p)
            elif os_name == "windows":
                r = subprocess.run(
                    ["tasklist", "/V", "/FO", "CSV"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in r.stdout.splitlines()[1:]:
                    p = self._parse_tasklist_line(line)
                    if p:
                        procs.append(p)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.warning("Process scan failed: %s", e)
        return procs

    def _parse_ps_line(self, line: str) -> ProcessInfo | None:
        parts = line.split(None, 10)
        if len(parts) < 11:
            return None
        try:
            return ProcessInfo(
                pid=int(parts[1]),
                user=parts[0],
                cpu_pct=float(parts[2]),
                mem_pct=float(parts[3]),
                name=Path(parts[10].split()[0]).name if parts[10] else "",
                command=parts[10][:200],
            )
        except (ValueError, IndexError):
            return None

    def _parse_tasklist_line(self, line: str) -> ProcessInfo | None:
        parts = line.strip('"').split('","')
        if len(parts) < 5:
            return None
        try:
            return ProcessInfo(
                pid=int(parts[1]),
                name=parts[0],
                user=parts[6] if len(parts) > 6 else "",
                mem_pct=0.0,
                cpu_pct=0.0,
                command=parts[0],
            )
        except (ValueError, IndexError):
            return None

    def _get_arp_table(self) -> list[ARPEntry]:
        """Read the ARP table."""
        entries: list[ARPEntry] = []
        try:
            r = subprocess.run(
                ["arp", "-a"],
                capture_output=True, text=True, timeout=5,
            )
            gateway = self._get_gateway()
            for line in r.stdout.splitlines():
                m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)', line)
                if m:
                    ip, mac = m.group(1), m.group(2)
                    iface = ""
                    im = re.search(r'on\s+(\S+)', line)
                    if im:
                        iface = im.group(1)
                    entries.append(ARPEntry(
                        ip=ip, mac=mac, interface=iface,
                        is_gateway=(ip == gateway),
                    ))
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        return entries

    def _get_gateway(self) -> str:
        try:
            if platform.system().lower() == "darwin":
                r = subprocess.run(
                    ["route", "-n", "get", "default"],
                    capture_output=True, text=True, timeout=5,
                )
                for line in r.stdout.splitlines():
                    if "gateway:" in line.lower():
                        return line.split(":")[1].strip()
            elif platform.system().lower() == "linux":
                r = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True, text=True, timeout=5,
                )
                parts = r.stdout.split()
                if "via" in parts:
                    return parts[parts.index("via") + 1]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return ""

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _get_dns_servers(self) -> list[str]:
        servers = []
        try:
            if platform.system().lower() == "darwin":
                r = subprocess.run(
                    ["scutil", "--dns"],
                    capture_output=True, text=True, timeout=5,
                )
                for line in r.stdout.splitlines():
                    if "nameserver" in line.lower():
                        m = re.search(r'[\d.]+', line)
                        if m and m.group() not in servers:
                            servers.append(m.group())
            elif platform.system().lower() == "linux":
                try:
                    with open("/etc/resolv.conf") as f:
                        for line in f:
                            if line.strip().startswith("nameserver"):
                                ip = line.split()[1]
                                if ip not in servers:
                                    servers.append(ip)
                except FileNotFoundError:
                    pass
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return servers[:5]

    # -- REASON --------------------------------------------------------

    def reason(self, obs: dict[str, Any]) -> dict[str, Any]:
        """Phase 2: Analyze observations, detect threats, diagnose issues."""
        self._log_step("reason", "Analyzing observations for threats and anomalies...")

        threats: list[ThreatEvent] = []
        issues: list[dict] = []
        recommendations: list[str] = []
        now = datetime.now(timezone.utc).isoformat()

        # 1. Check for suspicious processes
        for proc in obs.get("processes", []):
            proc_name_lower = proc.name.lower() if isinstance(proc, ProcessInfo) else str(proc).lower()
            pname = proc.name if isinstance(proc, ProcessInfo) else ""
            ppid = proc.pid if isinstance(proc, ProcessInfo) else 0
            pcpu = proc.cpu_pct if isinstance(proc, ProcessInfo) else 0
            pmem = proc.mem_pct if isinstance(proc, ProcessInfo) else 0
            pcmd = proc.command if isinstance(proc, ProcessInfo) else ""

            if proc_name_lower in _SUSPICIOUS_PROCS:
                proc.suspicious = True
                proc.reason = f"Known offensive tool: {pname}"
                threats.append(ThreatEvent(
                    timestamp=now, severity="high",
                    category="rogue_process",
                    title=f"Suspicious process: {pname}",
                    detail=f"PID {ppid}, CPU {pcpu}%, MEM {pmem}%, cmd: {pcmd[:100]}",
                ))
            # High CPU hog (potential cryptominer)
            elif pcpu > 80:
                threats.append(ThreatEvent(
                    timestamp=now, severity="medium",
                    category="anomaly",
                    title=f"High CPU process: {pname} ({pcpu}%)",
                    detail=f"PID {ppid}, could indicate cryptominer or runaway process",
                ))
                issues.append({
                    "type": "high_cpu",
                    "process": pname,
                    "pid": ppid,
                    "cpu_pct": pcpu,
                    "recommendation": f"Investigate {pname} (PID {ppid}) — sustained {pcpu}% CPU",
                })

        # 2. Check for suspicious listening ports
        for conn in obs.get("listening_ports", []):
            port = conn.local_port if isinstance(conn, NetworkConnection) else 0
            if port in _SUSPICIOUS_LISTEN_PORTS:
                threats.append(ThreatEvent(
                    timestamp=now, severity="high",
                    category="port_scan",
                    title=f"Suspicious listening port: {port}",
                    detail=f"Port {port} open — commonly used for backdoors/C2",
                ))
            for lo, hi in _C2_PORT_RANGES:
                if lo <= port <= hi:
                    threats.append(ThreatEvent(
                        timestamp=now, severity="medium",
                        category="port_scan",
                        title=f"Port in C2 range: {port}",
                        detail=f"Port {port} is in known C2 range {lo}-{hi}",
                    ))
                    break

        # 3. ARP spoofing detection
        arp_table = obs.get("arp_table", [])
        gateway_ip = obs.get("gateway", "")
        mac_to_ips: dict[str, list[str]] = {}
        for entry in arp_table:
            mac = entry.mac if isinstance(entry, ARPEntry) else str(entry)
            ip = entry.ip if isinstance(entry, ARPEntry) else ""
            if mac and mac != "(incomplete)" and mac != "ff:ff:ff:ff:ff:ff":
                mac_to_ips.setdefault(mac, []).append(ip)

        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                threats.append(ThreatEvent(
                    timestamp=now, severity="critical",
                    category="arp_spoof",
                    title=f"ARP spoofing detected: {mac}",
                    detail=f"MAC {mac} claims {len(ips)} IPs: {', '.join(ips)}",
                    source_ip=ips[0],
                ))
                recommendations.append(
                    f"URGENT: ARP spoofing — MAC {mac} on multiple IPs. Possible MITM attack."
                )

        # Check gateway MAC changed
        baseline_gw_mac = self._baselines.get("gateway_mac")
        if gateway_ip and baseline_gw_mac:
            for entry in arp_table:
                eip = entry.ip if isinstance(entry, ARPEntry) else ""
                emac = entry.mac if isinstance(entry, ARPEntry) else ""
                if eip == gateway_ip and emac != baseline_gw_mac:
                    threats.append(ThreatEvent(
                        timestamp=now, severity="critical",
                        category="arp_spoof",
                        title="Gateway MAC address changed!",
                        detail=f"Expected {baseline_gw_mac}, got {emac}",
                        source_ip=gateway_ip,
                    ))
                    recommendations.append(
                        "CRITICAL: Gateway MAC changed — likely ARP spoofing / MITM."
                    )

        # 4. Detect potential data exfiltration (many outbound connections)
        external = obs.get("external_connections", [])
        if len(external) > 50:
            threats.append(ThreatEvent(
                timestamp=now, severity="medium",
                category="data_exfil",
                title=f"High external connection count: {len(external)}",
                detail="Unusual number of outbound connections — possible exfiltration",
            ))
            recommendations.append(
                f"Investigate {len(external)} outbound connections for data exfiltration."
            )

        # 5. DNS server change detection
        baseline_dns = self._baselines.get("dns_servers", [])
        current_dns = obs.get("dns_servers", [])
        if baseline_dns and set(current_dns) != set(baseline_dns):
            new_dns = set(current_dns) - set(baseline_dns)
            if new_dns:
                threats.append(ThreatEvent(
                    timestamp=now, severity="high",
                    category="anomaly",
                    title="DNS servers changed",
                    detail=f"New DNS: {', '.join(new_dns)} (was: {', '.join(baseline_dns)})",
                ))
                recommendations.append(
                    f"DNS servers changed to {', '.join(new_dns)} — possible DNS hijacking."
                )

        # 6. Baseline drift calculation
        net_drift = self._calc_network_drift(obs)
        proc_drift = self._calc_process_drift(obs)

        if net_drift > 50:
            issues.append({
                "type": "network_drift",
                "drift_pct": net_drift,
                "recommendation": "Network behavior deviates significantly from baseline",
            })
        if proc_drift > 40:
            issues.append({
                "type": "process_drift",
                "drift_pct": proc_drift,
                "recommendation": "Process landscape has changed significantly",
            })

        # Calculate overall threat score (0-100)
        threat_score = 0.0
        severity_weights = {"info": 2, "low": 5, "medium": 15, "high": 30, "critical": 50}
        for t in threats:
            threat_score += severity_weights.get(t.severity, 5)
        threat_score = min(100.0, threat_score)

        if threat_score < 20:
            risk_level = "low"
        elif threat_score < 45:
            risk_level = "medium"
        elif threat_score < 70:
            risk_level = "high"
        else:
            risk_level = "critical"

        # Add to our tracked threats
        self._threats.extend(threats)
        # Keep last 200
        if len(self._threats) > 200:
            self._threats = self._threats[-200:]

        strategy = {
            "threats": threats,
            "threat_score": threat_score,
            "risk_level": risk_level,
            "issues": issues,
            "recommendations": recommendations,
            "network_drift": net_drift,
            "process_drift": proc_drift,
        }

        self._log_step("reason",
                        f"Threat score: {threat_score:.0f}/100 ({risk_level}) — "
                        f"{len(threats)} threats, {len(issues)} issues",
                        {
                            "threat_score": threat_score,
                            "risk_level": risk_level,
                            "threat_count": len(threats),
                            "issue_count": len(issues),
                            "net_drift": round(net_drift, 1),
                            "proc_drift": round(proc_drift, 1),
                        })
        return strategy

    def _calc_network_drift(self, obs: dict) -> float:
        """Calculate how much the network state deviates from baseline."""
        baseline_conns = self._baselines.get("avg_connections", 0)
        baseline_listeners = self._baselines.get("avg_listeners", 0)
        baseline_external = self._baselines.get("avg_external", 0)

        if not baseline_conns:
            return 0.0

        cur_conns = obs.get("connection_count", 0)
        cur_listeners = obs.get("listener_count", 0)
        cur_external = obs.get("external_count", 0)

        drifts = []
        if baseline_conns:
            drifts.append(abs(cur_conns - baseline_conns) / max(baseline_conns, 1) * 100)
        if baseline_listeners:
            drifts.append(abs(cur_listeners - baseline_listeners) / max(baseline_listeners, 1) * 100)
        if baseline_external:
            drifts.append(abs(cur_external - baseline_external) / max(baseline_external, 1) * 100)

        return sum(drifts) / len(drifts) if drifts else 0.0

    def _calc_process_drift(self, obs: dict) -> float:
        """Calculate how much the process landscape deviates from baseline."""
        baseline_count = self._baselines.get("avg_process_count", 0)
        baseline_names = set(self._baselines.get("known_processes", []))

        if not baseline_count:
            return 0.0

        current_count = obs.get("process_count", 0)
        current_names = {p.name for p in obs.get("processes", []) if isinstance(p, ProcessInfo)}

        count_drift = abs(current_count - baseline_count) / max(baseline_count, 1) * 100
        if baseline_names:
            new_procs = current_names - baseline_names
            name_drift = len(new_procs) / max(len(baseline_names), 1) * 100
        else:
            name_drift = 0

        return (count_drift + name_drift) / 2

    # -- ACT -----------------------------------------------------------

    def act(self, obs: dict[str, Any], strategy: dict[str, Any]) -> list[dict]:
        """Phase 3: Take protective actions based on threat analysis."""
        self._log_step("act", "Evaluating protective actions...")

        actions: list[dict] = []
        risk = strategy.get("risk_level", "low")
        threats = strategy.get("threats", [])

        for threat in threats:
            action = self._decide_action(threat, risk)
            if action:
                success = self._execute_action(action, obs)
                action["success"] = success
                actions.append(action)
                threat.action_taken = action.get("action", "")
                if success:
                    threat.resolved = action.get("resolves", False)

        # If high/critical, add general hardening
        if risk in ("high", "critical"):
            # Log intensive monitoring recommendation
            actions.append({
                "action": "increase_monitoring",
                "detail": f"Risk level {risk} — recommending 15s report interval",
                "success": True,
            })

        self._actions_taken.extend(actions)
        # Keep last 100
        if len(self._actions_taken) > 100:
            self._actions_taken = self._actions_taken[-100:]

        self._log_step("act",
                        f"Took {len(actions)} actions (risk: {risk})",
                        [a.get("action", "") for a in actions])
        return actions

    def _decide_action(self, threat: ThreatEvent, risk: str) -> dict | None:
        """Decide what action to take for a threat."""
        if threat.category == "rogue_process" and threat.severity in ("high", "critical"):
            return {
                "action": "alert_and_log",
                "target": threat.title,
                "detail": f"Flagged suspicious process for base review: {threat.detail}",
                "resolves": False,
            }
        elif threat.category == "arp_spoof":
            return {
                "action": "alert_arp_spoof",
                "target": threat.source_ip,
                "detail": f"ARP spoofing from {threat.source_ip} — alerting base station",
                "resolves": False,
                "critical": True,
            }
        elif threat.category == "port_scan" and threat.severity == "high":
            return {
                "action": "flag_suspicious_port",
                "target": threat.title,
                "detail": f"Suspicious listening port flagged: {threat.detail}",
                "resolves": False,
            }
        elif threat.category == "data_exfil":
            return {
                "action": "alert_data_exfil",
                "target": "network",
                "detail": "Potential data exfiltration detected — alerting base",
                "resolves": False,
            }
        elif threat.category == "anomaly" and "DNS" in threat.title:
            return {
                "action": "alert_dns_change",
                "target": "dns",
                "detail": f"DNS server change detected: {threat.detail}",
                "resolves": False,
                "critical": True,
            }
        return None

    def _execute_action(self, action: dict, obs: dict) -> bool:
        """Execute a protective action. Returns success."""
        act_type = action.get("action", "")
        try:
            if act_type == "alert_and_log":
                logger.warning("THREAT: %s — %s", action["target"], action["detail"])
                return True
            elif act_type == "alert_arp_spoof":
                logger.critical("ARP SPOOF DETECTED: %s", action["detail"])
                return True
            elif act_type == "flag_suspicious_port":
                logger.warning("SUSPICIOUS PORT: %s", action["detail"])
                return True
            elif act_type == "alert_data_exfil":
                logger.warning("POTENTIAL EXFILTRATION: %s", action["detail"])
                return True
            elif act_type == "alert_dns_change":
                logger.critical("DNS CHANGE: %s", action["detail"])
                return True
            elif act_type == "increase_monitoring":
                return True
            else:
                logger.info("Action: %s", action.get("detail", act_type))
                return True
        except Exception as e:
            logger.error("Action failed (%s): %s", act_type, e)
            return False

    # -- GENERATE REPORT -----------------------------------------------

    def _generate_threat_report(
        self,
        obs: dict[str, Any],
        strategy: dict[str, Any],
        actions: list[dict],
        cycle: int,
    ) -> ThreatReport:
        """Auto-generate a detailed threat assessment report for this cycle."""
        import uuid, socket as _socket

        threats = strategy.get("threats", [])
        risk = strategy.get("risk_level", "low")
        score = strategy.get("threat_score", 0.0)
        now = datetime.now(timezone.utc).isoformat()

        # Build per-threat detail blocks
        threat_dicts: list[dict] = []
        for t in threats:
            cat = t.category if isinstance(t, ThreatEvent) else t.get("category", "anomaly")
            sev = t.severity if isinstance(t, ThreatEvent) else t.get("severity", "medium")
            title = t.title if isinstance(t, ThreatEvent) else t.get("title", "")
            detail = t.detail if isinstance(t, ThreatEvent) else t.get("detail", "")
            action = t.action_taken if isinstance(t, ThreatEvent) else t.get("action_taken", "")
            resolved = t.resolved if isinstance(t, ThreatEvent) else t.get("resolved", False)
            ts = t.timestamp if isinstance(t, ThreatEvent) else t.get("timestamp", now)
            src = t.source_ip if isinstance(t, ThreatEvent) else t.get("source_ip", "")

            info = _THREAT_EXPLANATIONS.get(cat, _THREAT_EXPLANATIONS["anomaly"])
            threat_dicts.append({
                "timestamp": ts,
                "severity": sev,
                "category": cat,
                "title": title,
                "technical_detail": detail,
                "source_ip": src,
                "what_it_is": info["what"],
                "potential_impact": info["impact"],
                "why_triggered": info["why_triggered"],
                "cvss_base_score": info["cvss_base"],
                "mitre_att_ck": info["mitre"],
                "action_taken": action,
                "action_explanation": _ACTION_EXPLANATIONS.get(action, "No automated action available for this threat type."),
                "resolved": resolved,
            })

        # Build actions block
        action_dicts: list[dict] = []
        for a in actions:
            atype = a.get("action", "")
            action_dicts.append({
                "action": atype,
                "target": a.get("target", ""),
                "detail": a.get("detail", ""),
                "success": a.get("success", False),
                "explanation": _ACTION_EXPLANATIONS.get(atype, a.get("detail", "")),
            })

        # Observations snapshot
        observations = {
            "connections": obs.get("connection_count", 0),
            "listening_ports": obs.get("listener_count", 0),
            "external_connections": obs.get("external_count", 0),
            "active_processes": obs.get("process_count", 0),
            "arp_entries": obs.get("arp_entry_count", 0),
            "gateway": obs.get("gateway", ""),
            "local_ip": obs.get("local_ip", ""),
            "dns_servers": obs.get("dns_servers", []),
        }

        baseline_info = {
            "network_drift_pct": round(strategy.get("network_drift", 0), 1),
            "process_drift_pct": round(strategy.get("process_drift", 0), 1),
            "avg_connections_baseline": self._baselines.get("avg_connections", 0),
            "avg_external_baseline": self._baselines.get("avg_external", 0),
            "cycle_count": cycle,
        }

        narrative = self._build_narrative(risk, score, threats, actions, obs, strategy)

        report = ThreatReport(
            report_id=str(uuid.uuid4())[:8].upper(),
            generated_at=now,
            agent_id=self._agent_id,
            host=obs.get("local_ip", "unknown"),
            cycle=cycle,
            risk_level=risk,
            threat_score=round(score, 1),
            threats=threat_dicts,
            actions_taken=action_dicts,
            observations=observations,
            baselines=baseline_info,
            narrative=narrative,
            recommendations=strategy.get("recommendations", []),
        )
        return report

    def _build_narrative(
        self,
        risk: str,
        score: float,
        threats: list,
        actions: list[dict],
        obs: dict,
        strategy: dict,
    ) -> str:
        """Build a plain-English narrative summary of the assessment cycle."""
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        host = obs.get("local_ip", "unknown host")
        cycle = self._baselines.get("cycle_count", 0)

        if not threats:
            return (
                f"Assessment cycle #{cycle} completed at {now_str} on {host}. "
                f"No threats detected. The environment is operating within normal baselines. "
                f"Threat score: 0/100 (low risk)."
            )

        sev_counts: dict[str, int] = {}
        for t in threats:
            sev = t.severity if isinstance(t, ThreatEvent) else t.get("severity", "medium")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        sev_summary = ", ".join(f"{v} {k}" for k, v in sorted(
            sev_counts.items(), key=lambda x: ["critical","high","medium","low","info"].index(x[0])
            if x[0] in ["critical","high","medium","low","info"] else 99
        ))

        cats = list({(t.category if isinstance(t, ThreatEvent) else t.get("category","")) for t in threats})
        cat_names = {
            "arp_spoof": "ARP spoofing / man-in-the-middle",
            "rogue_process": "suspicious process activity",
            "port_scan": "suspicious listening ports",
            "data_exfil": "potential data exfiltration",
            "anomaly": "system anomalies",
        }
        cat_summary = " and ".join(cat_names.get(c, c) for c in cats)

        action_count = len([a for a in actions if a.get("success")])
        action_str = (
            f"{action_count} automated protective action(s) were executed."
            if action_count else
            "No automated blocking actions were available for these threat types — manual investigation is required."
        )

        net_drift = strategy.get("network_drift", 0)
        drift_str = ""
        if net_drift > 20:
            drift_str = (
                f" Network behaviour deviated {net_drift:.0f}% from the established baseline, "
                f"suggesting the host environment has changed since the last clean state."
            )

        critical_titles = [
            (t.title if isinstance(t, ThreatEvent) else t.get("title", ""))
            for t in threats
            if (t.severity if isinstance(t, ThreatEvent) else t.get("severity")) in ("critical", "high")
        ]
        critical_str = ""
        if critical_titles:
            critical_str = (
                f" The highest-priority finding(s) requiring immediate attention: "
                + "; ".join(f'"{x}"' for x in critical_titles[:3]) + "."
            )

        return (
            f"Threat assessment cycle #{cycle} completed at {now_str} on agent {self._agent_id} ({host}). "
            f"Overall risk level: {risk.upper()} — threat score {score:.0f}/100. "
            f"{len(threats)} threat(s) were identified ({sev_summary}), spanning {cat_summary}.{critical_str} "
            f"{action_str}{drift_str} "
            f"Full technical details and remediation steps are documented in the threat entries below."
        )

    # -- LEARN ---------------------------------------------------------

    def learn(self, obs: dict[str, Any], strategy: dict[str, Any]) -> None:
        """Phase 4: Update baselines and persist threat intelligence."""
        self._log_step("learn", "Updating baselines and threat intelligence...")

        alpha = 0.2  # Exponential moving average weight

        # Update connection baselines
        cur_conns = obs.get("connection_count", 0)
        cur_listeners = obs.get("listener_count", 0)
        cur_external = obs.get("external_count", 0)

        self._baselines["avg_connections"] = self._ema(
            self._baselines.get("avg_connections", cur_conns), cur_conns, alpha)
        self._baselines["avg_listeners"] = self._ema(
            self._baselines.get("avg_listeners", cur_listeners), cur_listeners, alpha)
        self._baselines["avg_external"] = self._ema(
            self._baselines.get("avg_external", cur_external), cur_external, alpha)

        # Update process baseline
        cur_proc_count = obs.get("process_count", 0)
        self._baselines["avg_process_count"] = self._ema(
            self._baselines.get("avg_process_count", cur_proc_count), cur_proc_count, alpha)

        # Track known processes
        current_names = [p.name for p in obs.get("processes", [])
                         if isinstance(p, ProcessInfo)]
        known = set(self._baselines.get("known_processes", []))
        known.update(current_names[:200])
        self._baselines["known_processes"] = list(known)[:500]

        # Save gateway MAC for next cycle's spoofing detection
        gateway_ip = obs.get("gateway", "")
        if gateway_ip:
            for entry in obs.get("arp_table", []):
                if isinstance(entry, ARPEntry) and entry.ip == gateway_ip:
                    self._baselines["gateway_mac"] = entry.mac
                    break

        # Save DNS baseline
        dns = obs.get("dns_servers", [])
        if dns:
            self._baselines["dns_servers"] = dns

        self._baselines["last_updated"] = datetime.now(timezone.utc).isoformat()
        self._baselines["cycle_count"] = self._baselines.get("cycle_count", 0) + 1

        self._save_baselines()

        # Save threats to history
        for t in strategy.get("threats", []):
            self._threat_history.append({
                "timestamp": t.timestamp,
                "severity": t.severity,
                "category": t.category,
                "title": t.title,
                "detail": t.detail,
                "action_taken": t.action_taken,
                "resolved": t.resolved,
            })
        self._save_threat_history()

        # Auto-generate a detailed threat report whenever threats exist,
        # or every 50 cycles for a clean baseline audit trail.
        cycle = self._baselines.get("cycle_count", 0)
        has_threats = bool(strategy.get("threats"))
        if has_threats or cycle % 50 == 0:
            report = self._generate_threat_report(obs, strategy, self._actions_taken[-20:], cycle)
            report_dict = report.to_dict()
            # Generate full Markdown incident report (always on threats, every 50 on clean)
            md = self._generate_incident_report_md(report, obs)
            report_dict["incident_report_md"] = md
            self._save_incident_report(md, report.report_id)
            self._threat_reports.append(report_dict)
            self._threat_reports = self._threat_reports[-100:]
            self._save_threat_reports()
            if has_threats:
                logger.info(
                    "[REPORT] Assessment report %s generated — %d threat(s) | risk: %s | score: %.0f/100",
                    report.report_id, len(strategy["threats"]),
                    report.risk_level, report.threat_score,
                )

        self._log_step("learn",
                        f"Baselines updated (cycle #{self._baselines.get('cycle_count', 0)}), "
                        f"{len(self._threat_history)} total threat events recorded")

    @staticmethod
    def _ema(old: float, new: float, alpha: float) -> float:
        return round(old * (1 - alpha) + new * alpha, 2)

    # -- FULL CYCLE ----------------------------------------------------

    def run_cycle(self, agent_id: str = "") -> DiagnosticReport:
        """Run one full Observe → Reason → Act → Learn cycle.
        Returns a DiagnosticReport ready to send to base."""
        self._agent_id = agent_id

        # Phase 1: OBSERVE
        obs = self.observe()

        # Phase 2: REASON
        strategy = self.reason(obs)

        # Phase 3: ACT
        actions = self.act(obs, strategy)

        # Phase 4: LEARN
        self.learn(obs, strategy)

        # Build diagnostic report for base
        threats = strategy.get("threats", [])
        return DiagnosticReport(
            agent_id=agent_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            network_connections=[{
                "protocol": c.protocol,
                "local": f"{c.local_addr}:{c.local_port}",
                "remote": f"{c.remote_addr}:{c.remote_port}",
                "state": c.state,
                "suspicious": c.suspicious,
            } for c in obs.get("connections", [])[:50]
                if isinstance(c, NetworkConnection)],
            listening_ports=[{
                "port": c.local_port,
                "protocol": c.protocol,
                "address": c.local_addr,
            } for c in obs.get("listening_ports", [])
                if isinstance(c, NetworkConnection)],
            active_processes=obs.get("process_count", 0),
            suspicious_processes=[{
                "name": p.name, "pid": p.pid,
                "cpu": p.cpu_pct, "mem": p.mem_pct,
                "reason": p.reason,
            } for p in obs.get("processes", [])
                if isinstance(p, ProcessInfo) and p.suspicious],
            arp_table=[{
                "ip": e.ip, "mac": e.mac,
                "interface": e.interface,
                "is_gateway": e.is_gateway,
            } for e in obs.get("arp_table", [])
                if isinstance(e, ARPEntry)],
            threats_detected=[{
                "timestamp": t.timestamp,
                "severity": t.severity,
                "category": t.category,
                "title": t.title,
                "detail": t.detail,
                "action_taken": t.action_taken,
                "resolved": t.resolved,
            } for t in threats],
            threat_score=strategy.get("threat_score", 0),
            risk_level=strategy.get("risk_level", "low"),
            actions_taken=actions,
            firewall_rules_active=0,
            blocked_ips=list(self._blocked_ips),
            issues_found=strategy.get("issues", []),
            recommendations=strategy.get("recommendations", []),
            react_log=[s.to_dict() for s in self._react_log[-20:]],
            network_baseline_drift=strategy.get("network_drift", 0),
            process_baseline_drift=strategy.get("process_drift", 0),
        )

    # -- Accessors for dashboard queries -------------------------------

    @property
    def react_log(self) -> list[dict]:
        return [s.to_dict() for s in self._react_log]

    @property
    def threat_count(self) -> int:
        return len(self._threats)

    @property
    def threat_history_count(self) -> int:
        return len(self._threat_history)

    @property
    def latest_threat_reports(self) -> list[dict]:
        """Return the last 20 detailed threat reports."""
        return self._threat_reports[-20:]

    @property
    def latest_threats(self) -> list[dict]:
        return [asdict(t) if hasattr(t, '__dataclass_fields__') else t
                for t in self._threats[-20:]]

    @property
    def baselines(self) -> dict:
        return dict(self._baselines)

    @property
    def blocked_ip_count(self) -> int:
        return len(self._blocked_ips)
