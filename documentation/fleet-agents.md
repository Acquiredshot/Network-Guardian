# Fleet Agents

Network Guardian deploys two types of field agents that phone home to the central dashboard over HTTPS using HMAC authentication. Neither agent exposes the dashboard base URL on the wire when covert flags are used.

---

## Agent Types

| Agent | Module | Purpose | Report Interval |
|---|---|---|---|
| **ng-probe** | `network_guardian.agent.probe` | Periodic full network scan | ~60 seconds |
| **ng-sentinel** | `network_guardian.agent.sentinel` | Persistent stay-behind surveillance | Continuous |

---

## ng-probe

### Purpose

Runs a full ReAct (Observe → Reason → Act → Learn) security scan on the host machine and surrounding network, then transmits a structured `AgentReport` to the dashboard fleet endpoint.

### Running

```bash
# Basic
python -m network_guardian.agent.probe \
  --base https://YOUR-DASHBOARD-URL \
  --key YOUR_FLEET_KEY

# With covert comms (recommended)
python -m network_guardian.agent.probe \
  --base https://YOUR-DASHBOARD-URL \
  --key YOUR_FLEET_KEY \
  --tor \
  --stealth

# With explicit credentials (not recommended — prefer interactive prompt)
python -m network_guardian.agent.probe \
  --base https://YOUR-DASHBOARD-URL \
  --key YOUR_FLEET_KEY \
  --username YOUR_USERNAME
```

### CLI Arguments

| Argument | Default | Description |
|---|---|---|
| `--base` | required | Dashboard base URL |
| `--key` | required | Fleet HMAC key |
| `--username` | prompts | Wolfpak team username for auth |
| `--password` | prompts | Wolfpak team password for auth |
| `--tor` | off | Route through Tor SOCKS5 proxy |
| `--proxy` | none | Custom proxy `socks5://host:port` or `http://host:port` |
| `--stealth` | off | Add 30–300s jitter + decoy HTTP requests |

### Agent Identity

Each probe generates a persistent identity on first run:

```json
{
  "agent_id": "NG-XXXXXXXX",
  "hostname": "your-hostname.local",
  "platform_os": "Darwin",
  "arch": "arm64",
  "python_ver": "3.11.x",
  "mac_addr": "<redacted>"
}
```

Stored at `~/.ng_agent/.ng_agent_id`.

### Authentication

Probes authenticate against the dashboard's Wolfpak team system:

1. On first run, prompts for username/password (or reads from CLI args/env vars)
2. Token is saved to `~/.ng_agent/wolfpak_auth.json` (file mode `0600`)
3. Token is valid for **30 days** — re-authentication happens automatically on expiry
4. Token contains: `operator`, `agent_token`, `authenticated_at`

### Report Structure (`AgentReport`)

Each probe cycle transmits:

```json
{
  "agent_id": "NG-XXXXXXXX",
  "hostname": "your-hostname.local",
  "timestamp": "2026-04-26T12:00:00Z",
  "platform": "darwin",
  "arch": "arm64",
  "uptime": 3600.5,
  "wifi_networks": [...],
  "diagnostics": { ... },
  "threat_reports": [...],
  "sentinel": null
}
```

---

## ng-sentinel

### Purpose

A persistent stay-behind surveillance bot. Unlike the probe (which runs and exits), sentinel runs **continuously**, monitoring WiFi environment changes and network flow patterns between cycles. It transmits a `NetworkDigest` summary to the fleet endpoint at each interval.

### Running

```bash
python -m network_guardian.agent.sentinel \
  --base https://YOUR-DASHBOARD \
  --key YOUR_FLEET_KEY \
  --tor --stealth
```

### What It Monitors

#### WiFi Intelligence (via `WiFiWatcher`)

- **AP appear/disappear events** — tracks all visible SSIDs over time
- **Signal drift** — average signal change per BSSID across scans
- **Rogue AP / evil twin detection:**
  - Triggers when 3+ APs share the same SSID
  - Signal spread > 20 dB between them indicates potential evil twin
  - Risk: `medium` if < 5 APs with same SSID, `low` if ≥ 5
- **Channel congestion** — count of networks per WiFi channel

#### Flow Intelligence (via `FlowMonitor`)

Tracks every TCP/UDP connection as a `FlowRecord`:

```python
FlowRecord:
  protocol, local_addr, local_port
  remote_addr, remote_port
  first_seen, last_seen
  state          # ESTABLISHED, LISTEN, etc.
  bytes_est      # estimated bytes transferred
  packet_count
  flagged        # True if anomaly detected
  flag_reason
```

Anomaly triggers:
- Sudden spike in new connections (>2× recent average)
- New external endpoints not seen in history
- Known C2 port ranges: (4440–4450), (5550–5560), (6660–6670)

#### `NetworkDigest` (per cycle transmission)

```json
{
  "agent_id": "NG-XXXX",
  "sentinel_id": "sentinel-uuid",
  "timestamp": "2026-04-26T12:00:00Z",
  "uptime_seconds": 7200,
  "wifi_ssid_count": 12,
  "wifi_changes": [{"type": "appeared", "ssid": "NewNet", ...}],
  "rogue_ap_alerts": [{"ssid": "HomeNet", "risk": "medium", ...}],
  "channel_congestion": {"6": 4, "11": 2},
  "active_flows": 43,
  "new_flows_since_last": 5,
  "external_endpoints": 8,
  "flow_anomalies": [...],
  "bandwidth_pattern": "normal",
  "strategy": {...},
  "sensitivity_level": "normal"
}
```

---

## ReAct Loop (`network_guardian/agent/react_agent.py`)

Both agents use a `ProbeReActAgent` that executes a four-phase reasoning cycle on every scan.

### Phases

```
Observe → Reason → Act → Learn
```

| Phase | What Happens |
|---|---|
| **Observe** | Collect network connections, listening ports, active processes, ARP table, WiFi networks |
| **Reason** | Analyze observations against baselines; identify threat categories |
| **Act** | Apply local firewall rules, log actions, update baselines |
| **Learn** | Generate `ThreatReport`, save to disk, transmit to dashboard |

### Threat Detection Categories

| Category | Trigger Condition |
|---|---|
| `arp_spoof` | ARP table inconsistency (multiple MACs for same IP, or gateway IP mismatch) |
| `rogue_process` | Process name matches `_SUSPICIOUS_PROCS` list |
| `port_scan` | Unusual spike in inbound connection attempts |
| `data_exfil` | ≥ 50 simultaneous external connections from single process |
| `anomaly` | Statistical deviation from established baseline (connections, processes, ports) |

### Suspicious Process Names

The agent flags any process whose name contains one of:

```
nmap, masscan, zmap, responder, ettercap, arpspoof, bettercap, mitmproxy,
wireshark, tcpdump, hashcat, john, hydra, medusa, metasploit, msfconsole,
msfvenom, netcat, nc, ncat, socat, cryptominer, xmrig, mimikatz, lazagne,
procdump, keylogger, aircrack, airodump, aireplay, wifite, kismet, reaver
```

### Suspicious Listening Ports

```
4444, 5555, 6666, 7777    # Common reverse shell ports
1337, 31337               # "Leet" ports
9001, 9050, 9150          # Tor ports
3128, 8888, 8118          # Open proxy ports
6667, 6697                # IRC C2
2222                      # Alternate SSH
```

### Baseline Tracking

The agent maintains persistent baselines in `~/.ng_agent/baselines.json`:

- **Network baseline**: expected number of connections, external endpoints, listening ports
- **Process baseline**: expected set of running process names
- **Drift tracking**: percentage deviation from baseline per cycle

Baselines update automatically as the environment is learned. Clean-baseline reports are generated every **10 cycles** (probe) to feed the AI engine.

---

## Covert Comms

When `--tor` or `--stealth` flags are used, the agent routes all HTTP through the covert communications layer (`network_guardian/agent/covert_comms.py`):

| Feature | Description |
|---|---|
| **Tor routing** | SOCKS5 proxy through `127.0.0.1:9050` |
| **Timing jitter** | Random 30–300 second delay between reports |
| **Decoy requests** | Random HTTP requests to benign sites alongside real reports |
| **UA rotation** | Rotates through realistic browser User-Agent strings |
| **Body padding** | Random padding bytes appended to request bodies |
| **Source rotation** | Rotates source IP presentation when multiple interfaces available |

The dashboard base URL is **never sent unencrypted** and **never appears in proxy logs** — all traffic appears as normal HTTPS.

---

## Standalone Probe (`ng_probe_standalone.py`)

For distributing an agent to a team member without requiring a full repo clone or `pip install`, a **zero-dependency single-file probe** is included at the project root.

### Requirements

- Python 3.11+ only — nothing to install

### Usage

```bash
python3 ng_probe_standalone.py              # run interactively (Ctrl+C to stop)
python3 ng_probe_standalone.py --once       # single report then exit
python3 ng_probe_standalone.py --install    # install as background service
python3 ng_probe_standalone.py --uninstall  # remove background service
python3 ng_probe_standalone.py --no-discovery  # skip host sweep (faster)
python3 ng_probe_standalone.py --deauth     # clear cached auth token
```

### Pre-configured constants

| Constant | Value |
|---|---|
| `_BASE_URL` | `https://network-guardian-cc8900c70290.herokuapp.com` |
| `_FLEET_KEY` | Permanent fleet key |
| `_INTERVAL` | 60 seconds |

### First Run

On first run the script prompts for a Wolfpak username and password (a valid team account must be created on the dashboard first via **Team Management → Add Member**). The token is cached to `~/.ng_agent/wolfpak_auth.json` (mode `0600`) for 30 days.

### What it does

- Scans WiFi (macOS `system_profiler`, Linux `nmcli`, Windows `netsh`)
- Discovers live hosts via async ICMP ping sweep of the local /24
- Collects system metrics (CPU load, disk, memory, uptime, connections, processes)
- Basic inline threat analysis (open WiFi, WEP networks, excessive connections, high CPU)
- HMAC-signs every report with the fleet key before transmitting
- Registers the agent identity on first phone-home

### Service install

`--install` creates a background service that auto-starts on reboot with no terminal required:

| OS | Method |
|---|---|
| macOS | LaunchAgent plist (`~/Library/LaunchAgents/com.wolfpak.ng-probe.plist`) |
| Linux | systemd user service (`~/.config/systemd/user/ng-probe.service`) |
| Windows | Scheduled Task (runs on login, highest privileges) |

---

## Fleet Store

The dashboard stores all agent data in `~/.network_guardian/fleet.json` via `FleetStore`.

### Per-Agent Data Structure

```json
{
  "agents": {
    "NG-XXXXXXXX": {
      "last_report": { ... },
      "last_seen": 1714132800,
      "report_count": 42,
      "identity": { ... },
      "label": "Office Mac",
      "last_diagnostics": { ... },
      "threat_history": [...],    // last 200 entries
      "threat_reports": [...],    // last 50 detailed reports
      "sentinel": { ... },
      "wifi_change_log": [...],
      "flow_anomaly_log": [...],
      "rogue_ap_log": [...],
      "covert_status": { ... }
    }
  }
}
```

### Agent Status Thresholds

| Status | Condition |
|---|---|
| **Online** | Last seen < 120 seconds ago |
| **Stale** | Last seen 120–300 seconds ago |
| **Offline** | Last seen > 300 seconds ago |

---

## WiFi Scanning

The probe scans WiFi networks using platform-specific methods:

| Platform | Method |
|---|---|
| macOS | `system_profiler SPAirPortDataType` → fallback to `/System/Library/PrivateFrameworks/.../airport` |
| Linux | `iwlist scan` or `nmcli dev wifi` |

Security string normalisation:

| Raw Value | Normalised |
|---|---|
| `WPA2 Personal`, `WPA2-PSK` | `WPA2` |
| `WPA3 Personal`, `WPA3-SAE` | `WPA3` |
| `WPA WPA2`, `mixed` | `WPA/WPA2` |
| `WEP` | `WEP` |
| `Open`, `none`, `` | `Open` |
