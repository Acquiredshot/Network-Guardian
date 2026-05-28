# Network Guardian — Complete System Startup Guide

**🚀 Run the Entire Integrated System on Your MacBook**

All components are now integrated and ready to run. Follow this guide to start everything.

---

## Quick Start (Recommended)

Open **4 Terminal Windows**:

### Terminal 1: Full System Coordinator
```bash
cd "Network Guardian"
python3 run_full_system.py
```
**What it does:**
- Initializes all 6 components (Firewall, Bridge, Harvester, Correlator, Scanner)
- Monitors system health
- Auto-persists data on shutdown
- Coordinates all components

**Expected output:**
```
Network Guardian — Full System Initialization
[1/6] Creating core engine... ✓ Engine created
[2/6] Initializing Smart Firewall Agent... ✓ Firewall running
[3/6] Initializing Probe-Firewall Bridge... ✓ Bridge ready
[4/6] Initializing Payload Harvester... ✓ Harvester ready
[5/6] Initializing Attack Correlator... ✓ Correlator ready
[6/6] Initializing Defensive Scanner... ✓ Scanner ready

System Ready — All Components Online
```

### Terminal 2: Web Dashboard
```bash
cd "Network Guardian"
python3 _start_dashboard.py
```
**What it does:**
- Starts the web interface on http://127.0.0.1:8080
- Shows all integrated systems in real-time
- Displays fleet map with probe status
- Shows threat detection, rules, correlations, etc.

**Access:**
- URL: http://127.0.0.1:8080
- Login: `admin` / `<password>`

### Terminal 3: Local Probe (Keeps MacBook Online)
```bash
cd "Network Guardian"
python3 run_local_probe.py
```
**What it does:**
- Simulates network probe on your MacBook
- Sends heartbeats every 30 seconds
- Keeps machine **online** on fleet map
- Reports system metrics (CPU, memory, disk)

**Expected output:**
```
Network Guardian — Local Probe Simulator
[*] Agent ID: B856F38A
[*] Hostname: Cortezs-MacBook-Air.local
[*] Platform: Darwin
[*] Reporting to dashboard every 30 seconds

[Cycle 001] Status: online | Hostname: Cortezs-MacBook-Air.local | Platform: Darwin
[Cycle 002] Status: online | Hostname: Cortezs-MacBook-Air.local | Platform: Darwin
```

### Terminal 4: Real-Time Monitoring
```bash
cd "Network Guardian"
python3 monitor_data.py monitor --interval 5
```
**What it does:**
- Shows live metrics updated every 5 seconds
- Displays firewall events, blocked IPs, rules, correlations
- Shows threats as they're detected

**Expected output:**
```
Network Guardian — Real-Time Monitoring Dashboard
[12:34:56] Events: 15 | Blocked IPs: 3 | Correlations: 2 | Rules: 4 | Discoveries: 5 | Vulns: 1 | Avg Conf: 0.82
    └─ Changes: Blocked IPs: +1 | Correlations: +1
[12:35:01] Events: 18 | Blocked IPs: 3 | Correlations: 2 | Rules: 4 | Discoveries: 5 | Vulns: 1 | Avg Conf: 0.83
    └─ Changes: Events: +3
```

---

## Alternative: Minimal Setup (2 Terminals)

If you want a simpler setup with just core components:

### Terminal 1: Full System + Dashboard
```bash
cd "Network Guardian"
# Start system coordinator
python3 run_full_system.py &

# Wait 3 seconds, then start dashboard
sleep 3
python3 _start_dashboard.py
```

### Terminal 2: Probe + Monitoring
```bash
cd "Network Guardian"
# Start probe
python3 run_local_probe.py &

# Wait 2 seconds, then start monitoring
sleep 2
python3 monitor_data.py monitor
```

---

## Testing the System (Optional)

To generate test data and see everything in action:

```bash
cd "Network Guardian"
python3 probe_integration_test.py
```

**What it does:**
- Simulates probe discoveries
- Exploits vulnerabilities (payloads)
- Tests payload harvesting
- Tests attack correlation
- Tests defensive scanning
- Tests firewall detection

**Watch in:**
- Dashboard: Threats appear in real-time
- Monitor terminal: Metrics update instantly
- Export after: `python3 export_test_data.py`

---

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│           Your MacBook Running on Dashboard             │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Terminal 1: System Coordinator                         │
│  ✓ Smart Firewall Agent (detection & blocking)         │
│  ✓ Probe-Firewall Bridge (intelligence sharing)        │
│  ✓ Payload Harvester (rule learning)                   │
│  ✓ Attack Correlator (discovery + attack matching)     │
│  ✓ Defensive Scanner (internal vulnerability testing)  │
│  ✓ Health Monitoring (cycles every 5 seconds)          │
│                                                          │
│  Terminal 2: Web Dashboard                              │
│  ✓ Fleet Map (shows probe online)                       │
│  ✓ Real-time threat detection                          │
│  ✓ Rule management                                      │
│  ✓ Correlation analysis                                │
│  ✓ Data export                                          │
│                                                          │
│  Terminal 3: Local Probe                                │
│  ✓ System metrics reporting                            │
│  ✓ Heartbeat (every 30 seconds)                        │
│  ✓ Keeps MacBook ONLINE on fleet map                   │
│  ✓ Network simulation                                   │
│                                                          │
│  Terminal 4: Monitoring                                 │
│  ✓ Live metrics (every 5 seconds)                      │
│  ✓ Real-time data collection                           │
│  ✓ Event tracking                                       │
│  ✓ Threat visualization                                │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## What's Happening in Each Component

### Smart Firewall Agent (Terminal 1)
- Runs detection cycles every 5 seconds
- Analyzes injection attempts
- Blocks hostile IPs automatically
- Learns from harvested rules

### Probe-Firewall Bridge (Terminal 1)
- Receives probe discovery events
- Adapts firewall rules for discovered services
- Feeds exploitation data to harvester
- Tracks service-specific security profiles

### Payload Harvester (Terminal 1)
- Converts exploited payloads to detection rules
- Stores rules with confidence scores
- Persists to `~/.network_guardian/payload_harvester/`

### Attack Correlator (Terminal 1)
- Tracks discovered endpoints
- Matches attacks to discoveries
- Calculates threat scores
- Persists correlations to `~/.network_guardian/attack_correlator/`

### Defensive Scanner (Terminal 1)
- Tests internal endpoints for vulnerabilities
- Uses firewall rules to validate findings
- Eliminates false positives
- Reports vulnerable endpoints

### Local Probe (Terminal 3)
- **Sends heartbeats every 30 seconds** ← Keeps you ONLINE
- Reports system metrics
- Simulates network discovery
- Updates dashboard with status

### Web Dashboard (Terminal 2)
- Shows all components in real-time
- Fleet map displays probe status (ONLINE ✓)
- Real-time threat visualization
- Data export and analysis

### Monitor (Terminal 4)
- Tracks metrics in real-time
- Shows firewall events, blocked IPs, rules
- Live threat correlation display
- Updates every 5 seconds

---

## Key Features Now Working

✅ **Probe Stays Online**
- Local probe sends heartbeats every 30 seconds
- Fleet map shows "ONLINE" status
- Dashboard shows real-time metrics

✅ **Threat Intelligence Feedback**
- Probe discoveries → Firewall adapts rules
- Service-specific detection enabled

✅ **Payload Harvesting**
- Exploits → Rules created automatically
- Rules added to firewall dynamically

✅ **Attack Correlation**
- Probe discoveries matched with firewall blocks
- High-confidence detections on known endpoints

✅ **Defensive Scanning**
- Internal vulnerability testing
- False-positive elimination

✅ **Real-Time Monitoring**
- Live metrics dashboard
- Event tracking
- Data export

---

## Troubleshooting

### Probe shows as OFFLINE
**Solution:** Make sure Terminal 3 is running:
```bash
python3 run_local_probe.py
```

### Dashboard won't load
**Solution:** Make sure Terminal 2 is running:
```bash
python3 _start_dashboard.py
```

### No events showing in monitoring
**Solution:** Run the test to generate data:
```bash
python3 probe_integration_test.py
```

### Data not persisting
**Check:** All data is saved to `~/.network_guardian/`
```bash
ls -la ~/.network_guardian/
```

---

## Data Access

### Live Dashboard
http://127.0.0.1:8080 (admin / <password>)

### Real-Time Metrics
```bash
python3 monitor_data.py status    # Current snapshot
python3 monitor_data.py stats     # Aggregated stats
python3 monitor_data.py monitor   # Live streaming
```

### Export All Data
```bash
python3 export_test_data.py
# Creates ./export/ with 10 CSV/JSON reports
```

### View Raw Data
```bash
# Firewall history
cat ~/.network_guardian/smart_firewall/injection_history.json

# Harvested rules
cat ~/.network_guardian/payload_harvester/harvested_rules.json

# Correlations
cat ~/.network_guardian/attack_correlator/correlations.json

# Discoveries
cat ~/.network_guardian/attack_correlator/discoveries.json
```

---

## System Statistics

After running for a while, you'll see:

| Metric | Expected |
|--------|----------|
| System uptime | Continuous |
| Probe status | ONLINE |
| Heartbeats sent | 1 per 30 seconds |
| Data collection cycles | 1 per 5 seconds |
| Firewall checks | Continuous |
| Rules in harvester | 0+ (grows with tests) |
| Discoveries tracked | 0+ (grows with tests) |
| Correlations | 0+ (grows with attacks) |

---

## Next Steps

1. **Open 4 terminals** as shown above
2. **Watch the dashboard** at http://127.0.0.1:8080
3. **Check probe status** - should show ONLINE
4. **Run test** to generate data: `python3 probe_integration_test.py`
5. **Export data** to analyze: `python3 export_test_data.py`

**Your MacBook is now fully integrated with Network Guardian! 🎯**
