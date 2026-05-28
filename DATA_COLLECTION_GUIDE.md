# Network Guardian — Data Collection & Analysis Guide

**⚠️ IMPORTANT: All data stays local on your machine**

- Only reads from: `~/.network_guardian/` (local directory)
- Only writes to: `./export/` and `~/.network_guardian/metrics/` (local directories)
- **NO external API calls** to any remote servers
- **NO internet connectivity** required
- **NO data transmission** or cloud uploads
- All processing is **100% offline and local**
- All data files are in standard formats (JSON, CSV) for easy inspection

Complete guide to collecting, monitoring, and analyzing test data during Network Guardian testing.

---

## Overview

Two tools work together to capture and analyze data:

1. **`monitor_data.py`** — Real-time monitoring dashboard (runs during testing)
2. **`export_test_data.py`** — Post-test analysis and reporting (runs after testing)

---

## Data Privacy & Security

✅ **All data is 100% local and private**

| Aspect | Status |
|--------|--------|
| Data Location | Local machine only (`~/.network_guardian/` and `./export/`) |
| Remote Transmission | ❌ Never - No internet calls |
| Cloud Sync | ❌ No cloud integrations |
| External APIs | ❌ No external API calls |
| Dependencies | ✅ Only Python standard library (json, csv, pathlib) |
| Data Retention | ✅ You control - stored in standard formats |
| Data Deletion | ✅ Delete with: `rm -rf ~/.network_guardian/` |
| Encryption | ✅ Use OS-level encryption (FileVault on macOS) |

**Verified with:**
- No `requests`, `urllib`, or `http` library calls
- No DNS lookups or network I/O
- All imports are from Python standard library
- All file I/O is to local directories

---

## Quick Start

### During Testing: Monitor in Real-Time

**Option 1: Live dashboard (updates every 5 seconds)**
```bash
python monitor_data.py monitor
```

**Option 2: Show current snapshot**
```bash
python monitor_data.py status
```

### After Testing: Export & Analyze

**Export all collected data to CSV/JSON**
```bash
python export_test_data.py
```

---

## `monitor_data.py` — Real-Time Monitoring

### Commands

#### 1. `monitor` — Continuous Live Dashboard

Displays real-time metrics while tests run. Start this in a separate terminal before running test scenarios.

```bash
python monitor_data.py monitor --interval 5
```

**Output:**
```
==================================================
  Network Guardian — Real-Time Monitoring Dashboard
==================================================
[*] Starting continuous data collection (interval: 5 seconds)
[*] Press Ctrl+C to stop

[12:34:56] Events: 15 | Blocked IPs: 3 | Correlations: 2 | Rules: 4 | Discoveries: 5 | Vulns: 1 | Avg Conf: 0.82
    └─ Changes: Blocked IPs: +1 | Correlations: +1
[12:35:01] Events: 18 | Blocked IPs: 3 | Correlations: 2 | Rules: 4 | Discoveries: 5 | Vulns: 1 | Avg Conf: 0.83
    └─ Changes: Events: +3
```

**Metrics explained:**
- **Events**: Total firewall injection detection events
- **Blocked IPs**: Unique source IPs blocked
- **Correlations**: Attack correlations detected (probe discoveries matched with attacks)
- **Rules**: Harvested detection rules created from exploits
- **Discoveries**: Services/endpoints discovered by probe
- **Vulns**: Vulnerabilities found by defensive scanner
- **Avg Conf**: Average confidence score across all rules

**Options:**
```bash
--interval N    Collection interval in seconds (default: 5)
```

#### 2. `status` — Current Snapshot

Show current metrics without continuous monitoring.

```bash
python monitor_data.py status
```

**Output:**
```
================================================================================
  Network Guardian — Live Dashboard
================================================================================

[*] Timestamp: 2026-05-28T12:34:56.789012

[+] Smart Firewall:
    - Total events recorded: 23
    - Unique blocked IPs: 5

[+] Attack Correlation:
    - Correlation events: 3
    - Discovered services: 8

[+] Payload Harvesting:
    - Harvested rules: 6
    - Avg confidence: 0.84

[+] Defensive Scanning:
    - Total scans: 12
    - Vulnerabilities found: 2

[+] Changes since last measurement:
    - Events: +3
    - Blocked IPs: +0
    - Correlations: +1
    - Rules: +0
```

#### 3. `stats` — Collection Statistics

Show aggregate statistics from all collected metrics.

```bash
python monitor_data.py stats
```

**Output:**
```
================================================================================
  Network Guardian — Collection Statistics
================================================================================

[*] Total measurements: 42
[*] Duration: 0:03:30

[+] Averages:
    - Firewall events per snapshot: 12.3
    - Blocked IPs per snapshot: 3.8
    - Avg rule confidence: 0.82

[+] Peaks:
    - Peak events: 35
    - Peak blocked IPs: 8
    - Peak vulnerabilities: 3

[+] Final state:
    - Firewall events: 28
    - Blocked IPs: 6
    - Correlation events: 4
    - Harvested rules: 7
    - Discovered services: 9
    - Vulnerabilities: 2
```

#### 4. `export` — Export to CSV

Export all collected metrics as CSV for spreadsheet analysis.

```bash
python monitor_data.py export
```

**Output:**
```
[+] Metrics exported to /Users/codycodesit/.network_guardian/metrics/metrics_export.csv
```

**CSV columns:**
- timestamp
- firewall_events
- blocked_ips
- correlation_events
- harvested_rules
- discovered_services
- scan_results
- vulnerabilities
- avg_confidence

---

## `export_test_data.py` — Data Analysis & Reporting

Export and analyze all collected data after testing completes.

```bash
python export_test_data.py
```

**Output:**
```
============================================================
  Network Guardian — Data Export & Analysis
============================================================

[*] Loading data files...
    ✓ Loaded injection_history.json
    ✓ Loaded harvested_rules.json
    ✓ Loaded discoveries.json
    ✓ Loaded correlations.json
    ✓ Loaded scan_results.json

[*] Exporting firewall statistics...
    ✓ Exported to firewall_stats.json
    ✓ Exported to firewall_blocked_ips.csv

[*] Exporting correlation analysis...
    ✓ Exported to correlation_analysis.json
    ✓ Exported to correlation_top_attackers.csv

[*] Exporting harvested rules statistics...
    ✓ Exported to harvested_rules_stats.json
    ✓ Exported to harvested_rules_effectiveness.csv

[*] Exporting discovery analysis...
    ✓ Exported to discovery_analysis.json
    ✓ Exported to discovered_services.csv

[*] Exporting scan results...
    ✓ Exported to scan_results_stats.json
    ✓ Exported to scan_vulnerabilities.csv

[*] Generating summary report...
    ✓ Exported to SUMMARY.json

[+] All data exported to: /Users/codycodesit/export/
[+] Files generated:
    - SUMMARY.json (1,245 bytes)
    - correlation_analysis.json (892 bytes)
    - correlation_top_attackers.csv (523 bytes)
    - discovered_services.csv (1,856 bytes)
    - discovery_analysis.json (634 bytes)
    - firewall_blocked_ips.csv (412 bytes)
    - firewall_stats.json (756 bytes)
    - harvested_rules_effectiveness.csv (1,234 bytes)
    - harvested_rules_stats.json (598 bytes)
    - scan_results_stats.json (445 bytes)
    - scan_vulnerabilities.csv (892 bytes)
```

### Generated Files

All files are created in `./export/` directory.

#### JSON Reports

**`SUMMARY.json`** — Overall test summary
```json
{
  "timestamp": "2026-05-28T12:45:30.123456",
  "firewall": {"total_ips": 6, "total_events": 28},
  "correlations": {"total": 4},
  "harvested_rules": {"total": 7},
  "discoveries": {"total": 9},
  "scans": {"total": 12}
}
```

**`firewall_stats.json`** — Smart Firewall statistics
```json
{
  "total_ips": 6,
  "total_events": 28,
  "injection_types": {
    "sql_injection": 8,
    "xss": 5,
    "command_injection": 3,
    "path_traversal": 2,
    ...
  },
  "top_blocked_ips": [
    ["192.168.1.100", 8],
    ["192.168.1.50", 5],
    ...
  ]
}
```

**`correlation_analysis.json`** — Attack correlation results
```json
{
  "total_correlations": 4,
  "confidence_distribution": {
    "high": 3,
    "medium": 1,
    "low": 0
  },
  "top_attacking_ips": [
    ["192.168.1.100", 3],
    ["10.0.0.50", 1]
  ]
}
```

**`harvested_rules_stats.json`** — Payload harvester metrics
```json
{
  "total_rules": 7,
  "by_injection_type": {"sql_injection": 3, "xss": 2, "cmd": 2},
  "by_severity": {"critical": 4, "high": 3},
  "by_confidence": {"80%": 2, "85%": 3, "90%": 2}
}
```

**`discovery_analysis.json`** — Probe discovery stats
```json
{
  "total_services": 9,
  "by_service_type": {"http": 5, "sql": 3, "soap": 1},
  "services_per_ip": {"192.168.1.100": 3, "192.168.1.200": 2, ...}
}
```

**`scan_results_stats.json`** — Defensive scanner results
```json
{
  "total_scans": 12,
  "vulnerabilities_found": 2,
  "false_positives": 0,
  "by_injection_type": {"xss": 1, "sql_injection": 1}
}
```

#### CSV Reports

**`firewall_blocked_ips.csv`** — Top blocked source IPs
```
IP Address,Event Count
192.168.1.100,8
192.168.1.50,5
10.0.0.100,4
```

**`correlation_top_attackers.csv`** — IPs with most correlations
```
Source IP,Correlation Count
192.168.1.100,3
10.0.0.50,1
```

**`harvested_rules_effectiveness.csv`** — Rule performance metrics
```
Rule Name,Type,Severity,Base Confidence,Successful Detections,Failed Detections,Total,Success Rate
HARVESTED-SQL_INJECTION-1,sql_injection,critical,0.85,5,0,5,100.00%
HARVESTED-XSS-2,xss,high,0.80,3,1,4,75.00%
```

**`discovered_services.csv`** — All discovered endpoints
```
IP Address,Port,Service Type
192.168.1.100,8080,http
192.168.1.100,3306,sql
192.168.1.200,80,http
```

**`scan_vulnerabilities.csv`** — Vulnerabilities found
```
Endpoint,Injection Type,Payload (truncated),Severity
192.168.1.100:8080,xss,<script>alert('xss')</script>,high
192.168.1.200:80,sql_injection,' UNION SELECT * FROM users--,critical
```

---

## Workflow Example: Complete Testing Session

### Setup (Terminal 1)
```bash
cd "Network Guardian"

# Start web dashboard
python _start_dashboard.py
```

### Monitoring (Terminal 2)
```bash
cd "Network Guardian"

# Start live monitoring
python monitor_data.py monitor --interval 5
```

### Testing (Terminal 3)
```bash
cd "Network Guardian"

# Run test scenario 1 (SQL injection)
python -c "
import asyncio
from network_guardian.agent.smart_firewall_agent import SmartFirewallAgent

agent = SmartFirewallAgent(ips=None, auto_block=False)

# Test multiple payloads
payloads = [
    \"' UNION SELECT username, password FROM users--\",
    \"' OR 1=1--\",
    \"'; DROP TABLE users;--\"
]

for payload in payloads:
    detections = asyncio.run(agent.scan_payload(
        payload,
        source_ip='192.168.1.100'
    ))
    print(f'Payload: {payload[:30]}... → {len(detections)} detections')
"

# Run scenario 2 (attack correlation)
python -c "
from network_guardian.agent.probe_attack_correlator import ProbeAttackCorrelator

correlator = ProbeAttackCorrelator()

# Simulate probe discovery
correlator.register_discovery(
    ip='192.168.1.50',
    port=8080,
    service_type='http'
)

# Simulate attack on discovered endpoint
from datetime import datetime, timezone
was_discovered, score = correlator.correlate_attack(
    source_ip='10.0.0.100',
    target_ip='192.168.1.50',
    target_port=8080,
    injection_type='sql_injection',
    detection_time=datetime.now(timezone.utc).isoformat()
)

print(f'Attack correlated: {was_discovered}, Score: {score:.2f}')
"

# Watch terminal 2 update in real-time
```

### Analysis (Terminal 3, after testing)
```bash
# Show current status
python monitor_data.py status

# Show aggregated statistics
python monitor_data.py stats

# Export all data to CSV/JSON
python export_test_data.py

# View generated reports
ls -lh export/
cat export/SUMMARY.json
```

---

## Data Persistence Locations

All data is automatically persisted to `~/.network_guardian/`:

```
~/.network_guardian/
├── smart_firewall/
│   └── injection_history.json          # Blocked events per IP
├── attack_correlator/
│   ├── discoveries.json                # Discovered services
│   └── correlations.json               # Correlation events
├── payload_harvester/
│   └── harvested_rules.json            # Created detection rules
├── defensive_scanner/
│   └── scan_results.json               # Scan results & vulnerabilities
└── metrics/
    └── metrics_history.json            # Historical metrics snapshots
```

---

## Interpreting the Data

### Firewall Statistics

**High event count** = Many injection attempts detected
- Good indicator that firewall is actively detecting attacks
- Higher if running penetration test scenarios

**Blocked IP count** = Number of unique attacking IPs
- Shows diversity of attacks
- Helps identify attackers vs. legitimate scanners

### Correlation Analysis

**High-confidence correlations** = Attacks on discovered endpoints
- Indicates probe found vulnerable services
- Attacker successfully targeted probe-discovered endpoints

**Correlation score breakdown:**
- **0.85+** = Exact IP/port match (high confidence)
- **0.50–0.75** = IP match, different port (medium confidence)
- **<0.50** = Blind attack (attacker didn't know about endpoint)

### Harvested Rules

**High success rate** = Rule is catching similar payloads effectively
- Rules with 100% detection rate are most valuable
- Rules with 50%+ success should be kept

**Confidence scores:**
- **0.90+** = Very reliable (command injection, XXE)
- **0.80–0.90** = Reliable (SQL, SOAP)
- **0.70–0.80** = Good (XSS, Path Traversal)

### Defensive Scanning

**Vulnerabilities found** = Internal endpoints that are exploitable
- Should trigger remediation workflows
- Re-scan after patching to verify fixes

**False positive rate**:
- **<3%** = Excellent (can trust findings)
- **3–5%** = Good (occasional false positives)
- **>5%** = Needs tuning

---

## Advanced Usage

### Continuous Monitoring During Long Tests

Run monitor in background and redirect output to file:

```bash
python monitor_data.py monitor --interval 10 > monitoring.log 2>&1 &
```

### Export Data at Intervals

Periodically export data to track progress:

```bash
for i in {1..10}; do
  echo "=== Export Run $i ==="
  python export_test_data.py
  sleep 300  # Wait 5 minutes
done
```

### Analyze Metrics Over Time

```bash
# Export metrics and open in spreadsheet application
python monitor_data.py export
open ~/.network_guardian/metrics/metrics_export.csv
```

### Compare Test Runs

Save exports with timestamps:

```bash
mkdir -p test_results
python export_test_data.py
mv export/* test_results/run_$(date +%Y%m%d_%H%M%S)/
```

---

## Troubleshooting

### No data collected

**Problem**: Scripts show empty statistics

**Solution**:
1. Verify data files exist: `ls ~/.network_guardian/*/`
2. Run at least one test scenario to generate data
3. Check data format: `cat ~/.network_guardian/smart_firewall/injection_history.json`

### Metrics not updating

**Problem**: Monitor shows same values repeatedly

**Solution**:
1. Verify tests are running in another terminal
2. Check export directory exists: `mkdir -p ~/export`
3. Run test scenario while monitor is active

### Export fails with JSON error

**Problem**: "JSONDecodeError" in export script

**Solution**:
1. Data file may be corrupted
2. Delete corrupted file: `rm ~/.network_guardian/*/data.json`
3. Re-run test to regenerate

---

## Next Steps

1. **During Testing**: Use `monitor_data.py monitor` to watch metrics in real-time
2. **After Testing**: Use `export_test_data.py` to generate comprehensive reports
3. **Analyze Results**: Open CSV files in spreadsheet app for visualization
4. **Share Findings**: Use SUMMARY.json + CSV files in reports

---

## Support

For issues:
1. Check troubleshooting section above
2. Verify test data exists in `~/.network_guardian/`
3. Run `python monitor_data.py status` to confirm collection works
4. Review generated CSV files for anomalies

---

## Data Management & Retention

### Where Data is Stored (All Local)

```
~/.network_guardian/
├── smart_firewall/
│   └── injection_history.json          # Your machine only
├── attack_correlator/
│   ├── discoveries.json
│   └── correlations.json
├── payload_harvester/
│   └── harvested_rules.json
├── defensive_scanner/
│   └── scan_results.json
├── metrics/
│   └── metrics_history.json
└── [other local data]

./export/                               # Current directory only
├── SUMMARY.json
├── firewall_stats.json
├── *.csv files
└── [other local reports]
```

### Controlling Data Retention

**View what data exists:**
```bash
du -sh ~/.network_guardian/
ls -lh ./export/
```

**Delete test data (keep application):**
```bash
# Delete only collected metrics (keeps rules/discoveries)
rm ~/.network_guardian/metrics/metrics_history.json

# Delete specific component data
rm ~/.network_guardian/smart_firewall/injection_history.json
rm ~/.network_guardian/attack_correlator/*.json
rm ~/.network_guardian/payload_harvester/harvested_rules.json
```

**Complete clean slate (delete all data):**
```bash
# ⚠️  This removes ALL collected data but not the app itself
rm -rf ~/.network_guardian/
```

**Delete exported reports:**
```bash
# Remove CSV/JSON exports from current directory
rm -rf ./export/
```

### Data Backup

**Back up your collected test data:**
```bash
# Copy to external drive or archive
cp -r ~/.network_guardian/ /Volumes/ExternalDrive/ng_backup_2026-05-28/
tar -czf ng_backup_2026-05-28.tar.gz ~/.network_guardian/
```

### Privacy Best Practices

1. **Do not share raw JSON files** - they contain full payload/correlation data
   - Instead: Export CSV summaries for analysis
   - Or: Use SUMMARY.json which is aggregated

2. **Sanitize before sharing reports** - remove IP addresses if needed
   ```bash
   sed 's/192\.168\.[0-9]\+\.[0-9]\+/[REDACTED_IP]/g' exported_file.csv
   ```

3. **Encrypt sensitive reports**
   ```bash
   gpg --symmetric export/SUMMARY.json
   ```

4. **Delete metrics after each test** if running on shared machine
   ```bash
   rm ~/.network_guardian/metrics/metrics_history.json
   ```

---

## Support

For issues:
1. Check troubleshooting section above
2. Verify test data exists in `~/.network_guardian/`
3. Run `python monitor_data.py status` to confirm collection works
4. Review generated CSV files for anomalies

