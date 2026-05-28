# Network Guardian — Deployment & Testing Guide

Complete guide to deploying and running Network Guardian on your machine for testing and data gathering.

---

## Pre-Deployment Checklist

### System Requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| **Python** | 3.11 | 3.11+ (up to 3.13) |
| **OS** | macOS / Linux / Windows | macOS / Linux (native; Windows via WSL2) |
| **RAM** | 2GB | 4GB+ |
| **Disk** | 500MB | 2GB (for logs, reports, SQLite DB) |
| **Network** | Loopback (127.0.0.1) | Local network access for full testing |

### Internet Requirements

- **OpenRouter API key** (optional) — needed only if testing Email Scanner v2 AI features
  - Sign up free at https://openrouter.ai
  - Get free tier API key
  - Model: `gpt-oss-120b` (open-source)

---

## Step 1: Clone & Install

### 1a. Clone the repository

```bash
git clone https://github.com/Acquiredshot/Network-Guardian.git
cd "Network Guardian"
```

### 1b. Check Python version

```bash
python3 --version
# Output should be: Python 3.11.X or higher
```

### 1c. Install dependencies

```bash
# Install the application in development mode (recommended for testing)
pip install -e ".[dev]"

# If you need remote control features (Twilio, SMS, Discord):
# pip install -e ".[remote]"
```

This installs:
- Core: PyYAML, Requests, BeautifulSoup4, lxml
- Dev: pytest, pytest-asyncio, ruff

**Installation time**: ~2-5 minutes depending on network speed

---

## Step 2: Configuration

### 2a. Create `.env` file (Optional — only for Email Scanner v2)

If you want to test Email Scanner v2 with AI threat classification:

```bash
cp .env.example .env

# Edit .env and add your OpenRouter API key
# nano .env  (or use your preferred editor)
```

If you **skip this step**, the application will still work — Email Scanner will just use SpamAssassin + ClamAV without AI analysis.

### 2b. Optional: Install external tools

#### Email Protection (optional)

If you want to test email scanning features:

**macOS:**
```bash
# SpamAssassin
brew install spamassassin

# ClamAV
brew install clamav
sudo freshclam  # Update virus definitions
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install spamassassin clamav

# Update virus definitions
sudo freshclam
```

**Windows (WSL2):**
```bash
wsl
sudo apt update && sudo apt install spamassassin clamav
sudo freshclam
```

#### Desktop GUI (optional)

If you want to test the native desktop firewall console:

```bash
pip install PyQt5
```

---

## Step 3: Run the Application

### Option A: Web Dashboard (Recommended for Testing)

**Starts**: Autonomous Smart Firewall agent + Web dashboard at http://127.0.0.1:8080

```bash
python _start_dashboard.py
```

Then open your browser:
```
http://127.0.0.1:8080
```

**What you'll see**:
- Fleet Map (currently empty until you add probes)
- Live IDS/IPS alert feed
- Smart Firewall injection detection stats
- AI Engine anomaly charts
- Threat reports

**Stop**: Press `Ctrl+C`

### Option B: Desktop GUI (Native PyQt5 Console)

**Requires**: PyQt5 installed

```bash
python -m network_guardian --desktop
```

**Features**:
- Live IDS alert feed with payload analysis
- One-click IP blocking
- Real-time blocked IPs panel
- Auto-respond toggle for IDS alerts

### Option C: Interactive CLI

**Starts**: Text-based interactive CLI with commands

```bash
network-guardian
```

**Available commands**:
```
> help
  status      — Show running subsystems
  audit       — Run network audit
  rules       — List IDS rules
  block       — Show blocked IPs
  history     — Show per-IP offense history
  firewall    — Smart Firewall stats
  quit        — Exit
```

### Option D: Standalone Smart Firewall Agent

**Test**: Injection detection without full engine

```bash
python -m network_guardian.agent.smart_firewall_agent
```

Prompts for SQL injection payload to test → shows detection result.

### Option E: Email Scanner (if dependencies installed)

**One-shot email scan:**
```bash
python -m network_guardian.agent.email_scanner
```

Prompts for:
- IMAP host (e.g., imap.gmail.com)
- Email address
- App-specific password (NOT your main password!)
- Mailbox (e.g., INBOX)
- Action mode (monitor / move_spam / delete_all)

### Option F: Run All Tests

**Verify**: Everything works correctly

```bash
pytest tests/ -v

# Run specific test suite (new v30 integration tests)
pytest tests/test_probe*.py tests/test_payload*.py -v
```

**Expected**: 66+ tests passing

---

## Step 4: Conduct Testing & Data Gathering

### Test Scenario 1: Injection Detection

**Goal**: Verify Smart Firewall blocks injection attempts

1. **Start web dashboard**:
   ```bash
   python _start_dashboard.py
   ```

2. **Open terminal in another window**:
   ```bash
   python -c "
   import asyncio
   from network_guardian.agent.smart_firewall_agent import SmartFirewallAgent
   
   agent = SmartFirewallAgent(ips=None, auto_block=False)
   
   # Test SQL injection
   detections = asyncio.run(agent.scan_payload(
       \"' UNION SELECT username, password FROM users--\",
       source_ip=\"192.168.1.100\"
   ))
   
   for d in detections:
       print(f'Detected: {d.injection_type.value} ({d.severity})')
   "
   ```

3. **Watch dashboard**: Events appear in real-time

### Test Scenario 2: Attack Correlation

**Goal**: Verify probe discoveries correlate with firewall blocks

1. **Register a discovery**:
   ```bash
   python -c "
   from network_guardian.agent.probe_attack_correlator import ProbeAttackCorrelator
   
   correlator = ProbeAttackCorrelator()
   correlator.register_discovery(
       ip='192.168.1.100',
       port=8080,
       service_type='http'
   )
   "
   ```

2. **Simulate attack on discovered endpoint**:
   ```bash
   python -c "
   from network_guardian.agent.probe_attack_correlator import ProbeAttackCorrelator
   from datetime import datetime, timezone
   
   correlator = ProbeAttackCorrelator()
   was_discovered, score = correlator.correlate_attack(
       source_ip='192.168.1.50',
       target_ip='192.168.1.100',
       target_port=8080,
       injection_type='sql_injection',
       detection_time=datetime.now(timezone.utc).isoformat()
   )
   
   print(f'Discovered: {was_discovered}, Correlation Score: {score:.2f}')
   "
   ```

3. **Expected**: Correlation score ~0.85 (high confidence)

### Test Scenario 3: Payload Harvesting

**Goal**: Verify harvested rules work

```bash
python -c "
from network_guardian.agent.payload_harvester import PayloadHarvester
from network_guardian.agent.smart_firewall_agent import SmartFirewallAgent
import asyncio

harvester = PayloadHarvester()

# Harvest a rule from SQL injection payload
rule = harvester.harvest_from_exploitation(
    payload=\"' UNION SELECT 1,2,3--\",
    vuln_type='sql_injection',
    source_ip='192.168.1.50',
    target_ip='192.168.1.100'
)

print(f'Harvested rule: {rule.name}')
print(f'Confidence: {rule.confidence:.2f}')

# Test that firewall detects similar payloads
agent = SmartFirewallAgent(ips=None, auto_block=False)
agent.add_dynamic_rule(rule)

detections = asyncio.run(agent.scan_payload(
    \"' UNION SELECT username, password FROM users--\",
    source_ip='192.168.1.50'
))

print(f'Detections: {len(detections)} (via harvested rule)')
"
```

### Test Scenario 4: Email Scanning (if tools installed)

**Goal**: Test email threat detection

```bash
python -m network_guardian.agent.email_scanner
# Follow prompts to connect to Gmail/Outlook/Yahoo account
# Select "monitor" mode (safe — doesn't delete)
# Watch for spam/malware verdicts
```

### Data Collection Points

During testing, data is collected to:

| Component | Storage Location | Data Collected |
|---|---|---|
| **Smart Firewall** | `~/.network_guardian/smart_firewall/injection_history.json` | Per-IP offense count, rules hit, timestamps |
| **Attack Correlator** | `~/.network_guardian/attack_correlator/` | Discovered services, correlation events, threat scores |
| **Payload Harvester** | `~/.network_guardian/payload_harvester/harvested_rules.json` | Harvested rules, success/failure rates |
| **Defensive Scanner** | `~/.network_guardian/defensive_scanner/scan_results.json` | Vulnerable endpoints, false-positive rate |
| **Email Scanner** | `network_guardian.db` (SQLite) | Scan results, AI classifications, actions taken |
| **IPS/IDS** | `~/.network_guardian/ips_blocks.json` | Blocked IPs, block reasons, durations |

---

## Potential Issues & Solutions

### Issue 1: Python version mismatch

**Error**: `Python 3.11+ required`

**Solution**:
```bash
# Check your Python version
python3 --version

# If you have multiple versions:
python3.11 --version

# Use specific version:
python3.11 -m pip install -e ".[dev]"
```

### Issue 2: pip install fails

**Error**: `pip: command not found` or permission denied

**Solution** (macOS/Linux):
```bash
# Use python3 -m pip instead
python3 -m pip install -e ".[dev]"

# Or with sudo if needed (NOT recommended):
# sudo python3 -m pip install -e ".[dev]"
```

### Issue 3: Port 8080 already in use

**Error**: `Address already in use`

**Solution**:
```bash
# Change port in _start_dashboard.py:
python _start_dashboard.py --port 9000

# Or find process using port 8080:
lsof -i :8080
kill -9 <PID>
```

### Issue 4: asyncio event loop errors

**Error**: `RuntimeError: Event loop is closed` or `no running event loop`

**Solution**: This is normal in testing. The code handles this automatically. If you see it repeatedly, try restarting the application.

### Issue 5: Email Scanner tool not found

**Error**: `spamc not found` or `clamscan not found`

**Solution**: 
- Email Scanner will skip that check and run with available tools
- If you want full email protection, install SpamAssassin + ClamAV (see Step 2b)
- For testing, this is OK — you can still test detection without these tools

### Issue 6: Low memory or slow performance

**Solution**:
- Close unnecessary applications
- Increase virtual memory (macOS: System Preferences > Memory; Linux: check swap)
- Use CLI mode instead of dashboard (lower memory footprint)

---

## Monitoring & Data Export

### View Live Stats

**CLI**:
```bash
python -c "
from pathlib import Path
import json

# View Smart Firewall history
history = Path.home() / '.network_guardian' / 'smart_firewall' / 'injection_history.json'
if history.exists():
    data = json.loads(history.read_text())
    for ip, events in data.items():
        print(f'{ip}: {len(events)} events')
"
```

**Dashboard**:
- Navigate to `/security` → Threat Detection page
- View real-time stats and PDF reports

### Export Data for Analysis

```bash
# Export all findings as JSON
cp ~/.network_guardian/*/\*.json ./export/

# Export email scanning results
sqlite3 network_guardian.db "SELECT * FROM email_scans LIMIT 100" > email_scans.csv
```

---

## Next Steps for Testing

1. **Start web dashboard** (simplest option)
   ```bash
   python _start_dashboard.py
   ```

2. **Run test scenarios** to generate data

3. **Check collected data** in `~/.network_guardian/`

4. **Monitor logs** for any errors

5. **Export data** for analysis

---

## Support

If you encounter issues:

1. Check this guide for your error message
2. Run full test suite: `pytest tests/ -v`
3. Check logs: `tail -f ~/.network_guardian/*.log` (if available)
4. Review code: issues are well-documented with inline comments

**Expected behavior**: All 66 tests pass, no data loss, graceful shutdown on `Ctrl+C`

---

## Performance Expectations

| Operation | Time | Data Generated |
|---|---|---|
| **Start dashboard** | 2–5 seconds | minimal |
| **Scan 1 payload** | 10–50ms | 1 detection record |
| **Email scan (50 msgs)** | 30–60 seconds | 50 records in SQLite |
| **Defensive scan (/24)** | 5 minutes | 20–50 endpoint results |
| **Full test suite** | 1 minute | test logs |

---

## You're Ready to Deploy! 🚀

Run this command to get started:

```bash
python _start_dashboard.py
```

Then visit: **http://127.0.0.1:8080**

Happy testing!
