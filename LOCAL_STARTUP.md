# Network Guardian — Local Startup Guide

## Quick Start (One Command)

To run the entire application locally on your MacBook:

```bash
cd "/Users/codycodesit/Network Guardian"
python3 start_all.py
```

That's it! This will start:
- ✅ **Dashboard** — Web interface for monitoring
- ✅ **Local Probe** — Keeps your MacBook online on the fleet map
- ✅ **All monitoring services**

## Access the Dashboard

**URL:** http://127.0.0.1:8080  
**Login:** admin / <password>

### Dashboard Features

- **Dashboard** — Real-time system status
- **IDS** — Intrusion Detection System alerts
- **IPS** — Intrusion Prevention System blocks
- **WiFi** — WiFi network scanning
- **Fleet** — Your MacBook probe status (NG-608852BB)
- **Explorer** — Network topology visualization
- **Auditor** — Security findings
- **AI Engine** — Anomaly detection

## Your MacBook on Fleet Map

Your MacBook is automatically registered and will appear as:

- **Agent ID:** NG-608852BB
- **Name:** Cortezs-MacBook-Air.local
- **Status:** Online (updates every 30 seconds)
- **Location:** Dashboard → Fleet page

The probe runs continuously and will restart automatically if it crashes.

## Stopping Everything

Press **Ctrl+C** in the terminal where `start_all.py` is running to gracefully shut down all services.

## Individual Commands (If Needed)

If you want to run components separately:

```bash
# Just the dashboard
python3 start_dashboard.py

# Just the probe
python3 run_local_probe.py

# Full system (includes additional monitoring)
python3 run_full_system.py
```

## Credentials

- **Dashboard Login:** admin / <password>
- **Probe Auth:** Automatic (uses admin credentials)

## Troubleshooting

**Port 8080 already in use?**
```bash
lsof -i :8080
kill -9 <PID>
```

**Probe not connecting?**
- Check dashboard is running first
- Ensure fleet.json exists at ~/.network_guardian/fleet.json
- Check probe logs in terminal output

**Dashboard not loading?**
- Clear browser cache
- Try http://127.0.0.1:8080/fleet directly
- Restart: Ctrl+C then `python3 start_all.py` again

## File Locations

```
~/.network_guardian/
├── fleet.json              # Fleet configuration & agent registry
├── wolfpak_team.json       # User credentials
├── smart_firewall/         # Firewall rules & IP history
├── payload_harvester/      # Harvested detection rules
├── attack_correlator/      # Correlation data
├── probe_firewall_bridge/  # Bridge state
└── metrics/               # Performance metrics
```

## Data Persistence

All data is automatically saved to ~/.network_guardian/ so your fleet map and configuration persist across restarts.

---

**Ready to go!** Just run:
```bash
cd "/Users/codycodesit/Network Guardian" && python3 start_all.py
```
