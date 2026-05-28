# Network Guardian — Cross-Platform Startup Guide

## 🚀 Quick Start (Any OS)

### macOS / Linux
```bash
cd "Network Guardian"
python3 start_all.py
```

### Windows (Command Prompt)
```cmd
cd "Network Guardian"
python start_all.py
```

### Windows (PowerShell)
```powershell
cd "Network Guardian"
.\Start-All.ps1
```

### Windows (Double-Click)
Just double-click **`START_ALL.bat`** in the folder!

---

## 📋 System Requirements

- **Python 3.9+** (installed and in PATH)
- **Port 8080** (must be available)
- Network access to localhost

### Check Python Installation

**macOS / Linux:**
```bash
python3 --version
```

**Windows:**
```cmd
python --version
```

Should show: `Python 3.9.x` or higher

---

## 🎯 What Starts

When you run any of these commands, the following starts automatically:

✅ **Dashboard** — Web interface at http://127.0.0.1:8080  
✅ **Local Probe** — Registers machine on fleet map  
✅ **All Monitoring** — Real-time system status  

---

## 🔑 Login Credentials

- **Username:** admin
- **Password:** <password>

---

## 📍 Access the Application

After startup, open a browser and go to:

```
http://127.0.0.1:8080
```

Login with the credentials above.

### Key Pages

- **Dashboard** — Real-time system status
- **Fleet** — Your machine registration (auto-updates every 30 seconds)
- **IDS** — Intrusion Detection alerts
- **IPS** — Intrusion Prevention blocks
- **WiFi** — Network scanning
- **Explorer** — Network topology
- **Auditor** — Security findings
- **AI Engine** — Anomaly detection

---

## ⏹️ Stopping the Application

Simply press **Ctrl+C** in the terminal/command prompt where you started it.

---

## 🔧 Individual Components (If Needed)

If you want to run components separately:

**Dashboard Only:**
```bash
python3 start_dashboard.py    # macOS/Linux
python start_dashboard.py      # Windows
```

**Probe Only:**
```bash
python3 run_local_probe.py    # macOS/Linux
python run_local_probe.py      # Windows
```

**Full System (with extra monitoring):**
```bash
python3 run_full_system.py    # macOS/Linux
python run_full_system.py      # Windows
```

---

## 🐛 Troubleshooting

### "Port 8080 already in use"

**macOS/Linux:**
```bash
lsof -i :8080
kill -9 <PID>
```

**Windows (Command Prompt):**
```cmd
netstat -ano | findstr :8080
taskkill /PID <PID> /F
```

**Windows (PowerShell):**
```powershell
Get-NetTCPConnection -LocalPort 8080
Stop-Process -Id <PID> -Force
```

Then restart: `python start_all.py`

### "Python not found" or "command not found"

Make sure Python 3.9+ is installed and added to your PATH.

**Test installation:**
```bash
python --version        # Windows
python3 --version       # macOS/Linux
```

### Probe not connecting

1. Ensure dashboard is running first (wait 3+ seconds)
2. Check file exists: `~/.network_guardian/fleet.json`
3. Verify credentials in terminal output
4. Restart: Ctrl+C then run `start_all.py` again

### Dashboard not loading

- Clear browser cache (Ctrl+Shift+Del or Cmd+Shift+Del)
- Try in private/incognito mode
- Try a different browser
- Restart the application

---

## 📂 Data Storage

All configuration and state is stored in:

```
~/.network_guardian/
├── fleet.json                  # Fleet configuration & agent registry
├── wolfpak_team.json          # User credentials
├── smart_firewall/            # Firewall rules & IP history
├── payload_harvester/         # Harvested detection rules
├── attack_correlator/         # Correlation data
├── probe_firewall_bridge/     # Bridge state
└── metrics/                   # Performance metrics
```

This persists across restarts, so your configuration is preserved.

---

## 🌐 Network & Deployment

### Local Testing
```bash
python start_all.py
```

### Team/Production Setup

1. Clone/pull repository to each machine
2. Ensure Python 3.9+ is installed
3. Run: `python start_all.py` (or batch file on Windows)
4. Access dashboard at `http://127.0.0.1:8080` on each machine
5. Each machine appears on its own fleet map at `http://its-ip:8080/fleet`

### Connect Multiple Machines

Each team member can run the application on their machine:
- All dashboards are local (no central server needed)
- Each machine has its own fleet map
- Run on the same network or different networks

---

## 📝 Platform-Specific Notes

### Windows

- Use **`START_ALL.bat`** for the easiest startup (just double-click!)
- Or use **PowerShell**: `.\Start-All.ps1`
- Or use **Command Prompt**: `python start_all.py`
- All three methods do the same thing

### macOS

- Make scripts executable (optional):
  ```bash
  chmod +x start_all.py
  ```
- Then run: `./start_all.py`
- Or just: `python3 start_all.py`

### Linux

- Same as macOS:
  ```bash
  chmod +x start_all.py
  python3 start_all.py
  ```

---

## ✅ Startup Checklist

- [ ] Python 3.9+ installed (`python --version` or `python3 --version`)
- [ ] Port 8080 is free (no other service using it)
- [ ] You're in the "Network Guardian" directory
- [ ] Run appropriate command for your OS
- [ ] Wait for "System Ready" message
- [ ] Open http://127.0.0.1:8080 in browser
- [ ] Login with admin / <password>

---

## 🎓 Getting Started

1. **Start the app:** Run `start_all.py` (or batch file on Windows)
2. **Open dashboard:** Go to http://127.0.0.1:8080
3. **Login:** Use admin / <password>
4. **Check fleet:** Dashboard → Fleet page (your machine should be listed as "online")
5. **Explore:** Try IDS, IPS, WiFi, Explorer pages

---

## 📞 Support

If you encounter issues:

1. **Check Python version:** `python --version` (need 3.9+)
2. **Check port:** Make sure 8080 is free
3. **Check directory:** Make sure you're in the Network Guardian folder
4. **Check logs:** Look at terminal output for error messages
5. **Restart:** Ctrl+C then run again

---

**Ready to go!** Just run the appropriate command for your operating system above.
