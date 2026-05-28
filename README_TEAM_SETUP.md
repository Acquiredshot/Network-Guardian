# Network Guardian — Team Setup & Deployment Guide

**Cross-Platform | Ready for Windows, macOS, Linux**

## 🚀 Quick Start (Pick Your OS)

### Windows
**Easiest way - Just double-click:** `START_ALL.bat`

Or from Command Prompt:
```cmd
cd Network Guardian
python start_all.py
```

Or from PowerShell:
```powershell
cd "Network Guardian"
.\Start-All.ps1
```

### macOS
```bash
cd "Network Guardian"
python3 start_all.py
```

### Linux
```bash
cd "Network Guardian"
python3 start_all.py
```

---

## ✅ Before You Run: System Verification

Run this once to verify your system is ready:

```bash
python3 verify_system.py     # macOS/Linux
python verify_system.py       # Windows
```

This checks:
- ✓ Python 3.9+ installed
- ✓ Port 8080 available
- ✓ All required files present
- ✓ Network Guardian module available

---

## 📊 What Starts

Running `start_all.py` starts:

1. **Dashboard** — Web interface at http://127.0.0.1:8080
2. **Local Probe** — Registers your machine on the fleet map
3. **All Monitoring** — Real-time system metrics & detection

---

## 🔑 Default Credentials

```
Username: admin
Password: <password>
```

---

## 📍 Access the Application

After startup (takes ~5 seconds):

**Open in browser:** http://127.0.0.1:8080

### Dashboard Features

| Page | Purpose |
|------|---------|
| **Dashboard** | Real-time system status & metrics |
| **Fleet** | Your machine registration (updates every 30s) |
| **IDS** | Intrusion Detection System alerts |
| **IPS** | Intrusion Prevention System blocks |
| **WiFi** | WiFi network discovery & analysis |
| **Explorer** | Network topology & host mapping |
| **Auditor** | Security findings & vulnerabilities |
| **AI Engine** | Anomaly detection & forecasting |

---

## 🎯 Team Deployment

### Each Team Member Does This:

1. **Clone/pull repository** to their machine
2. **Verify system:** `python verify_system.py` (or `python3`)
3. **Start application:** `python start_all.py` (or use `.bat` on Windows)
4. **Open dashboard:** http://127.0.0.1:8080
5. **Login:** admin / <password>

### Result

Each team member has:
- ✓ Local dashboard running on their machine
- ✓ Their machine registered on their local fleet map
- ✓ Real-time monitoring of their system
- ✓ Network intelligence & threat detection

**No central server needed** — each dashboard is independent and local.

---

## ⏹️ Stopping the Application

Press **Ctrl+C** in the terminal where the application is running.

---

## 🔧 Troubleshooting

### "Port 8080 already in use"

**Windows:**
```cmd
netstat -ano | findstr :8080
taskkill /PID <PID> /F
```

**macOS/Linux:**
```bash
lsof -i :8080
kill -9 <PID>
```

Then restart the application.

### "Python not found"

Ensure Python 3.9+ is installed and in your PATH:
```bash
python --version        # Windows
python3 --version       # macOS/Linux
```

Should show: `Python 3.9.x` or higher

### "Module not found"

Make sure you're in the **Network Guardian** directory:
```bash
cd "Network Guardian"  # Go to project directory
python start_all.py
```

### "Dashboard won't load"

- Clear browser cache (Ctrl+Shift+Del or Cmd+Shift+Del)
- Try private/incognito mode
- Try a different browser
- Verify: http://127.0.0.1:8080 returns a response

---

## 📂 File Structure

```
Network Guardian/
├── start_all.py                    # Main startup (Python)
├── START_ALL.bat                   # Main startup (Windows batch)
├── Start-All.ps1                   # Main startup (PowerShell)
├── start_dashboard.py              # Dashboard server
├── run_local_probe.py              # Machine fleet registration
├── verify_system.py                # System verification
├── CROSS_PLATFORM_SETUP.md         # Detailed setup guide
├── LOCAL_STARTUP.md                # Local running guide
└── network_guardian/               # Core application
    ├── core/
    ├── agent/
    ├── interface/
    └── ...
```

---

## 💾 Data Storage

Configuration and state stored in:

**macOS/Linux:** `~/.network_guardian/`  
**Windows:** `%USERPROFILE%\.network_guardian\`

Contents:
- `fleet.json` — Machine registration & configuration
- `wolfpak_team.json` — User credentials
- `smart_firewall/` — Firewall rules
- `payload_harvester/` — Detection rules
- `metrics/` — Performance data

**Data persists across restarts** — your configuration is preserved.

---

## 🌐 Network Notes

### Local Testing
Just run the app on your machine — everything works locally with no network needed.

### LAN Access (Optional)
Your dashboard is accessible from other machines on the network:
- Replace `127.0.0.1` with your machine's IP
- Example: `http://192.168.1.100:8080`

### Security Note
Default credentials are for **local testing only**. For production:
- Change passwords in `~/.network_guardian/wolfpak_team.json`
- Use proper network isolation if exposing over LAN

---

## 📋 Platform-Specific Quick Reference

### Windows
| Task | Command |
|------|---------|
| Easiest | Double-click `START_ALL.bat` |
| Command Prompt | `python start_all.py` |
| PowerShell | `.\Start-All.ps1` |
| Verify System | `python verify_system.py` |

### macOS
| Task | Command |
|------|---------|
| Start App | `python3 start_all.py` |
| Verify System | `python3 verify_system.py` |
| Check Port | `lsof -i :8080` |
| Kill Process | `kill -9 <PID>` |

### Linux
| Task | Command |
|------|---------|
| Start App | `python3 start_all.py` |
| Verify System | `python3 verify_system.py` |
| Check Port | `netstat -tulpn \| grep 8080` |
| Kill Process | `kill -9 <PID>` |

---

## ✨ Key Features

- ✅ **Cross-Platform** — Works on Windows, macOS, Linux
- ✅ **Self-Contained** — No external services needed
- ✅ **One-Command Startup** — Everything in one script
- ✅ **Auto-Restart** — Probes restart if they crash
- ✅ **Real-Time Monitoring** — Live metrics & alerts
- ✅ **Persistent Data** — Configuration survives restarts
- ✅ **No Central Server** — Each machine is independent

---

## 🎓 Getting Help

If something doesn't work:

1. **Run verification:** `python verify_system.py` (or `python3`)
2. **Check logs:** Look at terminal output for error messages
3. **Restart:** Ctrl+C then run again
4. **Reinstall:** Make sure you have the latest files from the repo

---

## 📞 Support Resources

- **CROSS_PLATFORM_SETUP.md** — Detailed setup for each OS
- **LOCAL_STARTUP.md** — Local running guide with troubleshooting
- **verify_system.py** — Automated system checks

---

## 🎯 Next Steps

1. **Clone repository** to your machine
2. **Run:** `python verify_system.py` to check system
3. **Start:** `python start_all.py` (or `.bat` on Windows)
4. **Open:** http://127.0.0.1:8080
5. **Login:** admin / <password>
6. **Explore:** Try different dashboard pages

---

**Ready to deploy!** Clone the repo and run `start_all.py` on any team member's machine.
