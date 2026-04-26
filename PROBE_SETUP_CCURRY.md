# Network Guardian Field Agent — Setup for C.Curry

Welcome to the Wolfpak. Follow these steps to get your probe running and reporting live to base.

---

## What you need

- Python 3.11 or newer (comes pre-installed on most Macs/Linux)
- The file: `ng_probe_standalone.py`
- Your Wolfpak credentials (below)

---

## Your credentials

| Field       | Value             |
|-------------|-------------------|
| Username    | `C.Curry`                      |
| Password    | *(provided separately)*        |
| Role        | `operator`                     |

> **Change your password** after your first login on the dashboard.

> **Security note:** Your password is provided separately and should not be stored in plain text or shared over unencrypted channels.

---

## Step 1 — Get the probe file

You should have received `ng_probe_standalone.py`. Save it anywhere on your machine (e.g. your Desktop or Downloads folder).

---

## Step 2 — Run the probe

Open a terminal and run:

```bash
python3 ng_probe_standalone.py
```

**First run only:** You'll be prompted for your username and password. Enter the credentials above. Your auth token is then cached for 30 days — you won't be asked again.

You'll see something like:
```
╔══════════════════════════════════════════════════╗
║   🛡  NETWORK GUARDIAN — Field Agent (Wolfpak)  ║
╚══════════════════════════════════════════════════╝

  Operator : C.Curry
  Role     : operator
  Base     : https://network-guardian-cc8900c70290.herokuapp.com
  Interval : every 60s

  📡 Phoning home every 60s
  📊 Live fleet feed: https://network-guardian-cc8900c70290.herokuapp.com/fleet

  [14:23:01] Report ✓ sent | WiFi: 8 | Hosts: 14 | Threats: 0
```

Your agent is now registered and phoning home to base every 60 seconds.

---

## Step 3 — Watch it live on the dashboard

Open a browser and go to:

**https://network-guardian-cc8900c70290.herokuapp.com**

Log in with your Wolfpak credentials. Then click **Fleet** in the nav bar.

You'll see your agent appear in the **Live Fleet Feed** in real time — your hostname, IP, WiFi networks, discovered hosts, system metrics, and any threat alerts.

---

## Install as a background service (optional — runs forever)

If you want the agent to run automatically in the background and survive reboots:

```bash
python3 ng_probe_standalone.py --install
```

This will:
- **macOS** — install a LaunchAgent (auto-starts on login, runs silently)
- **Linux** — install a systemd user service
- **Windows** — install a scheduled task (runs on login)

To stop and remove the background service:
```bash
python3 ng_probe_standalone.py --uninstall
```

---

## Useful options

| Command | What it does |
|---------|--------------|
| `python3 ng_probe_standalone.py` | Run interactively (Ctrl+C to stop) |
| `python3 ng_probe_standalone.py --once` | Send one report, then exit |
| `python3 ng_probe_standalone.py --no-discovery` | Skip host sweep (faster, less noisy) |
| `python3 ng_probe_standalone.py --install` | Install as background service |
| `python3 ng_probe_standalone.py --uninstall` | Remove background service |
| `python3 ng_probe_standalone.py --deauth` | Clear your cached auth token |

---

## Dashboard URL

**https://network-guardian-cc8900c70290.herokuapp.com**

- **Fleet page** — live feed of all active agents
- **AI Engine** — anomaly scores and threat forecasting
- **IDS/IPS** — intrusion detection events

---

## Need help?

Contact your Wolfpak administrator.

---

*Wolf-Pak Innovations LLC — Authorized members only. Probe traffic is HMAC-signed and encrypted in transit (HTTPS). Your credentials are stored locally in `~/.ng_agent/` with chmod 600.*
