#!/usr/bin/env bash
# =============================================================
#  Network Guardian — USB Auto-Setup (macOS / Linux)
#  WOLFPAK INTERNAL USE ONLY — AUTHORIZED PERSONNEL ONLY
# =============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_DIR="$HOME/.ng_agent"
VENV_DIR="$AGENT_DIR/venv"

# Configuration (set by build script or edit manually)
BASE_URL="${NG_BASE_URL:-__BASE_URL__}"
FLEET_KEY="${NG_FLEET_KEY:-__FLEET_KEY__}"
INTERVAL="${NG_INTERVAL:-60}"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║       NETWORK GUARDIAN — FIELD AGENT SETUP       ║"
echo "║              WOLFPAK INTERNAL ONLY               ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Check for Python 3.11+
PYTHON=""
for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [[ "$major" -ge 3 && "$minor" -ge 11 ]]; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    echo "  ERROR: Python 3.11+ is required but not found."
    echo "  Install Python from https://python.org/downloads/"
    exit 1
fi

echo "  Python: $($PYTHON --version)"
echo "  Base:   $BASE_URL"
echo ""

# Create agent directory
mkdir -p "$AGENT_DIR"

# Copy probe module
cp "$SCRIPT_DIR/probe.py" "$AGENT_DIR/probe.py"

# Wolfpak authentication (required on first setup)
echo "  Authenticating with Wolfpak base station..."
$PYTHON "$AGENT_DIR/probe.py" --base "$BASE_URL" --key "$FLEET_KEY" --once --no-discovery 2>/dev/null || true

# Install as auto-start service
echo ""
echo "  Installing auto-start service..."
OS="$(uname -s)"
if [[ "$OS" == "Darwin" ]]; then
    # macOS: LaunchAgent
    PLIST_DIR="$HOME/Library/LaunchAgents"
    PLIST_FILE="$PLIST_DIR/com.wolfpak.ng-probe.plist"
    mkdir -p "$PLIST_DIR"
    LOG_DIR="$AGENT_DIR/logs"
    mkdir -p "$LOG_DIR"

    cat > "$PLIST_FILE" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.wolfpak.ng-probe</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON</string>
        <string>$AGENT_DIR/probe.py</string>
        <string>--base</string>
        <string>$BASE_URL</string>
        <string>--key</string>
        <string>$FLEET_KEY</string>
        <string>--interval</string>
        <string>$INTERVAL</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$LOG_DIR/ng-probe.out.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_DIR/ng-probe.err.log</string>
    <key>ThrottleInterval</key>
    <integer>30</integer>
</dict>
</plist>
PLIST

    launchctl unload "$PLIST_FILE" 2>/dev/null || true
    launchctl load -w "$PLIST_FILE"
    echo "  [OK] macOS LaunchAgent installed — agent starts on login"

elif [[ "$OS" == "Linux" ]]; then
    # Linux: systemd user service
    SERVICE_DIR="$HOME/.config/systemd/user"
    mkdir -p "$SERVICE_DIR"

    cat > "$SERVICE_DIR/ng-probe.service" << SERVICE
[Unit]
Description=Network Guardian Field Agent (Wolfpak)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PYTHON $AGENT_DIR/probe.py --base $BASE_URL --key $FLEET_KEY --interval $INTERVAL
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
SERVICE

    systemctl --user daemon-reload
    systemctl --user enable --now ng-probe.service
    echo "  [OK] systemd service installed — agent starts on login"
fi

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║           SETUP COMPLETE — AGENT ACTIVE          ║"
echo "║                                                  ║"
echo "║  The agent is now monitoring this network and    ║"
echo "║  reporting to the Wolfpak base station.          ║"
echo "║                                                  ║"
echo "║  It will auto-start every time you log in.       ║"
echo "║                                                  ║"
echo "║  To uninstall:                                   ║"
echo "║    $PYTHON $AGENT_DIR/probe.py --uninstall       ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
