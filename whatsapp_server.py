"""
WhatsApp Test Server for Network Guardian.

Starts a local HTTP server that receives Twilio WhatsApp webhooks
and routes them through the Network Guardian engine.

=== SETUP GUIDE ===

1. Create a FREE Twilio account:
   https://www.twilio.com/try-twilio

2. Activate the WhatsApp Sandbox:
   - Go to: https://console.twilio.com/us1/develop/sms/try-it-out/whatsapp-learn
   - Follow the instructions to join the sandbox
   - Send the join code from YOUR phone's WhatsApp to the Twilio sandbox number
   - (Usually: send "join <word>-<word>" to +1 415 523 8886)

3. Get your credentials from Twilio Console -> Account Info:
   - Account SID   (starts with AC...)
   - Auth Token

4. Expose this server to the internet (Twilio needs to reach it):

   Option A — ngrok (recommended for testing):
     ngrok http 8765
     -> Copy the https://xxxx.ngrok-free.app URL

   Option B — Cloudflare Tunnel:
     cloudflared tunnel --url http://localhost:8765

5. Configure the webhook URL in Twilio:
   - Go to: WhatsApp Sandbox Settings
   - Set "WHEN A MESSAGE COMES IN" to:
     https://xxxx.ngrok-free.app/whatsapp
   - Method: POST

6. Run this server:
     python whatsapp_server.py

7. Send a message from your phone's WhatsApp to the sandbox number!
   Try: "ping", "status", "help", "ids status", "ids rules"

=== ENVIRONMENT VARIABLES ===

  TWILIO_ACCOUNT_SID    Your Twilio Account SID
  TWILIO_AUTH_TOKEN      Your Twilio Auth Token
  TWILIO_WHATSAPP_FROM   Sandbox number (default: whatsapp:+14155238886)
  WEBHOOK_SECRET         Optional HMAC secret for webhook verification
  ALLOWED_NUMBERS        Comma-separated phone numbers to allow (e.g. +12025551234)
  HOST                   Bind address (default: 0.0.0.0)
  PORT                   Bind port (default: 8765)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
from threading import Thread

# Ensure the package is importable
sys.path.insert(0, os.path.dirname(__file__))

from network_guardian.config import Config
from network_guardian.core.engine import Engine
from network_guardian.remote import (
    ChannelType,
    PermissionLevel,
    RemoteAccessManager,
    RemoteConfig,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("whatsapp_server")

# ── Configuration ─────────────────────────────────────────────────

ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID", "")
AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "")
FROM_NUMBER = os.environ.get("TWILIO_WHATSAPP_FROM", "whatsapp:+14155238886")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "network-guardian-test")
ALLOWED_NUMBERS = [
    n.strip() for n in os.environ.get("ALLOWED_NUMBERS", "").split(",") if n.strip()
]
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8765"))

# ── Engine setup ──────────────────────────────────────────────────

engine = Engine(Config())
remote_mgr = RemoteAccessManager(engine, RemoteConfig(
    max_output_length=1600,  # WhatsApp has ~1600 char limit per msg
))

# Set up the WhatsApp channel
whatsapp = remote_mgr.setup_whatsapp(
    account_sid=ACCOUNT_SID,
    auth_token=AUTH_TOKEN,
    from_number=FROM_NUMBER,
    webhook_secret=WEBHOOK_SECRET,
)

# Add allowed users
if ALLOWED_NUMBERS:
    for number in ALLOWED_NUMBERS:
        remote_mgr.permissions.add_user(
            number, ChannelType.WHATSAPP, PermissionLevel.ADMIN,
        )
        logger.info("Allowed WhatsApp user: %s", number)
else:
    # For testing: allow all numbers by adding a wildcard-like approach
    # In production, always configure specific allowed numbers!
    logger.warning(
        "No ALLOWED_NUMBERS set. The server will deny all messages. "
        "Set ALLOWED_NUMBERS=+1XXXXXXXXXX to allow your phone."
    )

# ── Async event loop in background thread ─────────────────────────

_loop = asyncio.new_event_loop()


def _start_loop(loop: asyncio.AbstractEventLoop) -> None:
    asyncio.set_event_loop(loop)
    loop.run_forever()


_thread = Thread(target=_start_loop, args=(_loop,), daemon=True)
_thread.start()


def run_async(coro):
    """Run an async coroutine from sync code."""
    future = asyncio.run_coroutine_threadsafe(coro, _loop)
    return future.result(timeout=30)


# ── HTTP Handler ──────────────────────────────────────────────────

class WhatsAppWebhookHandler(BaseHTTPRequestHandler):
    """Handles inbound Twilio WhatsApp webhook POST requests."""

    def do_GET(self):
        """Health check endpoint."""
        if self.path == "/health":
            self._respond(200, "application/json", json.dumps({
                "status": "ok",
                "service": "Network Guardian WhatsApp Server",
                "channels": 1,
                "users": remote_mgr.permissions.user_count,
            }))
        else:
            self._respond(200, "text/html", (
                "<h2>Network Guardian WhatsApp Server</h2>"
                "<p>POST to <code>/whatsapp</code> for Twilio webhooks.</p>"
                "<p>GET <code>/health</code> for health check.</p>"
            ))

    def do_POST(self):
        """Process inbound WhatsApp messages from Twilio."""
        if self.path != "/whatsapp":
            self._respond(404, "text/plain", "Not found")
            return

        # Read and parse the POST body
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length).decode("utf-8")

        # Parse URL-encoded form data (Twilio sends application/x-www-form-urlencoded)
        form_data = {}
        for key, values in parse_qs(raw_body).items():
            form_data[key] = values[0] if values else ""

        sender = form_data.get("From", "unknown")
        body = form_data.get("Body", "")
        logger.info("Incoming message from %s: %s", sender, body[:100])

        # Process through the WhatsApp channel
        try:
            twiml_response = run_async(whatsapp.handle_webhook(form_data))
        except Exception as e:
            logger.exception("Error processing message")
            twiml_response = (
                "<Response><Message>Internal error. Please try again.</Message></Response>"
            )

        logger.info("Reply to %s: %s", sender, twiml_response[:200])

        # Return TwiML response
        self._respond(200, "text/xml", twiml_response)

    def _respond(self, status: int, content_type: str, body: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        encoded = body.encode("utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        """Suppress default access logs; we use our own logger."""
        logger.debug(format, *args)


# ── Main ──────────────────────────────────────────────────────────

def main():
    print()
    print("=" * 60)
    print("  Network Guardian — WhatsApp Server")
    print("=" * 60)
    print()

    if not ALLOWED_NUMBERS:
        print("  ⚠  No ALLOWED_NUMBERS configured!")
        print("     Set the environment variable to your phone number:")
        print()
        print('     $env:ALLOWED_NUMBERS = "+12025551234"')
        print()

    if not ACCOUNT_SID:
        print("  ℹ  No TWILIO_ACCOUNT_SID set (optional for sandbox testing)")
        print()

    print(f"  Listening on http://{HOST}:{PORT}")
    print(f"  Webhook URL: http://<your-public-url>/whatsapp")
    print()
    print("  Quick test with curl:")
    print(f'    curl -X POST http://localhost:{PORT}/whatsapp \\')
    print('      -d "From=whatsapp:+12025551234&Body=ping"')
    print()
    print("  Available commands: help, status, ping, ids status,")
    print("    ids rules, ids scan <text>, ips status, cloak status,")
    print("    sensors list, audit <target>, explore <subnet>")
    print()
    print("  Press Ctrl+C to stop.")
    print()

    server = HTTPServer((HOST, PORT), WhatsAppWebhookHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.server_close()


if __name__ == "__main__":
    main()
