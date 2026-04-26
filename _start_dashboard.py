#!/usr/bin/env python3
"""Standalone dashboard launcher — no interactive CLI."""
import asyncio
import sys
import signal

sys.path.insert(0, ".")

from network_guardian.config import Config
from network_guardian.core.engine import Engine
from network_guardian.utils.logging import setup_logging


async def main() -> None:
    config = Config.load(None)
    setup_logging("INFO")
    engine = Engine(config)
    await engine.start()

    import os
    dash = engine.dashboard
    dash.host = "0.0.0.0"
    dash.port = int(os.environ.get("PORT", 8080))
    await dash.start()

    # Start IDS and IPS automatically
    await engine.ids.start()
    await engine.ips.start()

    print(f"Dashboard: http://127.0.0.1:8080  (login: admin / <password>)", flush=True)
    print("Press Ctrl+C to stop.", flush=True)

    stop_event = asyncio.Event()

    def _sig(*_):
        stop_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _sig)

    await stop_event.wait()
    await engine.stop()


if __name__ == "__main__":
    asyncio.run(main())
