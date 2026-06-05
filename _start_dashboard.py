# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
#!/usr/bin/env python3
"""Standalone dashboard launcher — no interactive CLI."""
import asyncio
import os
import sys
import signal

sys.path.insert(0, ".")

from network_guardian.config import Config
from network_guardian.core.engine import Engine
from network_guardian.saas import SaaSService
from network_guardian.utils.logging import setup_logging


def _saas_bind_host() -> str:
    host = os.environ.get("HOST")
    if host:
        return host
    return "0.0.0.0" if os.environ.get("DYNO") or os.environ.get("PORT") else "127.0.0.1"


async def main() -> None:
    config = Config.load(None)
    setup_logging("INFO")

    if config.saas.mode == "saas":
        service = SaaSService(
            config,
            host=_saas_bind_host(),
            port=int(os.environ.get("PORT", 8080)),
        )
        await service.run_forever()
        return

    engine = Engine(config)
    await engine.start()

    dash = engine.dashboard
    dash.host = os.environ.get("HOST", "127.0.0.1")
    dash.port = int(os.environ.get("PORT", 8080))
    await dash.start()

    # Start IDS and IPS automatically
    await engine.ids.start()
    await engine.ips.start()

    print(
        f"Dashboard: http://127.0.0.1:{dash.port}  (login: admin / <password>)",
        flush=True,
    )
    print("Press Ctrl+C to stop.", flush=True)

    stop_event = asyncio.Event()

    def _sig(*_):
        stop_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _sig)
        except NotImplementedError:
            # Windows event loops do not support add_signal_handler.
            signal.signal(sig, lambda *_: stop_event.set())

    await stop_event.wait()
    await engine.stop()


if __name__ == "__main__":
    asyncio.run(main())
