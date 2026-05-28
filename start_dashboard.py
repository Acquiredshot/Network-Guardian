#!/usr/bin/env python3
"""Start the dashboard server (cross-platform)."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from network_guardian.core.engine import Engine
from network_guardian.interface.dashboard import Dashboard

async def main():
    engine = Engine()
    dashboard = Dashboard(engine)
    await dashboard.start()
    if dashboard._server:
        await dashboard._server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nDashboard stopped")

