"""Serve an isolated local dashboard without starting scanning or enforcement."""

import asyncio
import logging
import os
import secrets
from pathlib import Path


async def main() -> None:
    runtime = Path(__file__).resolve().parents[1] / ".local-runtime"
    runtime.mkdir(exist_ok=True)
    password_file = runtime / "admin_password.txt"
    if not password_file.exists():
        password_file.write_text("Local!" + secrets.token_hex(24), encoding="utf-8")
    os.environ["NG_BOOTSTRAP_ADMIN_PASSWORD"] = password_file.read_text(encoding="utf-8")
    os.environ["USERPROFILE"] = str(runtime)
    os.environ["HOME"] = str(runtime)
    os.environ.setdefault("NSEP_DASHBOARD_URL", "http://127.0.0.1:18000/dashboard")
    os.chdir(runtime)

    from network_guardian.config import Config
    from network_guardian.core.engine import Engine
    from network_guardian.interface.dashboard import Dashboard

    logging.basicConfig(level=logging.ERROR)
    engine = Engine(Config())
    dashboard = Dashboard(engine, host="127.0.0.1", port=18080)
    await dashboard.start()
    print("Local dashboard: http://127.0.0.1:18080/ (username: admin)", flush=True)
    print(f"Local password file: {password_file}", flush=True)
    print("Engine not started: no automatic scans or enforcement.", flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        await dashboard.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
