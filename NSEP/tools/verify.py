from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]


def run_command(command: list[str], *, check: bool = True) -> None:
    print(f"$ {' '.join(command)}")
    subprocess.run(command, cwd=ROOT, check=check)


def check_python_dependencies() -> None:
    modules = ["fastapi", "celery", "psycopg", "redis", "pydantic_settings"]
    for module in modules:
        __import__(module)


def check_secret_safety() -> None:
    ignore_file = ROOT / ".gitignore"
    ignored_entries = {
        line.strip()
        for line in ignore_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    if ".env" not in ignored_entries:
        raise RuntimeError(".env is not ignored by Git")

    patterns = (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"sk-[A-Za-z0-9]{20,}"),
        re.compile(r"-----BEGIN (?:RSA|OPENSSH|EC) PRIVATE KEY-----"),
    )
    ignored_dirs = {".git", ".venv", "__pycache__", ".pytest_cache", "security_event_pipeline.egg-info"}
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in ignored_dirs for part in path.parts):
            continue
        if path.name in {".env", "verify.py"}:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if any(pattern.search(content) for pattern in patterns):
            raise RuntimeError(f"Potential credential pattern found in {path.relative_to(ROOT)}")


def check_health(base_url: str) -> None:
    for path, expected in (("/api/health", 200), ("/api/readiness", 200)):
        with urlopen(f"{base_url}{path}", timeout=5) as response:
            if response.status != expected:
                raise RuntimeError(f"{path} returned HTTP {response.status}")
            json.loads(response.read())


def wait_for_health(base_url: str) -> None:
    deadline = time.monotonic() + 30
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            check_health(base_url)
            return
        except (OSError, URLError, RuntimeError, json.JSONDecodeError) as exc:
            last_error = exc
            time.sleep(1)
    raise RuntimeError(f"API health checks did not pass: {last_error}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the complete local developer verification suite.")
    parser.add_argument("--skip-live", action="store_true", help="Skip Docker and live API checks")
    args = parser.parse_args()

    compose_started = False
    try:
        print("[1/6] Python compilation")
        run_command([sys.executable, "-m", "compileall", "-q", "services", "migrations", "tools"])

        print("[2/6] Dependency imports")
        check_python_dependencies()

        print("[3/6] Tests")
        run_command([sys.executable, "-m", "pytest", "-q"])

        print("[4/6] Compose configuration")
        run_command(["docker", "compose", "config", "--quiet"])

        print("[5/6] Security checks")
        check_secret_safety()

        print("[6/6] Live health checks")
        if args.skip_live:
            print("Skipped by request: --skip-live")
        else:
            run_command(["docker", "compose", "up", "-d", "postgres", "rabbitmq", "redis"])
            compose_started = True
            run_command(["docker", "compose", "run", "--rm", "db-migrate"])
            run_command(["docker", "compose", "up", "-d", "ingestion-api", "security-workers"])
            wait_for_health("http://127.0.0.1:8000")

        print("Verification passed.")
        return 0
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"Verification failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if compose_started:
            subprocess.run(["docker", "compose", "down"], cwd=ROOT, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
