"""Read-only navigation audit plus one labeled synthetic incident handoff."""

import argparse
import json
import runpy
import sqlite3
import time
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import requests

ROOT = Path(__file__).resolve().parents[1]
GUARDIAN = ROOT.parent if (ROOT.parent / "network_guardian").is_dir() else ROOT.parent / "Network-Guardian"


class PageElements(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: set[str] = set()
        self.assets: set[str] = set()
        self.buttons = 0
        self.inline_handlers = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "a" and values.get("href"):
            self.links.add(values["href"])
        if tag in ("script", "img") and values.get("src"):
            self.assets.add(values["src"])
        if tag == "link" and values.get("href"):
            self.assets.add(values["href"])
        if tag == "button":
            self.buttons += 1
        if any(name.startswith("on") for name in values):
            self.inline_handlers += 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    nsep = "http://127.0.0.1:18000"
    guardian = "http://127.0.0.1:18080"
    session = requests.Session()
    login = session.post(
        guardian + "/api/auth/login",
        json={
            "username": "admin",
            "password": (GUARDIAN / ".local-runtime" / "admin_password.txt").read_text(encoding="utf-8"),
        },
        headers={"X-Requested-With": "XMLHttpRequest"},
        timeout=10,
    )
    login.raise_for_status()
    if not login.json().get("ok"):
        raise RuntimeError("Local Network Guardian authentication failed")
    report: dict = {"checked_at": datetime.now(UTC).isoformat(), "checks": [], "limitations": []}

    def get(url: str, expected: int = 200) -> requests.Response:
        response = session.get(url, timeout=10, allow_redirects=False)
        report["checks"].append({"url": url, "expected": expected, "actual": response.status_code, "passed": response.status_code == expected})
        return response

    pages_module = runpy.run_path(str(ROOT / "services" / "ingestion-api" / "app" / "pages.py"))
    paths = [(nsep, "/" + page.route) for page in pages_module["PAGES"]]
    paths += [(guardian, path) for path in (
        "/", "/ids", "/ips", "/wifi", "/cloaking", "/explorer", "/auditor",
        "/ai", "/reports", "/incidents", "/fleet", "/security",
    )]
    seen: set[str] = set()
    controls = []
    for base, path in paths:
        url = base + path
        response = get(url)
        seen.add(url)
        elements = PageElements()
        elements.feed(response.text)
        controls.append({"url": url, "buttons": elements.buttons, "inline_handlers": elements.inline_handlers})
        for href in sorted(elements.links | elements.assets):
            target = urljoin(url, href)
            if href.startswith("#") or urlsplit(target).netloc not in (urlsplit(nsep).netloc, urlsplit(guardian).netloc):
                continue
            if urlsplit(target).path == "/logout" or target in seen:
                continue
            seen.add(target)
            get(target)

    report["page_controls"] = controls
    for path in ("/api/health", "/api/readiness", "/api/diagnostics", "/api/v1/dashboard/summary",
                 "/api/v1/events", "/api/v1/detections", "/api/v1/incidents", "/api/v1/integrations/status"):
        get(nsep + path)
    for path in ("/api/status", "/api/health", "/api/findings", "/api/events", "/api/hosts",
                 "/api/ids/stats", "/api/ips/stats", "/api/fleet/list", "/api/security-graph/summary"):
        get(guardian + path)

    event = session.post(nsep + "/api/v1/events", json={
        "source": "local-platform-audit",
        "event_type": "login_failure",
        "occurred_at": datetime.now(UTC).isoformat(),
        "payload": {"failed_logins": 6, "audit_only": True},
        "metadata": {"purpose": "synthetic local dependency and integration validation"},
    }, timeout=10)
    event.raise_for_status()
    event_id = event.json()["event_id"]
    final_status = None
    forwarded = None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status = session.get(nsep + "/api/v1/events/" + event_id, timeout=10)
        status.raise_for_status()
        final_status = status.json()["status"]
        db = GUARDIAN / ".local-runtime" / "wolfpak_events.db"
        if db.exists():
            with sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True) as connection:
                rows = connection.execute("SELECT id, payload FROM envelopes WHERE source = ?", ("NSEP",)).fetchall()
            for row_id, payload in rows:
                data = json.loads(payload)
                if data.get("event_id") == event_id:
                    forwarded = {"row_id": row_id, "incident_id": data["incident_id"], "event_id": event_id}
                    break
        if forwarded and final_status == "processed":
            break
        time.sleep(0.5)
    report["synthetic_handoff"] = {"status": final_status, "forwarded": forwarded, "passed": final_status == "processed" and forwarded is not None}
    if forwarded:
        incident = forwarded["incident_id"]
        for suffix in ("", "/timeline", "/graph"):
            get(nsep + "/api/v1/incidents/" + incident + suffix)
    report["limitations"] = [
        "Destructive controls, scans, blocking, quarantine, remote commands, and external AI calls were not executed.",
        "NSEP external-system inventory/activity pages are explicit placeholders, not working integrations.",
        "TCP reachability is not proof of delivery; synthetic handoff checks the actual persisted Network Guardian envelope.",
        "HTTP checks do not certify every action button; state-changing actions require separate authorized validation.",
    ]
    report["passed"] = all(check["passed"] for check in report["checks"]) and report["synthetic_handoff"]["passed"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({
        "passed": report["passed"],
        "http_checks": len(report["checks"]),
        "failed_checks": [check for check in report["checks"] if not check["passed"]],
        "synthetic_handoff": report["synthetic_handoff"],
        "pages_with_inline_handlers": [item["url"] for item in controls if item["inline_handlers"]],
    }, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
