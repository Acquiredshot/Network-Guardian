#\!/usr/bin/env python
"""
Interactive test monitor for SafeWebBrowsingAgent.
Run with:  python run_web_browsing_tests.py
"""

from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path
from queue import Empty, Queue

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.coordinate import Coordinate
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, Label, ProgressBar, RichLog


ICON = {
    "passed":  "[bold green] PASS [/]",
    "failed":  "[bold red] FAIL [/]",
    "error":   "[bold red] ERR  [/]",
    "waiting": "[dim] ···  [/]",
}

GROUP_MAP = {
    "TestExtractHostname":         "URL Parsing",
    "TestDomainInList":            "Domain Matching",
    "TestIsPrivateAddress":        "SSRF Guard",
    "TestCombinedConfidence":      "Confidence Math",
    "TestThreatScore":             "Threat Scoring",
    "TestVerdictCategory":         "Verdict Category",
    "TestAgentListChecks":         "Agent — List Checks",
    "TestDomainListManagement":    "Domain List Mgmt",
    "TestStatsAndHistory":         "Stats & History",
    "TestContentSignalDetection":  "Content Signals (17)",
    "TestIpsAutoBlock":            "IPS Auto-Block",
    "TestEventBusPublishing":      "Event Bus",
    "TestUrlVerdictSerialization": "Serialisation",
}


def _parse_test_id(node_id: str) -> tuple[str, str]:
    parts = node_id.split("::")
    if len(parts) >= 3:
        group = GROUP_MAP.get(parts[-2], parts[-2])
        name = parts[-1].replace("test_", "").replace("_", " ")
    else:
        group = "Other"
        name = parts[-1].replace("test_", "").replace("_", " ")
    return group, name


def collect_tests() -> list[str]:
    result = subprocess.run(
        [sys.executable, "-m", "pytest",
         "tests/test_web_browsing_agent.py",
         "--collect-only", "-q", "--no-header"],
        capture_output=True, text=True,
        cwd=Path(__file__).parent,
    )
    ids = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if "::" in line and not line.startswith(("=", "no tests", "selected")):
            ids.append(line)
    return ids


def run_tests(queue: Queue) -> None:
    proc = subprocess.Popen(
        [sys.executable, "-m", "pytest",
         "tests/test_web_browsing_agent.py",
         "-v", "--tb=short", "--no-header", "--color=no"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=Path(__file__).parent,
    )
    for line in proc.stdout:
        queue.put(("line", line.rstrip()))
    proc.wait()
    queue.put(("done", proc.returncode))


class TestMonitorApp(App):
    TITLE = "Network Guardian — Safe Web Browsing Agent Test Monitor"
    SUB_TITLE = "tests/test_web_browsing_agent.py"

    BINDINGS = [
        Binding("r", "rerun", "Re-run"),
        Binding("q", "quit", "Quit"),
    ]

    CSS = """
    Screen { background: #0d1117; }
    Header { background: #1a2332; color: #58a6ff; }
    Footer { background: #1a2332; }
    #stat-bar {
        height: 1; background: #161b22;
        padding: 0 2; border-bottom: solid #30363d; align: left middle;
    }
    #stat-bar Label { color: #c9d1d9; width: 1fr; }
    #prog-row {
        height: 3; padding: 0 2; background: #161b22;
        align: left middle; border-bottom: solid #30363d;
    }
    ProgressBar { width: 55; margin: 0 2 0 0; }
    #prog-label { color: #8b949e; min-width: 20; }
    #main { height: 1fr; }
    #left { width: 2fr; border-right: solid #30363d; }
    DataTable { background: #0d1117; height: 1fr; }
    DataTable > .datatable--header { background: #161b22; color: #58a6ff; }
    DataTable > .datatable--cursor { background: #1f2d3d; }
    #right { width: 1fr; background: #0d1117; }
    #log-head {
        background: #161b22; color: #8b949e;
        padding: 0 1; height: 1; border-bottom: solid #30363d;
    }
    RichLog { background: #0d1117; height: 1fr; padding: 0 1; }
    #bot-bar {
        height: 1; background: #161b22;
        padding: 0 2; border-top: solid #30363d; color: #8b949e;
    }
    """

    passed:  reactive[int]  = reactive(0)
    failed:  reactive[int]  = reactive(0)
    total:   reactive[int]  = reactive(0)
    running: reactive[bool] = reactive(False)

    def __init__(self) -> None:
        super().__init__()
        self._test_ids:  list[str]       = []
        self._row_index: dict[str, int]  = {}
        self._queue:     Queue           = Queue()
        self._thread:    threading.Thread | None = None
        self._in_fail:   bool            = False
        self._cur_fail:  list[str]       = []

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="stat-bar"):
            yield Label("", id="stat-lbl")
        with Horizontal(id="prog-row"):
            yield ProgressBar(total=100, show_eta=False, id="prog-bar")
            yield Label("collecting…", id="prog-label")
        with Horizontal(id="main"):
            with Vertical(id="left"):
                yield DataTable(cursor_type="row", zebra_stripes=True)
            with Vertical(id="right"):
                yield Label(" Output / Failures", id="log-head")
                yield RichLog(highlight=True, markup=True, id="log")
        yield Label("Press  R  to re-run   Q  to quit", id="bot-bar")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one(DataTable).add_columns("Status", "Group", "Test Name")
        self._start_run()

    def _start_run(self) -> None:
        self.passed = 0
        self.failed = 0
        self._in_fail = False
        self._cur_fail.clear()
        self._row_index.clear()

        table = self.query_one(DataTable)
        table.clear()
        log = self.query_one(RichLog)
        log.clear()
        log.write("[dim]Collecting tests…[/dim]")

        self.query_one("#prog-label", Label).update("collecting…")
        self.query_one(ProgressBar).update(progress=0)
        self._refresh_stat()

        self._test_ids = collect_tests()
        self.total = len(self._test_ids)
        self.query_one(ProgressBar).update(total=max(1, self.total))
        self.query_one("#prog-label", Label).update(f"0 / {self.total}")
        self._refresh_stat()

        for i, nid in enumerate(self._test_ids):
            group, name = _parse_test_id(nid)
            table.add_row(ICON["waiting"], group, name)
            self._row_index[nid] = i

        log.clear()
        log.write(f"[dim]Running {self.total} tests…[/dim]\n")

        self._queue = Queue()
        self.running = True
        self._thread = threading.Thread(
            target=run_tests, args=(self._queue,), daemon=True
        )
        self._thread.start()
        self.set_interval(0.05, self._poll)

    def _poll(self) -> None:
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "line":
                    self._handle_line(payload)
                else:
                    self._handle_done(payload)
                    return
        except Empty:
            pass

    def _handle_line(self, line: str) -> None:
        log   = self.query_one(RichLog)
        table = self.query_one(DataTable)

        if " PASSED" in line or " FAILED" in line or " ERROR" in line:
            self._in_fail = False
            parts = line.split()
            if not parts:
                return
            nid = parts[0]
            status = next((w.lower() for w in parts if w in ("PASSED", "FAILED", "ERROR")), None)

            row_num = self._row_index.get(nid)
            if row_num is not None and status:
                icon = ICON.get(status, ICON["waiting"])
                table.update_cell_at(Coordinate(row_num, 0), icon)
                group, name = _parse_test_id(nid)

                if status == "passed":
                    self.passed += 1
                    log.write(f"[green]✓[/green] [dim]{group}[/dim] › {name}")
                else:
                    self.failed += 1
                    self._in_fail = True
                    self._cur_fail = []
                    log.write(f"[red]✗[/red] [dim]{group}[/dim] › [bold red]{name}[/bold red]")

                self._refresh_stat()
                self.query_one(ProgressBar).advance(1)
                done = self.passed + self.failed
                self.query_one("#prog-label", Label).update(f"{done} / {self.total}")

        elif self._in_fail and line.strip():
            self._cur_fail.append(line)
            log.write(f"[red dim]  {line}[/]")

        elif line.strip().startswith("FAILED "):
            log.write(f"[bold red]{line}[/bold red]")

    def _handle_done(self, returncode: int) -> None:
        self.running = False
        self.query_one(ProgressBar).update(progress=self.total)
        log = self.query_one(RichLog)

        if self.failed == 0:
            log.write(f"\n[bold green]══ ALL {self.passed} TESTS PASSED ══[/bold green]")
            self.query_one("#bot-bar", Label).update(
                f"[green]✓ {self.passed} passed[/green]  ·  R = re-run   Q = quit"
            )
        else:
            log.write(f"\n[bold red]══ {self.failed} FAILED  ·  {self.passed} passed ══[/bold red]")
            self.query_one("#bot-bar", Label).update(
                f"[red]✗ {self.failed} failed[/red]  [green]{self.passed} passed[/green]"
                f"  ·  R = re-run   Q = quit"
            )

    def _refresh_stat(self) -> None:
        p, f, t = self.passed, self.failed, self.total
        self.query_one("#stat-lbl", Label).update(
            f"[white]Total[/white] [bold]{t}[/bold]    "
            f"[green]Passed[/green] [bold green]{p}[/bold green]    "
            f"[red]Failed[/red] [bold red]{f}[/bold red]"
        )

    def action_rerun(self) -> None:
        if not self.running:
            self._start_run()

    def action_quit(self) -> None:
        self.exit()


if __name__ == "__main__":
    TestMonitorApp().run()
