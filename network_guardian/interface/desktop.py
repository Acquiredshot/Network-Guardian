# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
PyQt5 desktop frontend for Network Guardian.

Thin client over the existing engine: subscribes to ``ids.alert`` events
and routes user actions to the IPS. All detection and blocking logic
lives in :mod:`network_guardian.ids` and :mod:`network_guardian.ips` —
this module only renders state and forwards intent.

Usage::

    python -m network_guardian.interface.desktop
"""

from __future__ import annotations

import asyncio
import logging
import sys
from threading import Event as ThreadEvent
from typing import Any

from PyQt5.QtCore import QThread, pyqtSignal, pyqtSlot, Qt
from PyQt5.QtWidgets import (
    QApplication, QCheckBox, QHBoxLayout, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QPushButton, QVBoxLayout, QWidget,
)

from network_guardian.config import Config
from network_guardian.core.engine import Engine
from network_guardian.core.events import Event
from network_guardian.ips import BlockReason
from network_guardian.models.network import Severity

logger = logging.getLogger("network_guardian.interface.desktop")


class EngineThread(QThread):
    """Runs the Engine on its own asyncio loop and re-emits alerts as Qt signals."""

    alert = pyqtSignal(dict)
    blocked = pyqtSignal(dict)
    unblocked = pyqtSignal(str)
    ready = pyqtSignal()

    def __init__(self, config: Config | None = None) -> None:
        super().__init__()
        self._config = config or Config()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._engine: Engine | None = None
        self._stop_flag = ThreadEvent()

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None:
            raise RuntimeError("Engine loop not ready yet")
        return self._loop

    @property
    def engine(self) -> Engine:
        if self._engine is None:
            raise RuntimeError("Engine not ready yet")
        return self._engine

    def run(self) -> None:  # QThread entry point
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._run_engine())
        finally:
            self._loop.close()

    async def _run_engine(self) -> None:
        self._engine = Engine(self._config)
        # Touch IDS/IPS so they exist before we subscribe / before alerts can fire.
        _ = self._engine.ids
        _ = self._engine.ips
        self._engine.event_bus.subscribe("ids.alert", self._on_alert)
        self._engine.event_bus.subscribe("ips.block", self._on_block)
        self._engine.event_bus.subscribe("ips.unblock", self._on_unblock)
        await self._engine.start()
        self.ready.emit()
        try:
            await asyncio.get_running_loop().run_in_executor(None, self._stop_flag.wait)
        finally:
            await self._engine.stop()

    async def _on_alert(self, event: Event) -> None:
        self.alert.emit(event.data.get("alert", {}))

    async def _on_block(self, event: Event) -> None:
        entry = event.data.get("entry", {})
        if entry:
            self.blocked.emit(entry)

    async def _on_unblock(self, event: Event) -> None:
        ip = event.data.get("ip", "")
        if ip:
            self.unblocked.emit(ip)

    def shutdown(self) -> None:
        self._stop_flag.set()


class SmartFirewall(QWidget):
    """Minimal desktop firewall console."""

    def __init__(self, engine_thread: EngineThread) -> None:
        super().__init__()
        self._engine_thread = engine_thread
        self._selected_alert: dict[str, Any] | None = None

        self.setWindowTitle("Network Guardian — Smart Firewall")
        self.resize(640, 480)

        self.status_label = QLabel("Starting engine…")
        self.payload_input = QLineEdit()
        self.payload_input.setPlaceholderText("Paste packet payload / request to analyse")
        self.analyze_btn = QPushButton("Analyze")
        self.analyze_btn.setEnabled(False)
        self.analyze_btn.clicked.connect(self._on_analyze_clicked)

        self.auto_respond_check = QCheckBox("Auto-respond to alerts (IPS blocks automatically)")
        self.auto_respond_check.setEnabled(False)
        self.auto_respond_check.toggled.connect(self._on_auto_respond_toggled)

        self.alert_list = QListWidget()
        self.alert_list.itemSelectionChanged.connect(self._on_alert_selected)

        self.block_btn = QPushButton("Block source IP")
        self.block_btn.setEnabled(False)
        self.block_btn.clicked.connect(self._on_block_clicked)

        self.blocked_list = QListWidget()
        self.blocked_list.itemSelectionChanged.connect(self._on_blocked_selected)

        self.unblock_btn = QPushButton("Unblock selected IP")
        self.unblock_btn.setEnabled(False)
        self.unblock_btn.clicked.connect(self._on_unblock_clicked)

        top_row = QHBoxLayout()
        top_row.addWidget(self.payload_input, 1)
        top_row.addWidget(self.analyze_btn)

        layout = QVBoxLayout()
        layout.addWidget(self.status_label)
        layout.addLayout(top_row)
        layout.addWidget(self.auto_respond_check)
        layout.addWidget(QLabel("Alerts:"))
        layout.addWidget(self.alert_list, 1)
        layout.addWidget(self.block_btn)
        layout.addWidget(QLabel("Blocked IPs:"))
        layout.addWidget(self.blocked_list, 1)
        layout.addWidget(self.unblock_btn)
        self.setLayout(layout)

        engine_thread.alert.connect(self._on_alert)
        engine_thread.blocked.connect(self._on_blocked)
        engine_thread.unblocked.connect(self._on_unblocked)
        engine_thread.ready.connect(self._on_engine_ready)

    @pyqtSlot()
    def _on_engine_ready(self) -> None:
        self.status_label.setText("Engine running. Enter a payload and click Analyze.")
        self.analyze_btn.setEnabled(True)
        self.auto_respond_check.setEnabled(True)

    @pyqtSlot(dict)
    def _on_alert(self, alert: dict[str, Any]) -> None:
        label = (f"[{alert.get('severity', '?').upper()}] "
                 f"{alert.get('category', '?')} — "
                 f"src={alert.get('source_ip', '?')} "
                 f"({alert.get('description', '')})")
        item = QListWidgetItem(label)
        item.setData(Qt.UserRole, alert)
        self.alert_list.addItem(item)

    @pyqtSlot(dict)
    def _on_blocked(self, entry: dict[str, Any]) -> None:
        ip = entry.get("ip", "?")
        reason = entry.get("reason", "?")
        suffix = " (permanent)" if entry.get("permanent") else " (timed)"
        item = QListWidgetItem(f"{ip} — reason={reason}{suffix}")
        item.setData(Qt.UserRole, ip)
        self.blocked_list.addItem(item)

    @pyqtSlot(str)
    def _on_unblocked(self, ip: str) -> None:
        for i in range(self.blocked_list.count() - 1, -1, -1):
            item = self.blocked_list.item(i)
            if item.data(Qt.UserRole) == ip:
                self.blocked_list.takeItem(i)

    def _on_blocked_selected(self) -> None:
        self.unblock_btn.setEnabled(bool(self.blocked_list.selectedItems()))

    def _on_unblock_clicked(self) -> None:
        items = self.blocked_list.selectedItems()
        if not items:
            return
        ip = items[0].data(Qt.UserRole)
        if not ip:
            return
        engine = self._engine_thread.engine
        asyncio.run_coroutine_threadsafe(
            engine.ips.unblock_ip(ip),
            self._engine_thread.loop,
        )
        self.status_label.setText(f"Unblock requested for {ip}.")

    def _on_auto_respond_toggled(self, checked: bool) -> None:
        engine = self._engine_thread.engine
        engine.ips.set_auto_respond(checked)
        state = "enabled" if checked else "disabled"
        self.status_label.setText(f"Auto-respond {state}.")

    def _on_alert_selected(self) -> None:
        items = self.alert_list.selectedItems()
        if not items:
            self._selected_alert = None
            self.block_btn.setEnabled(False)
            return
        self._selected_alert = items[0].data(Qt.UserRole)
        ip = self._selected_alert.get("source_ip", "")
        self.block_btn.setEnabled(bool(ip) and ip != "unknown")

    def _on_analyze_clicked(self) -> None:
        payload = self.payload_input.text().strip()
        if not payload:
            return
        engine = self._engine_thread.engine
        # Route through Smart Firewall agent for injection detection + auto-block,
        # then also pass to IDS for full signature analysis.
        asyncio.run_coroutine_threadsafe(
            engine.smart_firewall.scan_payload(payload, source_ip="desktop"),
            self._engine_thread.loop,
        )
        asyncio.run_coroutine_threadsafe(
            engine.ids.analyse_payload(payload, source_ip="desktop"),
            self._engine_thread.loop,
        )
        self.payload_input.clear()

    def _on_block_clicked(self) -> None:
        alert = self._selected_alert
        if not alert:
            return
        ip = alert.get("source_ip", "")
        if not ip:
            return
        severity = Severity(alert.get("severity", "high"))
        engine = self._engine_thread.engine
        asyncio.run_coroutine_threadsafe(
            engine.ips.block_ip(
                ip,
                reason=BlockReason.MANUAL,
                severity=severity,
                alert_id=alert.get("alert_id", ""),
                description=f"Blocked from desktop UI: {alert.get('description', '')}",
            ),
            self._engine_thread.loop,
        )
        self.status_label.setText(f"Block requested for {ip}.")


def main(config_path: str | None = None) -> int:
    logging.basicConfig(level=logging.INFO)
    app = QApplication(sys.argv)

    config = Config.load(config_path) if config_path else Config()
    engine_thread = EngineThread(config)
    window = SmartFirewall(engine_thread)
    window.show()

    engine_thread.start()
    app.aboutToQuit.connect(engine_thread.shutdown)

    exit_code = app.exec_()
    engine_thread.wait(5000)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
