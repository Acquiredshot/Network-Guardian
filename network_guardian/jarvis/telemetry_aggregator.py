"""
╔══════════════════════════════════════════════════════════════════╗
║  telemetry_aggregator.py  |  OS + Data-Store Intelligence Layer  ║
╠══════════════════════════════════════════════════════════════════╣
║  Reads : OS metrics (psutil)                                     ║
║          fleet.json                                              ║
║          smart_firewall/injection_history.db  (SQLite)           ║
║          lateral_movement.json                                   ║
╚══════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False


# ══════════════════════════════════════════════════════════════════
# BACKGROUND CPU SAMPLER
# Runs in a daemon thread so cpu_percent() never blocks a command.
# ══════════════════════════════════════════════════════════════════

_CPU_CACHE: float = 0.0
_CPU_LOCK   = threading.Lock()

# Process-count TTL cache (psutil.pids() is expensive)
_PIDS_COUNT: int   = 0
_PIDS_TS:    float = 0.0
_PIDS_TTL:   float = 3.0   # seconds between full PID scans
_PIDS_LOCK   = threading.Lock()


def _cpu_sampler_loop() -> None:
    """Continuously sample CPU usage every 1 s and store in _CPU_CACHE."""
    global _CPU_CACHE
    while True:
        try:
            val = psutil.cpu_percent(interval=1.0)
            with _CPU_LOCK:
                _CPU_CACHE = val
        except Exception:
            time.sleep(1.0)


def _cached_proc_count() -> int:
    """Return process count, re-querying at most every _PIDS_TTL seconds."""
    global _PIDS_COUNT, _PIDS_TS
    now = time.monotonic()
    with _PIDS_LOCK:
        if now - _PIDS_TS < _PIDS_TTL:
            return _PIDS_COUNT
        count = len(psutil.pids())
        _PIDS_COUNT = count
        _PIDS_TS    = now
        return count


if _PSUTIL:
    # Prime the counter (first call always returns 0.0 — sets baseline for delta)
    psutil.cpu_percent(interval=None)
    _sampler = threading.Thread(target=_cpu_sampler_loop, daemon=True, name="ng-cpu-sampler")
    _sampler.start()


# ══════════════════════════════════════════════════════════════════
# PATH RESOLUTION
# ══════════════════════════════════════════════════════════════════

_NG_DATA_ROOT = Path(os.environ.get("NG_DATA_ROOT",
    str(Path(os.environ.get("USERPROFILE", Path.home())) / ".network_guardian")
))

PATHS = {
    "fleet":     _NG_DATA_ROOT / "fleet.json",
    "lateral":   _NG_DATA_ROOT / "lateral_movement.json",
    "fw_db":     _NG_DATA_ROOT / "smart_firewall" / "injection_history.db",
}


# ══════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════

def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _fmt_timedelta(td: "timedelta") -> str:
    total_s = int(td.total_seconds())
    h, rem  = divmod(total_s, 3600)
    m, s    = divmod(rem, 60)
    return f"{h}h {m}m {s}s"


# ══════════════════════════════════════════════════════════════════
# TELEMETRY AGGREGATOR
# ══════════════════════════════════════════════════════════════════

class TelemetryAggregator:
    """
    Single access point for all local telemetry data sources.

    All methods return plain Python dicts/lists so callers have zero
    dependency on internal implementation details.
    """

    def __init__(self, data_root: Path | None = None) -> None:
        """
        Parameters
        ----------
        data_root : Override the NG data directory (useful in tests).
                    Defaults to ``~/.network_guardian``.
        """
        if data_root is not None:
            self._paths = {
                "fleet":   data_root / "fleet.json",
                "lateral": data_root / "lateral_movement.json",
                "fw_db":   data_root / "smart_firewall" / "injection_history.db",
            }
        else:
            self._paths = PATHS

        # Per-instance snapshot TTL cache (1 s) so compute_threat_level()
        # and print_summary() reuse the same snapshot when called together.
        self._snap_cache: dict | None = None
        self._snap_ts:    float       = 0.0
        self._SNAP_TTL:   float       = 1.0

    # ── OS Metrics ────────────────────────────────────────────────

    def get_os_metrics(self) -> dict[str, Any]:
        """
        Sample live OS metrics.  Falls back to os-module estimates
        if psutil is unavailable.
        """
        if _PSUTIL:
            return self._metrics_psutil()
        return self._metrics_fallback()

    def _metrics_psutil(self) -> dict[str, Any]:
        with _CPU_LOCK:
            cpu = _CPU_CACHE          # instant — from background sampler
        mem   = psutil.virtual_memory()
        try:
            disk = psutil.disk_usage("C:\\")
        except Exception:
            disk = psutil.disk_usage("/")
        procs = _cached_proc_count()  # TTL-cached
        boot  = datetime.fromtimestamp(psutil.boot_time())
        up    = datetime.now() - boot
        return {
            "cpu_percent":  round(cpu, 1),
            "mem_percent":  round(mem.percent, 1),
            "mem_used":     _fmt_bytes(mem.used),
            "mem_total":    _fmt_bytes(mem.total),
            "disk_percent": round(disk.percent, 1),
            "disk_used":    _fmt_bytes(disk.used),
            "disk_free":    _fmt_bytes(disk.free),
            "proc_count":   procs,
            "uptime":       _fmt_timedelta(up),
            "boot_time":    boot.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def _metrics_fallback(self) -> dict[str, Any]:
        return {
            "cpu_percent":  "N/A (install psutil)",
            "mem_percent":  "N/A",
            "mem_used":     "N/A",
            "mem_total":    "N/A",
            "disk_percent": "N/A",
            "disk_used":    "N/A",
            "disk_free":    "N/A",
            "proc_count":   "N/A",
            "uptime":       "N/A",
            "boot_time":    "N/A",
        }

    # ── fleet.json ────────────────────────────────────────────────

    def read_fleet(self) -> dict | list | None:
        path = self._paths["fleet"]
        if not path.exists():
            return None
        try:
            with path.open(encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            raise RuntimeError(f"fleet.json read error: {exc}") from exc

    def fleet_summary(self) -> dict[str, Any]:
        raw     = self.read_fleet() or []
        devices = raw if isinstance(raw, list) else raw.get("devices", [])
        total   = len(devices)
        online  = sum(1 for d in devices if str(d.get("status", "")).lower() == "online")
        offline = sum(1 for d in devices if str(d.get("status", "")).lower() == "offline")
        unknown = total - online - offline
        high_risk = [
            d.get("ip", d.get("hostname", "unknown"))
            for d in devices
            if str(d.get("risk", d.get("threat_level", ""))).lower() in ("high", "critical")
        ]
        return {
            "total":         total,
            "online":        online,
            "offline":       offline,
            "unknown":       unknown,
            "high_risk_ips": high_risk,
        }

    # ── injection_history.db ──────────────────────────────────────

    def read_injection_history(self, limit: int = 20) -> list[dict[str, Any]]:
        db_path = self._paths["fw_db"]
        if not db_path.exists():
            return []
        results: list[dict] = []
        try:
            with sqlite3.connect(str(db_path)) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
                )
                tables = [r[0] for r in cursor.fetchall()]
                if not tables:
                    return []
                target = next(
                    (t for t in tables
                     if any(kw in t.lower() for kw in ("injection", "history", "attack", "log"))),
                    tables[0],
                )
                cursor.execute(f"PRAGMA table_info({target});")
                cols   = [row["name"] for row in cursor.fetchall()]
                ts_col = next(
                    (c for c in cols
                     if any(kw in c.lower() for kw in ("time", "date", "created", "ts"))),
                    None,
                )
                order  = f"ORDER BY {ts_col} DESC" if ts_col else ""
                cursor.execute(f"SELECT * FROM {target} {order} LIMIT ?;", (limit,))
                results = [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as exc:
            raise RuntimeError(f"injection_history.db query error: {exc}") from exc
        return results

    def injection_summary(self) -> dict[str, Any]:
        records = self.read_injection_history(limit=500)
        total   = len(records)
        blocked = sum(
            1 for r in records
            if str(r.get("blocked", r.get("status", ""))).lower()
               in ("true", "1", "blocked", "yes")
        )
        types:   dict[str, int] = {}
        sources: dict[str, int] = {}
        for r in records:
            at = str(r.get("attack_type", r.get("type", "unknown")))
            types[at] = types.get(at, 0) + 1
            ip = str(r.get("source_ip", r.get("ip", "unknown")))
            sources[ip] = sources.get(ip, 0) + 1
        return {
            "total_fetched":   total,
            "blocked_count":   blocked,
            "top_attack_types": sorted(types.items(),   key=lambda x: x[1], reverse=True)[:5],
            "top_source_ips":  sorted(sources.items(), key=lambda x: x[1], reverse=True)[:5],
        }

    # ── lateral_movement.json ─────────────────────────────────────

    def read_lateral_movement(self) -> dict | list | None:
        path = self._paths["lateral"]
        if not path.exists():
            return None
        try:
            with path.open(encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            raise RuntimeError(f"lateral_movement.json read error: {exc}") from exc

    def lateral_summary(self) -> dict[str, Any]:
        raw    = self.read_lateral_movement() or []
        events = raw if isinstance(raw, list) else raw.get("events", [])
        severity_counts: dict[str, int] = {}
        recent = 0
        cutoff = datetime.now() - timedelta(hours=24)
        for e in events:
            sev = str(e.get("severity", "unknown")).upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            ts_str = e.get("timestamp", e.get("time", ""))
            if ts_str:
                try:
                    ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
                    if ts.replace(tzinfo=None) > cutoff:
                        recent += 1
                except ValueError:
                    pass
        return {
            "total":      len(events),
            "critical":   severity_counts.get("CRITICAL", 0),
            "high":       severity_counts.get("HIGH", 0),
            "medium":     severity_counts.get("MEDIUM", 0),
            "low":        severity_counts.get("LOW", 0),
            "recent_24h": recent,
        }

    # ── Combined snapshot ─────────────────────────────────────────

    def full_snapshot(self) -> dict[str, Any]:
        """Collect every data source in one call; failures per-source are isolated.

        Results are cached for 1 s so back-to-back callers (e.g.
        compute_threat_level + print_summary) pay the I/O cost only once.
        """
        now = time.monotonic()
        if self._snap_cache is not None and now - self._snap_ts < self._SNAP_TTL:
            return self._snap_cache

        snapshot: dict[str, Any] = {"timestamp": datetime.now().isoformat()}
        for key, fn in [
            ("os_metrics", self.get_os_metrics),
            ("fleet",      self.fleet_summary),
            ("injection",  self.injection_summary),
            ("lateral",    self.lateral_summary),
        ]:
            try:
                snapshot[key] = fn()
            except Exception as exc:
                snapshot[key] = {"error": str(exc)}

        self._snap_cache = snapshot
        self._snap_ts    = now
        return snapshot
