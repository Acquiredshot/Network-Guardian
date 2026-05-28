#!/usr/bin/env python3
"""
Automated Data Collection & Monitoring for Network Guardian Testing

Runs in background during testing to:
- Collect real-time metrics from all components
- Display live status dashboard
- Track event timelines
- Generate periodic snapshots
- Monitor for anomalies
"""

import json
import sys
import time
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import Any
import threading


@dataclass
class Metric:
    """Single metric measurement."""

    timestamp: str
    firewall_events: int
    blocked_ips: int
    correlation_events: int
    harvested_rules: int
    discovered_services: int
    scan_results: int
    vulnerabilities: int
    avg_confidence: float


class DataCollector:
    def __init__(self, data_dir: Path | None = None):
        self.data_dir = data_dir or Path.home() / ".network_guardian"
        self.metrics_dir = self.data_dir / "metrics"
        self.metrics_dir.mkdir(parents=True, exist_ok=True)

        self.metrics: list[Metric] = []
        self._load_metrics_history()
        self._running = False

    def _load_metrics_history(self) -> None:
        """Load previous metrics from disk."""
        metrics_file = self.metrics_dir / "metrics_history.json"
        if not metrics_file.exists():
            return

        try:
            data = json.loads(metrics_file.read_text())
            self.metrics = [Metric(**m) for m in data]
        except Exception as e:
            print(f"[!] Failed to load metrics history: {e}")

    def _save_metrics_history(self) -> None:
        """Persist metrics to disk."""
        metrics_file = self.metrics_dir / "metrics_history.json"
        try:
            data = [asdict(m) for m in self.metrics[-1000:]]  # Keep last 1000
            metrics_file.write_text(json.dumps(data, indent=2))
        except Exception as e:
            print(f"[!] Failed to save metrics: {e}")

    def _collect_snapshot(self) -> Metric | None:
        """Collect current system metrics."""
        try:
            firewall_events = 0
            blocked_ips = 0
            fw_history = self.data_dir / "smart_firewall" / "injection_history.json"
            if fw_history.exists():
                data = json.loads(fw_history.read_text())
                blocked_ips = len(data)
                firewall_events = sum(len(events) for events in data.values())

            correlation_events = 0
            correlations_file = self.data_dir / "attack_correlator" / "correlations.json"
            if correlations_file.exists():
                data = json.loads(correlations_file.read_text())
                correlation_events = len(data)

            harvested_rules = 0
            avg_confidence = 0.0
            harvested_file = self.data_dir / "payload_harvester" / "harvested_rules.json"
            if harvested_file.exists():
                data = json.loads(harvested_file.read_text())
                harvested_rules = len(data)
                if data:
                    confidences = [
                        v.get("base_confidence", 0) for v in data.values() if isinstance(v, dict)
                    ]
                    avg_confidence = sum(confidences) / len(confidences) if confidences else 0

            discovered_services = 0
            discoveries_file = self.data_dir / "attack_correlator" / "discoveries.json"
            if discoveries_file.exists():
                data = json.loads(discoveries_file.read_text())
                discovered_services = len(data)

            scan_results = 0
            vulnerabilities = 0
            scan_file = self.data_dir / "defensive_scanner" / "scan_results.json"
            if scan_file.exists():
                data = json.loads(scan_file.read_text())
                scan_results = len(data)
                vulnerabilities = sum(
                    1 for v in data.values() if isinstance(v, dict) and v.get("is_vulnerable")
                )

            metric = Metric(
                timestamp=datetime.now().isoformat(),
                firewall_events=firewall_events,
                blocked_ips=blocked_ips,
                correlation_events=correlation_events,
                harvested_rules=harvested_rules,
                discovered_services=discovered_services,
                scan_results=scan_results,
                vulnerabilities=vulnerabilities,
                avg_confidence=avg_confidence,
            )

            self.metrics.append(metric)
            return metric
        except Exception as e:
            print(f"[!] Error collecting snapshot: {e}")
            return None

    def _format_metric(self, metric: Metric) -> str:
        """Format metric for display."""
        timestamp = datetime.fromisoformat(metric.timestamp).strftime("%H:%M:%S")
        return (
            f"[{timestamp}] "
            f"Events: {metric.firewall_events:5d} | "
            f"Blocked IPs: {metric.blocked_ips:3d} | "
            f"Correlations: {metric.correlation_events:3d} | "
            f"Rules: {metric.harvested_rules:3d} | "
            f"Discoveries: {metric.discovered_services:3d} | "
            f"Vulns: {metric.vulnerabilities:2d} | "
            f"Avg Conf: {metric.avg_confidence:.2f}"
        )

    def _calculate_delta(self, metric: Metric) -> dict[str, Any]:
        """Calculate changes from last metric."""
        if len(self.metrics) < 2:
            return {}

        prev = self.metrics[-2]
        return {
            "firewall_events_delta": metric.firewall_events - prev.firewall_events,
            "blocked_ips_delta": metric.blocked_ips - prev.blocked_ips,
            "correlations_delta": metric.correlation_events - prev.correlation_events,
            "rules_delta": metric.harvested_rules - prev.harvested_rules,
            "discoveries_delta": metric.discovered_services - prev.discovered_services,
            "vulnerabilities_delta": metric.vulnerabilities - prev.vulnerabilities,
        }

    def collect_continuous(self, interval: int = 5) -> None:
        """Collect metrics continuously."""
        self._running = True
        print("\n" + "=" * 120)
        print("  Network Guardian — Real-Time Monitoring Dashboard")
        print("=" * 120)
        print(
            "[*] Starting continuous data collection (interval: {} seconds)".format(interval)
        )
        print("[*] Press Ctrl+C to stop\n")

        try:
            while self._running:
                metric = self._collect_snapshot()
                if metric:
                    print(self._format_metric(metric))

                    delta = self._calculate_delta(metric)
                    if delta and any(v > 0 for v in delta.values()):
                        delta_str = " | ".join(
                            f"{k.replace('_delta', '')}: +{v}"
                            for k, v in delta.items()
                            if v > 0
                        )
                        print(f"    └─ Changes: {delta_str}")

                self._save_metrics_history()
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[*] Monitoring stopped")
            self._running = False

    def generate_statistics(self) -> None:
        """Generate statistics from collected metrics."""
        if not self.metrics:
            print("[-] No metrics collected yet")
            return

        print("\n" + "=" * 80)
        print("  Network Guardian — Collection Statistics")
        print("=" * 80)

        print(f"\n[*] Total measurements: {len(self.metrics)}")

        # Time span
        if len(self.metrics) > 1:
            start_time = datetime.fromisoformat(self.metrics[0].timestamp)
            end_time = datetime.fromisoformat(self.metrics[-1].timestamp)
            duration = end_time - start_time
            print(f"[*] Duration: {duration}")

        # Averages
        avg_events = sum(m.firewall_events for m in self.metrics) / len(self.metrics)
        avg_blocked = sum(m.blocked_ips for m in self.metrics) / len(self.metrics)
        avg_confidence = sum(m.avg_confidence for m in self.metrics) / len(self.metrics)

        print(f"\n[+] Averages:")
        print(f"    - Firewall events per snapshot: {avg_events:.1f}")
        print(f"    - Blocked IPs per snapshot: {avg_blocked:.1f}")
        print(f"    - Avg rule confidence: {avg_confidence:.2f}")

        # Peaks
        peak_events = max(m.firewall_events for m in self.metrics)
        peak_blocked = max(m.blocked_ips for m in self.metrics)
        peak_vulns = max(m.vulnerabilities for m in self.metrics)

        print(f"\n[+] Peaks:")
        print(f"    - Peak events: {peak_events}")
        print(f"    - Peak blocked IPs: {peak_blocked}")
        print(f"    - Peak vulnerabilities: {peak_vulns}")

        # Final state
        final = self.metrics[-1]
        print(f"\n[+] Final state:")
        print(f"    - Firewall events: {final.firewall_events}")
        print(f"    - Blocked IPs: {final.blocked_ips}")
        print(f"    - Correlation events: {final.correlation_events}")
        print(f"    - Harvested rules: {final.harvested_rules}")
        print(f"    - Discovered services: {final.discovered_services}")
        print(f"    - Vulnerabilities: {final.vulnerabilities}")

    def export_metrics_csv(self) -> None:
        """Export metrics as CSV."""
        if not self.metrics:
            print("[-] No metrics to export")
            return

        import csv

        csv_file = self.metrics_dir / "metrics_export.csv"
        with open(csv_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=asdict(self.metrics[0]).keys())
            writer.writeheader()
            for metric in self.metrics:
                writer.writerow(asdict(metric))

        print(f"[+] Metrics exported to {csv_file}")

    def show_dashboard(self) -> None:
        """Display current dashboard."""
        metric = self._collect_snapshot()
        if not metric:
            print("[-] Failed to collect metrics")
            return

        print("\n" + "=" * 80)
        print("  Network Guardian — Live Dashboard")
        print("=" * 80)

        print(f"\n[*] Timestamp: {metric.timestamp}")
        print(f"\n[+] Smart Firewall:")
        print(f"    - Total events recorded: {metric.firewall_events}")
        print(f"    - Unique blocked IPs: {metric.blocked_ips}")

        print(f"\n[+] Attack Correlation:")
        print(f"    - Correlation events: {metric.correlation_events}")
        print(f"    - Discovered services: {metric.discovered_services}")

        print(f"\n[+] Payload Harvesting:")
        print(f"    - Harvested rules: {metric.harvested_rules}")
        print(f"    - Avg confidence: {metric.avg_confidence:.2f}")

        print(f"\n[+] Defensive Scanning:")
        print(f"    - Total scans: {metric.scan_results}")
        print(f"    - Vulnerabilities found: {metric.vulnerabilities}")

        # Trend analysis
        if len(self.metrics) > 1:
            prev = self.metrics[-1]
            print(f"\n[+] Changes since last measurement:")
            print(f"    - Events: {metric.firewall_events - prev.firewall_events:+d}")
            print(f"    - Blocked IPs: {metric.blocked_ips - prev.blocked_ips:+d}")
            print(f"    - Correlations: {metric.correlation_events - prev.correlation_events:+d}")
            print(f"    - Rules: {metric.harvested_rules - prev.harvested_rules:+d}")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Network Guardian — Automated Data Collection & Monitoring"
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=["monitor", "status", "stats", "export"],
        default="status",
        help="Command to execute",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=5,
        help="Collection interval in seconds (for monitor mode)",
    )

    args = parser.parse_args()
    collector = DataCollector()

    if args.command == "monitor":
        collector.collect_continuous(interval=args.interval)
    elif args.command == "status":
        collector.show_dashboard()
    elif args.command == "stats":
        collector.generate_statistics()
    elif args.command == "export":
        collector.export_metrics_csv()

    collector._save_metrics_history()


if __name__ == "__main__":
    main()
