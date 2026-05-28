#!/usr/bin/env python3
"""
Data Export & Analysis Tool for Network Guardian Testing

Extracts and analyzes data collected during test runs:
- Parses JSON files from ~/.network_guardian/
- Generates CSV/JSON reports with statistics
- Timeline analysis of events
- Threat correlation matrices
- Rule effectiveness metrics
"""

import json
import sys
from pathlib import Path
from collections import defaultdict
from datetime import datetime
import csv
from typing import Any, Optional


class DataExporter:
    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path.home() / ".network_guardian"
        self.export_dir = Path.cwd() / "export"
        self.export_dir.mkdir(exist_ok=True)

        self.firewall_data = {}
        self.correlations = {}
        self.harvested_rules = {}
        self.scan_results = {}
        self.discoveries = {}

    def load_all_data(self) -> None:
        """Load all available data files."""
        print("[*] Loading data files...")

        # Smart Firewall injection history
        fw_history = self.data_dir / "smart_firewall" / "injection_history.json"
        if fw_history.exists():
            try:
                self.firewall_data = json.loads(fw_history.read_text())
                print(f"    ✓ Loaded {fw_history.name}")
            except Exception as e:
                print(f"    ✗ Failed to load {fw_history.name}: {e}")

        # Harvested rules
        harvested = self.data_dir / "payload_harvester" / "harvested_rules.json"
        if harvested.exists():
            try:
                self.harvested_rules = json.loads(harvested.read_text())
                print(f"    ✓ Loaded {harvested.name}")
            except Exception as e:
                print(f"    ✗ Failed to load {harvested.name}: {e}")

        # Attack correlator discoveries
        discoveries = self.data_dir / "attack_correlator" / "discoveries.json"
        if discoveries.exists():
            try:
                self.discoveries = json.loads(discoveries.read_text())
                print(f"    ✓ Loaded {discoveries.name}")
            except Exception as e:
                print(f"    ✗ Failed to load {discoveries.name}: {e}")

        # Attack correlator correlations
        correlations = self.data_dir / "attack_correlator" / "correlations.json"
        if correlations.exists():
            try:
                self.correlations = json.loads(correlations.read_text())
                print(f"    ✓ Loaded {correlations.name}")
            except Exception as e:
                print(f"    ✗ Failed to load {correlations.name}: {e}")

        # Defensive scanner results
        scan_results = self.data_dir / "defensive_scanner" / "scan_results.json"
        if scan_results.exists():
            try:
                self.scan_results = json.loads(scan_results.read_text())
                print(f"    ✓ Loaded {scan_results.name}")
            except Exception as e:
                print(f"    ✗ Failed to load {scan_results.name}: {e}")

    def export_firewall_stats(self) -> None:
        """Export Smart Firewall statistics."""
        if not self.firewall_data:
            print("[-] No firewall data to export")
            return

        print("\n[*] Exporting firewall statistics...")

        stats = {
            "total_ips": len(self.firewall_data),
            "total_events": sum(len(events) for events in self.firewall_data.values()),
            "injection_types": defaultdict(int),
            "top_blocked_ips": [],
        }

        # Count injection types and events per IP
        ip_event_counts = {}
        for ip, events in self.firewall_data.items():
            ip_event_counts[ip] = len(events)
            for event in events:
                if isinstance(event, dict):
                    itype = event.get("injection_type", "unknown")
                    stats["injection_types"][itype] += 1

        # Top blocked IPs
        stats["top_blocked_ips"] = sorted(
            ip_event_counts.items(), key=lambda x: x[1], reverse=True
        )[:10]

        # Export as JSON
        output_file = self.export_dir / "firewall_stats.json"
        output_file.write_text(
            json.dumps(
                {k: v for k, v in stats.items() if k != "injection_types"}
                | {"injection_types": dict(stats["injection_types"])},
                indent=2,
            )
        )
        print(f"    ✓ Exported to {output_file.name}")

        # Export CSV of top blocked IPs
        csv_file = self.export_dir / "firewall_blocked_ips.csv"
        with open(csv_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IP Address", "Event Count"])
            for ip, count in stats["top_blocked_ips"]:
                writer.writerow([ip, count])
        print(f"    ✓ Exported to {csv_file.name}")

    def export_correlation_analysis(self) -> None:
        """Export attack correlation analysis."""
        if not self.correlations:
            print("[-] No correlation data to export")
            return

        print("\n[*] Exporting correlation analysis...")

        corr_stats = {
            "total_correlations": len(self.correlations),
            "high_confidence": 0,
            "medium_confidence": 0,
            "low_confidence": 0,
            "top_attacking_ips": defaultdict(int),
        }

        for corr_id, corr_data in self.correlations.items():
            if isinstance(corr_data, dict):
                score = corr_data.get("correlation_score", 0)
                if score >= 0.75:
                    corr_stats["high_confidence"] += 1
                elif score >= 0.50:
                    corr_stats["medium_confidence"] += 1
                else:
                    corr_stats["low_confidence"] += 1

                source_ip = corr_data.get("source_ip")
                if source_ip:
                    corr_stats["top_attacking_ips"][source_ip] += 1

        top_attackers = sorted(
            corr_stats["top_attacking_ips"].items(), key=lambda x: x[1], reverse=True
        )[:10]

        output_file = self.export_dir / "correlation_analysis.json"
        output_file.write_text(
            json.dumps(
                {
                    "total_correlations": corr_stats["total_correlations"],
                    "confidence_distribution": {
                        "high": corr_stats["high_confidence"],
                        "medium": corr_stats["medium_confidence"],
                        "low": corr_stats["low_confidence"],
                    },
                    "top_attacking_ips": top_attackers,
                },
                indent=2,
            )
        )
        print(f"    ✓ Exported to {output_file.name}")

        # CSV of top attacking IPs
        csv_file = self.export_dir / "correlation_top_attackers.csv"
        with open(csv_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Source IP", "Correlation Count"])
            for ip, count in top_attackers:
                writer.writerow([ip, count])
        print(f"    ✓ Exported to {csv_file.name}")

    def export_harvested_rules_stats(self) -> None:
        """Export payload harvester statistics."""
        if not self.harvested_rules:
            print("[-] No harvested rules data to export")
            return

        print("\n[*] Exporting harvested rules statistics...")

        stats = {
            "total_rules": len(self.harvested_rules),
            "by_injection_type": defaultdict(int),
            "by_severity": defaultdict(int),
            "by_confidence": defaultdict(int),
            "effectiveness": [],
        }

        for rule_name, rule_data in self.harvested_rules.items():
            if isinstance(rule_data, dict):
                itype = rule_data.get("injection_type", "unknown")
                severity = rule_data.get("severity", "unknown")
                confidence = rule_data.get("base_confidence", 0)

                stats["by_injection_type"][itype] += 1
                stats["by_severity"][severity] += 1

                conf_bucket = f"{int(confidence * 100)}%"
                stats["by_confidence"][conf_bucket] += 1

                successful = rule_data.get("successful_detections", 0)
                failed = rule_data.get("failed_detections", 0)
                total = successful + failed

                stats["effectiveness"].append(
                    {
                        "rule_name": rule_name,
                        "type": itype,
                        "severity": severity,
                        "confidence": confidence,
                        "successful": successful,
                        "failed": failed,
                        "total": total,
                        "success_rate": successful / max(total, 1),
                    }
                )

        output_file = self.export_dir / "harvested_rules_stats.json"
        output_file.write_text(
            json.dumps(
                {
                    "total_rules": stats["total_rules"],
                    "by_injection_type": dict(stats["by_injection_type"]),
                    "by_severity": dict(stats["by_severity"]),
                    "by_confidence": dict(stats["by_confidence"]),
                },
                indent=2,
            )
        )
        print(f"    ✓ Exported to {output_file.name}")

        # CSV of rule effectiveness
        csv_file = self.export_dir / "harvested_rules_effectiveness.csv"
        with open(csv_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "Rule Name",
                    "Type",
                    "Severity",
                    "Base Confidence",
                    "Successful Detections",
                    "Failed Detections",
                    "Total",
                    "Success Rate",
                ]
            )
            for r in sorted(stats["effectiveness"], key=lambda x: x["success_rate"], reverse=True):
                writer.writerow(
                    [
                        r["rule_name"],
                        r["type"],
                        r["severity"],
                        f"{r['confidence']:.2f}",
                        r["successful"],
                        r["failed"],
                        r["total"],
                        f"{r['success_rate']:.2%}",
                    ]
                )
        print(f"    ✓ Exported to {csv_file.name}")

    def export_discovery_analysis(self) -> None:
        """Export discovered services analysis."""
        if not self.discoveries:
            print("[-] No discovery data to export")
            return

        print("\n[*] Exporting discovery analysis...")

        stats = {
            "total_services": len(self.discoveries),
            "by_service_type": defaultdict(int),
            "by_ip": defaultdict(list),
        }

        for svc_key, svc_data in self.discoveries.items():
            if isinstance(svc_data, dict):
                svc_type = svc_data.get("service_type", "unknown")
                ip = svc_data.get("ip")
                port = svc_data.get("port")

                stats["by_service_type"][svc_type] += 1
                if ip:
                    stats["by_ip"][ip].append({"port": port, "type": svc_type})

        output_file = self.export_dir / "discovery_analysis.json"
        output_file.write_text(
            json.dumps(
                {
                    "total_services": stats["total_services"],
                    "by_service_type": dict(stats["by_service_type"]),
                    "services_per_ip": {
                        ip: len(svcs) for ip, svcs in stats["by_ip"].items()
                    },
                },
                indent=2,
            )
        )
        print(f"    ✓ Exported to {output_file.name}")

        # CSV of discovered services
        csv_file = self.export_dir / "discovered_services.csv"
        with open(csv_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IP Address", "Port", "Service Type"])
            for ip, services in sorted(stats["by_ip"].items()):
                for svc in services:
                    writer.writerow([ip, svc["port"], svc["type"]])
        print(f"    ✓ Exported to {csv_file.name}")

    def export_scan_results(self) -> None:
        """Export defensive scanner results."""
        if not self.scan_results:
            print("[-] No scan results data to export")
            return

        print("\n[*] Exporting scan results...")

        stats = {
            "total_scans": len(self.scan_results),
            "vulnerabilities_found": 0,
            "by_injection_type": defaultdict(int),
            "false_positives": 0,
        }

        vulnerabilities = []

        for scan_id, scan_data in self.scan_results.items():
            if isinstance(scan_data, dict):
                if scan_data.get("is_vulnerable"):
                    stats["vulnerabilities_found"] += 1
                    itype = scan_data.get("injection_type", "unknown")
                    stats["by_injection_type"][itype] += 1

                    vulnerabilities.append(
                        {
                            "endpoint": f"{scan_data.get('ip')}:{scan_data.get('port')}",
                            "type": itype,
                            "payload": scan_data.get("payload", "")[:50],
                            "severity": scan_data.get("severity", "unknown"),
                        }
                    )

                if scan_data.get("false_positive"):
                    stats["false_positives"] += 1

        output_file = self.export_dir / "scan_results_stats.json"
        output_file.write_text(
            json.dumps(
                {
                    "total_scans": stats["total_scans"],
                    "vulnerabilities_found": stats["vulnerabilities_found"],
                    "false_positives": stats["false_positives"],
                    "by_injection_type": dict(stats["by_injection_type"]),
                },
                indent=2,
            )
        )
        print(f"    ✓ Exported to {output_file.name}")

        # CSV of vulnerabilities
        if vulnerabilities:
            csv_file = self.export_dir / "scan_vulnerabilities.csv"
            with open(csv_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Endpoint", "Injection Type", "Payload (truncated)", "Severity"])
                for v in vulnerabilities:
                    writer.writerow(
                        [v["endpoint"], v["type"], v["payload"], v["severity"]]
                    )
            print(f"    ✓ Exported to {csv_file.name}")

    def export_summary_report(self) -> None:
        """Export comprehensive summary report."""
        print("\n[*] Generating summary report...")

        report = {
            "timestamp": datetime.now().isoformat(),
            "firewall": {
                "total_ips": len(self.firewall_data),
                "total_events": sum(
                    len(events) for events in self.firewall_data.values()
                ),
            },
            "correlations": {
                "total": len(self.correlations),
            },
            "harvested_rules": {
                "total": len(self.harvested_rules),
            },
            "discoveries": {
                "total": len(self.discoveries),
            },
            "scans": {
                "total": len(self.scan_results),
            },
        }

        output_file = self.export_dir / "SUMMARY.json"
        output_file.write_text(json.dumps(report, indent=2))
        print(f"    ✓ Exported to {output_file.name}")

    def run(self) -> None:
        """Execute full export."""
        print("\n" + "=" * 60)
        print("  Network Guardian — Data Export & Analysis")
        print("=" * 60)

        self.load_all_data()

        self.export_firewall_stats()
        self.export_correlation_analysis()
        self.export_harvested_rules_stats()
        self.export_discovery_analysis()
        self.export_scan_results()
        self.export_summary_report()

        print(f"\n[+] All data exported to: {self.export_dir}/")
        print("[+] Files generated:")
        for f in sorted(self.export_dir.glob("*")):
            if f.is_file():
                size = f.stat().st_size
                print(f"    - {f.name} ({size} bytes)")


if __name__ == "__main__":
    exporter = DataExporter()
    exporter.run()
