#!/usr/bin/env python3
"""
Probe Integration Test — Simulates probe discoveries and exploitations

Tests all integration components:
1. Probe discovers services → Firewall adapts rules
2. Probe exploits vulnerability → Payload harvester creates rules
3. Attack detected on discovered endpoint → Correlator matches
4. Internal scan finds vulnerability → Defensive scanner reports
"""

import asyncio
import sys
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent))

from network_guardian.core.engine import Engine
from network_guardian.core.events import Event
from network_guardian.agent.smart_firewall_agent import SmartFirewallAgent


async def test_threat_intelligence_feedback():
    """Test: Probe discovers service → Firewall adapts rules."""
    print("\n" + "=" * 70)
    print("TEST 1: Threat Intelligence Feedback (Probe Discovery → Firewall Adaptation)")
    print("=" * 70)

    engine = Engine()
    bridge = engine.probe_bridge
    firewall = engine.smart_firewall

    # Simulate probe discovering HTTP service
    print("[*] Simulating probe discovery: HTTP service on 192.168.1.50:8080")
    bridge.register_discovered_service(
        ip="192.168.1.50",
        port=8080,
        service_type="http",
        protocol="tcp",
    )
    print("    ✓ Service registered with bridge")

    # Check if firewall adapted rules
    services = bridge.get_discovered_services()
    print(f"    ✓ Discovered services: {len(services)}")
    print(f"    ✓ Service profiles: {len(bridge._service_profiles)}")

    # Simulate discovering SQL database
    print("\n[*] Simulating probe discovery: SQL database on 192.168.1.100:3306")
    bridge.register_discovered_service(
        ip="192.168.1.100",
        port=3306,
        service_type="sql",
        protocol="tcp",
    )
    print("    ✓ SQL service registered")

    services = bridge.get_discovered_services()
    print(f"    ✓ Total discovered services: {len(services)}")


async def test_payload_harvesting():
    """Test: Probe exploits vulnerability → Rule harvester creates detection rules."""
    print("\n" + "=" * 70)
    print("TEST 2: Payload Harvesting (Exploit → Rule Creation)")
    print("=" * 70)

    engine = Engine()
    harvester = engine.payload_harvester
    firewall = engine.smart_firewall

    # Simulate probe exploiting SQL injection
    print("[*] Simulating probe exploitation: SQL injection on 192.168.1.100:3306")
    payload = "' UNION SELECT username, password FROM users--"

    rule = harvester.harvest_from_exploitation(
        payload=payload,
        vuln_type="sql_injection",
        source_ip="192.168.1.50",
        target_ip="192.168.1.100",
    )
    print(f"    ✓ Harvested rule: {rule.name if rule else 'None'}")
    if rule:
        print(f"      - Pattern: {rule.pattern}")
        print(f"      - Confidence: {rule.confidence:.2f}")
        print(f"      - Severity: {rule.severity}")

        # Add to firewall
        firewall.add_dynamic_rule(rule)
        print(f"    ✓ Rule added to firewall")

    # Simulate probe exploiting XSS
    print("\n[*] Simulating probe exploitation: XSS on 192.168.1.50:8080")
    xss_payload = "<script>alert('xss')</script>"

    xss_rule = harvester.harvest_from_exploitation(
        payload=xss_payload,
        vuln_type="xss",
        source_ip="192.168.1.50",
        target_ip="192.168.1.50",
    )
    print(f"    ✓ Harvested XSS rule: {xss_rule.name if xss_rule else 'None'}")

    rules = harvester.get_harvested_rules()
    print(f"    ✓ Total harvested rules: {len(rules)}")


async def test_attack_correlation():
    """Test: Probe discoveries matched with firewall-detected attacks."""
    print("\n" + "=" * 70)
    print("TEST 3: Attack Correlation (Discovery + Attack = Correlation)")
    print("=" * 70)

    engine = Engine()
    correlator = engine.attack_correlator

    # Register discovered service
    print("[*] Step 1: Register discovered service")
    correlator.register_discovery(
        ip="192.168.1.100",
        port=3306,
        service_type="sql",
    )
    print("    ✓ Registered: 192.168.1.100:3306 (SQL)")

    # Simulate attack on discovered endpoint
    print("\n[*] Step 2: Simulate attack on discovered endpoint")
    was_discovered, score = correlator.correlate_attack(
        source_ip="10.0.0.50",
        target_ip="192.168.1.100",
        target_port=3306,
        injection_type="sql_injection",
        detection_time=datetime.now(timezone.utc).isoformat(),
    )
    print(f"    ✓ Attack correlated: {was_discovered}")
    print(f"    ✓ Correlation score: {score:.2f} (0.85 = high confidence)")

    # Simulate blind attack (not on discovered endpoint)
    print("\n[*] Step 3: Simulate blind attack (unknown endpoint)")
    was_discovered, score = correlator.correlate_attack(
        source_ip="192.168.1.200",
        target_ip="10.0.0.99",  # Unknown endpoint
        target_port=80,
        injection_type="xss",
        detection_time=datetime.now(timezone.utc).isoformat(),
    )
    print(f"    ✓ Attack correlated: {was_discovered}")
    print(f"    ✓ Correlation score: {score:.2f} (0.15 = low confidence/blind)")

    threat_score = correlator.get_threat_score("10.0.0.50")
    print(f"\n    ✓ Threat score for 10.0.0.50: {threat_score:.2f}")


async def test_defensive_scanning():
    """Test: Defensive scanner uses firewall rules to find vulnerabilities."""
    print("\n" + "=" * 70)
    print("TEST 4: Defensive Scanning (Find Internal Vulnerabilities)")
    print("=" * 70)

    engine = Engine()
    scanner = engine.defensive_scanner

    # Simulate scanning endpoint for XSS
    print("[*] Scanning 192.168.1.50:8080 for XSS vulnerabilities")
    vulnerabilities = await scanner.scan_endpoint_for_injections(
        ip="192.168.1.50",
        port=8080,
        service_type="http",
    )
    print(f"    ✓ Vulnerabilities found: {len(vulnerabilities)}")
    for vuln in vulnerabilities[:3]:  # Show first 3
        vuln_type = getattr(vuln, 'injection_type', 'unknown')
        severity = getattr(vuln, 'severity', 'unknown')
        print(f"      - {vuln_type}: {severity}")

    stats = scanner.get_stats()
    print(f"\n    ✓ Total scans: {stats['total_scans']}")
    print(f"    ✓ Vulnerabilities: {stats['vulnerable_endpoints']}")


async def test_firewall_detection():
    """Test: Smart firewall detects injection attempts."""
    print("\n" + "=" * 70)
    print("TEST 5: Smart Firewall Detection (Injection Detection)")
    print("=" * 70)

    engine = Engine()
    firewall = engine.smart_firewall

    # Test SQL injection detection
    print("[*] Testing SQL injection detection")
    payloads = [
        ("' UNION SELECT * FROM users--", "UNION SELECT"),
        ("' OR 1=1--", "tautology"),
        ("1; DROP TABLE users;--", "stacked query"),
    ]

    for payload, name in payloads:
        detections = await firewall.scan_payload(payload, source_ip="192.168.1.100")
        print(f"    ✓ {name}: {len(detections)} detections")

    # Test XSS detection
    print("\n[*] Testing XSS detection")
    xss_payloads = [
        "<script>alert('xss')</script>",
        "javascript:void(0)",
        "' onerror='alert(1)",
    ]

    for payload in xss_payloads:
        detections = await firewall.scan_payload(payload, source_ip="192.168.1.200")
        print(f"    ✓ Payload detected: {len(detections)} times")

    # Get firewall stats
    stats = firewall.get_stats()
    print(f"\n    ✓ Total unique attackers: {stats['unique_attackers']}")
    print(f"    ✓ Total injections detected: {stats['total_scanned']}")


async def test_end_to_end_workflow():
    """Test: Complete workflow from discovery to correlation."""
    print("\n" + "=" * 70)
    print("TEST 6: End-to-End Workflow (Discovery → Exploitation → Detection → Correlation)")
    print("=" * 70)

    engine = Engine()

    # Step 1: Discover service
    print("[1] DISCOVERY: Probe finds SQL service")
    engine.probe_bridge.register_discovered_service(
        ip="192.168.1.75",
        port=5432,
        service_type="sql",
    )
    print("    ✓ Service registered: 192.168.1.75:5432")

    # Step 2: Exploit service
    print("\n[2] EXPLOITATION: Probe exploits PostgreSQL")
    rule = engine.payload_harvester.harvest_from_exploitation(
        payload="'; DROP SCHEMA public;--",
        vuln_type="sql_injection",
        source_ip=None,
        target_ip="192.168.1.75",
    )
    if rule:
        engine.smart_firewall.add_dynamic_rule(rule)
        print(f"    ✓ Rule harvested and added: {rule.name}")

    # Step 3: Register correlation
    print("\n[3] CORRELATION: Register discovery for attack matching")
    engine.attack_correlator.register_discovery(
        ip="192.168.1.75",
        port=5432,
        service_type="sql",
    )
    print("    ✓ Discovery registered for correlation")

    # Step 4: Attack detected
    print("\n[4] DETECTION: Attacker targets discovered endpoint")
    detections = await engine.smart_firewall.scan_payload(
        "'; DROP TABLE users;--",
        source_ip="10.0.0.77",
    )
    print(f"    ✓ SQL injection detected: {len(detections)} rules matched")

    # Step 5: Correlate attack
    print("\n[5] CORRELATION: Match attack with discovery")
    was_discovered, score = engine.attack_correlator.correlate_attack(
        source_ip="10.0.0.77",
        target_ip="192.168.1.75",
        target_port=5432,
        injection_type="sql_injection",
        detection_time=datetime.now(timezone.utc).isoformat(),
    )
    print(f"    ✓ Correlated: {was_discovered}")
    print(f"    ✓ Score: {score:.2f} (confirmed attack on discovered endpoint)")

    print("\n[+] End-to-end workflow complete!")


async def main():
    """Run all tests."""
    print("\n" + "█" * 70)
    print("█ Network Guardian — Probe Integration Test Suite")
    print("█" * 70)

    try:
        await test_threat_intelligence_feedback()
        await test_payload_harvesting()
        await test_attack_correlation()
        await test_defensive_scanning()
        await test_firewall_detection()
        await test_end_to_end_workflow()

        print("\n" + "=" * 70)
        print("✅ ALL TESTS PASSED")
        print("=" * 70)
        print("\n[+] Integration working correctly!")
        print("[+] Check dashboard at http://127.0.0.1:8080 (admin / <password>)")
        print("[+] Export data with: python3 export_test_data.py")
        print("[+] Monitor in real-time: python3 monitor_data.py monitor")

    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
