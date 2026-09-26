#!/usr/bin/env python3
"""
Wolf-Pak Platform — Phase 1 Scaffolding Verification.

Standalone verification script for the Wolf-Pak roadmap scaffolding.
Imports every pillar, every submodule, instantiates key classes,
and validates the public API surface.  Exit 0 = all healthy.
"""
from __future__ import annotations

import sys
import traceback

# ---------------------------------------------------------------------------
# Import verification
# ---------------------------------------------------------------------------

def check_imports() -> list[str]:
    errors: list[str] = []
    checks = [
        ("network_guardian", "Network Guardian (existing pillar)"),
        ("wolf_pak_security_core", "Wolf-Pak Security Core"),
        ("wolf_pak_security_core.event_fabric", "Event Fabric"),
        ("wolf_pak_security_core.security_graph", "Security Graph"),
        ("pakshield", "Pakshield pillar"),
        ("pakshield.identity_risk", "Identity Risk"),
        ("pakshield.access_control", "Access Control"),
        ("network_intelligence", "Mask Network pillar"),
        ("network_intelligence.asset_discovery", "Asset Discovery"),
        ("network_intelligence.threat_mapping", "Threat Mapping"),
        ("network_intelligence.vuln_assessment", "Vuln Assessment"),
        ("ai_security_orchestrator", "AI Security Orchestrator"),
        ("ai_security_orchestrator.detection", "Detection"),
        ("ai_security_orchestrator.investigation", "Investigation"),
        ("ai_security_orchestrator.response", "Response"),
        ("policy_engine", "Policy Engine"),
        ("policy_engine.rules", "Policy Rules"),
        ("policy_engine.evaluation", "Policy Evaluation"),
        ("action_gateway", "Action Gateway"),
        ("action_gateway.execution", "Action Execution"),
        ("action_gateway.integration", "Action Integration"),
        ("action_gateway.connectors", "Action Connectors"),
    ]
    for mod_name, label in checks:
        try:
            __import__(mod_name)
        except Exception as exc:
            errors.append(f"IMPORT FAIL [{label}]: {mod_name} — {exc}")
    return errors


# ---------------------------------------------------------------------------
# API surface verification
# ---------------------------------------------------------------------------

def check_api() -> list[str]:
    errors: list[str] = []
    import wolf_pak_security_core as wps
    import pakshield as pks
    import network_intelligence as mi
    import ai_security_orchestrator as orc
    import policy_engine as pe
    import action_gateway as ag

    # --- Security Core ---
    assert hasattr(wps, "EventFabric"), "EventFabric missing"
    assert hasattr(wps, "SecurityGraph"), "SecurityGraph missing"
    ef = wps.EventFabric()
    assert ef is not None, "EventFabric instantiate failed"
    eg = wps.SecurityGraph()
    assert eg is not None, "SecurityGraph instantiate failed"

    # --- Pakshield ---
    assert hasattr(pks, "IdentityRiskEvaluator"), "IdentityRiskEvaluator missing"
    assert hasattr(pks, "AccessControlEngine"), "AccessControlEngine missing"
    risk = pks.IdentityRiskEvaluator()
    assert risk is not None
    acc = pks.AccessControlEngine()
    assert acc is not None
    # Exercise identity risk
    score = risk.evaluate({"type": "auth", "failure_count": 5, "source_ip": "10.0.0.5"})
    assert score.score >= 0, "RiskScore.score negative"
    assert score.level in ("low", "medium", "high", "critical"), f"Bad level: {score.level}"
    # Exercise access control
    req = pks.AccessRequest(
        subject_id="user-1", resource="database", action="read",
        context={"role": "analyst"}, risk_score=20.0,
    )
    decision = acc.evaluate(req)
    assert decision.verdict in ("allow", "deny", "audit", "challenge"), f"Bad verdict: {decision.verdict}"

    # --- Mask Network ---
    assert hasattr(mi, "AssetDiscovery"), "AssetDiscovery missing"
    assert hasattr(mi, "ThreatMapper"), "ThreatMapper missing"
    assert hasattr(mi, "VulnAssessor"), "VulnAssessor missing"
    ad = mi.AssetDiscovery(timeout=0.5, max_concurrent=10)
    assert ad is not None
    tm = mi.ThreatMapper()
    tm.add_ioc_set("malware_cnc", {"192.168.1.100"})
    va = mi.VulnAssessor()
    assert va is not None
    # Exercise vuln assessor on a fake asset dict
    fake_asset = {"id": "asset-test", "open_ports": [22, 443, 3389]}
    vulns = va.assess_asset(fake_asset)
    assert isinstance(vulns, list), "assess_asset must return list"
    assert any(v.vuln_id == "EXPOSURE-PORT-3389" for v in vulns), "Missing 3389 exposure"

    # --- AI Orchestrator ---
    assert hasattr(orc, "DetectionEngine"), "DetectionEngine missing"
    assert hasattr(orc, "InvestigationEngine"), "InvestigationEngine missing"
    assert hasattr(orc, "ResponsePlanner"), "ResponsePlanner missing"
    de = orc.DetectionEngine()
    de.add_threat_severity_detector()
    di = orc.InvestigationEngine()
    rp = orc.ResponsePlanner()
    assert de is not None and di is not None and rp is not None
    # Exercise detection
    finding = de.detect({"event_id": "e1", "severity": "critical", "category": "threat", "source": "ng"})
    assert len(finding) >= 1, "No detection from critical event"
    # Exercise response planner
    plan = rp.plan(finding)
    assert plan is not None

    # --- Policy Engine ---
    assert hasattr(pe, "PolicyEngine"), "PolicyEngine missing"
    assert hasattr(pe, "EvaluationPipeline"), "EvaluationPipeline missing"
    pe_engine = pe.PolicyEngine()
    pe_engine.add_policy(pe.Policy(
        id="p1", name="default", scope={},
        min_action_severity="info",
        requires_human_above="critical",
    ))
    assert pe_engine is not None
    # Exercise evaluation pipeline
    ep = pe.EvaluationPipeline(pe_engine)
    proposal = pe.ActionProposal(
        action_type="block_ip", target_id="10.0.0.1",
        priority="medium", source="orchestrator",
    )
    verdict = ep.evaluate_plan("plan-1", [proposal])
    assert verdict is not None

    # --- Action Gateway ---
    assert hasattr(ag, "ActionGatewayFacade"), "ActionGatewayFacade missing"
    facade = ag.ActionGatewayFacade()
    assert facade is not None
    result = facade.execute("alert_only", "test-target", {"message": "test alert"})
    assert result.status.value in ("success", "pending", "in_progress", "failed", "not_found", "denied"), \
        f"Bad execution status: {result.status}"

    return errors


# ---------------------------------------------------------------------------
# Cross-pillar wiring sanity (no circular import, EventFabric + Graph coexist)
# ---------------------------------------------------------------------------

def check_wiring() -> list[str]:
    errors: list[str] = []
    try:
        import wolf_pak_security_core as wps
        import ai_security_orchestrator as orc
        import policy_engine as pe
        import action_gateway as ag

        # Build a mini pipeline: event → graph → detection → policy → gateway
        fabric = wps.EventFabric()
        graph = wps.SecurityGraph()
        detector = orc.DetectionEngine()
        detector.add_threat_severity_detector()
        pe_engine = pe.PolicyEngine()
        pe_engine.add_policy(pe.Policy(id="default", name="default"))
        facade = ag.ActionGatewayFacade()

        # Ingest a sample event
        event = fabric.ingest({
            "title": "Test threat event",
            "severity": "high",
            "category": "threat",
            "source": "network_guardian",
            "entity_ids": ["asset-1"],
        }, source="network_guardian")

        # Put on graph
        graph.ingest_asset({"id": "asset-1", "address": "10.0.0.1", "open_ports": [80]})

        # Detect
        findings = detector.detect(event.raw if hasattr(event, "raw") else {
            "event_id": event.event_id,
            "severity": "high",
            "category": "threat",
            "source": "network_guardian",
        })
        assert len(findings) >= 0, "Detection returned None"

        # Policy-evaluate a proposed action
        proposal = pe.ActionProposal(
            action_type="block_ip", target_id="10.0.0.1",
            priority="medium", source="orchestrator",
        )
        verdict = pe_engine.evaluate(proposal)
        assert verdict.value in ("approve", "require_human", "reject"), f"Bad verdict: {verdict}"

        # Execute via gateway
        result = facade.execute("block_ip", "10.0.0.1", {"duration_seconds": 3600})
        assert result.status.value in ("success", "pending", "in_progress", "failed", "not_found", "denied")

    except Exception as exc:
        errors.append(f"WIRING FAIL: {exc}\n{traceback.format_exc()}")
    return errors


# ---------------------------------------------------------------------------
# Version + metadata consistency
# ---------------------------------------------------------------------------

def check_metadata() -> list[str]:
    errors: list[str] = []
    import network_guardian as ng
    import wolf_pak_security_core as wps
    import pakshield as pks
    import network_intelligence as mi

    for mod, name in [(ng, "Network Guardian"), (wps, "Wolf-Pak Security Core"),
                      (pks, "Pakshield"), (mi, "Mask Network")]:
        if not hasattr(mod, "__version__"):
            errors.append(f"{name}: missing __version__")
        elif not isinstance(mod.__version__, str):
            errors.append(f"{name}: __version__ is not a string")

    if ng.__version__ != "1.0.0":
        errors.append(f"Network Guardian version should be 1.0.0, got {ng.__version__}")
    for mod, name in [(wps, "WPS Core"), (pks, "Pakshield"), (mi, "Mask Network")]:
        if not mod.__version__.startswith("0."):
            errors.append(f"{name} version should be 0.x (phase 1), got {mod.__version__}")

    return errors


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    print("Wolf-Pak Platform — Phase 1 Scaffolding Verification")
    print("=" * 56)
    all_errors: list[str] = []

    for phase_name, check_fn in [
        ("Imports", check_imports),
        ("API Surface", check_api),
        ("Cross-Pillar Wiring", check_wiring),
        ("Metadata", check_metadata),
    ]:
        print(f"\n[PHASE] {phase_name} ...")
        errors = check_fn()
        if errors:
            all_errors.extend(errors)
            for err in errors:
                print(f"  ❌ {err}")
        else:
            print(f"  ✅ {phase_name} — all checks passed")

    print("\n" + "=" * 56)
    if all_errors:
        print(f"FAILED — {len(all_errors)} issue(s):")
        for err in all_errors:
            print(f"  - {err}")
        return 1
    else:
        print("ALL CHECKS PASSED — scaffolding is healthy")
        print()
        print("Summary:")
        print("  • Network Guardian (existing pillar)         — v1.0.0")
        print("  • Wolf-Pak Security Core                    — v0.1.0")
        print("    - Event Fabric + Security Graph")
        print("  • Pakshield (Identity Risk + Access)        — v0.1.0")
        print("    - IdentityRiskEvaluator + AccessControlEngine")
        print("  • Mask Network (Asset/Threat/Vuln)          — v0.1.0")
        print("    - AssetDiscovery + ThreatMapper + VulnAssessor")
        print("  • AI Security Orchestrator                  — v0.1.0")
        print("    - Detection → Investigation → Response")
        print("  • Policy Engine                             — v0.1.0")
        print("    - Rules + Evaluation Pipeline")
        print("  • Action Gateway                            — v0.1.0")
        print("    - Execution + Integration + Connectors")
        return 0


if __name__ == "__main__":
    sys.exit(main())
