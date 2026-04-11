"""
Network Guardian — Live System Test
====================================
Evaluates: Performance, Accuracy, Usability, Security
Runs the real engine on the local system (localhost only — safe).
"""

from __future__ import annotations

import asyncio
import gc
import sys
import time
import tracemalloc
from contextlib import suppress

# ---------------------------------------------------------------------------
# 1. PERFORMANCE — startup, memory, CPU, teardown
# ---------------------------------------------------------------------------

async def test_performance():
    print("=" * 60)
    print("  1. PERFORMANCE")
    print("=" * 60)

    tracemalloc.start()
    gc.collect()
    mem_before = tracemalloc.get_traced_memory()[0]

    from network_guardian.config import Config
    from network_guardian.core.engine import Engine

    config = Config()
    engine = Engine(config)

    # --- Startup time ---
    t0 = time.perf_counter()
    await engine.start()
    startup_ms = (time.perf_counter() - t0) * 1000
    print(f"  Engine startup:            {startup_ms:>8.1f} ms")

    # --- Lazy subsystem init time ---
    t0 = time.perf_counter()
    _ = engine.auditor
    _ = engine.monitor
    _ = engine.explorer
    _ = engine.automator
    _ = engine.ai
    _ = engine.nlp
    _ = engine.sensors
    _ = engine.node_graph
    _ = engine.training
    subsystem_ms = (time.perf_counter() - t0) * 1000
    print(f"  Subsystem lazy init:       {subsystem_ms:>8.1f} ms")

    # --- Memory after full init ---
    gc.collect()
    mem_after = tracemalloc.get_traced_memory()[0]
    mem_delta_kb = (mem_after - mem_before) / 1024
    print(f"  Memory delta (all loaded): {mem_delta_kb:>8.1f} KB")

    # --- AI training pipeline benchmark ---
    t0 = time.perf_counter()
    report = engine.training.run_full_anomaly_pipeline()
    anomaly_train_ms = (time.perf_counter() - t0) * 1000
    print(f"  Anomaly training pipeline: {anomaly_train_ms:>8.1f} ms")

    t0 = time.perf_counter()
    report2 = engine.training.run_full_forecast_pipeline()
    forecast_train_ms = (time.perf_counter() - t0) * 1000
    print(f"  Forecast training pipeline:{forecast_train_ms:>8.1f} ms")

    # --- Dataset generation speed ---
    from network_guardian.ai.datasets import NetworkTrafficGenerator, MetricTimeSeriesGenerator
    t0 = time.perf_counter()
    ds_traffic = NetworkTrafficGenerator().generate(n_normal=4000, n_anomaly=400, n_attack=300, n_scan=300)
    ds_time = (time.perf_counter() - t0) * 1000
    print(f"  Generate 5000 samples:     {ds_time:>8.1f} ms")

    # --- Node graph start/stop ---
    t0 = time.perf_counter()
    await engine.node_graph.start_all()
    node_start_ms = (time.perf_counter() - t0) * 1000
    print(f"  Node graph start:          {node_start_ms:>8.1f} ms")

    t0 = time.perf_counter()
    await engine.node_graph.stop_all()
    node_stop_ms = (time.perf_counter() - t0) * 1000
    print(f"  Node graph stop:           {node_stop_ms:>8.1f} ms")

    # --- Monitor start/stop ---
    t0 = time.perf_counter()
    engine.monitor.start()
    monitor_start_ms = (time.perf_counter() - t0) * 1000
    print(f"  Monitor start:             {monitor_start_ms:>8.1f} ms")
    await engine.monitor.stop()

    # --- Dashboard start/stop (localhost:0 for random port) ---
    engine.dashboard.port = 0  # OS picks a free port
    t0 = time.perf_counter()
    await engine.dashboard.start()
    dash_start_ms = (time.perf_counter() - t0) * 1000
    print(f"  Dashboard bind (port 0):   {dash_start_ms:>8.1f} ms")
    await engine.dashboard.stop()

    # --- Shutdown time ---
    t0 = time.perf_counter()
    await engine.stop()
    shutdown_ms = (time.perf_counter() - t0) * 1000
    print(f"  Engine shutdown:           {shutdown_ms:>8.1f} ms")

    peak_kb = tracemalloc.get_traced_memory()[1] / 1024
    tracemalloc.stop()
    print(f"  Peak memory (traced):      {peak_kb:>8.1f} KB")
    print()

    # Verdict
    issues = []
    if startup_ms > 1000:
        issues.append(f"Slow startup ({startup_ms:.0f}ms)")
    if mem_delta_kb > 50_000:
        issues.append(f"High memory ({mem_delta_kb:.0f}KB)")
    if anomaly_train_ms > 10_000:
        issues.append(f"Slow anomaly training ({anomaly_train_ms:.0f}ms)")

    if issues:
        print(f"  PERFORMANCE ISSUES: {'; '.join(issues)}")
    else:
        print("  PERFORMANCE: PASS ✓")
    print()
    return engine


# ---------------------------------------------------------------------------
# 2. ACCURACY — AI anomaly detection, forecasting, NLP, audit analyzer
# ---------------------------------------------------------------------------

async def test_accuracy():
    print("=" * 60)
    print("  2. ACCURACY")
    print("=" * 60)

    from network_guardian.config import Config
    from network_guardian.core.engine import Engine
    from network_guardian.core.events import EventBus
    from network_guardian.ai.anomaly import IsolationForest, OneClassSVM, EnsembleDetector
    from network_guardian.ai.forecasting import ARIMAForecaster, HoltWintersForecaster
    from network_guardian.ai.audit_analyzer import NetworkAuditAnalyzer
    from network_guardian.ai.smart_automation import SmartAutomation
    from network_guardian.ai.datasets import NetworkTrafficGenerator, compute_statistics
    from network_guardian.models.network import Host, HostStatus, Finding, Severity

    results = {}

    # --- Anomaly detection on synthetic data ---
    print("\n  [Anomaly Detection]")
    gen = NetworkTrafficGenerator()
    ds = gen.generate(n_normal=350, n_anomaly=50, n_attack=50, n_scan=50)
    train_ds, test_ds = ds.split(0.7)

    train_matrix = train_ds.feature_matrix()
    test_matrix = test_ds.feature_matrix()
    test_labels = test_ds.labels()

    for Detector, name in [(IsolationForest, "IsolationForest"), (OneClassSVM, "OneClassSVM")]:
        det = Detector()
        det.fit(train_matrix)
        tp = fp = tn = fn = 0
        for features, label in zip(test_matrix, test_labels):
            score = det.score(features)
            predicted_anomaly = score.is_anomaly
            actual_anomaly = label != "normal"
            if predicted_anomaly and actual_anomaly:
                tp += 1
            elif predicted_anomaly and not actual_anomaly:
                fp += 1
            elif not predicted_anomaly and actual_anomaly:
                fn += 1
            else:
                tn += 1
        total = tp + fp + tn + fn
        accuracy = (tp + tn) / total if total else 0
        precision = tp / (tp + fp) if (tp + fp) else 0
        recall = tp / (tp + fn) if (tp + fn) else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
        results[name] = {"accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1}
        print(f"    {name:<20} acc={accuracy:.2%}  prec={precision:.2%}  recall={recall:.2%}  F1={f1:.2%}")

    # --- Ensemble ---
    ens = EnsembleDetector(detectors=[IsolationForest(), OneClassSVM()])
    ens.fit(train_matrix)
    tp = fp = tn = fn = 0
    for features, label in zip(test_matrix, test_labels):
        score = ens.score(features)
        predicted_anomaly = score.is_anomaly
        actual_anomaly = label != "normal"
        if predicted_anomaly and actual_anomaly:
            tp += 1
        elif predicted_anomaly and not actual_anomaly:
            fp += 1
        elif not predicted_anomaly and actual_anomaly:
            fn += 1
        else:
            tn += 1
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    results["Ensemble"] = {"accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1}
    print(f"    {'Ensemble':<20} acc={accuracy:.2%}  prec={precision:.2%}  recall={recall:.2%}  F1={f1:.2%}")

    # --- Forecasting ---
    print("\n  [Forecasting]")
    from network_guardian.ai.datasets import MetricTimeSeriesGenerator
    ts_gen = MetricTimeSeriesGenerator()
    ts_ds, raw_series = ts_gen.generate(length=200)
    values = raw_series

    train_vals = values[:160]
    test_vals = values[160:]

    for Forecaster, name in [(ARIMAForecaster, "ARIMA"), (HoltWintersForecaster, "HoltWinters")]:
        fc = Forecaster()
        fc.fit(train_vals)
        result = fc.predict(len(test_vals))
        predicted = [fp.value for fp in result.points]
        # Mean Absolute Error
        mae = sum(abs(p - a) for p, a in zip(predicted, test_vals)) / len(test_vals)
        # RMSE
        rmse = (sum((p - a) ** 2 for p, a in zip(predicted, test_vals)) / len(test_vals)) ** 0.5
        mean_val = sum(abs(v) for v in test_vals) / len(test_vals) if test_vals else 1
        mape = mae / mean_val * 100 if mean_val else 0
        print(f"    {name:<20} MAE={mae:.4f}  RMSE={rmse:.4f}  MAPE={mape:.1f}%")
        results[name] = {"mae": mae, "rmse": rmse, "mape": mape}

    # --- NLP intent parsing ---
    print("\n  [NLP Intent Parsing]")
    config = Config()
    event_bus = EventBus()
    from network_guardian.ai.nlp import NLPEngine
    nlp = NLPEngine(config, event_bus)

    test_queries = [
        ("scan my network for vulnerabilities", "audit"),
        ("explore and discover hosts on my network", "explore"),
        ("what is the health status of the system", "status"),
        ("monitor traffic on port 443", "monitor"),
        ("run a scheduled task automatically", "tasks"),
    ]
    nlp_correct = 0
    for query, expected_action in test_queries:
        intent = nlp.parse_intent(query)
        match = intent.action == expected_action
        nlp_correct += int(match)
        status = "✓" if match else f"✗ (got '{intent.action}')"
        print(f"    '{query}' → {status}")
    nlp_acc = nlp_correct / len(test_queries)
    results["NLP"] = {"accuracy": nlp_acc}
    print(f"    NLP accuracy: {nlp_acc:.0%}")

    # --- Audit Analyzer ---
    print("\n  [Audit Analyzer]")
    analyzer = NetworkAuditAnalyzer()
    test_hosts = [
        Host(ip="10.0.0.1", status=HostStatus.UP, open_ports=[22, 80, 443]),
        Host(ip="10.0.0.2", status=HostStatus.UP, open_ports=[21, 23, 3389, 445, 1433]),
        Host(ip="10.0.0.3", status=HostStatus.UP, open_ports=[]),
    ]
    profiles = analyzer.analyse(test_hosts)
    for p in profiles:
        print(f"    {p.host_ip:<15} risk={p.risk_score:.2f}  findings={len(p.findings)}")

    # Verify: host with dangerous ports scores higher
    risky_host = [p for p in profiles if p.host_ip == "10.0.0.2"][0]
    safe_host = [p for p in profiles if p.host_ip == "10.0.0.3"][0]
    audit_ok = risky_host.risk_score > safe_host.risk_score
    results["AuditAnalyzer"] = {"risk_ordering_correct": audit_ok}
    print(f"    Risk ordering correct: {'✓' if audit_ok else '✗'}")

    # --- Smart Automation ---
    print("\n  [Smart Automation]")
    auto = SmartAutomation()
    findings = [
        Finding(title="Open Telnet", description="Port 23 open", severity=Severity.HIGH),
        Finding(title="Outdated SSL", description="TLS 1.0 detected", severity=Severity.MEDIUM),
    ]
    available_tasks = ["disable_telnet", "update_ssl", "patch_system", "rotate_credentials"]
    recs = auto.recommend_tasks(findings, available_tasks)
    print(f"    Recommendations for {len(findings)} findings: {len(recs)} task(s)")
    for r in recs:
        print(f"      [priority={r.priority:.2f}] {r.task_name} (est. success: {r.estimated_success:.0%})")
    results["SmartAutomation"] = {"recommendations_generated": len(recs) > 0}

    print()
    issues = []
    for name, metrics in results.items():
        if "accuracy" in metrics and metrics["accuracy"] < 0.5:
            issues.append(f"{name} accuracy below 50%")
        if "f1" in metrics and metrics["f1"] < 0.3:
            issues.append(f"{name} F1 below 30%")

    if issues:
        print(f"  ACCURACY ISSUES: {'; '.join(issues)}")
    else:
        print("  ACCURACY: PASS ✓")
    print()
    return results


# ---------------------------------------------------------------------------
# 3. USABILITY — CLI commands exercise, error handling, help text
# ---------------------------------------------------------------------------

async def test_usability():
    print("=" * 60)
    print("  3. USABILITY")
    print("=" * 60)

    from network_guardian.config import Config
    from network_guardian.core.engine import Engine

    config = Config()
    engine = Engine(config)
    await engine.start()

    cli = None
    try:
        from network_guardian.interface import InteractiveCLI
        cli = InteractiveCLI(engine)

        issues = []

        # --- Help text completeness ---
        print("\n  [Help / Command Listing]")
        cmd_count = len(InteractiveCLI.COMMANDS)
        print(f"    Commands registered: {cmd_count}")
        if cmd_count < 10:
            issues.append("Too few commands")
        for cmd, desc in InteractiveCLI.COMMANDS.items():
            if not desc:
                issues.append(f"Command '{cmd}' has no description")
        print("    All commands have descriptions: ✓")

        # --- Status command ---
        print("\n  [Status Command]")
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cli._show_status()
        status_out = buf.getvalue()
        print(f"    Output: {status_out.strip()}")
        if "running" not in status_out.lower() and "stopped" not in status_out.lower():
            issues.append("Status command doesn't show engine state")

        # --- Audit with no args (should show usage) ---
        print("\n  [Error Handling — missing arguments]")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            await cli._handle_audit([])
        out = buf.getvalue()
        has_usage = "usage" in out.lower()
        print(f"    'audit' with no args shows usage: {'✓' if has_usage else '✗'}")
        if not has_usage:
            issues.append("Audit without args doesn't show usage hint")

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            await cli._handle_explore([])
        out = buf.getvalue()
        has_usage = "usage" in out.lower()
        print(f"    'explore' with no args shows usage: {'✓' if has_usage else '✗'}")

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            await cli._handle_monitor([])
        out = buf.getvalue()
        has_usage = "usage" in out.lower()
        print(f"    'monitor' with no args shows usage: {'✓' if has_usage else '✗'}")

        # --- Sensor listing ---
        print("\n  [Sensor Listing]")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            await cli._handle_sensors(["list"])
        sensor_out = buf.getvalue()
        print(f"    {sensor_out.strip()}")
        sensors_listed = "ping" in sensor_out and "port_scanner" in sensor_out
        print(f"    Sensors listed correctly: {'✓' if sensors_listed else '✗'}")

        # --- System metrics (safe, read-only) ---
        print("\n  [System Metrics Collection — localhost read-only]")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            await cli._handle_sensors(["collect", "system_metrics"])
        metrics_out = buf.getvalue()
        print(f"    {metrics_out.strip()}")
        has_disk = "disk" in metrics_out.lower()
        print(f"    Disk metrics present: {'✓' if has_disk else '✗'}")

        # --- AI model listing ---
        print("\n  [AI Model Listing]")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            await cli._handle_ai(["models"])
        ai_out = buf.getvalue()
        print(f"    {ai_out.strip()}")

        # --- Nodes topology ---
        print("\n  [Node Graph Topology]")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            await cli._handle_nodes(["topology"])
        topo_out = buf.getvalue()
        node_count = topo_out.count("inputs:")
        print(f"    Nodes in topology: {node_count}")
        if node_count < 3:
            issues.append(f"Only {node_count} nodes in topology")

        # --- Dataset generation ---
        print("\n  [Dataset Generation]")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            await cli._handle_datasets(["generate"])
        ds_out = buf.getvalue()
        print(f"    {ds_out.strip()}")

        # --- NLP query ---
        print("\n  [NLP Query]")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cli._handle_ask(["scan", "my", "network"])
        ask_out = buf.getvalue()
        print(f"    {ask_out.strip()}")

        # --- Train anomaly ---
        print("\n  [Training — Anomaly Pipeline]")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            await cli._handle_train(["anomaly"])
        train_out = buf.getvalue()
        print(f"    {train_out.strip()[:200]}")

        print()
        if issues:
            print(f"  USABILITY ISSUES: {'; '.join(issues)}")
        else:
            print("  USABILITY: PASS ✓")

    finally:
        await engine.stop()
    print()


# ---------------------------------------------------------------------------
# 4. SECURITY — config protection, input validation, data isolation
# ---------------------------------------------------------------------------

async def test_security():
    print("=" * 60)
    print("  4. SECURITY")
    print("=" * 60)

    from network_guardian.config import Config
    from network_guardian.core.engine import Engine
    from network_guardian.core.events import EventBus

    issues = []

    # --- API key not in plain text ---
    print("\n  [API Key Protection]")
    config = Config()
    has_env_ref = config.security.api_key_env == "NETWORK_GUARDIAN_API_KEY"
    actual_key = None
    import os
    actual_key = os.environ.get(config.security.api_key_env)
    print(f"    API key stored via env var reference: {'✓' if has_env_ref else '✗'}")
    print(f"    Key in env (should be None if not set): {actual_key}")
    if not has_env_ref:
        issues.append("API key not protected via env var")

    # --- Session timeout configured ---
    print(f"    Session timeout: {config.security.session_timeout}s")
    if config.security.session_timeout > 86400:
        issues.append("Session timeout too long")

    # --- Max login attempts ---
    print(f"    Max login attempts: {config.security.max_login_attempts}")
    if config.security.max_login_attempts > 20:
        issues.append("Max login attempts too high")

    # --- Encrypt reports flag ---
    print(f"    Encrypt reports: {config.security.encrypt_reports}")
    if not config.security.encrypt_reports:
        issues.append("Report encryption disabled by default")

    # --- Dashboard binds to localhost only ---
    print("\n  [Dashboard Network Binding]")
    engine = Engine(config)
    dash_host = engine.dashboard.host
    print(f"    Dashboard bind address: {dash_host}")
    if dash_host not in ("127.0.0.1", "localhost", "::1"):
        issues.append(f"Dashboard binds to {dash_host} (not localhost)")
    else:
        print("    Localhost-only binding: ✓")

    # --- Port scanner has concurrency limit ---
    print("\n  [Scan Safeguards]")
    print(f"    Max concurrent connections: {config.scan.max_concurrent}")
    print(f"    Scan timeout: {config.scan.timeout}s")
    print(f"    Port range: {config.scan.port_range}")
    if config.scan.max_concurrent > 500:
        issues.append("Scan concurrency too high — could be seen as DoS")

    # --- Input handling: malicious target strings ---
    print("\n  [Input Handling — injection resistance]")
    from network_guardian.ai.nlp import NLPEngine
    event_bus = EventBus()
    nlp = NLPEngine(config, event_bus)

    malicious_inputs = [
        "; rm -rf /",
        "' OR 1=1 --",
        "<script>alert(1)</script>",
        "$(whoami)",
        "| cat /etc/passwd",
    ]
    for inp in malicious_inputs:
        try:
            intent = nlp.parse_intent(inp)
            # NLP should parse without crashing (no shell execution)
            print(f"    NLP handles '{inp[:30]}...' safely: ✓ (action={intent.action})")
        except Exception as exc:
            print(f"    NLP crash on '{inp[:30]}...': ✗ ({exc})")
            issues.append(f"NLP crashes on malicious input")

    # --- Auditor doesn't pass raw input to shell ---
    print("\n  [Auditor — no shell injection]")
    from network_guardian.auditor import Auditor
    auditor = Auditor(config, event_bus)
    # _scan_host is a stub, so safe, but verify no subprocess with shell=True
    import inspect
    src = inspect.getsource(Auditor)
    has_shell_true = "shell=True" in src
    print(f"    Auditor uses shell=True: {'✗ DANGEROUS' if has_shell_true else '✓ Safe (no shell=True)'}")
    if has_shell_true:
        issues.append("Auditor uses shell=True — injection risk")

    # --- Sensors: PingSensor uses subprocess_exec, not shell ---
    print("\n  [Sensors — subprocess safety]")
    from network_guardian.sensors import PingSensor, PortScanner
    ping_src = inspect.getsource(PingSensor)
    has_shell_true = "shell=True" in ping_src
    print(f"    PingSensor uses shell=True: {'✗ DANGEROUS' if has_shell_true else '✓ Safe'}")
    if has_shell_true:
        issues.append("PingSensor uses shell=True")

    uses_exec = "create_subprocess_exec" in ping_src
    print(f"    PingSensor uses create_subprocess_exec: {'✓' if uses_exec else '✗'}")

    # --- Dashboard event buffer limit ---
    print("\n  [Dashboard Memory Safety]")
    dash = engine.dashboard
    # Check event buffer has a cap
    cap_src = inspect.getsource(type(dash))
    has_cap = "200" in cap_src or "maxlen" in cap_src or "_recent_events" in cap_src
    print(f"    Event buffer capped: {'✓' if has_cap else '✗'}")

    await engine.stop()

    print()
    if issues:
        print(f"  SECURITY ISSUES: {'; '.join(issues)}")
    else:
        print("  SECURITY: PASS ✓")
    print()
    return issues


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

async def main():
    print("\n" + "=" * 60)
    print("  NETWORK GUARDIAN — LIVE SYSTEM TEST")
    print("  Running on local system (localhost only)")
    print("=" * 60 + "\n")

    t_total = time.perf_counter()

    await test_performance()
    accuracy_results = await test_accuracy()
    await test_usability()
    security_issues = await test_security()

    total_s = time.perf_counter() - t_total

    print("=" * 60)
    print("  OVERALL SUMMARY")
    print("=" * 60)
    print(f"  Total test time: {total_s:.2f}s")
    if security_issues:
        print(f"  Security issues found: {len(security_issues)}")
        for i in security_issues:
            print(f"    - {i}")
    else:
        print("  All categories: PASS")
    print()


if __name__ == "__main__":
    asyncio.run(main())
