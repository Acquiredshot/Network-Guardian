(() => {
  "use strict";

  const { $, $$, text, format } = window.NSEP;

  async function loadDashboardSummary() {
    try {
      const response = await NSEP.requestJson("/api/v1/dashboard/summary");
      if (!response.ok || !response.data) throw new Error(`Dashboard summary returned HTTP ${response.status}.`);
      const summary = response.data;
      text($("#eventCount"), format(summary.total_events));
      text($("#eventCount").nextElementSibling, "Persisted event records");
      text($("#threatCount"), format(summary.active_threats));
      text($("#threatCount").nextElementSibling, "Detections on active incidents");
      text($("#incidentCount"), format(summary.active_incidents));
      text($("#incidentCount").nextElementSibling, "Open or investigating");
      const testCounts = [summary.test_event_count, summary.test_active_detections, summary.test_active_incidents].map(value => Number(value) || 0);
      const testNotice = $("#testDataNotice");
      if (testCounts.some(count => count > 0)) {
        const parts = [];
        if (testCounts[0]) parts.push(`${format(testCounts[0])} test event${testCounts[0] === 1 ? "" : "s"}`);
        if (testCounts[1]) parts.push(`${format(testCounts[1])} related detection${testCounts[1] === 1 ? "" : "s"}`);
        if (testCounts[2]) parts.push(`${format(testCounts[2])} related active incident${testCounts[2] === 1 ? "" : "s"}`);
        text(testNotice, `Verification data is included in the totals: ${parts.join(" · ")}.`);
        testNotice.hidden = false;
      } else {
        testNotice.hidden = true;
      }
      NSEP.renderActivityChart($("#heatmapChart"), $("#heatmapEmpty"), summary.event_activity || [], "No events in this time window");
      NSEP.renderActivityChart($("#trafficChart"), $("#trafficEmpty"), summary.event_activity || [], "No events in this time window");
      NSEP.renderRuleSummary($("#ruleSummary"), $("#threatSummaryEmpty"), summary.active_detections_by_rule || []);
    } catch (error) {
      for (const id of ["#eventCount", "#threatCount", "#incidentCount"]) {
        text($(id), "N/A");
        text($(id).nextElementSibling, "Summary unavailable");
      }
      NSEP.renderActivityChart($("#heatmapChart"), $("#heatmapEmpty"), [], "Event history unavailable");
      NSEP.renderActivityChart($("#trafficChart"), $("#trafficEmpty"), [], "Event activity unavailable");
      const empty = $("#threatSummaryEmpty");
      empty.hidden = false;
      $("#ruleSummary").hidden = true;
      text($("strong", empty), error.message);
    }
  }

  function setTelemetry(name, state, detail, label) {
    NSEP.setStatusRow($(`[data-service="${name}"]`), state, detail, label);
  }

  async function refreshTelemetry(probe) {
    const button = $("#refreshTelemetry");
    button.disabled = true;
    $("#telemetryError").hidden = true;
    for (const name of ["api", "database", "broker", "cache"]) setTelemetry(name, "unknown", "Checking", "…");
    const { health, readiness, diagnostics, healthOk, healthError, pipeline, failures } = await (probe || NSEP.probeHealth());

    setTelemetry("api", healthOk ? "ready" : health && !health.ok ? "degraded" : "offline",
      health ? `${health.elapsed.toFixed(0)} ms · /api/health` : (healthError || "Health probe unavailable"),
      healthOk ? "HEALTHY" : health && !health.ok ? "DEGRADED" : "OFFLINE");

    const dependencyMap = diagnostics?.data?.dependencies;
    const readinessServices = readiness?.data?.services || readiness?.data?.error?.details;
    for (const name of ["database", "broker", "cache"]) {
      const diagnostic = dependencyMap && typeof dependencyMap === "object" ? dependencyMap[name] : undefined;
      const reportedState = diagnostic?.status || (readinessServices && readinessServices[name]);
      if (!reportedState) {
        setTelemetry(name, "unknown", "Not reported", "N/A");
        continue;
      }
      const normalized = stateName(reportedState);
      const latency = Number(diagnostic?.latency_ms);
      const detail = Number.isFinite(latency) ? `${latency.toFixed(2)} ms latency` : "Dependency probe";
      setTelemetry(name, normalized, detail, normalized === "ready" ? "READY" : normalized === "degraded" ? "ELEVATED" : normalized === "offline" ? "OFFLINE" : "N/A");
    }

    for (const [name, detail] of Object.entries({
      ingestion: "No dedicated probe",
      detection: "No worker health probe",
      "incident-processing": "No worker health probe"
    })) setTelemetry(name, "unknown", detail, "N/A");

    $("#pipelineKpi").dataset.state = pipeline.state;
    text($("#pipelineValue"), pipeline.label);
    text($("#pipelineNote"), pipeline.detail);

    if (failures.length) {
      const notice = $("#telemetryError");
      notice.hidden = false;
      text(notice, `Some telemetry could not be loaded: ${failures.join(" ")}`);
    }
    text($("#checkedAt"), `Checked ${new Date().toLocaleTimeString()}`);
    button.disabled = false;
  }

  function stateName(raw) {
    const value = String(raw || "unknown").toLowerCase();
    if (["ready", "healthy", "ok", "operational", "available"].includes(value)) return "ready";
    if (["elevated", "degraded", "warning", "warn", "partial"].includes(value)) return "degraded";
    if (["offline", "unavailable", "down", "failed", "critical"].includes(value)) return "offline";
    return "unknown";
  }

  async function loadIntegrations() {
    const integrations = await NSEP.loadIntegrations(document, $("#integrationsSummaryTag"));
    for (const label of $$("[data-integration-label]")) {
      const item = integrations?.find(candidate => candidate.key === label.dataset.integrationLabel);
      if (!item) { text(label, "Status unavailable"); continue; }
      if (!item.configured) text(label, "Disabled");
      else if (item.reachable) text(label, "Reachable");
      else if (item.reachable === false) text(label, "Unreachable");
      else text(label, item.detail);
    }
  }

  NSEP.renderWorkerRules($("[data-worker-rules]"));
  $("#refreshTelemetry").addEventListener("click", () => void refreshTelemetry());
  void refreshTelemetry(NSEP.health);
  void loadDashboardSummary();
  void loadIntegrations();
  window.setInterval(loadDashboardSummary, 30000);
  window.setInterval(loadIntegrations, 30000);
})();
