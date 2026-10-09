(() => {
  "use strict";

  const { $, text, format, countOf, fetchPage, SEVERITIES } = window.NSEP;
  const sampleSize = 100;
  const eventStatuses = ["accepted", "published", "processing", "processed", "failed"];
  const incidentStatuses = ["open", "investigating", "resolved"];
  const riskBands = [["Critical (75-100)", 75, 100, "critical"], ["High (50-74)", 50, 74, "high"], ["Medium (25-49)", 25, 49, "medium"], ["Low (0-24)", 0, 24, "low"]];
  let report = null;

  const counts = (endpoint, key, values) => Promise.all(values.map(value => countOf(endpoint, { [key]: value })));
  const rows = (labels, values, tones = labels) => labels.map((label, index) => ({ label: label.toUpperCase(), count: values[index], tone: tones[index] }));

  // Each section settles independently so one failing endpoint does not blank the report.
  async function section(name, loader) {
    try {
      return await loader();
    } catch (error) {
      const container = $(`[data-breakdown="${name}"]`);
      if (container) NSEP.showDataState(container, "API not available", "Statistics unavailable", error.message);
      return { error: error.message };
    }
  }

  function trend(name, buckets, coverage, emptyMessage, unit) {
    NSEP.renderActivityChart($(`[data-chart="${name}"]`), $(`[data-empty="${name}"]`), buckets, emptyMessage, unit);
    if (coverage !== undefined) text($(`[data-coverage="${name}"]`), coverage);
  }

  async function buildReport() {
    $("#exportJson").disabled = true;
    $("#exportCsv").disabled = true;
    text($("#reportGenerated"), "Generating report…");
    const result = { generated_at: new Date().toISOString(), statistics: {}, trends: {} };

    const [summary, eventsByStatus, eventsBySeverity, detections, incidents, detectionSample, incidentSample, activeIncidents] = await Promise.all([
      section("summary", async () => {
        const response = await NSEP.requestJson("/api/v1/dashboard/summary");
        if (!response.ok || !response.data) throw new Error(`Dashboard summary returned HTTP ${response.status}.`);
        return response.data;
      }),
      section("eventsByStatus", () => counts("/api/v1/events", "status", eventStatuses)),
      section("eventsBySeverity", () => counts("/api/v1/events", "severity", SEVERITIES)),
      section("detectionsBySeverity", async () => {
        const [total, bySeverity, byRule] = await Promise.all([
          countOf("/api/v1/detections"),
          counts("/api/v1/detections", "severity", SEVERITIES),
          counts("/api/v1/detections", "rule", NSEP.WORKER_RULES.map(item => item.rule))
        ]);
        return { total, bySeverity, byRule };
      }),
      section("incidentsByStatus", () => counts("/api/v1/incidents", "status", incidentStatuses)),
      section("detectionSample", () => fetchPage("/api/v1/detections", { limit: sampleSize })),
      section("riskBands", () => fetchPage("/api/v1/incidents", { limit: sampleSize })),
      section("activeRisk", () => Promise.all(["open", "investigating"].map(status => fetchPage("/api/v1/incidents", { status, limit: sampleSize }))))
    ]);

    const totalEvents = summary.error ? null : summary.total_events;
    text($('[data-stat="events"]'), totalEvents === null ? "N/A" : format(totalEvents));
    if (!eventsByStatus.error) {
      NSEP.renderBreakdown($('[data-breakdown="eventsByStatus"]'), rows(eventStatuses, eventsByStatus));
      result.statistics.events_by_status = Object.fromEntries(eventStatuses.map((status, index) => [status, eventsByStatus[index]]));
    }
    if (!eventsBySeverity.error) {
      const classified = eventsBySeverity.reduce((sum, count) => sum + count, 0);
      const severityRows = rows(SEVERITIES, eventsBySeverity);
      // Severity comes from detections; events without one are unclassified.
      if (totalEvents !== null) severityRows.push({ label: "UNCLASSIFIED", count: Math.max(0, totalEvents - classified) });
      NSEP.renderBreakdown($('[data-breakdown="eventsBySeverity"]'), severityRows);
      result.statistics.events_by_severity = Object.fromEntries(severityRows.map(row => [row.label.toLowerCase(), row.count]));
    }
    if (!detections.error) {
      text($('[data-stat="detections"]'), format(detections.total));
      NSEP.renderBreakdown($('[data-breakdown="detectionsBySeverity"]'), rows(SEVERITIES, detections.bySeverity));
      const ruleRows = NSEP.WORKER_RULES.map(({ rule, severity }, index) => ({ label: rule, count: detections.byRule[index], tone: severity }));
      const other = detections.total - detections.byRule.reduce((sum, count) => sum + count, 0);
      if (other > 0) ruleRows.push({ label: "OTHER RULES", count: other });
      NSEP.renderBreakdown($('[data-breakdown="detectionsByRule"]'), ruleRows);
      result.statistics.detections_total = detections.total;
      result.statistics.detections_by_severity = Object.fromEntries(SEVERITIES.map((severity, index) => [severity, detections.bySeverity[index]]));
      result.statistics.detections_by_rule = Object.fromEntries(ruleRows.map(row => [row.label, row.count]));
    } else {
      text($('[data-stat="detections"]'), "N/A");
      NSEP.showDataState($('[data-breakdown="detectionsByRule"]'), "API not available", "Statistics unavailable", detections.error);
    }
    if (!incidents.error) {
      text($('[data-stat="incidents"]'), format(incidents.reduce((sum, count) => sum + count, 0)));
      NSEP.renderBreakdown($('[data-breakdown="incidentsByStatus"]'), rows(incidentStatuses, incidents, ["open", "investigating", "resolved"]));
      result.statistics.incidents_by_status = Object.fromEntries(incidentStatuses.map((status, index) => [status, incidents[index]]));
    } else {
      text($('[data-stat="incidents"]'), "N/A");
    }

    if (!incidentSample.error) {
      const bandCounts = riskBands.map(([, min, max]) => incidentSample.items.filter(item => item.risk >= min && item.risk <= max).length);
      NSEP.renderBreakdown($('[data-breakdown="riskBands"]'), riskBands.map(([label, , , tone], index) => ({ label, count: bandCounts[index], tone })));
      const coverage = NSEP.coverageLabel(incidentSample.total, incidentSample.items.length, "incidents");
      text($('[data-coverage="riskBands"]'), coverage);
      result.statistics.incident_risk_bands = { coverage, ...Object.fromEntries(riskBands.map(([label], index) => [label, bandCounts[index]])) };
      // Incidents are listed by status then update time, so a partial sample is not "latest created".
      const incidentCoverage = incidentSample.total <= incidentSample.items.length ? coverage : `Partial · ${format(incidentSample.items.length)} of ${format(incidentSample.total)} incidents sampled · no incident trend endpoint`;
      const buckets = NSEP.bucketByHour(incidentSample.items, "created_at");
      trend("incidents", buckets, incidentCoverage, "No incidents created in the last 24 hours", "incidents");
      result.trends.incidents_per_hour = { coverage: incidentCoverage, buckets };
    } else {
      trend("incidents", [], `API NOT AVAILABLE · ${incidentSample.error}`, "Incident history unavailable");
    }

    if (!activeIncidents.error) {
      const active = activeIncidents.flatMap(page => page.items);
      const activeTotal = activeIncidents.reduce((sum, page) => sum + page.total, 0);
      const mean = active.length ? Math.round(active.reduce((sum, item) => sum + item.risk, 0) / active.length) : null;
      text($('[data-stat="risk"]'), mean === null ? "—" : String(mean));
      text($('[data-stat-note="risk"]'), mean === null ? "No active incidents" : NSEP.coverageLabel(activeTotal, active.length, "active incidents"));
      result.statistics.mean_active_risk = mean;
    } else {
      text($('[data-stat="risk"]'), "N/A");
    }

    if (!summary.error) {
      trend("events", summary.event_activity || [], undefined, "No events in the last 24 hours", "events");
      result.statistics.total_events = summary.total_events;
      result.statistics.active_threats = summary.active_threats;
      result.statistics.active_incidents = summary.active_incidents;
      result.trends.events_per_hour = { coverage: "Complete", buckets: summary.event_activity || [] };
    } else {
      trend("events", [], undefined, "Event history unavailable");
    }
    if (!detectionSample.error) {
      const coverage = NSEP.coverageLabel(detectionSample.total, detectionSample.items.length, "detections");
      const buckets = NSEP.bucketByHour(detectionSample.items, "detected_at");
      trend("detections", buckets, coverage, "No detections in the last 24 hours", "detections");
      result.trends.detections_per_hour = { coverage, buckets };
    } else {
      trend("detections", [], `API NOT AVAILABLE · ${detectionSample.error}`, "Detection history unavailable");
    }
    result.trends.risk_over_time = "NOT IMPLEMENTED";

    report = result;
    text($("#reportGenerated"), `Report generated ${NSEP.formattedDate(result.generated_at)}`);
    $("#exportJson").disabled = false;
    $("#exportCsv").disabled = false;
  }

  // Flattens the report into metric/value pairs; hourly buckets become one row per hour.
  function flatten(value, path = "") {
    if (Array.isArray(value)) return value.map(item => [`${path}.${item.timestamp}`, item.count]);
    if (value && typeof value === "object") return Object.entries(value).flatMap(([key, child]) => flatten(child, path ? `${path}.${key}` : key));
    return [[path, value]];
  }

  const csvCell = value => `"${String(value ?? "").replaceAll('"', '""')}"`;
  const stamp = () => report.generated_at.replaceAll(":", "-").slice(0, 19);

  $("#refreshReport").addEventListener("click", () => void buildReport());
  $("#exportJson").addEventListener("click", () => NSEP.downloadFile(`nsep-report-${stamp()}.json`, JSON.stringify(report, null, 2), "application/json"));
  $("#exportCsv").addEventListener("click", () => {
    const lines = [["metric", "value"], ...flatten(report)].map(row => row.map(csvCell).join(","));
    NSEP.downloadFile(`nsep-report-${stamp()}.csv`, `${lines.join("\n")}\n`, "text/csv");
  });
  void buildReport();
})();
