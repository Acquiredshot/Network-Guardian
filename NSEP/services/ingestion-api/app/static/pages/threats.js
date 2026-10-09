(() => {
  "use strict";

  const { $, text, format, createCell, nodeCell, createLink, severityPill, statusPill, riskMeter, formattedDate } = window.NSEP;
  const sampleSize = 100;

  function detectionRow(detection) {
    const row = document.createElement("tr");
    row.append(
      createCell(formattedDate(detection.detected_at)),
      createCell(detection.rule),
      nodeCell(severityPill(detection.severity)),
      createCell(`${detection.source} · ${detection.event_type}`),
      nodeCell(statusPill(detection.incident_status)),
      nodeCell(riskMeter(detection.risk)),
      nodeCell(createLink(detection.event_id.slice(0, 8), `/explorer?event=${encodeURIComponent(detection.event_id)}`)),
      nodeCell(createLink(detection.incident_id.slice(0, 8), `/incidents?incident=${encodeURIComponent(detection.incident_id)}`))
    );
    return row;
  }

  async function loadSummary() {
    try {
      const response = await NSEP.requestJson("/api/v1/dashboard/summary");
      if (!response.ok || !response.data) throw new Error(`Dashboard summary returned HTTP ${response.status}.`);
      text($('[data-kpi="active_threats"]'), format(response.data.active_threats));
      text($('[data-kpi="active_incidents"]'), format(response.data.active_incidents));
      NSEP.renderRuleSummary($("#activeRules"), $("#activeRulesEmpty"), response.data.active_detections_by_rule || []);
    } catch (error) {
      for (const key of ["active_threats", "active_incidents"]) text($(`[data-kpi="${key}"]`), "N/A");
      $("#activeRules").hidden = true;
      NSEP.showDataState($("#activeRulesEmpty"), "API not available", "Detection summary unavailable", error.message);
    }
  }

  async function loadSeverityCounts() {
    for (const severity of ["critical", "high"]) {
      try {
        text($(`[data-kpi="${severity}"]`), format(await NSEP.countOf("/api/v1/detections", { severity })));
      } catch {
        text($(`[data-kpi="${severity}"]`), "N/A");
      }
    }
  }

  async function loadRuleBreakdown() {
    const container = $("#ruleBreakdown");
    try {
      const [total, ...ruleCounts] = await Promise.all([
        NSEP.countOf("/api/v1/detections"),
        ...NSEP.WORKER_RULES.map(({ rule }) => NSEP.countOf("/api/v1/detections", { rule }))
      ]);
      const rows = NSEP.WORKER_RULES.map(({ rule, severity }, index) => ({ label: rule, count: ruleCounts[index], tone: severity }));
      const other = total - ruleCounts.reduce((sum, count) => sum + count, 0);
      if (other > 0) rows.push({ label: "OTHER RULES", count: other });
      NSEP.renderBreakdown(container, rows, { emptyHeading: "No detections recorded", emptyDetail: "Detections appear once the workers match a rule." });
      text($("#ruleBreakdownTotal"), `${format(total)} TOTAL`);
    } catch (error) {
      NSEP.showDataState(container, "API not available", "Detection counts unavailable", error.message);
      text($("#ruleBreakdownTotal"), "UNAVAILABLE");
    }
  }

  async function loadTimeline() {
    try {
      const page = await NSEP.fetchPage("/api/v1/detections", { limit: sampleSize });
      NSEP.renderActivityChart($("#threatTimeline"), $("#threatTimelineEmpty"), NSEP.bucketByHour(page.items, "detected_at"), "No detections in the last 24 hours", "detections");
      text($("#threatTimelineCoverage"), NSEP.coverageLabel(page.total, page.items.length, "detections"));
    } catch (error) {
      NSEP.renderActivityChart($("#threatTimeline"), $("#threatTimelineEmpty"), [], "Detection history unavailable");
      text($("#threatTimelineCoverage"), `API NOT AVAILABLE · ${error.message}`);
    }
  }

  async function loadRiskList() {
    const container = $("#riskList");
    try {
      const pages = await Promise.all(["open", "investigating"].map(status => NSEP.fetchPage("/api/v1/incidents", { status, limit: sampleSize })));
      const incidents = pages.flatMap(page => page.items).sort((a, b) => b.risk - a.risk).slice(0, 8);
      container.replaceChildren();
      if (!incidents.length) {
        container.append(NSEP.dataState("Awaiting data", "No active incidents", "Risk scores appear when incidents are open or investigating."));
        return;
      }
      for (const incident of incidents) {
        const row = createLink("", `/incidents?incident=${encodeURIComponent(incident.incident_id)}`, "risk-row");
        const label = document.createElement("span");
        label.append(NSEP.shortId(incident.incident_id), NSEP.element("small", "", `${incident.event_source} · ${incident.event_type}`));
        row.append(label, statusPill(incident.status), riskMeter(incident.risk));
        container.append(row);
      }
    } catch (error) {
      NSEP.showDataState(container, "API not available", "Incident risk unavailable", error.message);
    }
  }

  NSEP.createPagedList({
    root: $("#detectionList"),
    endpoint: "/api/v1/detections",
    label: "detections",
    columns: 8,
    syncUrl: true,
    filters: { q: "", severity: "", rule: "" },
    renderRow: detectionRow
  }).load();
  void loadSummary();
  void loadSeverityCounts();
  void loadRuleBreakdown();
  void loadTimeline();
  void loadRiskList();
})();
