(() => {
  "use strict";

  const { $, text, format, createCell, nodeCell, createButton, createLink, severityPill, formattedDate } = window.NSEP;
  const sampleSize = 100;
  const endpointFields = [
    ["Source IP", "source_ip"], ["Source port", "source_port"],
    ["Destination IP", "destination_ip"], ["Destination port", "destination_port"],
    ["Protocol", "protocol"], ["User", "user"], ["Action", "action"]
  ];

  for (const { rule } of NSEP.WORKER_RULES) $("[data-rule-options]").append(new Option(rule, rule));
  text($('[data-kpi="signatures"]'), format(NSEP.WORKER_RULES.length));

  const list = NSEP.createPagedList({
    root: $("#idsList"),
    endpoint: "/api/v1/detections",
    label: "detections",
    columns: 7,
    syncUrl: true,
    filters: { q: "", severity: "", rule: "" },
    renderRow(detection) {
      const row = document.createElement("tr");
      row.append(
        createCell(formattedDate(detection.detected_at)),
        createCell(detection.rule),
        nodeCell(severityPill(detection.severity)),
        createCell(detection.source),
        createCell(detection.event_type),
        nodeCell(createLink(detection.incident_id.slice(0, 8), `/incidents?incident=${encodeURIComponent(detection.incident_id)}`)),
        nodeCell(createButton("Src / Dst", "inspectDetection", String(detection.detection_id)))
      );
      return row;
    }
  });

  async function showDetection(detection) {
    const panel = $("#idsDetail");
    const grid = $("#idsDetailFields");
    text($("#idsDetailTitle"), `${detection.rule} · ${detection.source}`);
    $("#idsExplorerLink").href = `/explorer?event=${encodeURIComponent(detection.event_id)}`;
    $("#idsIncidentLink").href = `/incidents?incident=${encodeURIComponent(detection.incident_id)}`;
    NSEP.renderDetailGrid(grid, [["Status", "Loading source event…"]]);
    text($("#idsDetailJson"), JSON.stringify(detection.details, null, 2));
    panel.hidden = false;
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
    try {
      const event = await NSEP.findEvent(detection.event_id);
      if (!event) throw new Error("Source event not found.");
      NSEP.renderDetailGrid(grid, [
        ["Signature", detection.rule],
        ["Detected", formattedDate(detection.detected_at)],
        ["Sensor / source", event.source],
        ["Event type", event.event_type],
        ...endpointFields.map(([label, key]) => [label, NSEP.getPayloadValue(event, key) ?? "Not in payload"])
      ]);
      text($("#idsDetailJson"), JSON.stringify({ detection: detection.details, payload: event.payload, metadata: event.metadata }, null, 2));
    } catch (error) {
      NSEP.renderDetailGrid(grid, [["Source event", `API NOT AVAILABLE · ${error.message}`]]);
    }
  }

  $("#idsList [data-rows]").addEventListener("click", event => {
    const button = event.target.closest("[data-inspect-detection]");
    const detection = button && list.records().find(item => String(item.detection_id) === button.dataset.inspectDetection);
    if (detection) void showDetection(detection);
  });
  $("#closeIdsDetail").addEventListener("click", () => { $("#idsDetail").hidden = true; });

  async function loadSignatures() {
    const body = $("#signatureRows");
    try {
      const [total, ...latest] = await Promise.all([
        NSEP.countOf("/api/v1/detections"),
        ...NSEP.WORKER_RULES.map(({ rule }) => NSEP.fetchPage("/api/v1/detections", { rule, limit: 1 }))
      ]);
      text($('[data-kpi="detections"]'), format(total));
      body.replaceChildren();
      NSEP.WORKER_RULES.forEach(({ rule, severity, condition }, index) => {
        const row = document.createElement("tr");
        const last = latest[index].items[0];
        row.append(createCell(rule), createCell(condition), nodeCell(severityPill(severity)), createCell(format(latest[index].total)), createCell(last ? formattedDate(last.detected_at) : "Never"));
        body.append(row);
      });
    } catch (error) {
      text($('[data-kpi="detections"]'), "N/A");
      NSEP.setTableMessage(body, 5, `API NOT AVAILABLE · ${error.message}`);
    }
  }

  async function loadTimeline() {
    try {
      const page = await NSEP.fetchPage("/api/v1/detections", { limit: sampleSize });
      NSEP.renderActivityChart($("#idsTimeline"), $("#idsTimelineEmpty"), NSEP.bucketByHour(page.items, "detected_at"), "No detections in the last 24 hours", "detections");
      text($("#idsTimelineCoverage"), NSEP.coverageLabel(page.total, page.items.length, "detections"));
    } catch (error) {
      NSEP.renderActivityChart($("#idsTimeline"), $("#idsTimelineEmpty"), [], "Detection history unavailable");
      text($("#idsTimelineCoverage"), `API NOT AVAILABLE · ${error.message}`);
    }
  }

  void list.load();
  void loadSignatures();
  void loadTimeline();
})();
