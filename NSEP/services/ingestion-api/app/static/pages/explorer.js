(() => {
  "use strict";

  const { $, $$, text, createCell, nodeCell, createButton, createLink, severityPill, statusPill, shortId, formattedDate } = window.NSEP;
  const inspector = $("#inspector");
  let selected = null;
  let jsonView = "payload";

  const list = NSEP.createPagedList({
    root: $("#explorerList"),
    endpoint: "/api/v1/events",
    label: "events",
    columns: 9,
    syncUrl: true,
    filters: { q: "", source: "", event_type: "", status: "", severity: "", sort_by: "occurred_at", sort_order: "desc" },
    renderRow(record) {
      const row = document.createElement("tr");
      row.append(
        nodeCell(shortId(record.event_id)),
        createCell(formattedDate(record.occurred_at)),
        createCell(formattedDate(record.accepted_at)),
        createCell(record.source),
        createCell(record.event_type),
        nodeCell(severityPill(record.severity)),
        nodeCell(statusPill(record.status)),
        createCell(record.retry_count),
        nodeCell(createButton("Inspect", "inspectEvent", record.event_id))
      );
      return row;
    }
  });

  function renderJson() {
    if (!selected) return;
    const views = { payload: selected.payload, metadata: selected.metadata, record: selected };
    text($("#jsonViewer"), JSON.stringify(views[jsonView], null, 2));
    for (const tab of $$("[data-json-view]")) {
      const active = tab.dataset.jsonView === jsonView;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", String(active));
    }
  }

  function renderLifecycle(record) {
    const detections = record.detections || [];
    const stages = {
      accepted: [Boolean(record.accepted_at), formattedDate(record.accepted_at)],
      published: [Boolean(record.published_at), record.published_at ? formattedDate(record.published_at) : "Not published"],
      processed: [Boolean(record.processed_at), record.processed_at ? formattedDate(record.processed_at) : record.status === "failed" ? `Failed: ${record.failure_reason || "unknown"}` : "Awaiting worker"],
      detection: [detections.length > 0, detections.length ? `${detections.length} rule match${detections.length === 1 ? "" : "es"}` : record.processed_at ? "No rule matched" : "Pending processing"],
      incident: [Boolean(record.incident_id), record.incident_id ? record.incident_id.slice(0, 8) : "None raised"]
    };
    for (const [stage, [complete, detail]] of Object.entries(stages)) {
      const item = $(`#lifecycle [data-stage="${stage}"]`);
      item.dataset.state = complete ? "complete" : "pending";
      text($("small", item), detail);
    }
    const detectionList = $("#eventDetections");
    detectionList.replaceChildren();
    if (!detections.length) detectionList.append(NSEP.dataState("Awaiting data", "No detections", "No worker rule matched this event."));
    for (const detection of detections) {
      const row = NSEP.element("div", "rule-summary-row");
      row.append(NSEP.element("strong", "", detection.rule), severityPill(detection.severity), createLink("All hits →", `/threats?rule=${encodeURIComponent(detection.rule)}`));
      detectionList.append(row);
    }
  }

  async function loadRelated(record) {
    const container = $("#relatedEvents");
    container.replaceChildren(NSEP.element("p", "module-footnote", "Loading related events…"));
    try {
      const page = await NSEP.fetchPage("/api/v1/events", { source: record.source, limit: 6 });
      const related = page.items.filter(item => item.event_id !== record.event_id).slice(0, 5);
      container.replaceChildren();
      if (!related.length) {
        container.append(NSEP.dataState("Awaiting data", "No other events from this source", ""));
        return;
      }
      for (const item of related) {
        const link = createLink("", `/explorer?event=${encodeURIComponent(item.event_id)}`, "related-row");
        link.dataset.eventId = item.event_id;
        link.append(shortId(item.event_id), NSEP.element("span", "", item.event_type), NSEP.element("small", "", formattedDate(item.occurred_at)), statusPill(item.status));
        container.append(link);
      }
      const more = Math.max(0, page.total - 1 - related.length);
      if (more) container.append(createLink(`+${NSEP.format(more)} more from ${record.source} →`, `/explorer?source=${encodeURIComponent(record.source)}`, "related-more"));
    } catch (error) {
      container.replaceChildren(NSEP.dataState("API not available", "Related events unavailable", error.message));
    }
  }

  async function loadIncident(record) {
    const root = $("#incidentCorrelation");
    const empty = $("#incidentCorrelationEmpty");
    $("[data-incident-result]", root).hidden = true;
    $("[data-incident-investigation]", root).hidden = true;
    if (!record.incident_id) {
      NSEP.showDataState(empty, "Awaiting data", "No incident correlated", "The workers raise an incident only when a detection rule matches.");
      return;
    }
    empty.replaceChildren(createLink("Open in Incidents →", `/incidents?incident=${encodeURIComponent(record.incident_id)}`));
    await NSEP.loadIncidentInvestigation(root, record.incident_id);
  }

  function inspect(record) {
    selected = record;
    $("#inspectorEmpty").hidden = true;
    inspector.hidden = false;
    NSEP.renderEventDetail($("#eventInspection"), record, [
      ["Accepted", formattedDate(record.accepted_at)],
      ["Retries", record.retry_count],
      ["Failure reason", record.failure_reason]
    ]);
    $("#eventIdInput").value = record.event_id;
    NSEP.updateUrlParams({ event: record.event_id });
    renderJson();
    renderLifecycle(record);
    void loadRelated(record);
    void loadIncident(record);
  }

  async function inspectById(eventId) {
    try {
      const record = await NSEP.findEvent(eventId);
      if (!record) throw new Error(`No persisted event with ID ${eventId}.`);
      inspect(record);
      inspector.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
      selected = null;
      inspector.hidden = true;
      NSEP.showDataState($("#inspectorEmpty"), "Not found", "Event could not be loaded", error.message);
    }
  }

  $("#explorerList [data-rows]").addEventListener("click", event => {
    const button = event.target.closest("[data-inspect-event]");
    const record = button && list.records().find(item => item.event_id === button.dataset.inspectEvent);
    if (!record) return;
    inspect(record);
    inspector.scrollIntoView({ behavior: "smooth", block: "start" });
  });
  $("#relatedEvents").addEventListener("click", event => {
    const link = event.target.closest("[data-event-id]");
    if (!link) return;
    event.preventDefault();
    void inspectById(link.dataset.eventId);
  });
  $("#eventLookupForm").addEventListener("submit", event => {
    event.preventDefault();
    void inspectById($("#eventIdInput").value.trim());
  });
  for (const tab of $$("[data-json-view]")) {
    tab.addEventListener("click", () => {
      jsonView = tab.dataset.jsonView;
      renderJson();
    });
  }
  $("#copyJson").addEventListener("click", async () => {
    const button = $("#copyJson");
    try {
      await navigator.clipboard.writeText($("#jsonViewer").textContent);
      text(button, "Copied");
    } catch {
      text(button, "Copy unavailable");
    }
    window.setTimeout(() => text(button, "Copy JSON"), 1500);
  });

  void list.load();
  const initialEvent = new URLSearchParams(window.location.search).get("event");
  if (initialEvent) void inspectById(initialEvent);
})();
