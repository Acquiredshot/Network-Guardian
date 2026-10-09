(() => {
  "use strict";

  const { $, $$, text, format, createCell, nodeCell, createButton, severityPill, statusPill, riskMeter, formattedDate } = window.NSEP;
  const investigation = $("#incidentInvestigation");

  const list = NSEP.createPagedList({
    root: $("#incidentList"),
    endpoint: "/api/v1/incidents",
    label: "incidents",
    columns: 7,
    syncUrl: true,
    filters: { q: "", status: "" },
    renderRow(incident) {
      const row = document.createElement("tr");
      const id = NSEP.element("code", "", incident.incident_id);
      const source = NSEP.element("small", "", `${incident.event_source} · ${incident.event_type}`);
      row.append(
        createCell(formattedDate(incident.updated_at)),
        nodeCell(id, document.createElement("br"), source),
        nodeCell(severityPill(incident.highest_severity)),
        nodeCell(riskMeter(incident.risk)),
        nodeCell(statusPill(incident.status)),
        createCell(incident.detection_count),
        nodeCell(createButton("Open", "openIncident", incident.incident_id))
      );
      return row;
    },
    onLoad: highlightStatusCard
  });

  function highlightStatusCard() {
    for (const card of $$("[data-status-filter]")) card.classList.toggle("active", card.dataset.statusFilter === (list.state.status || ""));
  }

  async function loadStatusCounts() {
    await Promise.all(["open", "investigating", "resolved", ""].map(async status => {
      const target = $(`[data-status-count="${status}"]`);
      try {
        text(target, format(await NSEP.countOf("/api/v1/incidents", status ? { status } : {})));
      } catch {
        text(target, "N/A");
      }
    }));
  }

  async function openIncident(incidentId) {
    $("#incidentIdInput").value = incidentId;
    $("#investigationEmpty").hidden = true;
    NSEP.updateUrlParams({ incident: incidentId });
    const incident = await NSEP.loadIncidentInvestigation(investigation, incidentId);
    const graphEvent = $("[data-incident-graph] [data-kind='event']", investigation);
    const eventId = graphEvent?.dataset.nodeId?.replace(/^event:/, "");
    $("#incidentLinks").hidden = !eventId;
    if (eventId) $("#incidentEventLink").href = `/explorer?event=${encodeURIComponent(eventId)}`;
    if (incident) {
      const detections = Array.isArray(incident.detections) ? incident.detections : [];
      text($("#playbookTrigger"), detections.length ? `${detections.length} detection${detections.length === 1 ? "" : "s"} on incident` : "No detections reported");
    }
  }

  $("#incidentList [data-rows]").addEventListener("click", event => {
    const button = event.target.closest("[data-open-incident]");
    if (!button) return;
    void openIncident(button.dataset.openIncident);
    investigation.scrollIntoView({ behavior: "smooth", block: "start" });
  });
  for (const card of $$("[data-status-filter]")) {
    card.addEventListener("click", () => void list.applyFilters({ ...list.state, status: card.dataset.statusFilter }));
  }
  $("#incidentLookupForm").addEventListener("submit", async event => {
    event.preventDefault();
    const button = $("button[type=submit]", event.currentTarget);
    button.disabled = true;
    try {
      await openIncident($("#incidentIdInput").value.trim());
    } finally {
      button.disabled = false;
    }
  });
  $("#simulatePlaybook").addEventListener("click", () => {
    const result = $("#playbookResult");
    result.hidden = false;
    result.textContent = `Preview only: ${$("#playbookTrigger").textContent} → analyst approval required → no response action executed → no notification sent.`;
  });

  void list.load();
  void loadStatusCounts();
  void NSEP.loadIntegrations(document);
  const initialIncident = new URLSearchParams(window.location.search).get("incident");
  if (initialIncident) void openIncident(initialIncident);
})();
