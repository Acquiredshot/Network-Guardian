(() => {
  "use strict";

  const { $, createCell, nodeCell, createButton, createLink, severityPill, statusPill, formattedDate } = window.NSEP;
  const detail = $("#eventDetail");

  const list = NSEP.createPagedList({
    root: $("#eventList"),
    endpoint: "/api/v1/events",
    label: "events",
    columns: 7,
    syncUrl: true,
    filters: { q: "", source: "", event_type: "", severity: "", status: "", sort_by: "occurred_at", sort_order: "desc" },
    renderRow(record) {
      const row = document.createElement("tr");
      row.append(
        createCell(formattedDate(record.occurred_at)),
        createCell(record.source),
        createCell(record.event_type),
        nodeCell(severityPill(record.severity)),
        nodeCell(statusPill(record.status)),
        record.incident_id ? nodeCell(createLink(record.incident_id.slice(0, 8), `/incidents?incident=${encodeURIComponent(record.incident_id)}`)) : createCell("—"),
        nodeCell(createButton("Inspect", "openEvent", record.event_id))
      );
      row.firstChild.title = record.event_id;
      return row;
    }
  });

  $("#eventList [data-rows]").addEventListener("click", event => {
    const button = event.target.closest("[data-open-event]");
    const record = button && list.records().find(item => item.event_id === button.dataset.openEvent);
    if (!record) return;
    NSEP.renderEventDetail(detail, record);
    detail.scrollIntoView({ behavior: "smooth", block: "nearest" });
  });
  $("#closeEventDetail").addEventListener("click", () => { detail.hidden = true; });

  $("#eventForm").addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = $("button[type=submit]", form);
    const output = $("#eventSubmitResult");
    button.disabled = true;
    try {
      const values = new FormData(form);
      let payload;
      let metadata;
      try {
        payload = JSON.parse(values.get("payload"));
        metadata = JSON.parse(values.get("metadata") || "{}");
      } catch {
        throw new Error("Payload and metadata must be valid JSON objects.");
      }
      if (!payload || Array.isArray(payload) || typeof payload !== "object" || !metadata || Array.isArray(metadata) || typeof metadata !== "object") {
        throw new Error("Payload and metadata must each be JSON objects.");
      }
      const occurredAt = new Date(values.get("occurred_at"));
      if (Number.isNaN(occurredAt.getTime())) throw new Error("Enter a valid event timestamp.");
      const body = {
        source: String(values.get("source")).trim(),
        event_type: String(values.get("event_type")).trim(),
        occurred_at: occurredAt.toISOString(),
        payload,
        metadata
      };
      const response = await NSEP.requestJson("/api/v1/events", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (!response.ok) throw new Error(response.data?.error?.message || `Event request returned HTTP ${response.status}.`);
      NSEP.showResult(output, "Event accepted", response.data);
      if (response.data.event_id) output.append(createLink("Track in Explorer →", `/explorer?event=${encodeURIComponent(response.data.event_id)}`));
      await list.load();
    } catch (error) {
      NSEP.showResult(output, "Event submission failed", error.message, true);
    } finally {
      button.disabled = false;
    }
  });

  $("input[name=occurred_at]").value = new Date(Date.now() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  void list.load();
})();
