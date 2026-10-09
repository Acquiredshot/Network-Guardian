(() => {
  "use strict";
  const { $, text, setStatusRow } = window.NSEP;

  (async () => {
    const result = await window.NSEP.health;
    const summary = $("#healthSummaryTag");

    const rows = {
      health: result.health,
      readiness: result.readiness,
      diagnostics: result.diagnostics
    };
    for (const [key, response] of Object.entries(rows)) {
      const row = $(`[data-health="${key}"]`);
      if (!response) {
        setStatusRow(row, "offline", "Request failed or timed out", "OFFLINE");
        continue;
      }
      if (response.ok && response.data?.status === "ok") {
        setStatusRow(row, "ready", "Reporting healthy", "OK");
      } else if (response.ok) {
        setStatusRow(row, "degraded", `status=${response.data?.status ?? "unknown"}`, "DEGRADED");
      } else {
        setStatusRow(row, "degraded", `HTTP ${response.status}`, "DEGRADED");
      }
    }

    summary.dataset.state = result.pipeline.state;
    text(summary, result.pipeline.label);

    text($("#diagnosticsRaw"), result.diagnostics?.data ? JSON.stringify(result.diagnostics.data, null, 2) : "Diagnostics response unavailable.");
  })();
})();
