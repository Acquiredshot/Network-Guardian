(() => {
  "use strict";
  const { $, text, requestJson, fetchPage, format } = window.NSEP;
  const namespace = "http://www.w3.org/2000/svg";
  const nodes = [
    { id: "source", name: "Event sources", x: 20, y: 210, role: "Sensors submit validated events. No source heartbeat is collected.", href: "/events" },
    { id: "api", name: "NSEP API / Dashboard", x: 310, y: 210, role: "Accepts events, publishes jobs, and serves persisted data.", href: "/dashboard" },
    { id: "rabbitmq", name: "RabbitMQ", x: 600, y: 210, role: "Carries Celery jobs on the security-events queue.", href: "/admin/health" },
    { id: "worker", name: "Celery worker", x: 890, y: 210, role: "Enriches events, runs detection rules, scores risk, and sends incident notifications. No worker heartbeat endpoint exists.", href: "/threats" },
    { id: "postgres", name: "PostgreSQL", x: 310, y: 390, role: "Stores accepted/processed events, incidents, detections, and timelines.", href: "/incidents" },
    { id: "redis", name: "Redis", x: 890, y: 390, role: "Celery result backend. Connectivity does not prove a worker is running.", href: "/admin/health" },
    { id: "guardian", name: "Guardian Event Fabric", x: 600, y: 560, role: "Receives outbound NSEP incidents. TCP reachability is not proof of delivery or active protection.", href: $(".platform-return").href },
    { id: "zammad", name: "Zammad", x: 890, y: 560, role: "Optional ticket creation on new incidents. Ticket lookup is not implemented in NSEP.", href: "/zammad" },
    { id: "mcp", name: "NSEP MCP server", x: 310, y: 30, role: "Exposes seven read-only investigation tools backed by NSEP's HTTP API.", href: "/hermes" },
    { id: "hermes", name: "Hermes client", x: 20, y: 30, role: "External MCP client. NSEP does not observe its sessions or activity.", href: "/hermes" },
    { id: "pakshield", name: "PakShield adapter", x: 20, y: 560, role: "Independent identity/access event producer. Its installation and activity are not observed by NSEP.", href: "/network-guardian" },
    { id: "mask", name: "Mask adapter", x: 20, y: 390, role: "Independent asset/network event producer. Its installation and activity are not observed by NSEP.", href: "/network-guardian" }
  ];
  const edges = [
    ["source", "api", "HTTP events"], ["api", "rabbitmq", "enqueue"],
    ["rabbitmq", "worker", "consume"], ["api", "postgres", "persist / query"],
    ["worker", "postgres", "results", false, true], ["worker", "redis", "result backend"],
    ["worker", "guardian", "incident push", false, true], ["worker", "zammad", "optional tickets", true, true],
    ["hermes", "mcp", "read-only MCP", true], ["mcp", "api", "HTTP query"],
    ["pakshield", "guardian", "identity events", true],
    ["mask", "guardian", "asset events", true, true]
  ];
  const observations = new Map();
  let selected = null;
  let refreshing = false;

  function svgElement(tag, attrs, content) {
    const node = document.createElementNS(namespace, tag);
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
    if (content) node.textContent = content;
    return node;
  }

  function selectNode(id) {
    selected = id;
    const node = nodes.find(item => item.id === id);
    const observation = observations.get(id) || { state: "unknown", label: "UNKNOWN", detail: "No live observation available." };
    text($("#topologyNodeTitle"), node.name);
    text($("#topologyNodeRole"), node.role);
    text($("#topologyNodeState"), observation.label);
    $("#topologyNodeState").dataset.state = observation.state;
    text($("#topologyNodeEvidence"), observation.detail);
    $("#topologyNodeLink").href = node.href;
    $("#topologyNodeLink").hidden = false;
    document.querySelectorAll("[data-topology-node]").forEach(item => item.classList.toggle("selected", item.dataset.topologyNode === id));
  }

  const graph = $("#topologyGraph");
  const defs = svgElement("defs", {});
  const marker = svgElement("marker", { id: "topologyArrow", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: "auto" });
  marker.append(svgElement("path", { d: "M 0 0 L 10 5 L 0 10 z", fill: "#7897a4" }));
  defs.append(marker);
  graph.append(defs);
  for (const [from, to, label, optional, diagonal] of edges) {
    const start = nodes.find(node => node.id === from);
    const end = nodes.find(node => node.id === to);
    const vertical = start.x === end.x || diagonal;
    const x1 = vertical ? start.x + 130 : start.x + 260;
    const y1 = vertical ? start.y + 90 : start.y + 45;
    const x2 = vertical ? end.x + 130 : end.x;
    const y2 = vertical ? end.y : end.y + 45;
    let path = `M${x1},${y1} L${x2},${y2}`;
    let labelX = (x1 + x2) / 2;
    let labelY = vertical ? (y1 + y2) / 2 - 8 : start.y - 10;
    if (from === "worker" && to === "zammad") {
      path = `M1150,255 H1180 V530 H1020 V560`;
      labelX = 1080;
      labelY = 518;
    } else if (from === "worker" && to === "guardian") {
      path = `M1020,300 L850,330 L730,560`;
      labelX = 785;
      labelY = 438;
    }
    graph.append(svgElement("path", { d: path, class: optional ? "topology-edge optional" : "topology-edge", "marker-end": "url(#topologyArrow)" }));
    graph.append(svgElement("text", { x: labelX, y: labelY, class: "topology-edge-label", "text-anchor": "middle" }, label));
  }
  for (const node of nodes) {
    const group = svgElement("g", { transform: `translate(${node.x},${node.y})`, class: "topology-node", tabindex: "0", role: "button", "aria-label": `${node.name}: status unknown`, "data-topology-node": node.id, "data-state": "unknown" });
    group.append(svgElement("rect", { width: 260, height: 90, rx: 10 }));
    group.append(svgElement("text", { x: 15, y: 28, class: "topology-node-name" }, node.name));
    group.append(svgElement("text", { x: 15, y: 52, "data-node-status": node.id }, "UNKNOWN"));
    group.append(svgElement("text", { x: 15, y: 74, class: "topology-node-note" }, "Select for evidence"));
    group.addEventListener("click", () => selectNode(node.id));
    group.addEventListener("keydown", event => {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); selectNode(node.id); }
    });
    graph.append(group);
  }

  function observe(id, state, label, detail) {
    observations.set(id, { state, label, detail });
    const node = $(`[data-topology-node="${id}"]`);
    node.dataset.state = state;
    node.setAttribute("aria-label", `${nodes.find(item => item.id === id).name}: ${label}`);
    text($(`[data-node-status="${id}"]`), label);
  }

  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    $("#topologyRefresh").disabled = true;
    const errors = [];
    for (const node of nodes) observe(node.id, "unknown", "UNKNOWN", "No live telemetry is available for this component.");
    for (const id of ["topologyEventCount", "topologyIncidentCount", "topologyProcessedCount", "topologyFailedCount"]) text($("#" + id), "N/A");
    text($("#topologyRecent"), "Recent event data unavailable.");
    async function section(label, load) {
      try { await load(); }
      catch (error) { errors.push(`${label}: ${error.message}`); }
    }
    async function get(url) {
      const response = await requestJson(url);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.data;
    }
    try {
      await Promise.all([
        section("API health", async () => {
          const health = await get("/api/health");
          if (health?.status !== "ok") throw new Error("Unhealthy or malformed response");
          observe("api", "ready", "HTTP HEALTHY", "The NSEP liveness endpoint reports ok. Dependency health is shown separately.");
        }),
        section("Dependencies", async () => {
          const diagnostics = await get("/api/diagnostics");
          for (const [id, key] of [["postgres", "database"], ["rabbitmq", "broker"], ["redis", "cache"]]) {
            const diagnostic = diagnostics?.dependencies?.[key];
            if (!diagnostic) throw new Error(`Missing ${id} diagnostic`);
            observe(id, diagnostic.status === "ready" ? "ready" : "degraded", diagnostic.status.toUpperCase(), `Protocol probe: ${diagnostic.status}. Latency: ${diagnostic.latency_ms ?? "unavailable"} ms.`);
          }
        }),
        section("Integrations", async () => {
          const data = await get("/api/v1/integrations/status");
          if (!Array.isArray(data?.integrations)) throw new Error("Malformed integration response");
          for (const [id, key] of [["guardian", "network_guardian"], ["zammad", "zammad"], ["mcp", "mcp_server"]]) {
            const integration = data.integrations.find(item => item.key === key);
            if (!integration) throw new Error(`Missing ${key} status`);
            const state = !integration.configured ? "unknown" : integration.reachable === true ? "ready" : "degraded";
            const label = !integration.configured ? "DISABLED" : integration.reachable === true ? "TCP REACHABLE" : "UNREACHABLE";
            observe(id, state, label, `${integration.detail}. This probe does not verify application protocol, credentials, or delivery.`);
          }
        }),
        section("Persisted statistics", async () => {
          const [summary, processed, failed, incidents] = await Promise.all([
            get("/api/v1/dashboard/summary"),
            fetchPage("/api/v1/events", { status: "processed", limit: 1 }),
            fetchPage("/api/v1/events", { status: "failed", limit: 1 }),
            fetchPage("/api/v1/incidents", { limit: 1 })
          ]);
          if (!Number.isInteger(summary?.total_events)) throw new Error("Malformed event count");
          text($("#topologyEventCount"), format(summary.total_events));
          text($("#topologyIncidentCount"), format(incidents.total));
          text($("#topologyProcessedCount"), format(processed.total));
          text($("#topologyFailedCount"), format(failed.total));
          observe("worker", "unknown", "NO HEARTBEAT", `${format(processed.total)} persisted processed events; ${format(failed.total)} failed. Historical processing does not prove the worker is currently running.`);
        }),
        section("Recent event", async () => {
          const events = await fetchPage("/api/v1/events", { limit: 1 });
          const event = events.items[0];
          text($("#topologyRecent"), event ? `Latest event: ${event.source} / ${event.event_type} / ${event.status} / ${event.event_id}` : "No persisted events yet.");
        })
      ]);
      text($("#topologyUpdated"), `${errors.length ? "Partial refresh" : "Refreshed"} at ${new Date().toLocaleTimeString()} - next refresh in 10 seconds.`);
      const errorPanel = $("#topologyErrors");
      text(errorPanel, errors.join(" | "));
      errorPanel.hidden = errors.length === 0;
      if (selected) selectNode(selected);
    } finally {
      refreshing = false;
      $("#topologyRefresh").disabled = false;
    }
  }
  $("#topologyRefresh").addEventListener("click", refresh);
  selectNode("api");
  void refresh();
  const timer = window.setInterval(refresh, 10000);
  window.addEventListener("pagehide", () => window.clearInterval(timer), { once: true });
})();
