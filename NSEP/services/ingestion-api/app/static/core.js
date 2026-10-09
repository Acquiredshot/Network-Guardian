(() => {
  "use strict";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const requestTimeout = 7000;
  const numberFormat = new Intl.NumberFormat();
  const text = (element, value) => { if (element) element.textContent = value; };
  const format = value => numberFormat.format(Number(value) || 0);

  // Mirrors services/security-workers/app/detection/rules.py and risk/scoring.py.
  const WORKER_RULES = [
    { rule: "BRUTE_FORCE", severity: "high", condition: "payload.failed_logins ≥ 5" },
    { rule: "MALWARE_ACTIVITY", severity: "critical", condition: "event_type is malware or ransomware" }
  ];
  const RISK_WEIGHTS = { low: 20, medium: 50, high: 75, critical: 100 };
  const SEVERITIES = ["critical", "high", "medium", "low"];

  function queryString(values) {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(values)) {
      if (key === "total") continue;
      if (value !== "" && value !== null && value !== undefined) params.set(key, String(value));
    }
    return params.toString();
  }

  async function requestJson(url, options = {}) {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), requestTimeout);
    const started = performance.now();
    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: { Accept: "application/json", ...(options.headers || {}) }
      });
      const responseText = await response.text();
      let data = null;
      if (responseText) {
        try { data = JSON.parse(responseText); }
        catch { throw new Error("The API returned malformed JSON."); }
      }
      return { ok: response.ok, status: response.status, data, elapsed: performance.now() - started };
    } catch (error) {
      if (error.name === "AbortError") throw new Error("The request timed out.");
      throw error;
    } finally {
      window.clearTimeout(timeout);
    }
  }

  async function fetchPage(endpoint, params = {}) {
    const response = await requestJson(`${endpoint}?${queryString(params)}`);
    if (!response.ok || !Array.isArray(response.data?.items)) throw new Error(`${endpoint} returned HTTP ${response.status}.`);
    return response.data;
  }

  async function countOf(endpoint, params = {}) {
    return (await fetchPage(endpoint, { ...params, limit: 1 })).total;
  }

  async function findEvent(eventId) {
    const page = await fetchPage("/api/v1/events", { q: eventId, limit: 5 });
    return page.items.find(item => item.event_id === eventId) || null;
  }

  function formattedDate(value) {
    if (!value) return "N/A";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
  }

  function displayValue(value) {
    if (value === undefined || value === null || value === "") return "N/A";
    return typeof value === "object" ? JSON.stringify(value) : String(value);
  }

  function getPayloadValue(record, key) {
    const payload = record.payload && typeof record.payload === "object" ? record.payload : {};
    const metadata = record.metadata && typeof record.metadata === "object" ? record.metadata : {};
    return payload[key] ?? metadata[key] ?? null;
  }

  function element(tag, className = "", content = "") {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (content !== "") node.textContent = content;
    return node;
  }

  function setTableMessage(body, columns, message) {
    const row = document.createElement("tr");
    const cell = element("td", "table-empty", message);
    cell.colSpan = columns;
    row.append(cell);
    body.replaceChildren(row);
  }

  function createCell(value, className = "") {
    return element("td", className, value === null || value === undefined || value === "" ? "N/A" : String(value));
  }

  function nodeCell(...nodes) {
    const cell = document.createElement("td");
    cell.append(...nodes);
    return cell;
  }

  function createButton(label, action, value) {
    const button = element("button", "row-action", label);
    button.type = "button";
    button.dataset[action] = value;
    return button;
  }

  function createLink(label, href, className = "row-action") {
    const link = element("a", className, label);
    link.href = href;
    return link;
  }

  function severityPill(severity) {
    const pill = element("span", "severity-pill", severity ? String(severity).toUpperCase() : "N/A");
    pill.dataset.severity = severity || "unknown";
    return pill;
  }

  function statusPill(status) {
    const pill = element("span", "record-status", status ? String(status).toUpperCase() : "N/A");
    pill.dataset.status = status || "unknown";
    return pill;
  }

  function riskMeter(risk) {
    const value = Math.max(0, Math.min(100, Number(risk) || 0));
    const wrapper = element("span", "risk-meter");
    wrapper.dataset.band = value >= 75 ? "high" : value >= 50 ? "medium" : "low";
    const bar = element("span", "risk-meter-bar");
    bar.style.setProperty("--risk", `${value}%`);
    wrapper.append(bar, element("span", "risk-meter-value", String(value)));
    return wrapper;
  }

  function shortId(id) {
    const code = element("code", "", String(id).slice(0, 8));
    code.title = String(id);
    return code;
  }

  // Professional placeholder for data the backend does not provide.
  function dataState(kind, heading, detail) {
    const box = element("div", "data-state");
    box.dataset.kind = kind.toLowerCase().replaceAll(" ", "-");
    box.append(element("span", "data-state-badge", kind.toUpperCase()), element("strong", "", heading));
    if (detail) box.append(element("p", "", detail));
    return box;
  }

  function showDataState(container, kind, heading, detail) {
    container.replaceChildren(dataState(kind, heading, detail));
    container.hidden = false;
  }

  function showResult(target, heading, payload, error = false) {
    target.replaceChildren(element("div", "result-heading", heading));
    target.hidden = false;
    if (error) {
      target.append(element("p", "result-error", payload));
      return;
    }
    target.append(element("pre", "", JSON.stringify(payload, null, 2)));
  }

  function renderActivityChart(chart, empty, buckets, emptyMessage, unit = "events") {
    const maxCount = Math.max(0, ...buckets.map(bucket => Number(bucket.count) || 0));
    if (!buckets.length || maxCount === 0) {
      chart.hidden = true;
      empty.hidden = false;
      text($(".empty-copy strong", empty), emptyMessage);
      return;
    }
    chart.replaceChildren();
    for (const [index, bucket] of buckets.entries()) {
      const count = Number(bucket.count) || 0;
      const bar = element("div", "activity-bar");
      bar.dataset.count = String(count);
      bar.style.setProperty("--bar-height", `${count ? Math.max(5, count / maxCount * 100) : 2}%`);
      const timestamp = new Date(bucket.timestamp);
      const label = Number.isNaN(timestamp.getTime()) ? "Unknown time" : timestamp.toLocaleString();
      bar.title = `${label}: ${format(count)} ${unit}`;
      if (index % 4 === 0 || index === buckets.length - 1) {
        const timeLabel = element("time", "", Number.isNaN(timestamp.getTime()) ? "--" : timestamp.toLocaleTimeString([], { hour: "2-digit" }));
        timeLabel.dateTime = bucket.timestamp;
        bar.append(timeLabel);
      }
      chart.append(bar);
    }
    empty.hidden = true;
    chart.hidden = false;
  }

  // Hourly buckets for the last `hours` hours, matching the dashboard summary's event_activity shape.
  function bucketByHour(records, field, hours = 24) {
    const hour = 3600000;
    const end = Math.floor(Date.now() / hour) * hour;
    const start = end - (hours - 1) * hour;
    const counts = new Array(hours).fill(0);
    for (const record of records) {
      const time = new Date(record[field]).getTime();
      if (Number.isNaN(time) || time < start || time >= end + hour) continue;
      counts[Math.floor((time - start) / hour)] += 1;
    }
    return counts.map((count, index) => ({ timestamp: new Date(start + index * hour).toISOString(), count }));
  }

  // Describes whether a sampled page covers the full dataset.
  function coverageLabel(total, sampled, noun) {
    if (total <= sampled) return `Complete · all ${format(total)} ${noun}`;
    return `Partial · latest ${format(sampled)} of ${format(total)} ${noun}`;
  }

  function renderBreakdown(container, rows, { emptyHeading = "No records yet", emptyDetail = "" } = {}) {
    const total = rows.reduce((sum, row) => sum + (Number(row.count) || 0), 0);
    container.replaceChildren();
    if (!total) {
      container.append(dataState("Awaiting data", emptyHeading, emptyDetail));
      return;
    }
    const max = Math.max(...rows.map(row => Number(row.count) || 0));
    for (const row of rows) {
      const item = element("div", "breakdown-row");
      if (row.tone) item.dataset.tone = row.tone;
      const bar = element("span", "breakdown-bar");
      bar.style.setProperty("--share", `${max ? (Number(row.count) || 0) / max * 100 : 0}%`);
      const share = total ? Math.round((Number(row.count) || 0) / total * 100) : 0;
      item.append(element("span", "breakdown-label", row.label), bar, element("span", "breakdown-count", `${format(row.count)} · ${share}%`));
      container.append(item);
    }
  }

  function renderRuleSummary(list, empty, rules) {
    list.replaceChildren();
    if (!rules.length) {
      list.hidden = true;
      empty.hidden = false;
      text($("strong", empty), "No active detections");
      text($("p", empty), "No detections are currently linked to open or investigating incidents.");
      return;
    }
    for (const item of rules) {
      const row = element("div", "rule-summary-row");
      row.append(element("strong", "", item.rule), element("span", "", item.severity.toUpperCase()), element("span", "rule-count", format(item.count)));
      list.append(row);
    }
    empty.hidden = true;
    list.hidden = false;
  }

  function renderWorkerRules(container) {
    container.replaceChildren();
    for (const { rule, severity, condition } of WORKER_RULES) {
      const row = element("div", "rule-row");
      const mark = element("span", `severity-mark ${severity}`);
      const label = document.createElement("div");
      label.append(element("strong", "", rule), element("small", "", condition));
      row.append(mark, label, element("span", `severity-label ${severity}-text`, severity.toUpperCase()));
      container.append(row);
    }
  }

  function renderDetailGrid(grid, fields) {
    grid.replaceChildren();
    for (const [label, value] of fields) {
      const wrapper = document.createElement("div");
      wrapper.append(element("dt", "", label), element("dd", "", displayValue(value)));
      grid.append(wrapper);
    }
  }

  // Fills an event detail panel. `root` contains [data-detail-*] hooks.
  function renderEventDetail(root, record, extraFields = []) {
    const payloadFields = ["user", "source_ip", "destination_ip", "action"];
    renderDetailGrid($("[data-detail-fields]", root), [
      ["Event ID", record.event_id],
      ["Timestamp", formattedDate(record.occurred_at)],
      ["Source", record.source],
      ["Event type", record.event_type],
      ["Severity", record.severity],
      ["Status", record.status],
      ["Incident ID", record.incident_id],
      ...payloadFields.map(key => [key.replaceAll("_", " "), getPayloadValue(record, key)]),
      ...extraFields
    ]);
    text($("[data-detail-title]", root), `${record.source} · ${record.event_type}`);
    const json = $("[data-detail-json]", root);
    if (json) text(json, JSON.stringify({ payload: record.payload, metadata: record.metadata }, null, 2));
    const explorerLink = $("[data-link-explorer]", root);
    if (explorerLink) explorerLink.href = `/explorer?event=${encodeURIComponent(record.event_id)}`;
    const incidentLink = $("[data-link-incident]", root);
    if (incidentLink) {
      incidentLink.hidden = !record.incident_id;
      if (record.incident_id) incidentLink.href = `/incidents?incident=${encodeURIComponent(record.incident_id)}`;
    }
    root.hidden = false;
  }

  function renderIncidentTimeline(list, entries) {
    list.replaceChildren();
    for (const entry of entries) {
      const item = document.createElement("li");
      const time = element("time", "", formattedDate(entry.timestamp));
      time.dateTime = entry.timestamp;
      item.append(time, element("strong", "", entry.summary), element("small", "", `${entry.kind} · ${JSON.stringify(entry.details)}`));
      list.append(item);
    }
    if (!entries.length) list.append(element("li", "", "No persisted timeline entries."));
  }

  function renderIncidentGraph(root, graph) {
    const nodes = new Map((graph.nodes || []).map(node => [node.id, node]));
    root.replaceChildren();
    if (!nodes.size) {
      text(root, "No persisted relationships for this incident.");
      return;
    }
    const rendered = new Set();
    for (const edge of graph.edges || []) {
      const source = nodes.get(edge.source);
      const target = nodes.get(edge.target);
      if (!source || !target) continue;
      for (const node of [source, target]) {
        if (rendered.has(node.id)) continue;
        rendered.add(node.id);
        const button = element("button", "relationship-node");
        button.type = "button";
        button.dataset.kind = node.kind;
        button.dataset.nodeId = node.id;
        button.title = JSON.stringify(node.details);
        button.append(element("strong", "", node.kind.toUpperCase()), element("small", "", node.label));
        root.append(button);
      }
      root.append(element("span", "graph-link", `→ ${edge.relation} →`));
    }
  }

  // Loads incident details, timeline, and relationship graph into `root`,
  // which contains [data-incident-*] hooks. Graph nodes show their details on click.
  async function loadIncidentInvestigation(root, incidentId) {
    const output = $("[data-incident-result]", root);
    const investigation = $("[data-incident-investigation]", root);
    const graphRoot = $("[data-incident-graph]", root);
    investigation.hidden = false;
    const base = `/api/v1/incidents/${encodeURIComponent(incidentId)}`;
    const [incidentResult, timelineResult, graphResult] = await Promise.allSettled([
      requestJson(base), requestJson(`${base}/timeline`), requestJson(`${base}/graph`)
    ]);
    let incident = null;
    if (incidentResult.status === "fulfilled" && incidentResult.value.ok) {
      incident = incidentResult.value.data;
      showResult(output, "Incident details", incident);
    } else {
      const reason = incidentResult.status === "rejected" ? incidentResult.reason.message : incidentResult.value.data?.error?.message || `Incident lookup returned HTTP ${incidentResult.value.status}.`;
      showResult(output, "Incident lookup failed", reason, true);
    }
    const timeline = timelineResult.status === "fulfilled" && timelineResult.value.ok && Array.isArray(timelineResult.value.data) ? timelineResult.value.data : [];
    renderIncidentTimeline($("[data-incident-timeline]", root), timeline);
    const graph = graphResult.status === "fulfilled" && graphResult.value.ok ? graphResult.value.data : null;
    if (graph) renderIncidentGraph(graphRoot, graph);
    else text(graphRoot, "Relationship data unavailable.");
    graphRoot.onclick = event => {
      const node = event.target.closest("[data-node-id]");
      const item = node && graph?.nodes.find(candidate => candidate.id === node.dataset.nodeId);
      if (item) showResult(output, `${item.kind} details`, item.details);
    };
    return incident;
  }

  function setSystemState(state) {
    const system = $("#systemState");
    system.dataset.state = state;
    text($("#systemStateText"), state === "ready" ? "Observability core online" : state === "offline" ? "API offline" : state === "degraded" ? "Pipeline degraded" : "Status unknown");
  }

  // Runs the health, readiness, and diagnostics probes and updates the header state.
  async function probeHealth() {
    const [healthResult, readinessResult, diagnosticsResult] = await Promise.allSettled([
      requestJson("/api/health"),
      requestJson("/api/readiness"),
      requestJson("/api/diagnostics")
    ]);
    const health = healthResult.status === "fulfilled" ? healthResult.value : null;
    const readiness = readinessResult.status === "fulfilled" ? readinessResult.value : null;
    const diagnostics = diagnosticsResult.status === "fulfilled" ? diagnosticsResult.value : null;
    const healthOk = Boolean(health && health.ok && health.data && health.data.status === "ok");
    let pipeline = { state: "unknown", label: "UNKNOWN", detail: "Health telemetry unavailable" };
    if (health && !health.ok) {
      pipeline = { state: "degraded", label: "DEGRADED", detail: `Health returned HTTP ${health.status}` };
    } else if (!health) {
      pipeline = { state: "offline", label: "OFFLINE", detail: healthResult.reason?.message || "Health probe unavailable" };
    } else if (healthOk && diagnostics?.ok && diagnostics.data?.status === "ok" && readiness?.ok && readiness.data?.status === "ok") {
      pipeline = { state: "ready", label: "OPERATIONAL", detail: "Health, readiness, and dependencies ready" };
    } else if (healthOk) {
      pipeline = { state: "degraded", label: "DEGRADED", detail: "One or more dependencies are not ready" };
    }
    setSystemState(pipeline.state);
    const failures = [healthResult, readinessResult, diagnosticsResult].filter(result => result.status === "rejected").map(result => result.reason.message);
    return { health, readiness, diagnostics, healthOk, healthError: healthResult.reason?.message, pipeline, failures };
  }

  function setStatusRow(row, state, detail, label) {
    if (!row) return;
    const chip = $(".status-chip", row);
    chip.dataset.state = state;
    text(chip, label || state.toUpperCase());
    text($(".telemetry-detail", row), detail);
  }

  // Updates every [data-integration] row inside `root` from /api/v1/integrations/status.
  async function loadIntegrations(root, summaryTag = null) {
    const rows = $$("[data-integration]", root);
    try {
      const response = await requestJson("/api/v1/integrations/status");
      if (!response.ok || !response.data) throw new Error(`Integrations status returned HTTP ${response.status}.`);
      const integrations = response.data.integrations || [];
      for (const row of rows) {
        const item = integrations.find(candidate => candidate.key === row.dataset.integration);
        if (!item) setStatusRow(row, "unknown", "Not reported by the API", "N/A");
        else if (!item.configured) setStatusRow(row, "unknown", item.detail, "DISABLED");
        else if (item.reachable === null || item.reachable === undefined) setStatusRow(row, "unknown", item.detail, "N/A");
        else if (item.reachable) setStatusRow(row, "ready", item.detail, "REACHABLE");
        else setStatusRow(row, "degraded", item.detail, "UNREACHABLE");
      }
      if (summaryTag) {
        const enabled = integrations.filter(item => item.configured).length;
        summaryTag.dataset.state = enabled > 0 ? "ready" : "unknown";
        text(summaryTag, `${enabled}/${integrations.length} ENABLED`);
      }
      return integrations;
    } catch (error) {
      for (const row of rows) setStatusRow(row, "unknown", error.message, "N/A");
      if (summaryTag) {
        summaryTag.dataset.state = "offline";
        text(summaryTag, "UNAVAILABLE");
      }
      return null;
    }
  }

  function updateUrlParams(values) {
    const url = new URL(window.location.href);
    for (const [key, value] of Object.entries(values)) {
      if (value === "" || value === null || value === undefined || (key === "offset" && Number(value) === 0)) url.searchParams.delete(key);
      else url.searchParams.set(key, String(value));
    }
    window.history.replaceState(null, "", `${url.pathname}${url.search}`);
  }

  // Paged, filterable table bound to a list endpoint. `root` contains
  // [data-rows] (tbody), [data-page-info], [data-prev], [data-next], and
  // optionally [data-total], form[data-filters], and [data-sort].
  function createPagedList({ root, endpoint, label, columns, renderRow, filters = {}, pageSize = 10, syncUrl = false, onLoad = null }) {
    const state = { offset: 0, total: 0, ...filters };
    const keys = Object.keys(filters);
    const body = $("[data-rows]", root);
    const form = $("form[data-filters]", root);
    let records = [];
    let requestId = 0;

    if (syncUrl) {
      const params = new URLSearchParams(window.location.search);
      for (const key of keys) if (params.has(key)) state[key] = params.get(key);
      state.offset = Math.max(0, Number(params.get("offset")) || 0);
    }
    const fillForm = () => {
      if (!form) return;
      for (const key of keys) if (form.elements[key]) form.elements[key].value = state[key] ?? "";
    };
    fillForm();

    async function load() {
      const id = ++requestId;
      setTableMessage(body, columns, `Loading ${label}…`);
      try {
        const data = await fetchPage(endpoint, { ...state, limit: pageSize });
        if (id !== requestId) return;
        state.total = data.total;
        records = data.items;
        body.replaceChildren();
        if (!records.length) setTableMessage(body, columns, state.total ? `No ${label} on this page.` : `No ${label} match these filters.`);
        for (const record of records) body.append(renderRow(record));
        const start = state.total === 0 ? 0 : state.offset + 1;
        const end = Math.min(state.offset + pageSize, state.total);
        text($("[data-page-info]", root), `${start}-${end} of ${format(state.total)}`);
        $("[data-prev]", root).disabled = state.offset === 0;
        $("[data-next]", root).disabled = state.offset + pageSize >= state.total;
        text($("[data-total]", root), `${format(state.total)} records`);
        if (syncUrl) updateUrlParams(Object.fromEntries([...keys.map(key => [key, state[key] === filters[key] ? "" : state[key]]), ["offset", state.offset]]));
        onLoad?.(data);
      } catch (error) {
        if (id !== requestId) return;
        setTableMessage(body, columns, `API NOT AVAILABLE · ${error.message}`);
        text($("[data-page-info]", root), `${label[0].toUpperCase()}${label.slice(1)} unavailable`);
        text($("[data-total]", root), "Unavailable");
      }
    }

    function applyFilters(values) {
      for (const key of keys) state[key] = values[key] ?? "";
      state.offset = 0;
      fillForm();
      return load();
    }

    form?.addEventListener("submit", event => {
      event.preventDefault();
      void applyFilters(Object.fromEntries(new FormData(form)));
    });
    form?.addEventListener("reset", () => window.setTimeout(() => void applyFilters(filters)));
    $("[data-prev]", root).addEventListener("click", () => {
      state.offset = Math.max(0, state.offset - pageSize);
      void load();
    });
    $("[data-next]", root).addEventListener("click", () => {
      if (state.offset + pageSize < state.total) state.offset += pageSize;
      void load();
    });
    $("[data-sort]", root)?.addEventListener("click", () => {
      state.sort_order = state.sort_order === "asc" ? "desc" : "asc";
      void load();
    });

    return { state, load, applyFilters, records: () => records };
  }

  function downloadFile(name, content, type) {
    const url = URL.createObjectURL(new Blob([content], { type }));
    const link = element("a");
    link.href = url;
    link.download = name;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  window.NSEP = {
    $, $$, text, format, element, WORKER_RULES, RISK_WEIGHTS, SEVERITIES,
    queryString, requestJson, fetchPage, countOf, findEvent,
    formattedDate, displayValue, getPayloadValue,
    setTableMessage, createCell, nodeCell, createButton, createLink, severityPill, statusPill, riskMeter, shortId,
    dataState, showDataState, showResult,
    renderActivityChart, bucketByHour, coverageLabel, renderBreakdown, renderRuleSummary, renderWorkerRules,
    renderDetailGrid, renderEventDetail, renderIncidentTimeline, renderIncidentGraph, loadIncidentInvestigation,
    setSystemState, probeHealth, setStatusRow, loadIntegrations, updateUrlParams, createPagedList, downloadFile
  };
  // Keep the active tab visible when the nav scrolls horizontally on narrow screens.
  for (const activeLink of $$(".primary-nav .nav-link.active, .secondary-nav .nav-link.active")) {
    activeLink.parentElement.scrollLeft = activeLink.offsetLeft - activeLink.parentElement.offsetLeft - 12;
  }
  // Every page shows live pipeline state in the shared header.
  window.NSEP.health = probeHealth();
})();
