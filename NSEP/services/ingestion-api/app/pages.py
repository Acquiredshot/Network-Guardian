"""Server-composed SOC pages.

Each top-level navigation item is its own route and HTML document. Pages share one
layout (header, navigation, footer) and differ only in their content fragment and
page script, so every route survives a browser refresh without client-side routing.

Pages are organized into groups (NSEP, Network Guardian, Zammad, Hermes Agent,
Administration). Dashboard has no group and renders as a standalone top-level item.
Each group keeps its own backend boundary -- this module only composes navigation
and static shells; it never proxies or merges another system's API.
"""

from dataclasses import dataclass
from html import escape
from pathlib import Path
from urllib.parse import urljoin

TEMPLATES_DIR = Path(__file__).parent / "templates"


@dataclass(frozen=True)
class Page:
    route: str
    label: str
    title: str
    intro: str
    script: str | None = None
    group: str | None = None


GROUPS: tuple[str, ...] = ("NSEP", "Network Guardian", "Zammad", "Hermes Agent", "Administration")

PAGES: tuple[Page, ...] = (
    Page("dashboard", "Dashboard", "Security operations overview", "", "dashboard.js"),
    Page("topology", "Live Topology", "Live platform topology", "Observed service health and persisted activity alongside the configured data-flow architecture.", "pages/topology.js"),

    # NSEP -- existing routes, unchanged URLs and behavior.
    Page("events", "Events", "Event stream", "Persisted security events with filtering, drill-down, and event submission.", "pages/events.js", "NSEP"),
    Page("threats", "Threats", "Threat detections", "Detection summary, risk scores, active threats, and rule breakdown from persisted detections.", "pages/threats.js", "NSEP"),
    Page("ids", "IDS", "Intrusion detection", "Signature-based detections raised by the security workers, with source and destination drill-down.", "pages/ids.js", "NSEP"),
    Page("ips", "IPS", "Intrusion prevention", "Prevention and enforcement activity. The pipeline is currently detect-only.", "pages/ips.js", "NSEP"),
    Page("explorer", "Explorer", "Event explorer", "Advanced event search, payload inspection, and correlation drill-down.", "pages/explorer.js", "NSEP"),
    Page("incidents", "Incidents", "Incident register", "Open, investigating, and resolved incidents with timeline, relationships, and ticketing status.", "pages/incidents.js", "NSEP"),
    Page("reports", "Reports", "Security reports", "Event, detection, incident, and risk statistics aggregated from the live API.", "pages/reports.js", "NSEP"),

    # Network Guardian -- external system. NSEP only pushes incidents out (Event Fabric);
    # it has no inbound query API into Network Guardian, so most pages are honest placeholders.
    Page("network-guardian", "Network Overview", "Network Guardian", "Outbound incident notification status. NSEP does not query Network Guardian for data -- it only pushes incidents to its Event Fabric intake.", "pages/network-guardian/overview.js", "Network Guardian"),
    Page("network-guardian/devices", "Devices", "Device inventory", "Network Guardian device inventory is not queryable from NSEP.", None, "Network Guardian"),
    Page("network-guardian/events", "Network Events", "Network events", "Network Guardian's own event stream is not exposed to NSEP.", None, "Network Guardian"),
    Page("network-guardian/threats", "Threat Detection", "Threat detection", "Network Guardian's IDS/IPS/AI anomaly findings are not exposed to NSEP.", None, "Network Guardian"),
    Page("network-guardian/investigations", "Investigations", "Investigations", "Network Guardian's AI Security Orchestrator investigations are not exposed to NSEP.", None, "Network Guardian"),

    # Zammad -- external system. NSEP creates tickets on new incidents but does not store
    # ticket numbers or query Zammad's ticket/customer data, so most pages are placeholders.
    Page("zammad", "Tickets", "Zammad tickets", "Live status of the Zammad integration. NSEP creates a ticket per new incident but does not store ticket numbers or list tickets locally.", "pages/zammad/tickets.js", "Zammad"),
    Page("zammad/queues", "Queues", "Ticket queues", "Zammad queue/group data is not queryable from NSEP.", None, "Zammad"),
    Page("zammad/customers", "Customers", "Customers", "Zammad organization/customer data is not queryable from NSEP.", None, "Zammad"),
    Page("zammad/analytics", "Ticket Analytics", "Ticket analytics", "Zammad reporting/analytics data is not queryable from NSEP.", None, "Zammad"),

    # Hermes Agent -- connects TO NSEP's MCP server as a client; NSEP has no channel
    # for Hermes to report its own activity back, so most pages are placeholders.
    Page("hermes", "Agent Dashboard", "Hermes Agent", "Hermes Agent is an external MCP client that connects to NSEP's MCP server. NSEP has no telemetry channel for what Hermes itself is doing.", "pages/hermes/dashboard.js", "Hermes Agent"),
    Page("hermes/investigations", "Investigations", "Agent investigations", "Hermes does not report investigation results back to NSEP.", None, "Hermes Agent"),
    Page("hermes/actions", "Actions", "Agent actions", "Hermes tool-call history is not reported back to NSEP. All NSEP MCP tools are read-only.", None, "Hermes Agent"),
    Page("hermes/activity", "Agent Activity", "Agent activity", "Hermes session/activity telemetry is not reported back to NSEP.", None, "Hermes Agent"),

    # Administration -- NSEP's own operational surface. Fully live.
    Page("admin/health", "System Health", "System health", "Live health, readiness, and dependency diagnostics for the ingestion API.", "pages/admin/health.js", "Administration"),
    Page("admin/integrations", "Integrations", "Integrations", "Live reachability of Zammad, Network Guardian, and the MCP server.", "pages/admin/integrations.js", "Administration"),
    Page("admin/settings", "Settings", "Settings", "Configuration is managed per-service through environment variables. This page never displays secrets.", None, "Administration"),
)

PAGES_BY_ROUTE: dict[str, Page] = {page.route: page for page in PAGES}


def _group_pages(group: str) -> list[Page]:
    return [page for page in PAGES if page.group == group]


def _group_default_route(group: str) -> str:
    pages = _group_pages(group)
    return pages[0].route if pages else ""


def _nav_link(page: Page, active: str, extra_class: str = "") -> str:
    classes = "nav-link" + (f" {extra_class}" if extra_class else "")
    attrs = f' class="{classes} active" aria-current="page"' if page.route == active else f' class="{classes}"'
    return f'<a{attrs} href="/{page.route}">{escape(page.label)}</a>'


def _primary_navigation(active_page: Page) -> str:
    links = [_nav_link(PAGES_BY_ROUTE[route], active_page.route) for route in ("dashboard", "topology")]
    for group in GROUPS:
        pages = _group_pages(group)
        if not pages:
            continue
        is_active_group = active_page.group == group
        default_page = pages[0]
        attrs = ' class="nav-link nav-group-link active" aria-current="true"' if is_active_group else ' class="nav-link nav-group-link"'
        links.append(f'<a{attrs} href="/{default_page.route}">{escape(group)}</a>')
    return "\n      ".join(links)


def _secondary_navigation(active_page: Page) -> str:
    if not active_page.group:
        return ""
    pages = _group_pages(active_page.group)
    links = "\n      ".join(_nav_link(page, active_page.route) for page in pages)
    return f'<nav class="secondary-nav" aria-label="{escape(active_page.group)} pages">{links}</nav>'


def _page_header(page: Page) -> str:
    if page.route == "dashboard":
        return ""
    back_route = _group_default_route(page.group) if page.group else "dashboard"
    back_label = page.group if page.group else "Dashboard"
    return (
        '<div class="page-header">'
        f'<a class="back-link" href="/dashboard"><span aria-hidden="true">←</span> Dashboard</a>'
        f'<div><p class="section-label">{escape(back_label)}</p><h2 class="page-title">{escape(page.title)}</h2>'
        f'<p class="page-intro">{escape(page.intro)}</p></div>'
        "</div>"
    )


def _placeholder_content(page: Page) -> str:
    """Shared, honest "not queryable from here" content for pages with no real data source.

    Reuses the same CSS classes as every other data-state panel in the app --
    no fabricated numbers, no simulated activity.
    """
    return f'''
      <div class="data-state data-state-banner" data-kind="not-implemented">
        <span class="data-state-badge">API NOT AVAILABLE</span>
        <strong>{escape(page.title)} is not queryable from NSEP.</strong>
        <p>{escape(page.intro)}</p>
      </div>
      <section class="panel module" aria-label="{escape(page.title)}">
        <div class="module-heading"><div><p class="section-label">Status</p><h2>Why this page has no data</h2></div><span class="quiet-tag">NOT AVAILABLE</span></div>
        <ul class="telemetry-list">
          <li><span class="telemetry-name">Data source</span><span class="telemetry-detail">No API exposes this to NSEP today</span><span class="status-chip" data-state="unknown">N/A</span></li>
          <li><span class="telemetry-name">Fabricated data</span><span class="telemetry-detail">Never shown -- see the dashboard's data rule</span><span class="status-chip" data-state="unknown">DISABLED</span></li>
        </ul>
        <p class="module-footnote">See <a href="/admin/integrations">Administration → Integrations</a> for what NSEP can actually reach today.</p>
      </section>
    '''


def render_pages(*, network_guardian_dashboard_url: str = "http://localhost:8080/") -> dict[str, str]:
    layout = (TEMPLATES_DIR / "layout.html").read_text(encoding="utf-8")
    rendered = {}
    for page in PAGES:
        template_path = TEMPLATES_DIR / "pages" / f"{page.route}.html"
        content = template_path.read_text(encoding="utf-8") if template_path.exists() else _placeholder_content(page)
        page_script_tag = f'<script src="/static/{page.script}" defer></script>' if page.script else ""
        rendered[page.route] = (
            layout.replace("{{page_label}}", escape(page.label))
            .replace("{{route}}", page.route)
            .replace("{{page_script}}", page_script_tag)
            .replace("{{navigation}}", _primary_navigation(page))
            .replace("{{secondary_navigation}}", _secondary_navigation(page))
            .replace("{{page_header}}", _page_header(page))
            .replace("{{content}}", content)
            .replace("{{network_guardian_dashboard_url}}", escape(network_guardian_dashboard_url, quote=True))
            .replace("{{network_guardian_incidents_url}}", escape(urljoin(network_guardian_dashboard_url, "/incidents"), quote=True))
        )
    return rendered
