"""
OWASP Top 10 Security Scan — Network Guardian Dashboard
=========================================================
Tests all OWASP 2021 Top 10 categories against the live dashboard.
Starts the engine + dashboard on an ephemeral port, then attacks it.

Categories tested:
  A01 - Broken Access Control
  A02 - Cryptographic Failures
  A03 - Injection
  A04 - Insecure Design
  A05 - Security Misconfiguration
  A06 - Vulnerable & Outdated Components
  A07 - Identification & Authentication Failures
  A08 - Software & Data Integrity Failures
  A09 - Security Logging & Monitoring Failures
  A10 - Server-Side Request Forgery (SSRF)
"""

from __future__ import annotations

import asyncio
import inspect
import json
import socket
import sys
import time
from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class Finding:
    """A security finding from the scan."""
    def __init__(self, category: str, severity: str, title: str, detail: str, remediation: str = ""):
        self.category = category
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.title = title
        self.detail = detail
        self.remediation = remediation

    def __str__(self):
        return f"[{self.severity}] {self.category}: {self.title}"


FINDINGS: list[Finding] = []

def report(category: str, severity: str, title: str, detail: str, remediation: str = ""):
    f = Finding(category, severity, title, detail, remediation)
    FINDINGS.append(f)
    marker = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": "~", "INFO": "."}
    print(f"    {marker.get(severity, '?')} [{severity}] {title}")
    if detail:
        for line in detail.split("\n"):
            print(f"        {line}")

def report_pass(category: str, title: str):
    print(f"    . [PASS] {title}")


async def raw_request(host: str, port: int, request: str, timeout: float = 5.0) -> str:
    """Send a raw HTTP request and return the full response."""
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(request.encode())
    await writer.drain()
    try:
        data = await asyncio.wait_for(reader.read(65536), timeout=timeout)
        return data.decode(errors="replace")
    except asyncio.TimeoutError:
        return ""
    finally:
        writer.close()


def parse_response(raw: str) -> tuple[int, dict[str, str], str]:
    """Parse raw HTTP response into (status, headers_dict, body)."""
    if not raw:
        return 0, {}, ""
    parts = raw.split("\r\n\r\n", 1)
    header_block = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    lines = header_block.split("\r\n")
    status = 0
    if lines:
        sp = lines[0].split(" ", 2)
        if len(sp) >= 2:
            try:
                status = int(sp[1])
            except ValueError:
                pass
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers, body


# ===========================================================================
# OWASP A01 — Broken Access Control
# ===========================================================================

async def test_a01(host: str, port: int):
    print("\n  [A01] Broken Access Control")
    print("  " + "-" * 50)

    # Test 1: Path traversal
    traversal_paths = [
        "/../../../etc/passwd",
        "/..\\..\\..\\windows\\system32\\config\\sam",
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/....//....//....//etc/passwd",
        "/api/../../../etc/passwd",
    ]
    for path in traversal_paths:
        req = f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
        resp = await raw_request(host, port, req)
        status, headers, body = parse_response(resp)
        if status == 200 and ("root:" in body or "SYSTEM" in body.upper()):
            report("A01", "CRITICAL", "Path traversal exposes system files",
                   f"Path: {path}\nReturned sensitive content",
                   "Sanitise path input, reject '..' sequences")
            break
    else:
        report_pass("A01", "Path traversal attacks return 404 (no file disclosure)")

    # Test 2: HTTP verb tampering
    for verb in ["DELETE", "PUT", "PATCH", "OPTIONS", "TRACE"]:
        req = f"{verb} /api/status HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
        resp = await raw_request(host, port, req)
        status, _, body = parse_response(resp)
        if verb == "TRACE" and status == 200 and verb in body.upper():
            report("A01", "MEDIUM", f"TRACE method enabled",
                   "Server reflects request body back — enables XST attacks",
                   "Disable TRACE method")
            break
    else:
        report_pass("A01", "Dangerous HTTP methods not exploitable")

    # Test 3: Forced browsing to internal paths
    hidden_paths = ["/admin", "/config", "/debug", "/internal",
                    "/api/internal", "/.env", "/api/config"]
    leaks = []
    for path in hidden_paths:
        req = f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
        resp = await raw_request(host, port, req)
        status, _, body = parse_response(resp)
        if status == 200 and len(body) > 10:
            leaks.append(path)

    if leaks:
        report("A01", "MEDIUM", "Hidden endpoints accessible without auth",
               f"Paths returning 200: {', '.join(leaks)}",
               "Add authentication or return 404 for internal paths")
    else:
        report_pass("A01", "No hidden/admin endpoints discoverable")


# ===========================================================================
# OWASP A02 — Cryptographic Failures
# ===========================================================================

async def test_a02(host: str, port: int):
    print("\n  [A02] Cryptographic Failures")
    print("  " + "-" * 50)

    # Test 1: HTTP (no TLS)
    report("A02", "MEDIUM", "Dashboard serves over plain HTTP",
           "No TLS/SSL encryption — traffic is in cleartext on the network",
           "Add TLS via reverse proxy (nginx/caddy) or implement native TLS")

    # Test 2: Check if sensitive data is exposed in API responses
    req = f"GET /api/status HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    resp = await raw_request(host, port, req)
    _, _, body = parse_response(resp)

    sensitive_keywords = ["password", "secret", "api_key", "token", "private_key",
                          "credentials", "auth_token"]
    found = [kw for kw in sensitive_keywords if kw in body.lower()]
    if found:
        report("A02", "HIGH", "Sensitive data in API response",
               f"Keywords found: {', '.join(found)}",
               "Remove sensitive data from API responses")
    else:
        report_pass("A02", "No sensitive data keywords in /api/status response")

    # Test 3: Check config for encryption defaults
    from network_guardian.config import Config
    config = Config()
    if not config.security.encrypt_reports:
        report("A02", "MEDIUM", "Report encryption disabled by default",
               "encrypt_reports = False",
               "Set encrypt_reports = True in default config")
    else:
        report_pass("A02", "Report encryption enabled by default")


# ===========================================================================
# OWASP A03 — Injection
# ===========================================================================

async def test_a03(host: str, port: int):
    print("\n  [A03] Injection")
    print("  " + "-" * 50)

    # Test 1: Header injection (CRLF)
    crlf_paths = [
        "/api/status%0d%0aSet-Cookie:%20hacked=true",
        "/api/status%0d%0aX-Injected:%20yes",
        "/api/status\r\nInjected: header",
    ]
    for path in crlf_paths:
        req = f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
        resp = await raw_request(host, port, req)
        _, headers, _ = parse_response(resp)
        if "x-injected" in headers or "set-cookie" in headers:
            report("A03", "HIGH", "HTTP response splitting (CRLF injection)",
                   f"Path: {path}\nInjected headers appear in response",
                   "URL-decode and reject CRLF characters in path")
            break
    else:
        report_pass("A03", "No CRLF / header injection possible")

    # Test 2: XSS in path (reflected)
    xss_paths = [
        "/<script>alert(1)</script>",
        "/\"><img src=x onerror=alert(1)>",
        "/api/<svg onload=alert(1)>",
    ]
    for path in xss_paths:
        req = f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
        resp = await raw_request(host, port, req)
        _, _, body = parse_response(resp)
        if "<script>" in body or "onerror=" in body or "<svg" in body:
            report("A03", "HIGH", "Reflected XSS in error page",
                   f"Path: {path}\nScript tag reflected in response body",
                   "HTML-encode all user input in error responses")
            break
    else:
        report_pass("A03", "No reflected XSS in error responses")

    # Test 3: SQL injection payloads (should not crash)
    sqli_paths = ["/api/status?id=1'+OR+'1'='1", "/api/status?id=1;DROP+TABLE+users",
                  "/api/hosts?q='+UNION+SELECT+*+FROM+information_schema.tables--"]
    for path in sqli_paths:
        req = f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
        resp = await raw_request(host, port, req)
        status, _, body = parse_response(resp)
        if status == 500 or "error" in body.lower() and "sql" in body.lower():
            report("A03", "MEDIUM", "SQL-like error from injection payload",
                   f"Path: {path}\nStatus: {status}",
                   "Use parameterised queries, sanitise input")
            break
    else:
        report_pass("A03", "No SQL injection errors triggered")

    # Test 4: Command injection in Host header
    req = f"GET /api/health HTTP/1.1\r\nHost: ;whoami\r\n\r\n"
    resp = await raw_request(host, port, req)
    _, _, body = parse_response(resp)
    # Only flag if the response contains a system username that is NOT part of a
    # normal JSON field (e.g. data_dir may contain the username by design).
    import os as _os
    username = _os.environ.get("USERNAME", _os.environ.get("USER", "")).lower()
    # Health endpoint returns {"status":"ok","engine_running":true} — no paths.
    body_lower = body.lower()
    is_injection = (
        username and username in body_lower
        and "data_dir" not in body_lower
        and ("whoami" not in body_lower)
    )
    if is_injection:
        report("A03", "CRITICAL", "Command injection via Host header",
               "Server executed system command from Host header",
               "Never pass headers to shell commands")
    else:
        report_pass("A03", "No command injection via Host header")

    # Test 5: Code-level check — no shell=True in the codebase sensors
    from network_guardian.sensors import PingSensor, PortScanner
    for cls in [PingSensor, PortScanner]:
        src = inspect.getsource(cls)
        if "shell=True" in src:
            report("A03", "CRITICAL", f"{cls.__name__} uses shell=True",
                   "Subprocess calls with shell=True allow command injection",
                   "Use create_subprocess_exec (argument list) instead")
    report_pass("A03", "No shell=True in sensor subprocess calls")


# ===========================================================================
# OWASP A04 — Insecure Design
# ===========================================================================

async def test_a04(host: str, port: int):
    print("\n  [A04] Insecure Design")
    print("  " + "-" * 50)

    # Test 1: Rate limiting
    start = time.perf_counter()
    count = 0
    for _ in range(100):
        req = f"GET /api/health HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
        resp = await raw_request(host, port, req, timeout=2.0)
        status, _, _ = parse_response(resp)
        if status == 200:
            count += 1
    elapsed = time.perf_counter() - start

    if count >= 95:
        report("A04", "MEDIUM", "No rate limiting on API endpoints",
               f"Sent 100 requests in {elapsed:.1f}s — {count} succeeded (no throttling)",
               "Implement rate limiting (e.g., token bucket per IP)")
    else:
        report_pass("A04", f"Rate limiting active ({count}/100 succeeded)")

    # Test 2: No authentication on any endpoint
    endpoints = ["/api/status", "/api/findings", "/api/events",
                 "/api/hosts", "/api/tasks", "/api/health"]
    unauth = []
    for ep in endpoints:
        req = f"GET {ep} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
        resp = await raw_request(host, port, req)
        status, _, _ = parse_response(resp)
        if status == 200:
            unauth.append(ep)

    if unauth:
        report("A04", "HIGH", "No authentication required on API endpoints",
               f"All {len(unauth)} endpoints accessible without credentials:\n" +
               "\n".join(f"  {ep}" for ep in unauth),
               "Add API key or token-based authentication")
    else:
        report_pass("A04", "API endpoints require authentication")

    # Test 3: Error messages don't leak stack traces
    req = f"GET /nonexistent HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    resp = await raw_request(host, port, req)
    _, _, body = parse_response(resp)
    if "Traceback" in body or "File \"" in body or "line " in body:
        report("A04", "MEDIUM", "Stack trace leaked in error response",
               f"Body contains Python traceback",
               "Return generic error messages, log details server-side")
    else:
        report_pass("A04", "Error pages don't leak stack traces")


# ===========================================================================
# OWASP A05 — Security Misconfiguration
# ===========================================================================

async def test_a05(host: str, port: int):
    print("\n  [A05] Security Misconfiguration")
    print("  " + "-" * 50)

    # Test 1: Missing security headers
    req = f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    resp = await raw_request(host, port, req)
    _, headers, _ = parse_response(resp)

    required_headers = {
        "x-content-type-options": "Prevents MIME-type sniffing",
        "x-frame-options": "Prevents clickjacking",
        "content-security-policy": "Prevents XSS and data injection",
        "x-xss-protection": "Legacy XSS protection",
        "strict-transport-security": "Enforces HTTPS",
        "referrer-policy": "Controls referrer leakage",
        "permissions-policy": "Restricts browser features",
    }

    missing = []
    present = []
    for header, desc in required_headers.items():
        if header in headers:
            present.append(header)
        else:
            missing.append(f"{header} ({desc})")

    if missing:
        report("A05", "HIGH", f"Missing {len(missing)} security headers",
               "\n".join(f"  - {h}" for h in missing),
               "Add security headers to all HTTP responses")
    if present:
        report_pass("A05", f"{len(present)} security headers present")

    # Test 2: Server banner leakage
    if "server" in headers:
        report("A05", "LOW", f"Server header reveals software: {headers['server']}",
               "Server version disclosure aids reconnaissance",
               "Remove or genericise the Server header")
    else:
        report_pass("A05", "No Server header leakage")

    # Test 3: Directory listing
    dir_paths = ["/static/", "/assets/", "/files/", "/uploads/"]
    for path in dir_paths:
        req = f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
        resp = await raw_request(host, port, req)
        _, _, body = parse_response(resp)
        if "Index of" in body or "<li>" in body and ".." in body:
            report("A05", "MEDIUM", f"Directory listing enabled at {path}",
                   "Attackers can enumerate files",
                   "Disable directory listing")
            break
    else:
        report_pass("A05", "No directory listing exposed")

    # Test 4: CORS misconfiguration
    req = f"GET /api/status HTTP/1.1\r\nHost: {host}:{port}\r\nOrigin: https://evil.com\r\n\r\n"
    resp = await raw_request(host, port, req)
    _, headers, _ = parse_response(resp)
    acao = headers.get("access-control-allow-origin", "")
    if acao == "*" or "evil.com" in acao:
        report("A05", "HIGH", "CORS allows any origin",
               f"Access-Control-Allow-Origin: {acao}",
               "Restrict CORS to trusted origins only")
    else:
        report_pass("A05", "CORS not misconfigured (no wildcard origin)")


# ===========================================================================
# OWASP A06 — Vulnerable & Outdated Components
# ===========================================================================

async def test_a06(host: str, port: int):
    print("\n  [A06] Vulnerable & Outdated Components")
    print("  " + "-" * 50)

    # Check Python version
    ver = sys.version_info
    if ver < (3, 10):
        report("A06", "MEDIUM", f"Python {ver.major}.{ver.minor} may lack security patches",
               "Older Python versions stop receiving CVE fixes",
               "Upgrade to Python 3.12+")
    else:
        report_pass("A06", f"Python {ver.major}.{ver.minor}.{ver.micro} (supported)")

    # Check dependencies for known issues
    try:
        import yaml
        yaml_ver = getattr(yaml, "__version__", "unknown")
        # Check if yaml.safe_load is used vs yaml.load
        from network_guardian.config import Config
        src = inspect.getsource(Config)
        if "yaml.load(" in src and "Loader=" not in src:
            report("A06", "HIGH", "Unsafe yaml.load() without Loader",
                   "yaml.load() without SafeLoader allows arbitrary code execution",
                   "Use yaml.safe_load() instead")
        elif "safe_load" in src:
            report_pass("A06", f"PyYAML {yaml_ver} uses safe_load (safe)")
        else:
            report_pass("A06", f"PyYAML {yaml_ver} present")
    except ImportError:
        report_pass("A06", "PyYAML not installed (no YAML parsing risk)")

    # Check for hardcoded credentials in source
    import pathlib
    src_dir = pathlib.Path(__file__).parent / "network_guardian"
    cred_patterns = ["password=", "secret=", "api_key=", "token=", "private_key="]
    found_creds = []
    for py_file in src_dir.rglob("*.py"):
        content = py_file.read_text(errors="replace")
        for pattern in cred_patterns:
            if pattern in content.lower():
                # exclude config env var references and test patterns
                lines = [l.strip() for l in content.split("\n") if pattern in l.lower()]
                for line in lines:
                    if "env" not in line.lower() and "test" not in line.lower() and "#" not in line[:5]:
                        found_creds.append(f"{py_file.name}: {line[:80]}")

    if found_creds:
        report("A06", "HIGH", "Possible hardcoded credentials in source",
               "\n".join(found_creds[:5]),
               "Move credentials to environment variables or a secrets manager")
    else:
        report_pass("A06", "No hardcoded credentials found in source")


# ===========================================================================
# OWASP A07 — Identification & Authentication Failures
# ===========================================================================

async def test_a07(host: str, port: int):
    print("\n  [A07] Identification & Authentication Failures")
    print("  " + "-" * 50)

    # Test 1: No auth on any endpoint (already checked in A04 but distinct category)
    req = f"GET /api/findings HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    resp = await raw_request(host, port, req)
    status, _, _ = parse_response(resp)
    if status == 200:
        report("A07", "HIGH", "API exposes audit findings without authentication",
               "/api/findings returns data to any unauthenticated request",
               "Implement bearer token or session-based authentication")
    else:
        report_pass("A07", "Findings endpoint requires authentication")

    # Test 2: Session management
    from network_guardian.config import Config
    config = Config()
    if config.security.session_timeout > 7200:
        report("A07", "LOW", f"Long session timeout: {config.security.session_timeout}s",
               "Extended sessions increase hijacking risk",
               "Set session timeout to 3600s or less")
    else:
        report_pass("A07", f"Session timeout: {config.security.session_timeout}s (reasonable)")

    # Test 3: Brute-force protection
    if config.security.max_login_attempts > 10:
        report("A07", "MEDIUM", f"High max login attempts: {config.security.max_login_attempts}",
               "Allows brute-force attacks",
               "Set max attempts to 5 or less, add exponential backoff")
    else:
        report_pass("A07", f"Max login attempts: {config.security.max_login_attempts} (configured)")


# ===========================================================================
# OWASP A08 — Software & Data Integrity Failures
# ===========================================================================

async def test_a08(host: str, port: int):
    print("\n  [A08] Software & Data Integrity Failures")
    print("  " + "-" * 50)

    # Test 1: Inline scripts without integrity hashes (CSP/SRI)
    req = f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    resp = await raw_request(host, port, req)
    _, headers, body = parse_response(resp)

    if "<script>" in body and "integrity=" not in body:
        report("A08", "MEDIUM", "Inline JavaScript without integrity protection",
               "Dashboard HTML contains <script> blocks without CSP nonce or SRI hash",
               "Add Content-Security-Policy with script-src nonce, or use external scripts with SRI")
    elif "<script" in body and "integrity=" in body:
        report_pass("A08", "Scripts have integrity attributes")
    else:
        report_pass("A08", "No inline scripts found")

    # Test 2: Check if API responses include anti-tampering
    if "x-content-type-options" not in headers:
        report("A08", "LOW", "Missing X-Content-Type-Options header",
               "Browser may MIME-sniff responses, enabling content injection",
               "Add X-Content-Type-Options: nosniff")

    # Test 3: Check for unsigned/unverified data deserialization
    from network_guardian.config import Config
    src = inspect.getsource(Config)
    if "pickle" in src or "marshal" in src or "shelve" in src:
        report("A08", "CRITICAL", "Unsafe deserialization (pickle/marshal/shelve)",
               "Deserialization of untrusted data enables remote code execution",
               "Use JSON or safe serialization only")
    else:
        report_pass("A08", "No unsafe deserialization (pickle/marshal) in Config")


# ===========================================================================
# OWASP A09 — Security Logging & Monitoring Failures
# ===========================================================================

async def test_a09(host: str, port: int):
    print("\n  [A09] Security Logging & Monitoring Failures")
    print("  " + "-" * 50)

    # Test 1: Check if logging is configured
    from network_guardian.utils.logging import setup_logging
    import logging
    setup_logging("INFO")
    logger = logging.getLogger("network_guardian")
    if not logger.handlers and not logging.getLogger().handlers:
        report("A09", "MEDIUM", "No log handlers configured",
               "Security events won't be captured",
               "Configure file and/or syslog handlers")
    else:
        report_pass("A09", f"Logging configured ({len(logger.handlers) or len(logging.getLogger().handlers)} handler(s))")

    # Test 2: Check if security events are logged
    from network_guardian.core.events import EventBus
    bus = EventBus()
    security_topics = ["audit.finding", "monitor.anomaly", "ai.anomaly_detected"]
    # The Dashboard subscribes to these for the event feed
    from network_guardian.interface.dashboard import Dashboard
    src = inspect.getsource(Dashboard.__init__)
    logged_topics = [t for t in security_topics if t in src]
    if len(logged_topics) < len(security_topics):
        missing = set(security_topics) - set(logged_topics)
        report("A09", "LOW", f"Dashboard doesn't capture all security events",
               f"Missing: {', '.join(missing)}",
               "Subscribe to all security-relevant event topics")
    else:
        report_pass("A09", f"Dashboard captures {len(logged_topics)} security event types")

    # Test 3: Failed requests aren't logged in detail
    # Send a malicious request and check dashboard logging
    src_handle = inspect.getsource(Dashboard._handle_client)
    if "logger" in src_handle:
        if "request" in src_handle.lower() or "client" in src_handle.lower():
            report_pass("A09", "Client errors are logged")
        else:
            report("A09", "LOW", "Dashboard logs errors but not request details",
                   "Failed requests don't log client IP or path — limits forensics",
                   "Log client IP, method, path, and status for all requests")
    else:
        report("A09", "MEDIUM", "Dashboard handler doesn't log anything",
               "No audit trail for failed or malicious requests",
               "Add request logging with client details")


# ===========================================================================
# OWASP A10 — Server-Side Request Forgery (SSRF)
# ===========================================================================

async def test_a10(host: str, port: int):
    print("\n  [A10] Server-Side Request Forgery (SSRF)")
    print("  " + "-" * 50)

    # Test 1: Check if any API endpoint accepts URLs/IPs as parameters
    # Dashboard routes are static — no user-supplied URLs
    from network_guardian.interface.dashboard import Dashboard
    src = inspect.getsource(Dashboard._route)
    if "request" in src and ("url" in src.lower() or "fetch" in src.lower() or "proxy" in src.lower()):
        report("A10", "HIGH", "Dashboard routes may accept user-supplied URLs",
               "Could enable SSRF if URLs are fetched server-side",
               "Validate and whitelist all URLs before server-side fetching")
    else:
        report_pass("A10", "Dashboard routes are static — no user-supplied URL handling")

    # Test 2: Check sensors for SSRF-like behaviour
    from network_guardian.sensors import PingSensor, PortScanner, NmapSensor
    # PingSensor and PortScanner accept target IPs — these are by design
    # but check they don't auto-resolve internal hostnames to cloud metadata
    report("A10", "INFO", "Sensors accept target IPs by design (audit/scan tools)",
           "PingSensor, PortScanner, NmapSensor accept targets — expected for a network tool.\n"
           "Ensure CLI validates targets before passing to sensors.",
           "Add target validation: reject cloud metadata IPs (169.254.169.254), "
           "localhost redirects, and non-routable ranges unless explicitly allowed")


# ===========================================================================
# BONUS — Extra security checks
# ===========================================================================

async def test_bonus(host: str, port: int):
    print("\n  [BONUS] Additional Security Checks")
    print("  " + "-" * 50)

    # Test 1: Slowloris-style slow request
    try:
        reader, writer = await asyncio.open_connection(host, port)
        # Send partial request
        writer.write(b"GET / HTTP/1.1\r\nHost: test\r\n")
        await writer.drain()
        # Wait and see if server times us out
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=12)
            # If we got data or disconnect within 12s, server has a timeout
            report_pass("BONUS", "Server enforces request read timeout (good)")
        except asyncio.TimeoutError:
            report("BONUS", "LOW", "No request timeout — possible Slowloris vulnerability",
                   "Server waited >10s for incomplete request",
                   "Add request header read timeout (e.g., 10 seconds)")
        finally:
            writer.close()
    except (OSError, ConnectionError):
        report_pass("BONUS", "Server refused slow connection")

    # Test 2: Large header attack
    huge_header = "X-Test: " + "A" * 100000
    req = f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\n{huge_header}\r\n\r\n"
    try:
        resp = await raw_request(host, port, req, timeout=5.0)
        status, _, _ = parse_response(resp)
        if status == 200:
            report("BONUS", "LOW", "Server accepted 100KB header without rejection",
                   "Large headers can cause memory exhaustion",
                   "Limit header size to 8KB")
        elif status in (413, 431, 400):
            report_pass("BONUS", f"Server rejected oversized header (status {status})")
        else:
            report_pass("BONUS", f"Large header handled gracefully (status {status})")
    except (OSError, ConnectionError):
        report_pass("BONUS", "Server rejected oversized request")

    # Test 3: Null byte injection
    req = f"GET /api/status%00.html HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    resp = await raw_request(host, port, req)
    status, _, _ = parse_response(resp)
    if status == 200:
        report("BONUS", "LOW", "Null byte in path returns 200",
               "Null byte injection may bypass security filters",
               "Reject paths containing null bytes")
    else:
        report_pass("BONUS", "Null byte paths handled correctly")


# ===========================================================================
# MAIN
# ===========================================================================

async def main():
    print("\n" + "=" * 70)
    print("  OWASP TOP 10 SECURITY SCAN — NETWORK GUARDIAN DASHBOARD")
    print("  " + "=" * 66)
    print("  Target: localhost (ephemeral port)")
    print("  Method: Black-box + Gray-box (code inspection)")
    print("=" * 70)

    # Start the engine and dashboard
    from network_guardian.config import Config
    from network_guardian.core.engine import Engine

    config = Config()
    engine = Engine(config)
    await engine.start()

    # Bind to port 0 (OS picks a free port)
    engine.dashboard.port = 0
    await engine.dashboard.start()

    # Get actual bound port
    sockets = engine.dashboard._server.sockets
    actual_port = sockets[0].getsockname()[1]
    host = "127.0.0.1"

    print(f"  Dashboard started on http://{host}:{actual_port}")
    print("=" * 70)

    t0 = time.perf_counter()

    try:
        await test_a01(host, actual_port)
        await test_a02(host, actual_port)
        await test_a03(host, actual_port)
        await test_a04(host, actual_port)
        await test_a05(host, actual_port)
        await test_a06(host, actual_port)
        await test_a07(host, actual_port)
        await test_a08(host, actual_port)
        await test_a09(host, actual_port)
        await test_a10(host, actual_port)
        await test_bonus(host, actual_port)
    finally:
        await engine.stop()

    elapsed = time.perf_counter() - t0

    # ---------------------------------------------------------------------------
    # Summary report
    # ---------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  SCAN SUMMARY")
    print("=" * 70)
    print(f"  Scan duration: {elapsed:.1f}s")
    print(f"  Total findings: {len(FINDINGS)}")

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    by_severity = {}
    for f in FINDINGS:
        by_severity.setdefault(f.severity, []).append(f)

    for sev in severity_order:
        items = by_severity.get(sev, [])
        if items:
            print(f"\n  [{sev}] ({len(items)})")
            for f in items:
                print(f"    - {f.category}: {f.title}")
                if f.remediation:
                    print(f"      Fix: {f.remediation}")

    risk_score = (
        len(by_severity.get("CRITICAL", [])) * 10 +
        len(by_severity.get("HIGH", [])) * 7 +
        len(by_severity.get("MEDIUM", [])) * 4 +
        len(by_severity.get("LOW", [])) * 1
    )

    print(f"\n  Risk Score: {risk_score}/100")
    if risk_score == 0:
        print("  Grade: A+ (No findings)")
    elif risk_score <= 10:
        print("  Grade: A (Minimal risk)")
    elif risk_score <= 25:
        print("  Grade: B (Low risk)")
    elif risk_score <= 50:
        print("  Grade: C (Moderate risk)")
    elif risk_score <= 75:
        print("  Grade: D (High risk)")
    else:
        print("  Grade: F (Critical risk)")
    print()


if __name__ == "__main__":
    asyncio.run(main())
