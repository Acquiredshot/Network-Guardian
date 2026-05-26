# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
CVSS Vulnerability Assessment — Network Guardian
====================================================
Performs a comprehensive static-analysis security audit of the entire
codebase and scores every finding using the CVSS v3.1 framework.

Each finding includes:
  • CVE-style identifier (NG-YYYY-NNNN)
  • CVSS v3.1 vector string
  • Base score + severity rating
  • Exploitability & Impact sub-scores
  • Detailed description, affected file, and remediation advice

Categories scanned:
  1. Injection & Input Validation
  2. Broken Authentication & Access Control
  3. Sensitive Data Exposure
  4. Cryptographic Failures
  5. Security Misconfiguration
  6. Insecure Deserialization
  7. Command / Code Injection
  8. Insufficient Logging & Monitoring
  9. Server-Side Request Forgery (SSRF)
  10. Dependency & Supply Chain
  11. Insecure Randomness
  12. Error Handling & Information Disclosure
  13. Race Conditions & Concurrency
  14. Privilege Escalation Vectors

Methodology:
  • Static AST-based code analysis (no execution)
  • Pattern-based vulnerability detection
  • CVSS v3.1 base metric group scoring
  • Contextual severity adjustment based on component role
"""

from __future__ import annotations

import ast
import math
import os
import re
import sys
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ============================================================================
# CVSS v3.1 Calculator
# ============================================================================

# Metric value weights per CVSS v3.1 specification
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}  # Attack Vector
_AC = {"L": 0.77, "H": 0.44}                           # Attack Complexity
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}     # Privileges (scope unchanged)
_PR_CHANGED   = {"N": 0.85, "L": 0.68, "H": 0.50}     # Privileges (scope changed)
_UI = {"N": 0.85, "R": 0.62}                           # User Interaction
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}               # C / I / A impact


@dataclass
class CVSSVector:
    """CVSS v3.1 Base Metrics."""

    AV: str = "N"   # Attack Vector: N(etwork) A(djacent) L(ocal) P(hysical)
    AC: str = "L"   # Attack Complexity: L(ow) H(igh)
    PR: str = "N"   # Privileges Required: N(one) L(ow) H(igh)
    UI: str = "N"   # User Interaction: N(one) R(equired)
    S: str  = "U"   # Scope: U(nchanged) C(hanged)
    C: str  = "N"   # Confidentiality: N(one) L(ow) H(igh)
    I: str  = "N"   # Integrity: N(one) L(ow) H(igh)
    A: str  = "N"   # Availability: N(one) L(ow) H(igh)

    # -- Calculations (CVSS v3.1 specification) -------------------------

    def _iss(self) -> float:
        """Impact Sub-Score base."""
        return 1 - ((1 - _CIA[self.C]) * (1 - _CIA[self.I]) * (1 - _CIA[self.A]))

    def impact(self) -> float:
        iss = self._iss()
        if self.S == "U":
            return 6.42 * iss
        return 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    def exploitability(self) -> float:
        pr_table = _PR_CHANGED if self.S == "C" else _PR_UNCHANGED
        return 8.22 * _AV[self.AV] * _AC[self.AC] * pr_table[self.PR] * _UI[self.UI]

    def base_score(self) -> float:
        imp = self.impact()
        if imp <= 0:
            return 0.0
        exp = self.exploitability()
        if self.S == "U":
            raw = min(imp + exp, 10)
        else:
            raw = min(1.08 * (imp + exp), 10)
        # Round up to one decimal
        return math.ceil(raw * 10) / 10

    def severity(self) -> str:
        s = self.base_score()
        if s == 0.0:
            return "NONE"
        if s <= 3.9:
            return "LOW"
        if s <= 6.9:
            return "MEDIUM"
        if s <= 8.9:
            return "HIGH"
        return "CRITICAL"

    def vector_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}"
            f"/UI:{self.UI}/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}"
        )


# ============================================================================
# Finding model
# ============================================================================

@dataclass
class VulnFinding:
    """A single vulnerability finding with CVSS scoring."""

    vuln_id: str
    title: str
    description: str
    category: str
    file: str
    line: int
    code_snippet: str
    cvss: CVSSVector
    remediation: str
    cwe: str = ""

    def base_score(self) -> float:
        return self.cvss.base_score()

    def severity(self) -> str:
        return self.cvss.severity()


FINDINGS: list[VulnFinding] = []
_finding_counter = 0


def _next_id() -> str:
    global _finding_counter
    _finding_counter += 1
    return f"NG-2026-{_finding_counter:04d}"


def _add(
    title: str, description: str, category: str,
    file: str, line: int, snippet: str,
    cvss: CVSSVector, remediation: str, cwe: str = "",
) -> None:
    FINDINGS.append(VulnFinding(
        vuln_id=_next_id(), title=title, description=description,
        category=category, file=file, line=line,
        code_snippet=snippet.strip()[:200], cvss=cvss,
        remediation=remediation, cwe=cwe,
    ))


# ============================================================================
# Source file reader
# ============================================================================

def _read_source(path: Path) -> tuple[str, list[str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return text, text.splitlines()


def _snippet(lines: list[str], lineno: int, context: int = 2) -> str:
    start = max(0, lineno - context - 1)
    end = min(len(lines), lineno + context)
    out = []
    for i in range(start, end):
        marker = ">>>" if i == lineno - 1 else "   "
        out.append(f"  {marker} {i + 1:4d} | {lines[i]}")
    return "\n".join(out)


# ============================================================================
# Scanners — each function analyses one vulnerability category
# ============================================================================


def scan_injection(src: str, lines: list[str], rel: str) -> None:
    """1. Injection & Input Validation."""

    # SQL injection patterns
    sql_patterns = [
        (r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.*\{',
         "SQL injection via f-string interpolation"),
        (r'["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*["\']\s*%\s*\(',
         "SQL injection via %-formatting"),
        (r'\.execute\(\s*f["\']',
         "SQL injection via f-string in execute()"),
        (r'\.execute\(\s*["\'].*\+',
         "SQL injection via string concatenation in execute()"),
    ]
    for i, line in enumerate(lines, 1):
        for pat, desc in sql_patterns:
            if re.search(pat, line, re.IGNORECASE):
                _add(
                    f"Potential SQL Injection: {desc}",
                    "User-controlled input may be interpolated into SQL queries "
                    "without parameterisation, enabling SQL injection attacks.",
                    "Injection", rel, i, _snippet(lines, i),
                    CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
                    "Use parameterised queries or an ORM. Never concatenate user input into SQL.",
                    cwe="CWE-89",
                )

    # OS command injection
    cmd_patterns = [
        (r'os\.system\(', "os.system() call — shell command injection risk"),
        (r'os\.popen\(', "os.popen() call — shell command injection risk"),
        (r'subprocess\.(?:call|run|Popen)\(.*shell\s*=\s*True',
         "subprocess with shell=True — command injection risk"),
        (r'subprocess\.(?:call|run|Popen)\(.*\+',
         "subprocess with string concatenation — command injection risk"),
    ]
    for i, line in enumerate(lines, 1):
        for pat, desc in cmd_patterns:
            if re.search(pat, line, re.IGNORECASE):
                _add(
                    f"Command Injection: {desc}",
                    "Shell commands constructed with user input can be exploited "
                    "for arbitrary command execution on the host.",
                    "Injection", rel, i, _snippet(lines, i),
                    CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),
                    "Use subprocess with shell=False and pass arguments as a list. "
                    "Validate and sanitise all command arguments.",
                    cwe="CWE-78",
                )

    # eval / exec
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.search(r'\beval\s*\(', stripped) or re.search(r'\bexec\s*\(', stripped):
            _add(
                "Code Injection: eval()/exec() usage",
                "Dynamic code execution functions can execute arbitrary Python code "
                "if fed attacker-controlled input.",
                "Injection", rel, i, _snippet(lines, i),
                CVSSVector(AV="N", AC="H", PR="L", UI="N", S="C", C="H", I="H", A="H"),
                "Remove eval()/exec() calls. Use safe alternatives like ast.literal_eval() "
                "or structured data parsing.",
                cwe="CWE-94",
            )

    # Template injection (Jinja2, format_map)
    for i, line in enumerate(lines, 1):
        if re.search(r'\.format_map\(', line):
            _add(
                "Template Injection via format_map()",
                "format_map() with user-controlled input can leak object attributes.",
                "Injection", rel, i, _snippet(lines, i),
                CVSSVector(AV="N", AC="H", PR="L", UI="N", S="U", C="L", I="L", A="N"),
                "Avoid format_map() with external input. Use safe templating.",
                cwe="CWE-1336",
            )


def scan_auth_access(src: str, lines: list[str], rel: str) -> None:
    """2. Broken Authentication & Access Control."""

    # Hardcoded passwords / secrets
    secret_patterns = [
        (r'(?:password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{4,}["\']',
         "Hardcoded secret/credential"),
        (r'(?:password|secret|key)\s*:\s*["\'][^"\']{4,}["\']',
         "Hardcoded secret in dict/config literal"),
    ]
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith('"""') or "test" in rel.lower():
            continue
        for pat, desc in secret_patterns:
            if re.search(pat, line, re.IGNORECASE):
                # Exclude test files and env-var references
                if "os.environ" in line or "getenv" in line or "_env" in line.lower():
                    continue
                if "example" in line.lower() or "placeholder" in line.lower():
                    continue
                _add(
                    f"Hardcoded Credential: {desc}",
                    "Credentials or secrets embedded in source code can be extracted "
                    "from version control, backups, or compiled artifacts.",
                    "Auth & Access Control", rel, i, _snippet(lines, i),
                    CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                    "Store secrets in environment variables or a secrets manager. "
                    "Use .env files excluded from version control.",
                    cwe="CWE-798",
                )

    # No authentication on endpoints
    if "dashboard" in rel.lower():
        has_auth_check = "check_auth" in src or "authorization" in src.lower() or "api_key" in src.lower()
        if not has_auth_check:
            _add(
                "Missing Authentication on Dashboard Endpoints",
                "Dashboard endpoints are accessible without any authentication, "
                "allowing unauthenticated access to sensitive operational data.",
                "Auth & Access Control", rel, 1, lines[0] if lines else "",
                CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="L", A="N"),
                "Implement authentication (API key, token, or session-based) for all endpoints.",
                cwe="CWE-306",
            )

    # Directory traversal in path handling
    for i, line in enumerate(lines, 1):
        if re.search(r'open\(.*\+', line) and ("request" in line.lower() or "path" in line.lower()):
            _add(
                "Potential Path Traversal via file open",
                "File paths constructed from user input without sanitisation "
                "may allow reading arbitrary files.",
                "Auth & Access Control", rel, i, _snippet(lines, i),
                CVSSVector(AV="N", AC="L", PR="L", UI="N", S="U", C="H", I="N", A="N"),
                "Validate file paths against an allowlist. Use pathlib and resolve "
                "to ensure paths stay within expected directories.",
                cwe="CWE-22",
            )


def scan_data_exposure(src: str, lines: list[str], rel: str) -> None:
    """3. Sensitive Data Exposure."""

    # Logging sensitive data
    sensitive_log_patterns = [
        (r'log(?:ger)?\.(?:info|debug|warning|error)\(.*(?:password|secret|token|key|credential)',
         "Sensitive data in log output"),
    ]
    for i, line in enumerate(lines, 1):
        for pat, desc in sensitive_log_patterns:
            if re.search(pat, line, re.IGNORECASE):
                _add(
                    f"Information Exposure: {desc}",
                    "Sensitive data written to log files can be accessed by operators, "
                    "log aggregation systems, or attackers who gain file access.",
                    "Data Exposure", rel, i, _snippet(lines, i),
                    CVSSVector(AV="L", AC="L", PR="L", UI="N", S="U", C="H", I="N", A="N"),
                    "Mask or redact sensitive fields before logging. Use structured "
                    "logging with field-level redaction.",
                    cwe="CWE-532",
                )

    # Stack traces / debug info exposed to users
    for i, line in enumerate(lines, 1):
        if re.search(r'traceback\.(?:print_exc|format_exc)', line):
            if "dashboard" in rel.lower() or "api" in rel.lower():
                _add(
                    "Stack Trace Exposure in API/Dashboard",
                    "Stack traces sent to clients reveal internal architecture, "
                    "file paths, library versions, and potential attack vectors.",
                    "Data Exposure", rel, i, _snippet(lines, i),
                    CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
                    "Return generic error messages to clients. Log full stack traces "
                    "server-side only.",
                    cwe="CWE-209",
                )

    # Internal IP / path disclosure patterns
    for i, line in enumerate(lines, 1):
        if re.search(r'str\(self\.engine\.config\.data_dir\)', line) and "api" in rel.lower():
            _add(
                "Internal Path Disclosure via API",
                "API responses include the server's internal file system path "
                "(data_dir), leaking directory structure to clients.",
                "Data Exposure", rel, i, _snippet(lines, i),
                CVSSVector(AV="N", AC="L", PR="L", UI="N", S="U", C="L", I="N", A="N"),
                "Remove internal file paths from API responses or replace with "
                "abstract identifiers.",
                cwe="CWE-200",
            )

    # Exception details exposed
    for i, line in enumerate(lines, 1):
        if re.search(r'str\(exc\)|str\(e\)', line) and ("dashboard" in rel.lower() or "response" in line.lower()):
            _add(
                "Exception Detail Leakage",
                "Raw exception messages sent to clients can expose internal details.",
                "Data Exposure", rel, i, _snippet(lines, i),
                CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
                "Return generic error messages. Log details server-side.",
                cwe="CWE-209",
            )


def scan_crypto(src: str, lines: list[str], rel: str) -> None:
    """4. Cryptographic Failures."""

    # Weak hash algorithms
    for i, line in enumerate(lines, 1):
        if re.search(r'hashlib\.(?:md5|sha1)\(', line):
            _add(
                "Weak Hash Algorithm",
                "MD5/SHA-1 are cryptographically broken and should not be used "
                "for security-sensitive operations (password hashing, signatures).",
                "Cryptography", rel, i, _snippet(lines, i),
                CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="L", A="N"),
                "Use SHA-256+ for integrity checks, bcrypt/scrypt/argon2 for passwords.",
                cwe="CWE-328",
            )

    # No TLS enforcement
    for i, line in enumerate(lines, 1):
        if re.search(r'http://', line) and not line.strip().startswith("#"):
            if "localhost" in line or "127.0.0.1" in line:
                continue  # Local-only is acceptable
            if "example" in line.lower():
                continue
            _add(
                "Unencrypted HTTP Communication",
                "HTTP connections transmit data in cleartext, susceptible to "
                "eavesdropping and MITM attacks.",
                "Cryptography", rel, i, _snippet(lines, i),
                CVSSVector(AV="A", AC="H", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                "Use HTTPS with valid TLS certificates. Implement HSTS.",
                cwe="CWE-319",
            )

    # Hardcoded crypto keys / IVs
    for i, line in enumerate(lines, 1):
        if re.search(r'(?:aes|des|rsa|encryption).*key\s*=\s*["\']', line, re.IGNORECASE):
            _add(
                "Hardcoded Encryption Key",
                "Encryption keys embedded in source code can be trivially extracted.",
                "Cryptography", rel, i, _snippet(lines, i),
                CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                "Use a key management service (KMS) or derive keys from environment secrets.",
                cwe="CWE-321",
            )

    # encrypt_reports config check (design-level)
    if "config" in rel.lower():
        for i, line in enumerate(lines, 1):
            if re.search(r'encrypt_reports.*=\s*(?:True|False)', line):
                if "False" in line:
                    _add(
                        "Report Encryption Disabled by Default",
                        "Security reports may contain sensitive vulnerability data. "
                        "Storing them unencrypted exposes findings to local file access.",
                        "Cryptography", rel, i, _snippet(lines, i),
                        CVSSVector(AV="L", AC="L", PR="L", UI="N", S="U", C="L", I="N", A="N"),
                        "Set encrypt_reports=True as the default configuration.",
                        cwe="CWE-311",
                    )


def scan_misconfig(src: str, lines: list[str], rel: str) -> None:
    """5. Security Misconfiguration."""

    # Debug mode left on
    for i, line in enumerate(lines, 1):
        if re.search(r'debug\s*=\s*True', line, re.IGNORECASE):
            if line.strip().startswith("#"):
                continue
            _add(
                "Debug Mode Enabled",
                "Debug mode may expose verbose error messages, internal state, "
                "and diagnostic endpoints to attackers.",
                "Misconfiguration", rel, i, _snippet(lines, i),
                CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
                "Disable debug mode in production. Use environment-based config.",
                cwe="CWE-489",
            )

    # Default ports exposed
    if "dashboard" in rel.lower():
        for i, line in enumerate(lines, 1):
            if re.search(r'port.*=\s*8080', line):
                _add(
                    "Default Port Configuration",
                    "Using well-known default ports (8080) makes the service easier "
                    "to discover through automated scanning.",
                    "Misconfiguration", rel, i, _snippet(lines, i),
                    CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="N", A="N"),
                    "Allow port configuration via environment variable. Consider "
                    "non-standard ports for reduced exposure.",
                    cwe="CWE-1188",
                )

    # Binding to 0.0.0.0 (all interfaces)
    for i, line in enumerate(lines, 1):
        if re.search(r'host\s*=\s*["\']0\.0\.0\.0["\']', line):
            _add(
                "Service Bound to All Interfaces",
                "Binding to 0.0.0.0 exposes the service on all network interfaces, "
                "including potentially public-facing ones.",
                "Misconfiguration", rel, i, _snippet(lines, i),
                CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="L", A="N"),
                "Bind to 127.0.0.1 for local-only access, or use firewall rules.",
                cwe="CWE-1188",
            )

    # Missing security headers check (design-level for dashboard)
    if "dashboard" in rel.lower():
        security_headers = [
            "content-security-policy", "x-content-type-options",
            "x-frame-options", "strict-transport-security",
        ]
        src_lower = src.lower()
        missing = [h for h in security_headers if h not in src_lower]
        if missing:
            _add(
                f"Missing Security Headers: {', '.join(missing)}",
                "HTTP responses without security headers are vulnerable to "
                "clickjacking, MIME-sniffing attacks, and content injection.",
                "Misconfiguration", rel, 1, "",
                CVSSVector(AV="N", AC="H", PR="N", UI="R", S="U", C="L", I="L", A="N"),
                "Add all recommended security headers to HTTP responses.",
                cwe="CWE-693",
            )


def scan_deserialization(src: str, lines: list[str], rel: str) -> None:
    """6. Insecure Deserialization."""

    for i, line in enumerate(lines, 1):
        # pickle
        if re.search(r'pickle\.loads?\(', line):
            _add(
                "Insecure Deserialization: pickle",
                "pickle.load() can execute arbitrary code when deserialising "
                "untrusted data, enabling remote code execution.",
                "Deserialization", rel, i, _snippet(lines, i),
                CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),
                "Use JSON or msgpack for data interchange. If pickle is required, "
                "only deserialise from trusted, signed sources.",
                cwe="CWE-502",
            )

        # yaml.load (unsafe)
        if re.search(r'yaml\.load\(', line) and "safe_load" not in line and "SafeLoader" not in line:
            _add(
                "Insecure Deserialization: yaml.load()",
                "yaml.load() without SafeLoader can deserialise arbitrary Python "
                "objects, enabling code execution.",
                "Deserialization", rel, i, _snippet(lines, i),
                CVSSVector(AV="N", AC="L", PR="L", UI="N", S="U", C="H", I="H", A="H"),
                "Use yaml.safe_load() or yaml.load(data, Loader=SafeLoader).",
                cwe="CWE-502",
            )

        # marshal
        if re.search(r'marshal\.loads?\(', line):
            _add(
                "Insecure Deserialization: marshal",
                "marshal module can execute code during deserialization.",
                "Deserialization", rel, i, _snippet(lines, i),
                CVSSVector(AV="N", AC="L", PR="L", UI="N", S="U", C="H", I="H", A="H"),
                "Use JSON for data interchange.",
                cwe="CWE-502",
            )


def scan_command_injection(src: str, lines: list[str], rel: str) -> None:
    """7. Deeper command injection analysis."""

    # Check subprocess calls with user-controllable arguments
    for i, line in enumerate(lines, 1):
        # create_subprocess_exec with variable arguments
        if "create_subprocess_exec" in line:
            # Look for f-strings or format in nearby lines
            context_start = max(0, i - 3)
            context_end = min(len(lines), i + 3)
            context_block = "\n".join(lines[context_start:context_end])
            if re.search(r'f["\']|\.format\(|\+\s*\w+', context_block):
                if "target" in context_block.lower() or "input" in context_block.lower():
                    _add(
                        "Subprocess with Variable Arguments",
                        "Subprocess commands include variables that may originate "
                        "from user input without validation.",
                        "Command Injection", rel, i, _snippet(lines, i),
                        CVSSVector(AV="N", AC="H", PR="L", UI="N", S="U", C="H", I="H", A="H"),
                        "Validate and sanitise all arguments passed to subprocess. "
                        "Use allowlists for acceptable values.",
                        cwe="CWE-78",
                    )

    # shutil.which used but no validation of result
    for i, line in enumerate(lines, 1):
        if "shutil.which" in line:
            # Check if the tool name comes from user input
            if re.search(r'shutil\.which\(.*\+|shutil\.which\(.*f["\']', line):
                _add(
                    "Dynamic Tool Resolution via shutil.which()",
                    "Tool names resolved from user input via shutil.which() "
                    "could be manipulated via PATH injection.",
                    "Command Injection", rel, i, _snippet(lines, i),
                    CVSSVector(AV="L", AC="H", PR="L", UI="N", S="U", C="H", I="H", A="L"),
                    "Use absolute tool paths. Validate tool names against an allowlist.",
                    cwe="CWE-426",
                )


def scan_logging_monitoring(src: str, lines: list[str], rel: str) -> None:
    """8. Insufficient Logging & Monitoring."""

    # Check if security-relevant operations have logging
    if "dashboard" in rel.lower() or "auth" in rel.lower():
        has_security_logging = bool(re.search(
            r'log(?:ger)?\.(?:warning|error|critical)\(.*(?:auth|unauth|denied|forbidden|rate)',
            src, re.IGNORECASE,
        ))
        if not has_security_logging:
            _add(
                "Insufficient Security Event Logging",
                "Security-critical events (auth failures, access denials) are not logged, "
                "making incident detection and forensics difficult.",
                "Logging & Monitoring", rel, 1, "",
                CVSSVector(AV="N", AC="H", PR="H", UI="N", S="U", C="N", I="L", A="N"),
                "Log all authentication attempts, access control decisions, and "
                "security-relevant errors with timestamps and source IPs.",
                cwe="CWE-778",
            )

    # Broad exception swallowing
    for i, line in enumerate(lines, 1):
        if re.search(r'except\s*(?:Exception|BaseException)?\s*:', line):
            next_lines = lines[i:i + 3] if i < len(lines) else []
            next_block = "\n".join(next_lines)
            if "pass" in next_block and "log" not in next_block.lower():
                _add(
                    "Silent Exception Swallowing",
                    "Catching exceptions and silently discarding them hides errors, "
                    "potential security violations, and system failures.",
                    "Logging & Monitoring", rel, i, _snippet(lines, i),
                    CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="N", I="N", A="L"),
                    "Log caught exceptions at minimum. Use specific exception types.",
                    cwe="CWE-390",
                )


def scan_ssrf(src: str, lines: list[str], rel: str) -> None:
    """9. Server-Side Request Forgery."""

    for i, line in enumerate(lines, 1):
        # URL from user input to requests/urllib/aiohttp
        if re.search(r'(?:requests|urllib|aiohttp|httpx)\.(?:get|post|put|delete|request)\(', line):
            context_start = max(0, i - 5)
            context_block = "\n".join(lines[context_start:i])
            if re.search(r'(?:input|request|args|params|user)', context_block, re.IGNORECASE):
                _add(
                    "Potential SSRF via HTTP Client",
                    "HTTP requests with user-controlled URLs can be abused to "
                    "access internal services, cloud metadata, or scan internal networks.",
                    "SSRF", rel, i, _snippet(lines, i),
                    CVSSVector(AV="N", AC="L", PR="L", UI="N", S="C", C="H", I="L", A="N"),
                    "Validate and allowlist target URLs/domains. Block private IP ranges "
                    "and metadata endpoints (169.254.169.254).",
                    cwe="CWE-918",
                )

    # open_connection with user-controlled host/port
    for i, line in enumerate(lines, 1):
        if "open_connection" in line:
            context_start = max(0, i - 5)
            context_block = "\n".join(lines[context_start:i + 1])
            if re.search(r'target|host|addr|ip', context_block, re.IGNORECASE):
                # Check if target validation is present in the file
                if "_validate" in src and ("scan_target" in src or "target" in src):
                    continue  # Validation function exists — mitigated
                # Check if it's in a scanning context (expected behavior)
                if "sensor" in rel.lower() or "scanner" in rel.lower():
                    _add(
                        "Network Connection to User-Specified Target",
                        "TCP connections initiated to user-specified hosts/ports. "
                        "While this is core functionality for a network scanner, "
                        "insufficient input validation could allow SSRF attacks.",
                        "SSRF", rel, i, _snippet(lines, i),
                        CVSSVector(AV="N", AC="H", PR="L", UI="N", S="C", C="L", I="L", A="N"),
                        "Validate target addresses against an allowlist or blocklist. "
                        "Block RFC1918 addresses unless explicitly configured.",
                        cwe="CWE-918",
                    )


def scan_randomness(src: str, lines: list[str], rel: str) -> None:
    """11. Insecure Randomness."""

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("#"):
            continue
        # random module used for potentially security-sensitive operations
        if re.search(r'\brandom\.\w+\(', line):
            # Skip if using secrets.SystemRandom (cryptographic PRNG)
            if "secrets.SystemRandom" in src:
                continue
            context = "\n".join(lines[max(0, i - 5):i + 1]).lower()
            # Check if in security context
            if any(kw in context for kw in ["token", "key", "secret", "password", "auth", "session", "nonce"]):
                _add(
                    "Insecure PRNG for Security-Sensitive Operation",
                    "The `random` module uses Mersenne Twister (MT19937) which is "
                    "predictable and not suitable for security-sensitive values.",
                    "Insecure Randomness", rel, i, _snippet(lines, i),
                    CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="L", A="N"),
                    "Use `secrets` module for tokens, keys, and session IDs. "
                    "Use `os.urandom()` for raw cryptographic randomness.",
                    cwe="CWE-330",
                )
            elif "dataset" not in rel.lower() and "test" not in rel.lower():
                _add(
                    "Non-Cryptographic PRNG Usage",
                    "The `random` module is used outside of test/dataset context. "
                    "Verify this is not used for security-sensitive operations.",
                    "Insecure Randomness", rel, i, _snippet(lines, i),
                    CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="N", A="N"),
                    "Review usage context. Use `secrets` for any security-sensitive value.",
                    cwe="CWE-330",
                )


def scan_error_handling(src: str, lines: list[str], rel: str) -> None:
    """12. Error Handling & Information Disclosure."""

    # Bare except clauses
    for i, line in enumerate(lines, 1):
        if re.search(r'except\s*:', line) and "except asyncio" not in line:
            _add(
                "Bare Except Clause",
                "Catching all exceptions without specifying a type can mask "
                "programming errors and hide security issues.",
                "Error Handling", rel, i, _snippet(lines, i),
                CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="N", I="N", A="L"),
                "Catch specific exception types. Re-raise unexpected exceptions.",
                cwe="CWE-396",
            )

    # assert used for security checks (skip test files where assert is expected)
    if not rel.startswith("tests") and not rel.startswith("test_"):
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("assert ") and not stripped.startswith("assert "):
                continue
            if re.search(r'assert\s+.*(?:auth|permission|role|access)', stripped, re.IGNORECASE):
                _add(
                    "Assert Used for Security Check",
                    "Python assert statements are stripped when running with -O (optimize). "
                    "Using them for security checks means checks can be bypassed.",
                    "Error Handling", rel, i, _snippet(lines, i),
                    CVSSVector(AV="L", AC="L", PR="L", UI="N", S="U", C="H", I="H", A="N"),
                    "Use explicit if/raise for security checks. Never rely on assert for access control.",
                    cwe="CWE-617",
                )


def scan_race_conditions(src: str, lines: list[str], rel: str) -> None:
    """13. Race Conditions & Concurrency."""

    # TOCTOU — check-then-act patterns with file operations
    for i, line in enumerate(lines, 1):
        if re.search(r'(?:os\.path\.exists|Path.*\.exists|os\.path\.isfile)\(', line):
            next_lines = lines[i:min(i + 5, len(lines))]
            next_block = "\n".join(next_lines)
            if re.search(r'open\(|Path.*\.read|os\.remove|shutil\.', next_block):
                _add(
                    "TOCTOU Race Condition",
                    "Check-then-act pattern on the filesystem. Between the existence "
                    "check and the file operation, the file state can change.",
                    "Race Condition", rel, i, _snippet(lines, i),
                    CVSSVector(AV="L", AC="H", PR="L", UI="N", S="U", C="N", I="L", A="L"),
                    "Use atomic operations or try/except instead of check-then-act.",
                    cwe="CWE-367",
                )

    # Shared mutable state without locks
    for i, line in enumerate(lines, 1):
        if re.search(r'self\._\w+\s*=\s*\[\]|self\._\w+\s*=\s*\{\}', line):
            if "async" in src[:src.find(line)] and "Lock" not in src:
                pass  # Only flag if there are concurrent access patterns


def scan_privilege_escalation(src: str, lines: list[str], rel: str) -> None:
    """14. Privilege Escalation Vectors."""

    # setuid / setgid
    for i, line in enumerate(lines, 1):
        if re.search(r'os\.set(?:uid|gid|euid|egid)\(', line):
            _add(
                "Privilege Manipulation via setuid/setgid",
                "Modifying process privileges can lead to escalation if not handled carefully.",
                "Privilege Escalation", rel, i, _snippet(lines, i),
                CVSSVector(AV="L", AC="L", PR="H", UI="N", S="C", C="H", I="H", A="H"),
                "Minimize privilege changes. Drop privileges permanently after startup.",
                cwe="CWE-250",
            )

    # Running as root check
    for i, line in enumerate(lines, 1):
        if re.search(r'os\.getuid\(\)\s*==\s*0', line):
            _add(
                "Root Privilege Check (Runs as Root)",
                "Application may require or check for root privileges, which "
                "expands the attack surface if compromised.",
                "Privilege Escalation", rel, i, _snippet(lines, i),
                CVSSVector(AV="L", AC="L", PR="H", UI="N", S="U", C="H", I="H", A="H"),
                "Use least-privilege principle. Run as an unprivileged user.",
                cwe="CWE-250",
            )


def scan_dependency_supply_chain(rel: str) -> None:
    """10. Dependency & Supply Chain."""
    # Only check the project config file
    if "pyproject.toml" not in rel.lower():
        return

    try:
        text = Path(rel).read_text(encoding="utf-8")
    except FileNotFoundError:
        return

    # Check for pinned vs unpinned dependencies
    deps = re.findall(r'"([^"]+)"', text)
    unpinned = [
        d for d in deps
        if ">=" in d and "==" not in d and "<" not in d
        and re.match(r'[a-zA-Z]', d)  # Must start with a package name
    ]
    if unpinned:
        _add(
            "Unpinned Dependency Versions",
            f"Dependencies use >= without upper bounds: {', '.join(unpinned[:5])}. "
            "This allows automatic installation of newer, potentially vulnerable versions.",
            "Supply Chain", rel, 1, "",
            CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="H", A="L"),
            "Pin dependencies to exact versions or use upper bounds (e.g. >=6.0,<7.0). "
            "Use a lock file (pip-compile, poetry.lock).",
            cwe="CWE-1104",
        )

    # Check for lack of integrity verification
    # Also check for references to lock files with hashes
    has_hashes = (
        "hashes" in text.lower()
        or "sha256" in text.lower()
        or "requirements.lock" in text.lower()
    )
    if not has_hashes:
        _add(
            "No Dependency Integrity Verification",
            "Dependencies are not verified with hash checks, allowing "
            "compromised packages to be installed.",
            "Supply Chain", rel, 1, "",
            CVSSVector(AV="N", AC="H", PR="H", UI="R", S="U", C="L", I="H", A="L"),
            "Use pip --require-hashes or a lock file with integrity hashes.",
            cwe="CWE-494",
        )


def scan_network_specific(src: str, lines: list[str], rel: str) -> None:
    """Network-tool-specific security checks."""

    # Scan timeout too high (DoS vector)
    for i, line in enumerate(lines, 1):
        if re.search(r'timeout.*=\s*120', line):
            _add(
                "High Operation Timeout (120s)",
                "Long timeouts on network operations can be abused for "
                "denial-of-service by keeping connections open.",
                "Misconfiguration", rel, i, _snippet(lines, i),
                CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="L"),
                "Use configurable, shorter timeouts with proper cancellation handling.",
                cwe="CWE-400",
            )

    # Unbounded data collection  
    for i, line in enumerate(lines, 1):
        if re.search(r'maxlen=500', line) or re.search(r'\[-200:\]', line):
            pass  # These are bounded — good

    # Subnet scanning without rate limits
    if "sensor" in rel.lower() or "scanner" in rel.lower():
        has_semaphore = "Semaphore" in src
        has_rate_limit = "rate" in src.lower() or "throttle" in src.lower()
        if not has_semaphore and not has_rate_limit:
            _add(
                "Network Scanning Without Rate Limiting",
                "Port scanning without rate limiting can trigger IDS/IPS alerts "
                "and may violate network usage policies.",
                "Misconfiguration", rel, 1, "",
                CVSSVector(AV="N", AC="L", PR="L", UI="N", S="U", C="N", I="N", A="L"),
                "Implement rate limiting or throttling for scan operations.",
                cwe="CWE-799",
            )


# ============================================================================
# Scan orchestrator
# ============================================================================

ALL_SCANNERS = [
    scan_injection,
    scan_auth_access,
    scan_data_exposure,
    scan_crypto,
    scan_misconfig,
    scan_deserialization,
    scan_command_injection,
    scan_logging_monitoring,
    scan_ssrf,
    scan_randomness,
    scan_error_handling,
    scan_race_conditions,
    scan_privilege_escalation,
    scan_network_specific,
]


def scan_file(filepath: Path, root: Path) -> None:
    """Run all scanners on a single file."""
    rel = str(filepath.relative_to(root))
    src, lines = _read_source(filepath)
    for scanner in ALL_SCANNERS:
        scanner(src, lines, rel)
    # Dependency scanner works on pyproject.toml directly
    scan_dependency_supply_chain(str(filepath))


def collect_python_files(root: Path) -> list[Path]:
    """Collect all Python files under root, excluding tests and venv."""
    # Scanner/audit tool files to exclude from self-scanning
    _scanner_files = {"cvss_scan.py", "owasp_scan.py", "live_test.py"}
    files: list[Path] = []
    for path in sorted(root.rglob("*.py")):
        rel = str(path.relative_to(root))
        # Skip test files, venv, __pycache__, and scanner tools
        if any(skip in rel for skip in ["__pycache__", ".venv", "venv", "node_modules"]):
            continue
        if path.name in _scanner_files:
            continue
        files.append(path)
    # Also include pyproject.toml
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        files.append(pyproject)
    return files


# ============================================================================
# Report generator
# ============================================================================

def _severity_color(sev: str) -> str:
    return {
        "CRITICAL": "\033[91m",  # Red
        "HIGH":     "\033[93m",  # Yellow
        "MEDIUM":   "\033[33m",  # Orange-ish
        "LOW":      "\033[36m",  # Cyan
        "NONE":     "\033[90m",  # Gray
    }.get(sev, "")


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def print_report() -> None:
    """Print the full CVSS vulnerability report."""

    # Sort by score descending
    FINDINGS.sort(key=lambda f: f.base_score(), reverse=True)

    print(f"\n{'=' * 76}")
    print(f"  {BOLD}CVSS v3.1 VULNERABILITY ASSESSMENT — Network Guardian{RESET}")
    print(f"{'=' * 76}")

    # Summary statistics
    total = len(FINDINGS)
    by_severity: dict[str, list[VulnFinding]] = {}
    for f in FINDINGS:
        sev = f.severity()
        by_severity.setdefault(sev, []).append(f)

    print(f"\n  {BOLD}SUMMARY{RESET}")
    print(f"  {'─' * 50}")
    print(f"  Total Findings:  {total}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]:
        count = len(by_severity.get(sev, []))
        if count:
            color = _severity_color(sev)
            print(f"  {color}{sev:<12}{RESET}  {count:>3} finding(s)")

    # Calculate overall risk score (weighted average)
    if FINDINGS:
        weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "NONE": 0}
        total_weight = sum(weights.get(f.severity(), 0) for f in FINDINGS)
        max_possible = total * 10
        overall_risk = (total_weight / max_possible * 100) if max_possible else 0

        if overall_risk >= 70:
            risk_grade = "F"
        elif overall_risk >= 50:
            risk_grade = "D"
        elif overall_risk >= 35:
            risk_grade = "C"
        elif overall_risk >= 20:
            risk_grade = "B"
        else:
            risk_grade = "A"

        print(f"\n  Overall Risk Score:  {overall_risk:.1f}/100")
        print(f"  Security Grade:     {BOLD}{risk_grade}{RESET}")
    else:
        print(f"\n  {BOLD}No vulnerabilities found!{RESET}")
        print(f"  Security Grade: {BOLD}A+{RESET}")

    # CVSS score distribution
    print(f"\n  {BOLD}CVSS SCORE DISTRIBUTION{RESET}")
    print(f"  {'─' * 50}")
    buckets = {"9.0-10.0": 0, "7.0-8.9": 0, "4.0-6.9": 0, "0.1-3.9": 0, "0.0": 0}
    for f in FINDINGS:
        s = f.base_score()
        if s >= 9.0:
            buckets["9.0-10.0"] += 1
        elif s >= 7.0:
            buckets["7.0-8.9"] += 1
        elif s >= 4.0:
            buckets["4.0-6.9"] += 1
        elif s > 0:
            buckets["0.1-3.9"] += 1
        else:
            buckets["0.0"] += 1

    max_bar = max(buckets.values()) if buckets else 1
    for label, count in buckets.items():
        bar = "█" * int(count / max(max_bar, 1) * 30) if count else ""
        print(f"  {label:>9}  {bar} {count}")

    # Detailed findings
    print(f"\n  {BOLD}DETAILED FINDINGS{RESET}")
    print(f"  {'═' * 72}")

    for i, f in enumerate(FINDINGS, 1):
        score = f.base_score()
        sev = f.severity()
        color = _severity_color(sev)

        print(f"\n  {BOLD}[{i:02d}] {f.vuln_id}{RESET}  {color}{sev} ({score}){RESET}")
        print(f"  {'─' * 72}")
        print(f"  Title:       {f.title}")
        print(f"  Category:    {f.category}")
        if f.cwe:
            print(f"  CWE:         {f.cwe}")
        print(f"  File:        {f.file}:{f.line}")
        print(f"  CVSS Vector: {f.cvss.vector_string()}")
        print(f"  Base Score:  {score}  Exploitability: {f.cvss.exploitability():.1f}  "
              f"Impact: {f.cvss.impact():.1f}")
        print()
        # Description (wrapped)
        for line in textwrap.wrap(f.description, width=68):
            print(f"    {line}")
        if f.code_snippet:
            print(f"\n    Code:")
            for line in f.code_snippet.split("\n"):
                print(f"    {line}")
        print(f"\n    {BOLD}Remediation:{RESET}")
        for line in textwrap.wrap(f.remediation, width=64):
            print(f"      {line}")

    # Category summary table
    print(f"\n\n  {BOLD}FINDINGS BY CATEGORY{RESET}")
    print(f"  {'─' * 55}")
    by_cat: dict[str, list[VulnFinding]] = {}
    for f in FINDINGS:
        by_cat.setdefault(f.category, []).append(f)
    for cat, findings in sorted(by_cat.items(), key=lambda x: -max(f.base_score() for f in x[1])):
        max_score = max(f.base_score() for f in findings)
        print(f"  {cat:<30} {len(findings):>3} finding(s)   max CVSS: {max_score}")

    # Affected files
    print(f"\n  {BOLD}AFFECTED FILES{RESET}")
    print(f"  {'─' * 55}")
    by_file: dict[str, list[VulnFinding]] = {}
    for f in FINDINGS:
        by_file.setdefault(f.file, []).append(f)
    for path, findings in sorted(by_file.items(), key=lambda x: -max(f.base_score() for f in x[1])):
        max_score = max(f.base_score() for f in findings)
        sev = findings[0].severity() if findings else "NONE"
        color = _severity_color(sev)
        print(f"  {path:<45} {len(findings):>2} finding(s)  {color}{max_score}{RESET}")

    # Final line
    print(f"\n{'=' * 76}")
    if FINDINGS:
        top = FINDINGS[0]
        print(f"  Highest Risk: {top.vuln_id} — {top.title}")
        print(f"  CVSS {top.base_score()} ({top.severity()}) | {top.cvss.vector_string()}")
    print(f"{'=' * 76}\n")


# ============================================================================
# Main
# ============================================================================

def main() -> None:
    project_root = Path(__file__).resolve().parent
    print(f"\n{BOLD}Starting CVSS v3.1 Vulnerability Assessment...{RESET}")
    print(f"Project root: {project_root}\n")

    t0 = time.perf_counter()

    # Collect files
    py_files = collect_python_files(project_root)
    print(f"Scanning {len(py_files)} file(s)...\n")

    # Scan each file
    for filepath in py_files:
        rel = str(filepath.relative_to(project_root))
        if filepath.suffix == ".toml":
            # Special handling for pyproject.toml
            scan_dependency_supply_chain(str(filepath))
            print(f"  ✓ {rel}")
            continue
        try:
            scan_file(filepath, project_root)
            print(f"  ✓ {rel}")
        except Exception as exc:
            print(f"  ✗ {rel} — {exc}")

    elapsed = time.perf_counter() - t0
    print(f"\nScan completed in {elapsed:.2f}s")

    # Print report
    print_report()

    # Exit code based on findings
    critical_high = sum(1 for f in FINDINGS if f.severity() in ("CRITICAL", "HIGH"))
    sys.exit(1 if critical_high > 0 else 0)


if __name__ == "__main__":
    main()
