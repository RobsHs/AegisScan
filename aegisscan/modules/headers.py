"""
HTTP Security Headers Audit Module.
Analyzes response headers according to OWASP Secure Headers Project recommendations.
"""

from typing import Dict, List, Tuple
from aegisscan.core.models import Finding, FindingCategory, HeaderAuditItem, Severity


def audit_headers(headers: Dict[str, str], url: str) -> Tuple[List[HeaderAuditItem], List[Finding]]:
    """
    Audits HTTP response headers for missing security protections,
    misconfigurations, and information leakage.
    """
    # Normalize headers to lowercase keys
    norm_headers = {k.lower(): v for k, v in headers.items()}
    audit_items: List[HeaderAuditItem] = []
    findings: List[Finding] = []

    # 1. Content-Security-Policy (CSP)
    csp = norm_headers.get("content-security-policy")
    if not csp:
        audit_items.append(
            HeaderAuditItem(
                header="Content-Security-Policy",
                present=False,
                value=None,
                status="FAIL",
                recommendation="Implement a strict CSP to prevent Cross-Site Scripting (XSS) and data injection attacks.",
                severity_if_missing=Severity.HIGH,
            )
        )
        findings.append(
            Finding(
                id="SEC-HDR-001",
                category=FindingCategory.HEADERS,
                severity=Severity.HIGH,
                title="Missing Content-Security-Policy (CSP) Header",
                description="The server does not return a Content-Security-Policy header, leaving the application more vulnerable to Cross-Site Scripting (XSS) and clickjacking attacks.",
                impact="Attackers can inject malicious scripts into pages viewed by users, steal session tokens, or execute unauthorized actions.",
                remediation="Configure a Content-Security-Policy header. Example: default-src 'self'; script-src 'self'; object-src 'none';",
                references=["https://owasp.org/www-project-secure-headers/#content-security-policy"],
            )
        )
    else:
        # Evaluate CSP directives
        csp_issues = []
        if "'unsafe-inline'" in csp:
            csp_issues.append("Contains 'unsafe-inline' which weakens XSS protections.")
        if "'unsafe-eval'" in csp:
            csp_issues.append("Contains 'unsafe-eval' allowing runtime code execution.")
        if "data:" in csp and "script-src" in csp:
            csp_issues.append("Allows 'data:' scheme in scripts.")

        if csp_issues:
            audit_items.append(
                HeaderAuditItem(
                    header="Content-Security-Policy",
                    present=True,
                    value=csp,
                    status="WARN",
                    recommendation="Remove 'unsafe-inline'/'unsafe-eval' using nonces or hashes.",
                    severity_if_missing=Severity.HIGH,
                )
            )
            findings.append(
                Finding(
                    id="SEC-HDR-001W",
                    category=FindingCategory.HEADERS,
                    severity=Severity.MEDIUM,
                    title="Weak Directives Detected in Content-Security-Policy",
                    description=f"Content-Security-Policy contains weak directives: {'; '.join(csp_issues)}",
                    impact="Reduces the effectiveness of CSP against Cross-Site Scripting.",
                    remediation="Refactor inline scripts to external scripts and use cryptographic nonces or SHA hashes.",
                    evidence=csp[:200] + ("..." if len(csp) > 200 else ""),
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                )
            )
        else:
            audit_items.append(
                HeaderAuditItem(
                    header="Content-Security-Policy",
                    present=True,
                    value=csp,
                    status="PASS",
                    recommendation="CSP is implemented with standard protections.",
                    severity_if_missing=Severity.HIGH,
                )
            )

    # 2. Strict-Transport-Security (HSTS)
    hsts = norm_headers.get("strict-transport-security")
    is_https = url.lower().startswith("https://")
    if not hsts:
        if is_https:
            audit_items.append(
                HeaderAuditItem(
                    header="Strict-Transport-Security",
                    present=False,
                    value=None,
                    status="FAIL",
                    recommendation="Enforce HTTPS with 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
                    severity_if_missing=Severity.HIGH,
                )
            )
            findings.append(
                Finding(
                    id="SEC-HDR-002",
                    category=FindingCategory.HEADERS,
                    severity=Severity.HIGH,
                    title="Missing HTTP Strict Transport Security (HSTS)",
                    description="The web server does not enforce HTTPS via the Strict-Transport-Security header.",
                    impact="Users are vulnerable to SSL-stripping and man-in-the-middle (MitM) attacks during initial HTTP connections.",
                    remediation="Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    references=["https://owasp.org/www-project-secure-headers/#strict-transport-security"],
                )
            )
        else:
            audit_items.append(
                HeaderAuditItem(
                    header="Strict-Transport-Security",
                    present=False,
                    value=None,
                    status="FAIL",
                    recommendation="Site is served over unencrypted HTTP. Enable HTTPS and HSTS immediately.",
                    severity_if_missing=Severity.HIGH,
                )
            )
    else:
        # Check max-age
        has_subdomains = "includesubdomains" in hsts.lower()
        has_preload = "preload" in hsts.lower()
        audit_items.append(
            HeaderAuditItem(
                header="Strict-Transport-Security",
                present=True,
                value=hsts,
                status="PASS" if has_subdomains else "WARN",
                recommendation="HSTS is present." + (" Consider adding includeSubDomains and preload." if not has_subdomains else ""),
                severity_if_missing=Severity.HIGH,
            )
        )

    # 3. X-Frame-Options (Clickjacking defense)
    xfo = norm_headers.get("x-frame-options")
    if not xfo and ("frame-ancestors" not in (csp or "")):
        audit_items.append(
            HeaderAuditItem(
                header="X-Frame-Options",
                present=False,
                value=None,
                status="FAIL",
                recommendation="Set X-Frame-Options to 'DENY' or 'SAMEORIGIN' to prevent Clickjacking.",
                severity_if_missing=Severity.MEDIUM,
            )
        )
        findings.append(
            Finding(
                id="SEC-HDR-003",
                category=FindingCategory.HEADERS,
                severity=Severity.MEDIUM,
                title="Missing Anti-Clickjacking Header (X-Frame-Options)",
                description="Neither X-Frame-Options nor CSP frame-ancestors directive was detected.",
                impact="Attackers can embed the target application inside an iframe to trick users into executing unwanted actions (Clickjacking).",
                remediation="Configure 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
                references=["https://owasp.org/www-project-secure-headers/#x-frame-options"],
            )
        )
    else:
        audit_items.append(
            HeaderAuditItem(
                header="X-Frame-Options",
                present=bool(xfo),
                value=xfo or "Covered by CSP frame-ancestors",
                status="PASS",
                recommendation="Clickjacking defense is active.",
                severity_if_missing=Severity.MEDIUM,
            )
        )

    # 4. X-Content-Type-Options (MIME-sniffing)
    xcto = norm_headers.get("x-content-type-options")
    if not xcto or "nosniff" not in xcto.lower():
        audit_items.append(
            HeaderAuditItem(
                header="X-Content-Type-Options",
                present=bool(xcto),
                value=xcto,
                status="FAIL",
                recommendation="Set 'X-Content-Type-Options: nosniff' to disable MIME-type sniffing.",
                severity_if_missing=Severity.LOW,
            )
        )
        findings.append(
            Finding(
                id="SEC-HDR-004",
                category=FindingCategory.HEADERS,
                severity=Severity.LOW,
                title="Missing or Incomplete X-Content-Type-Options Header",
                description="The X-Content-Type-Options header is missing or not set to 'nosniff'.",
                impact="Browsers may attempt to detect the MIME type of a response by sniffing its content, which can lead to drive-by code execution.",
                remediation="Configure 'X-Content-Type-Options: nosniff' on all web responses.",
                references=["https://owasp.org/www-project-secure-headers/#x-content-type-options"],
            )
        )
    else:
        audit_items.append(
            HeaderAuditItem(
                header="X-Content-Type-Options",
                present=True,
                value=xcto,
                status="PASS",
                recommendation="MIME sniffing protection is enabled.",
                severity_if_missing=Severity.LOW,
            )
        )

    # 5. Referrer-Policy
    ref_pol = norm_headers.get("referrer-policy")
    if not ref_pol:
        audit_items.append(
            HeaderAuditItem(
                header="Referrer-Policy",
                present=False,
                value=None,
                status="WARN",
                recommendation="Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                severity_if_missing=Severity.LOW,
            )
        )
        findings.append(
            Finding(
                id="SEC-HDR-005",
                category=FindingCategory.HEADERS,
                severity=Severity.LOW,
                title="Missing Referrer-Policy Header",
                description="No Referrer-Policy header was specified. Sensitive URL query parameters may leak in HTTP referer headers to third-party domains.",
                impact="Information disclosure of session IDs, user tokens, or internal endpoints via the Referer request header.",
                remediation="Add header: Referrer-Policy: strict-origin-when-cross-origin",
                references=["https://owasp.org/www-project-secure-headers/#referrer-policy"],
            )
        )
    else:
        audit_items.append(
            HeaderAuditItem(
                header="Referrer-Policy",
                present=True,
                value=ref_pol,
                status="PASS",
                recommendation="Referrer-Policy is configured.",
                severity_if_missing=Severity.LOW,
            )
        )

    # 6. Permissions-Policy (Feature-Policy)
    perm_pol = norm_headers.get("permissions-policy") or norm_headers.get("feature-policy")
    if not perm_pol:
        audit_items.append(
            HeaderAuditItem(
                header="Permissions-Policy",
                present=False,
                value=None,
                status="WARN",
                recommendation="Configure Permissions-Policy to restrict browser features (camera, microphone, geolocation).",
                severity_if_missing=Severity.LOW,
            )
        )
    else:
        audit_items.append(
            HeaderAuditItem(
                header="Permissions-Policy",
                present=True,
                value=perm_pol,
                status="PASS",
                recommendation="Browser feature restrictions are configured.",
                severity_if_missing=Severity.LOW,
            )
        )

    # 7. Information Leakage via Headers (Server, X-Powered-By, etc.)
    leak_headers = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-runtime", "x-generator"]
    for lk in leak_headers:
        val = norm_headers.get(lk)
        if val:
            findings.append(
                Finding(
                    id="SEC-INF-001",
                    category=FindingCategory.INFORMATION,
                    severity=Severity.LOW,
                    title=f"Technology Fingerprint Disclosed in '{lk}' Header",
                    description=f"The server exposes underlying software/framework information via the '{lk}: {val}' header.",
                    impact="Assists attackers in targeting known vulnerabilities for the specific server or framework version.",
                    remediation=f"Suppress or mask the '{lk}' header in your web server/reverse proxy configuration.",
                    evidence=f"{lk}: {val}",
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-web_application_security_testing/01-information_gathering/02-fingerprint_web_server"],
                )
            )

    return audit_items, findings

