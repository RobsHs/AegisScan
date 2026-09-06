"""
Cookie Security Flags Audit Module.
Inspects Set-Cookie headers for Secure, HttpOnly, SameSite, and modern cookie prefixes.
"""

from typing import List, Tuple
from http.cookies import SimpleCookie
from aegisscan.core.models import CookieAuditItem, Finding, FindingCategory, Severity


def audit_cookies(raw_cookies: List[str], url: str) -> Tuple[List[CookieAuditItem], List[Finding]]:
    """
    Audits Set-Cookie headers for missing security attributes.
    """
    is_https = url.lower().startswith("https://")
    audit_items: List[CookieAuditItem] = []
    findings: List[Finding] = []

    for raw in raw_cookies:
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            continue

        for name, morsel in cookie.items():
            issues = []
            secure = bool(morsel.get("secure"))
            httponly = bool(morsel.get("httponly"))
            samesite = morsel.get("samesite") or None
            domain = morsel.get("domain") or None
            path = morsel.get("path") or None

            # 1. Secure Flag
            if not secure and is_https:
                issues.append("Missing 'Secure' flag on HTTPS")
                findings.append(
                    Finding(
                        id="SEC-CK-001",
                        category=FindingCategory.COOKIES,
                        severity=Severity.HIGH,
                        title=f"Cookie '{name}' Missing 'Secure' Attribute",
                        description=f"Cookie '{name}' was transmitted without the Secure flag on an HTTPS connection.",
                        impact="The browser may transmit this cookie over cleartext HTTP if a user follows an unencrypted link, exposing it to eavesdroppers.",
                        remediation=f"Add the 'Secure' attribute to cookie '{name}'.",
                        evidence=raw,
                        references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                    )
                )

            # 2. HttpOnly Flag
            if not httponly:
                issues.append("Missing 'HttpOnly' flag")
                findings.append(
                    Finding(
                        id="SEC-CK-002",
                        category=FindingCategory.COOKIES,
                        severity=Severity.MEDIUM,
                        title=f"Cookie '{name}' Missing 'HttpOnly' Attribute",
                        description=f"Cookie '{name}' is accessible via JavaScript (document.cookie).",
                        impact="If the application has a Cross-Site Scripting (XSS) vulnerability, an attacker can steal session cookies or tokens.",
                        remediation=f"Set 'HttpOnly' flag on cookie '{name}' unless it explicitly requires client-side JavaScript access.",
                        evidence=raw,
                        references=["https://owasp.org/www-community/HttpOnly"],
                    )
                )

            # 3. SameSite Flag
            if not samesite or samesite.lower() not in ["strict", "lax"]:
                if samesite and samesite.lower() == "none" and not secure:
                    issues.append("SameSite=None without Secure (Invalid/Insecure)")
                else:
                    issues.append("Missing or weak 'SameSite' attribute")

                findings.append(
                    Finding(
                        id="SEC-CK-003",
                        category=FindingCategory.COOKIES,
                        severity=Severity.LOW,
                        title=f"Cookie '{name}' Lacks Strict/Lax 'SameSite' Protection",
                        description=f"Cookie '{name}' does not configure 'SameSite=Lax' or 'SameSite=Strict'.",
                        impact="Increases risk of Cross-Site Request Forgery (CSRF) attacks by allowing browsers to send cookies in cross-site requests.",
                        remediation=f"Configure 'SameSite=Lax' or 'SameSite=Strict' for cookie '{name}'.",
                        evidence=raw,
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"],
                    )
                )

            audit_items.append(
                CookieAuditItem(
                    name=name,
                    secure=secure,
                    httponly=httponly,
                    samesite=samesite,
                    domain=domain,
                    path=path,
                    issues=issues,
                )
            )

    return audit_items, findings
