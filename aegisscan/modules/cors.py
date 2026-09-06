"""
CORS (Cross-Origin Resource Sharing) Misconfiguration Audit Module.
Tests for arbitrary origin reflection and credential exposure.
"""

from typing import Tuple, List, Optional
import httpx
from aegisscan.core.models import CorsAuditItem, Finding, FindingCategory, Severity


async def audit_cors(url: str, timeout: float = 5.0) -> Tuple[Optional[CorsAuditItem], List[Finding]]:
    """
    Tests the endpoint for Cross-Origin Resource Sharing (CORS) misconfigurations.
    """
    findings: List[Finding] = []
    test_origin = "https://evil-attacker.com"

    try:
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.get(
                url,
                headers={
                    "Origin": test_origin,
                    "User-Agent": "AegisScan/1.0 (+https://github.com/RobsHs/AegisScan)",
                },
                timeout=timeout,
                follow_redirects=True,
            )

            acao = resp.headers.get("access-control-allow-origin")
            acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"

            if not acao:
                # No CORS headers returned
                return CorsAuditItem(tested=True, vulnerable=False), findings

            reflected = (acao == test_origin)
            wildcard = (acao == "*")

            if reflected and acac:
                findings.append(
                    Finding(
                        id="SEC-CORS-001",
                        category=FindingCategory.CORS,
                        severity=Severity.CRITICAL,
                        title="Critical CORS Misconfiguration: Arbitrary Origin Reflection with Credentials",
                        description=f"The endpoint dynamically reflects arbitrary Origin headers ('{test_origin}') and enables 'Access-Control-Allow-Credentials: true'.",
                        impact="Attackers can steal authenticated user data, CSRF tokens, or private resources from another website.",
                        remediation="Do not reflect arbitrary Origin headers. Maintain an explicit whitelist of trusted domains and disallow credentials unless necessary.",
                        evidence=f"Origin: {test_origin}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: true",
                        references=["https://portswigger.net/web-security/cors"],
                    )
                )
                return (
                    CorsAuditItem(
                        tested=True,
                        vulnerable=True,
                        reflected_origin=acao,
                        allows_credentials=True,
                        details="Critical: Arbitrary origin reflected with credentials enabled.",
                    ),
                    findings,
                )

            if reflected and not acac:
                findings.append(
                    Finding(
                        id="SEC-CORS-002",
                        category=FindingCategory.CORS,
                        severity=Severity.MEDIUM,
                        title="Insecure CORS: Arbitrary Origin Reflection (Without Credentials)",
                        description=f"The endpoint reflects arbitrary Origin headers ('{test_origin}') into Access-Control-Allow-Origin.",
                        impact="Third-party sites can read responses intended only for same-origin contexts.",
                        remediation="Validate Origin against an allowed list of origins before setting Access-Control-Allow-Origin.",
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        references=["https://portswigger.net/web-security/cors"],
                    )
                )
                return (
                    CorsAuditItem(
                        tested=True,
                        vulnerable=True,
                        reflected_origin=acao,
                        allows_credentials=False,
                        details="Medium: Arbitrary origin reflected without credentials.",
                    ),
                    findings,
                )

            if wildcard and acac:
                findings.append(
                    Finding(
                        id="SEC-CORS-003",
                        category=FindingCategory.CORS,
                        severity=Severity.HIGH,
                        title="Invalid / Dangerous CORS: Wildcard Origin with Credentials",
                        description="Access-Control-Allow-Origin is set to '*' while Access-Control-Allow-Credentials is true.",
                        impact="Modern browsers reject this, but it signifies misconfigured access controls on sensitive resources.",
                        remediation="Remove wildcard origin or disable credentials.",
                        evidence="Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true",
                        references=["https://fetch.spec.whatwg.org/#cors-protocol-and-credentials"],
                    )
                )
                return (
                    CorsAuditItem(
                        tested=True,
                        vulnerable=True,
                        wildcard_with_credentials=True,
                        details="High: Wildcard with credentials.",
                    ),
                    findings,
                )

            # Benign or standard CORS
            return (
                CorsAuditItem(
                    tested=True,
                    vulnerable=False,
                    reflected_origin=acao,
                    allows_credentials=acac,
                    details=f"Configured: {acao}",
                ),
                findings,
            )

    except Exception:
        return CorsAuditItem(tested=False), findings
