"""
SSL / TLS and Certificate Health Audit Module.
Analyzes SSL/TLS protocols, cipher negotiation, validity dates, and certificate trust.
"""

import socket
import ssl
from datetime import datetime, timezone
from typing import Optional, Tuple, List
from urllib.parse import urlparse
from aegisscan.core.models import Finding, FindingCategory, Severity, TlsAuditItem


def _parse_cert_date(date_str: str) -> Optional[datetime]:
    """
    Parses certificate date string (e.g., 'May 10 12:00:00 2026 GMT').
    """
    try:
        dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def audit_tls(url: str, timeout: float = 6.0) -> Tuple[Optional[TlsAuditItem], List[Finding]]:
    """
    Inspects the TLS certificate and encryption protocol for the given URL.
    """
    parsed = urlparse(url)
    host = parsed.hostname or url
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    findings: List[Finding] = []

    if parsed.scheme == "http" and port == 80:
        findings.append(
            Finding(
                id="SEC-TLS-000",
                category=FindingCategory.TLS,
                severity=Severity.HIGH,
                title="Unencrypted Cleartext HTTP Service",
                description=f"The service at {url} is using unencrypted HTTP.",
                impact="Network eavesdroppers can capture sensitive data, cookies, and credentials in plaintext.",
                remediation="Enable HTTPS with a valid TLS certificate and redirect all HTTP traffic to HTTPS.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
            )
        )
        return (
            TlsAuditItem(
                supported=False,
                issues=["Service operates on cleartext HTTP without TLS encryption."],
            ),
            findings,
        )

    # Attempt TLS handshake
    context = ssl.create_default_context()
    cert = None
    protocol_version = None
    is_self_signed = False
    handshake_error = None

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol_version = ssock.version()
    except ssl.SSLCertVerificationError as e:
        handshake_error = str(e)
        # Try connecting without verification to inspect the bad cert
        try:
            insecure_ctx = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with insecure_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    protocol_version = ssock.version()
        except Exception:
            pass
    except Exception as e:
        handshake_error = str(e)

    if not cert:
        issues = [f"TLS handshake failed: {handshake_error or 'Unknown error'}"]
        findings.append(
            Finding(
                id="SEC-TLS-001",
                category=FindingCategory.TLS,
                severity=Severity.HIGH,
                title="TLS Handshake or Certificate Failure",
                description=f"Could not establish a verified TLS connection to {host}:{port}. Error: {handshake_error}",
                impact="Users will see browser certificate warnings, and secure traffic cannot be guaranteed.",
                remediation="Ensure the server has a valid, properly installed TLS certificate issued by a recognized Certificate Authority.",
                references=["https://letsencrypt.org/"],
            )
        )
        return TlsAuditItem(supported=False, issues=issues), findings

    # Extract certificate attributes
    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
    subject_dict = dict(x[0] for x in cert.get("subject", []))

    issuer = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown Issuer"
    subject = subject_dict.get("commonName") or host

    not_before_str = cert.get("notBefore")
    not_after_str = cert.get("notAfter")

    not_after = _parse_cert_date(not_after_str) if not_after_str else None
    not_before = _parse_cert_date(not_before_str) if not_before_str else None

    now = datetime.now(timezone.utc)
    days_left = None
    is_expired = False
    is_expiring_soon = False
    issues = []

    if not_after:
        days_left = (not_after - now).days
        if days_left < 0:
            is_expired = True
            issues.append(f"Certificate expired {abs(days_left)} days ago ({not_after_str})")
            findings.append(
                Finding(
                    id="SEC-TLS-002",
                    category=FindingCategory.TLS,
                    severity=Severity.CRITICAL,
                    title="TLS Certificate Has Expired",
                    description=f"The SSL/TLS certificate for {host} expired on {not_after_str}.",
                    impact="Modern browsers block user access with severe security warnings.",
                    remediation="Renew and install the TLS certificate immediately.",
                )
            )
        elif days_left < 30:
            is_expiring_soon = True
            issues.append(f"Certificate expires soon ({days_left} days left on {not_after_str})")
            findings.append(
                Finding(
                    id="SEC-TLS-003",
                    category=FindingCategory.TLS,
                    severity=Severity.MEDIUM,
                    title="TLS Certificate Expiring Soon",
                    description=f"The TLS certificate for {host} will expire in {days_left} days ({not_after_str}).",
                    impact="If not renewed before expiration, service will become unavailable to users.",
                    remediation="Renew the certificate or ensure automated ACME renewal (e.g. Certbot) is working.",
                )
            )

    # Check for self-signed
    if issuer_dict == subject_dict and issuer_dict:
        is_self_signed = True
        issues.append("Certificate is self-signed")
        findings.append(
            Finding(
                id="SEC-TLS-004",
                category=FindingCategory.TLS,
                severity=Severity.HIGH,
                title="Self-Signed TLS Certificate in Use",
                description="The server uses a self-signed certificate rather than one issued by a trusted CA.",
                impact="Vulnerable to Man-in-the-Middle (MitM) attacks; browsers do not trust the connection.",
                remediation="Obtain a valid certificate from a trusted CA such as Let's Encrypt.",
            )
        )

    # Check TLS protocol version
    if protocol_version in ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]:
        issues.append(f"Legacy unsecure protocol: {protocol_version}")
        findings.append(
            Finding(
                id="SEC-TLS-005",
                category=FindingCategory.TLS,
                severity=Severity.HIGH,
                title=f"Outdated TLS Protocol Version ({protocol_version})",
                description=f"The server negotiated {protocol_version}, which suffers from known cryptographic flaws (POODLE, BEAST).",
                impact="Cryptographic downgrade attacks and eavesdropping on encrypted traffic.",
                remediation="Disable SSLv3, TLS 1.0, and TLS 1.1 on your server. Enforce TLS 1.2 and TLS 1.3.",
                references=["https://datatracker.ietf.org/doc/rfc8996/"],
            )
        )

    audit_item = TlsAuditItem(
        supported=True,
        issuer=issuer,
        subject=subject,
        valid_from=not_before_str,
        valid_until=not_after_str,
        days_left=days_left,
        protocol_version=protocol_version,
        is_expired=is_expired,
        is_expiring_soon=is_expiring_soon,
        is_self_signed=is_self_signed,
        issues=issues,
    )

    return audit_item, findings

