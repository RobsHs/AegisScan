"""
DNS and Email Defense Posture Audit Module.
Audits SPF, DMARC, MX records, and DNSSEC to evaluate phishing and domain spoofing protections.
"""

from typing import Tuple, List, Optional
from urllib.parse import urlparse
import dns.resolver
from aegisscan.core.models import DnsMailAuditItem, Finding, FindingCategory, Severity


def audit_dns_mail(url: str, timeout: float = 4.0) -> Tuple[Optional[DnsMailAuditItem], List[Finding]]:
    """
    Audits DNS records for SPF, DMARC, and email security configurations.
    """
    parsed = urlparse(url)
    domain = parsed.hostname or url

    # Remove any www prefix for base domain SPF/DMARC checks if desired
    parts = domain.split(".")
    base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    audit_item = DnsMailAuditItem(domain=domain)
    findings: List[Finding] = []

    # 1. SPF Check
    spf_record = None
    try:
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt_str = "".join([s.decode("utf-8", errors="ignore") for s in rdata.strings])
            if txt_str.startswith("v=spf1"):
                spf_record = txt_str
                break
    except Exception:
        # Check base_domain if different
        if base_domain != domain:
            try:
                answers = resolver.resolve(base_domain, "TXT")
                for rdata in answers:
                    txt_str = "".join([s.decode("utf-8", errors="ignore") for s in rdata.strings])
                    if txt_str.startswith("v=spf1"):
                        spf_record = txt_str
                        break
            except Exception:
                pass

    if spf_record:
        audit_item.has_spf = True
        audit_item.spf_record = spf_record
        if "+all" in spf_record:
            audit_item.spf_status = "CRITICAL_MISCONFIG"
            audit_item.issues.append("SPF record contains '+all' which allows ANY IP to send emails on your behalf.")
            findings.append(
                Finding(
                    id="SEC-DNS-001",
                    category=FindingCategory.DNS_MAIL,
                    severity=Severity.CRITICAL,
                    title="Insecure SPF '+all' Directive Configured",
                    description="The SPF record specifies '+all', explicitly permitting any IP address in the world to forge emails from this domain.",
                    impact="Trivial email spoofing and spear-phishing attacks against users and partners.",
                    remediation="Change '+all' to '~all' (SoftFail) or '-all' (HardFail) in the SPF record.",
                    evidence=spf_record,
                    references=["https://datatracker.ietf.org/doc/html/rfc7208"],
                )
            )
        elif "-all" in spf_record:
            audit_item.spf_status = "ENFORCED (-all)"
        elif "~all" in spf_record:
            audit_item.spf_status = "SOFTFAIL (~all)"
        else:
            audit_item.spf_status = "WEAK"
    else:
        audit_item.spf_status = "MISSING"
        audit_item.issues.append("Missing SPF record")
        findings.append(
            Finding(
                id="SEC-DNS-002",
                category=FindingCategory.DNS_MAIL,
                severity=Severity.MEDIUM,
                title="Missing Sender Policy Framework (SPF) Record",
                description=f"Domain '{domain}' has no valid SPF record published in DNS.",
                impact="Attackers can spoof emails appearing to originate from your domain.",
                remediation=f"Publish a TXT record for '{domain}' with 'v=spf1 -all' (or include your mail servers).",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Email_Security_Cheat_Sheet.html"],
            )
        )

    # 2. DMARC Check
    dmarc_domain = f"_dmarc.{domain}"
    dmarc_record = None
    try:
        answers = resolver.resolve(dmarc_domain, "TXT")
        for rdata in answers:
            txt_str = "".join([s.decode("utf-8", errors="ignore") for s in rdata.strings])
            if txt_str.startswith("v=DMARC1"):
                dmarc_record = txt_str
                break
    except Exception:
        # Check base domain DMARC if domain was a subdomain
        if base_domain != domain:
            try:
                base_dmarc = f"_dmarc.{base_domain}"
                answers = resolver.resolve(base_dmarc, "TXT")
                for rdata in answers:
                    txt_str = "".join([s.decode("utf-8", errors="ignore") for s in rdata.strings])
                    if txt_str.startswith("v=DMARC1"):
                        dmarc_record = txt_str
                        break
            except Exception:
                pass

    if dmarc_record:
        audit_item.has_dmarc = True
        audit_item.dmarc_record = dmarc_record

        # Extract policy (p=reject, p=quarantine, p=none)
        if "p=reject" in dmarc_record.lower():
            audit_item.dmarc_policy = "reject"
            audit_item.dmarc_status = "ENFORCED (reject)"
        elif "p=quarantine" in dmarc_record.lower():
            audit_item.dmarc_policy = "quarantine"
            audit_item.dmarc_status = "ENFORCED (quarantine)"
        elif "p=none" in dmarc_record.lower():
            audit_item.dmarc_policy = "none"
            audit_item.dmarc_status = "WEAK (p=none)"
            audit_item.issues.append("DMARC policy is set to 'p=none' (monitoring only, no enforcement)")
            findings.append(
                Finding(
                    id="SEC-DNS-003",
                    category=FindingCategory.DNS_MAIL,
                    severity=Severity.LOW,
                    title="DMARC Policy Set to Monitoring Only (p=none)",
                    description="The DMARC policy does not quarantine or reject spoofed emails.",
                    impact="Spoofed emails may still be delivered to recipient inboxes.",
                    remediation="Upgrade DMARC policy to 'p=quarantine' or 'p=reject' once legitimate email streams are verified.",
                    evidence=dmarc_record,
                    references=["https://dmarc.org/overview/"],
                )
            )
        else:
            audit_item.dmarc_status = "CUSTOM"
    else:
        audit_item.dmarc_status = "MISSING"
        audit_item.issues.append("Missing DMARC record")
        findings.append(
            Finding(
                id="SEC-DNS-004",
                category=FindingCategory.DNS_MAIL,
                severity=Severity.MEDIUM,
                title="Missing DMARC Record",
                description=f"Domain '{domain}' has no DMARC record configured under '_dmarc.{domain}'.",
                impact="Lacks email spoofing feedback loops and policy enforcement.",
                remediation=f"Publish a TXT record for '_dmarc.{domain}' e.g., 'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{base_domain}'",
                references=["https://dmarc.org/"],
            )
        )

    # 3. MX Records Check
    try:
        mx_answers = resolver.resolve(domain, "MX")
        audit_item.has_mx = True
        audit_item.mx_records = [str(r.exchange).rstrip(".") for r in mx_answers]
    except Exception:
        audit_item.has_mx = False

    # 4. DNSSEC Check
    try:
        resolver.resolve(domain, "DNSKEY")
        audit_item.dnssec_enabled = True
    except Exception:
        audit_item.dnssec_enabled = False

    return audit_item, findings
