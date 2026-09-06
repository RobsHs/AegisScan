"""
Data models and schemas for AegisScan.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingCategory(str, Enum):
    HEADERS = "Security Headers"
    COOKIES = "Cookie Security"
    EXPOSURE = "Sensitive Exposure"
    TLS = "SSL / TLS"
    DNS_MAIL = "DNS & Email Defense"
    CORS = "CORS Configuration"
    INFORMATION = "Information Disclosure"


@dataclass
class Finding:
    id: str
    category: FindingCategory
    severity: Severity
    title: str
    description: str
    impact: str
    remediation: str
    evidence: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "references": self.references,
        }


@dataclass
class HeaderAuditItem:
    header: str
    present: bool
    value: Optional[str]
    status: str  # PASS, WARN, FAIL
    recommendation: str
    severity_if_missing: Severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "header": self.header,
            "present": self.present,
            "value": self.value,
            "status": self.status,
            "recommendation": self.recommendation,
            "severity_if_missing": self.severity_if_missing.value,
        }


@dataclass
class CookieAuditItem:
    name: str
    secure: bool
    httponly: bool
    samesite: Optional[str]
    domain: Optional[str]
    path: Optional[str]
    issues: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "secure": self.secure,
            "httponly": self.httponly,
            "samesite": self.samesite,
            "domain": self.domain,
            "path": self.path,
            "issues": self.issues,
        }


@dataclass
class ExposureAuditItem:
    path: str
    url: str
    status_code: int
    exposed: bool
    category: str
    risk_level: Severity
    evidence_snippet: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "url": self.url,
            "status_code": self.status_code,
            "exposed": self.exposed,
            "category": self.category,
            "risk_level": self.risk_level.value,
            "evidence_snippet": self.evidence_snippet,
        }


@dataclass
class TlsAuditItem:
    supported: bool
    issuer: Optional[str] = None
    subject: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    days_left: Optional[int] = None
    protocol_version: Optional[str] = None
    is_expired: bool = False
    is_expiring_soon: bool = False  # < 30 days
    is_self_signed: bool = False
    issues: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "supported": self.supported,
            "issuer": self.issuer,
            "subject": self.subject,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "days_left": self.days_left,
            "protocol_version": self.protocol_version,
            "is_expired": self.is_expired,
            "is_expiring_soon": self.is_expiring_soon,
            "is_self_signed": self.is_self_signed,
            "issues": self.issues,
        }


@dataclass
class DnsMailAuditItem:
    domain: str
    has_spf: bool = False
    spf_record: Optional[str] = None
    spf_status: str = "MISSING"  # SECURE, WEAK, MISSING
    has_dmarc: bool = False
    dmarc_record: Optional[str] = None
    dmarc_policy: Optional[str] = None
    dmarc_status: str = "MISSING"  # ENFORCED (reject/quarantine), WEAK (none), MISSING
    has_mx: bool = False
    mx_records: List[str] = field(default_factory=list)
    dnssec_enabled: bool = False
    issues: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "has_spf": self.has_spf,
            "spf_record": self.spf_record,
            "spf_status": self.spf_status,
            "has_dmarc": self.has_dmarc,
            "dmarc_record": self.dmarc_record,
            "dmarc_policy": self.dmarc_policy,
            "dmarc_status": self.dmarc_status,
            "has_mx": self.has_mx,
            "mx_records": self.mx_records,
            "dnssec_enabled": self.dnssec_enabled,
            "issues": self.issues,
        }


@dataclass
class CorsAuditItem:
    tested: bool
    vulnerable: bool = False
    reflected_origin: Optional[str] = None
    allows_credentials: bool = False
    wildcard_with_credentials: bool = False
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tested": self.tested,
            "vulnerable": self.vulnerable,
            "reflected_origin": self.reflected_origin,
            "allows_credentials": self.allows_credentials,
            "wildcard_with_credentials": self.wildcard_with_credentials,
            "details": self.details,
        }


@dataclass
class ScanSummary:
    target_url: str
    target_host: str
    scan_date: str
    scan_duration_sec: float
    score: int
    grade: str  # A+, A, B, C, D, F
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    total_findings: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "target_host": self.target_host,
            "scan_date": self.scan_date,
            "scan_duration_sec": self.scan_duration_sec,
            "score": self.score,
            "grade": self.grade,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "total_findings": self.total_findings,
        }


@dataclass
class ScanResult:
    summary: ScanSummary
    findings: List[Finding] = field(default_factory=list)
    headers: List[HeaderAuditItem] = field(default_factory=list)
    cookies: List[CookieAuditItem] = field(default_factory=list)
    exposures: List[ExposureAuditItem] = field(default_factory=list)
    tls: Optional[TlsAuditItem] = None
    dns_mail: Optional[DnsMailAuditItem] = None
    cors: Optional[CorsAuditItem] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "headers": [h.to_dict() for h in self.headers],
            "cookies": [c.to_dict() for c in self.cookies],
            "exposures": [e.to_dict() for e in self.exposures],
            "tls": self.tls.to_dict() if self.tls else None,
            "dns_mail": self.dns_mail.to_dict() if self.dns_mail else None,
            "cors": self.cors.to_dict() if self.cors else None,
        }

