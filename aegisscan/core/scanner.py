"""
Asynchronous Scan Orchestrator Engine for AegisScan.
Runs modular audits concurrently, aggregates results, and computes security scores.
"""

import asyncio
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Optional, Callable, Dict, Any

import httpx

from aegisscan.core.models import (
    Finding,
    FindingCategory,
    ScanResult,
    ScanSummary,
    Severity,
)
from aegisscan.modules.headers import audit_headers
from aegisscan.modules.cookies import audit_cookies
from aegisscan.modules.exposure import audit_exposure
from aegisscan.modules.tls_check import audit_tls
from aegisscan.modules.dns_mail import audit_dns_mail
from aegisscan.modules.cors import audit_cors


def _normalize_url(raw_url: str) -> str:
    """Ensures the target URL has a scheme."""
    raw = raw_url.strip()
    if not raw.startswith("http://") and not raw.startswith("https://"):
        return f"https://{raw}"
    return raw


def _compute_score_and_grade(findings: list[Finding]) -> tuple[int, str]:
    """
    Computes a 0-100 security posture score and letter grade (A+ to F).
    """
    crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
    med_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    low_count = sum(1 for f in findings if f.severity == Severity.LOW)

    score = 100 - (crit_count * 25 + high_count * 15 + med_count * 7 + low_count * 2)
    score = max(0, min(100, score))

    if crit_count >= 2 or score < 60:
        grade = "F"
    elif crit_count == 1 or score < 70:
        grade = "D"
    elif score < 80:
        grade = "C"
    elif score < 90:
        grade = "B"
    elif score < 96:
        grade = "A"
    else:
        grade = "A+"

    return score, grade


class AegisScanner:
    """
    Main scanner engine that coordinates audits and produces ScanResult.
    """

    def __init__(
        self,
        target_url: str,
        timeout: float = 8.0,
        max_concurrency: int = 10,
        skip_exposure: bool = False,
        skip_dns: bool = False,
        user_agent: str = "AegisScan/1.0 (+https://github.com/RobsHs/AegisScan)",
    ):
        self.target_url = _normalize_url(target_url)
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.skip_exposure = skip_exposure
        self.skip_dns = skip_dns
        self.user_agent = user_agent
        parsed = urlparse(self.target_url)
        self.target_host = parsed.hostname or self.target_url

    async def run_scan(self, progress_callback: Optional[Callable[[str], None]] = None) -> ScanResult:
        """
        Executes the full suite of security audits.
        """
        start_time = time.time()
        scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        if progress_callback:
            progress_callback(f"Probing base endpoint: {self.target_url}...")

        # 1. Base HTTP Request
        headers_dict: Dict[str, str] = {}
        raw_cookies: list[str] = []
        final_url = self.target_url

        try:
            async with httpx.AsyncClient(verify=False) as client:
                resp = await client.get(
                    self.target_url,
                    headers={"User-Agent": self.user_agent},
                    follow_redirects=True,
                    timeout=self.timeout,
                )
                headers_dict = dict(resp.headers)
                final_url = str(resp.url)
                # Extract Set-Cookie headers
                raw_cookies = resp.headers.get_list("set-cookie")
        except Exception as e:
            # Service unreachable or connection error
            return ScanResult(
                summary=ScanSummary(
                    target_url=self.target_url,
                    target_host=self.target_host,
                    scan_date=scan_date,
                    scan_duration_sec=round(time.time() - start_time, 2),
                    score=0,
                    grade="F",
                    critical_count=1,
                    high_count=0,
                    medium_count=0,
                    low_count=0,
                    info_count=0,
                    total_findings=1,
                ),
                findings=[
                    Finding(
                        id="SEC-CONN-ERR",
                        category=FindingCategory.INFORMATION,
                        severity=Severity.CRITICAL,
                        title="Target Host Unreachable",
                        description=f"Could not establish HTTP connection to {self.target_url}. Error: {str(e)}",
                        impact="Host is down or blocking scanning requests.",
                        remediation="Check host availability, firewall/WAF blocks, and DNS resolution.",
                    )
                ],
            )

        # 2. Concurrently run audit modules
        all_findings: list[Finding] = []

        if progress_callback:
            progress_callback("Auditing HTTP security headers and cookies...")
        header_items, header_findings = audit_headers(headers_dict, final_url)
        cookie_items, cookie_findings = audit_cookies(raw_cookies, final_url)
        all_findings.extend(header_findings)
        all_findings.extend(cookie_findings)

        # Asynchronous tasks
        loop = asyncio.get_running_loop()

        async def _run_exposure():
            if self.skip_exposure:
                return [], []
            if progress_callback:
                progress_callback("Scanning for sensitive file exposures & leaks...")
            return await audit_exposure(final_url, self.max_concurrency)

        async def _run_tls():
            if progress_callback:
                progress_callback("Auditing TLS/SSL certificate and cipher suite...")
            return await loop.run_in_executor(None, audit_tls, final_url, self.timeout)

        async def _run_dns():
            if self.skip_dns:
                return None, []
            if progress_callback:
                progress_callback("Auditing DNS records, SPF, DMARC, and email posture...")
            return await loop.run_in_executor(None, audit_dns_mail, final_url, self.timeout)

        async def _run_cors():
            if progress_callback:
                progress_callback("Testing CORS policies for origin reflection...")
            return await audit_cors(final_url, self.timeout)

        # Run in parallel
        (
            (exposure_items, exposure_findings),
            (tls_item, tls_findings),
            (dns_item, dns_findings),
            (cors_item, cors_findings),
        ) = await asyncio.gather(_run_exposure(), _run_tls(), _run_dns(), _run_cors())

        all_findings.extend(exposure_findings)
        all_findings.extend(tls_findings)
        all_findings.extend(dns_findings)
        all_findings.extend(cors_findings)

        # Deduplicate findings by title
        seen_titles = set()
        unique_findings = []
        for f in all_findings:
            if f.title not in seen_titles:
                seen_titles.add(f.title)
                unique_findings.append(f)

        # Severity counts
        crit_count = sum(1 for f in unique_findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in unique_findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in unique_findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in unique_findings if f.severity == Severity.LOW)
        info_count = sum(1 for f in unique_findings if f.severity == Severity.INFO)

        score, grade = _compute_score_and_grade(unique_findings)
        duration = round(time.time() - start_time, 2)

        summary = ScanSummary(
            target_url=final_url,
            target_host=self.target_host,
            scan_date=scan_date,
            scan_duration_sec=duration,
            score=score,
            grade=grade,
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            info_count=info_count,
            total_findings=len(unique_findings),
        )

        return ScanResult(
            summary=summary,
            findings=unique_findings,
            headers=header_items,
            cookies=cookie_items,
            exposures=exposure_items,
            tls=tls_item,
            dns_mail=dns_item,
            cors=cors_item,
        )
