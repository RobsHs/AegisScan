"""
Sensitive File and Path Exposure Audit Module.
High-speed asynchronous scanner with signature verification to prevent false positives.
"""

import asyncio
import re
from typing import List, Tuple, Dict, Any, Optional
from urllib.parse import urljoin
import httpx
from aegisscan.core.models import ExposureAuditItem, Finding, FindingCategory, Severity

# Target paths to test, their category, severity, and verification signatures
EXPOSURE_TARGETS = [
    # Version Control
    {
        "path": "/.git/HEAD",
        "category": "Version Control",
        "severity": Severity.CRITICAL,
        "signature": re.compile(r"^ref:\s*refs/|[0-9a-f]{40}", re.MULTILINE | re.IGNORECASE),
        "title": "Exposed Git Repository Root (.git/HEAD)",
        "desc": "The root of a Git repository is publicly accessible. Attackers can reconstruct the entire source code and commit history.",
        "remediation": "Block access to '.git' directories in your web server config (e.g. 'location ~ /\\.git { deny all; }' in Nginx).",
    },
    {
        "path": "/.git/config",
        "category": "Version Control",
        "severity": Severity.CRITICAL,
        "signature": re.compile(r"\[core\]|repositoryformatversion", re.IGNORECASE),
        "title": "Exposed Git Configuration (.git/config)",
        "desc": "Git configuration file containing remote repository URLs and internal credentials is exposed.",
        "remediation": "Block access to '.git' directories.",
    },
    {
        "path": "/.svn/entries",
        "category": "Version Control",
        "severity": Severity.HIGH,
        "signature": re.compile(r"svn:entry|dir\n\d+", re.IGNORECASE),
        "title": "Exposed Subversion Metadata (.svn/entries)",
        "desc": "Subversion repository directory structure is publicly accessible.",
        "remediation": "Block public access to '.svn' directories.",
    },
    # Secrets & Environment
    {
        "path": "/.env",
        "category": "Environment & Secrets",
        "severity": Severity.CRITICAL,
        "signature": re.compile(r"^[A-Z0-9_]+=\S+", re.MULTILINE),
        "title": "Exposed Environment Configuration File (.env)",
        "desc": "A production .env file containing database passwords, API keys, and secrets is publicly downloadable.",
        "remediation": "Immediately move '.env' out of the web document root and rotate all compromised keys.",
    },
    {
        "path": "/.env.local",
        "category": "Environment & Secrets",
        "severity": Severity.CRITICAL,
        "signature": re.compile(r"^[A-Z0-9_]+=\S+", re.MULTILINE),
        "title": "Exposed Local Environment File (.env.local)",
        "desc": "A local environment file containing application credentials is exposed.",
        "remediation": "Restrict web server access to all .env* files.",
    },
    {
        "path": "/.env.production",
        "category": "Environment & Secrets",
        "severity": Severity.CRITICAL,
        "signature": re.compile(r"^[A-Z0-9_]+=\S+", re.MULTILINE),
        "title": "Exposed Production Environment File (.env.production)",
        "desc": "Production credentials and database connection strings are publicly accessible.",
        "remediation": "Restrict web server access to all .env* files and rotate secrets.",
    },
    {
        "path": "/web.config",
        "category": "Server Configuration",
        "severity": Severity.HIGH,
        "signature": re.compile(r"<configuration>|<system\.webServer>", re.IGNORECASE),
        "title": "Exposed IIS Configuration File (web.config)",
        "desc": "IIS web.config disclosing connection strings and authentication settings is readable.",
        "remediation": "Ensure IIS blocks serving .config files under request filtering.",
    },
    # Cloud & DevOps
    {
        "path": "/docker-compose.yml",
        "category": "DevOps & Infrastructure",
        "severity": Severity.HIGH,
        "signature": re.compile(r"(version:\s*['\"]?\d|services:\s*\n)", re.IGNORECASE),
        "title": "Exposed Docker Compose File (docker-compose.yml)",
        "desc": "Docker compose specification detailing microservices architecture and environment variables is exposed.",
        "remediation": "Remove container orchestration files from public web directories.",
    },
    {
        "path": "/Dockerfile",
        "category": "DevOps & Infrastructure",
        "severity": Severity.MEDIUM,
        "signature": re.compile(r"^\s*FROM\s+[\w\.\-\:]+", re.MULTILINE | re.IGNORECASE),
        "title": "Exposed Container Dockerfile",
        "desc": "The Docker build instructions and base images are exposed to the public.",
        "remediation": "Remove Dockerfile from public web server roots.",
    },
    {
        "path": "/id_rsa",
        "category": "Cryptographic Keys",
        "severity": Severity.CRITICAL,
        "signature": re.compile(r"-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----"),
        "title": "Exposed Private SSH Key (id_rsa)",
        "desc": "A private SSH key is stored directly in the web server directory and publicly downloadable.",
        "remediation": "Delete the file immediately, revoke this key on all servers, and generate fresh keypairs.",
    },
    {
        "path": "/server.key",
        "category": "Cryptographic Keys",
        "severity": Severity.CRITICAL,
        "signature": re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
        "title": "Exposed TLS Private Key (server.key)",
        "desc": "The server's private SSL/TLS key is exposed, allowing attackers to decrypt traffic or impersonate the domain.",
        "remediation": "Revoke and reissue the TLS certificate immediately, and move keys to secure storage.",
    },
    # Database & Backups
    {
        "path": "/dump.sql",
        "category": "Database Backups",
        "severity": Severity.CRITICAL,
        "signature": re.compile(r"(CREATE\s+TABLE|INSERT\s+INTO|--\s*MySQL\s*dump)", re.IGNORECASE),
        "title": "Exposed Database Dump File (dump.sql)",
        "desc": "A raw SQL database backup containing database records and schemas is publicly accessible.",
        "remediation": "Remove SQL dump files from public web roots and store backups in encrypted private buckets.",
    },
    {
        "path": "/backup.sql",
        "category": "Database Backups",
        "severity": Severity.CRITICAL,
        "signature": re.compile(r"(CREATE\s+TABLE|INSERT\s+INTO|--\s*MySQL\s*dump)", re.IGNORECASE),
        "title": "Exposed Database Backup File (backup.sql)",
        "desc": "A database backup file is directly accessible.",
        "remediation": "Remove SQL backups from public web roots.",
    },
    {
        "path": "/db.sqlite3",
        "category": "Database Backups",
        "severity": Severity.CRITICAL,
        "signature": re.compile(r"^SQLite format 3", re.MULTILINE),
        "title": "Exposed SQLite Database File (db.sqlite3)",
        "desc": "An active or backup SQLite database containing application data is downloadable.",
        "remediation": "Move database files outside web server document roots.",
    },
    # Debug & Framework Endpoints
    {
        "path": "/phpinfo.php",
        "category": "Debug & Diagnostics",
        "severity": Severity.MEDIUM,
        "signature": re.compile(r"PHP Version|<title>phpinfo\(\)", re.IGNORECASE),
        "title": "Exposed PHP Information Page (phpinfo.php)",
        "desc": "A phpinfo diagnostic script discloses full PHP configuration, module versions, and server paths.",
        "remediation": "Delete phpinfo.php and any diagnostic test scripts from production servers.",
    },
    {
        "path": "/actuator/env",
        "category": "Framework Endpoints",
        "severity": Severity.CRITICAL,
        "signature": re.compile(r"\"propertySources\"|\"activeProfiles\"", re.IGNORECASE),
        "title": "Exposed Spring Boot Actuator Environment (/actuator/env)",
        "desc": "Spring Boot Actuator environment endpoint discloses internal application properties and configuration.",
        "remediation": "Disable or secure Spring Actuator endpoints via Spring Security.",
    },
    {
        "path": "/actuator/health",
        "category": "Framework Endpoints",
        "severity": Severity.LOW,
        "signature": re.compile(r"\"status\"\s*:\s*\"(UP|DOWN)\"", re.IGNORECASE),
        "title": "Publicly Exposed Health Actuator (/actuator/health)",
        "desc": "Spring Boot health endpoint discloses system status and disk/database health metrics.",
        "remediation": "Restrict actuator endpoints to internal monitoring networks.",
    },
    {
        "path": "/swagger.json",
        "category": "API Documentation",
        "severity": Severity.LOW,
        "signature": re.compile(r"\"swagger\"\s*:\s*\"2\.0\"|\"openapi\"\s*:\s*\"3\.", re.IGNORECASE),
        "title": "Public OpenAPI / Swagger Specification (/swagger.json)",
        "desc": "API schema file detailing all internal API endpoints, parameters, and models is exposed.",
        "remediation": "If the API is private, restrict access to Swagger specifications with authentication.",
    },
    {
        "path": "/openapi.json",
        "category": "API Documentation",
        "severity": Severity.LOW,
        "signature": re.compile(r"\"openapi\"\s*:\s*\"3\.", re.IGNORECASE),
        "title": "Public OpenAPI 3.0 Specification (/openapi.json)",
        "desc": "Public OpenAPI specification disclosing full API schema.",
        "remediation": "Restrict API schema access if internal endpoints should not be publicly documented.",
    },
]


def load_community_signatures(signatures_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    """Loads community custom signatures from JSON files."""
    import json
    from pathlib import Path

    loaded = []
    search_dirs = [
        Path(signatures_dir) if signatures_dir else None,
        Path("signatures"),
        Path(__file__).resolve().parent.parent.parent / "signatures",
    ]
    for s_dir in search_dirs:
        if s_dir and s_dir.is_dir():
            for json_file in s_dir.glob("*.json"):
                try:
                    data = json.loads(json_file.read_text(encoding="utf-8"))
                    if isinstance(data, dict) and "path" in data and "pattern" in data:
                        sev_str = data.get("severity", "MEDIUM").upper()
                        severity = getattr(Severity, sev_str, Severity.MEDIUM)
                        loaded.append({
                            "path": data["path"],
                            "category": data.get("category", "Community Signature"),
                            "severity": severity,
                            "signature": re.compile(data["pattern"], re.IGNORECASE),
                            "title": data.get("title", f"Exposed {data['path']}"),
                            "desc": data.get("description", "Exposed sensitive file or endpoint detected by community signature."),
                            "remediation": data.get("remediation", "Restrict access or delete sensitive resource."),
                        })
                except Exception:
                    continue
            break
    return loaded


async def _check_single_path(
    client: httpx.AsyncClient,
    base_url: str,
    target: Dict[str, Any],
    semaphore: asyncio.Semaphore,
) -> Tuple[Optional[ExposureAuditItem], Optional[Finding]]:
    """
    Checks a single path with concurrency limit and signature verification.
    """
    path = target["path"]
    full_url = urljoin(base_url, path)

    async with semaphore:
        try:
            resp = await client.get(
                full_url,
                headers={"User-Agent": "AegisScan/1.0 (+https://github.com/RobsHs/AegisScan)"},
                follow_redirects=False,
                timeout=6.0,
            )

            # We only inspect successful 200 OK responses
            if resp.status_code == 200:
                body_sample = resp.text[:4000]
                sig: re.Pattern = target["signature"]

                # Verify against signature to prevent SPA / Custom 404 false positives
                if sig.search(body_sample):
                    # Mask potential secrets from snippet preview
                    evidence = body_sample[:180].strip()

                    audit_item = ExposureAuditItem(
                        path=path,
                        url=full_url,
                        status_code=resp.status_code,
                        exposed=True,
                        category=target["category"],
                        risk_level=target["severity"],
                        evidence_snippet=evidence,
                    )

                    finding = Finding(
                        id=f"SEC-EXP-{abs(hash(path)) % 9000 + 1000}",
                        category=FindingCategory.EXPOSURE,
                        severity=target["severity"],
                        title=target["title"],
                        description=target["desc"],
                        impact="Sensitive data, infrastructure configuration, or internal code structure is exposed to unauthorized users.",
                        remediation=target["remediation"],
                        evidence=f"URL: {full_url}\nStatus: {resp.status_code}\nSample:\n{evidence}",
                        references=["https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"],
                    )

                    return audit_item, finding

            return (
                ExposureAuditItem(
                    path=path,
                    url=full_url,
                    status_code=resp.status_code,
                    exposed=False,
                    category=target["category"],
                    risk_level=target["severity"],
                ),
                None,
            )
        except Exception:
            return (
                ExposureAuditItem(
                    path=path,
                    url=full_url,
                    status_code=0,
                    exposed=False,
                    category=target["category"],
                    risk_level=target["severity"],
                ),
                None,
            )


async def audit_exposure(base_url: str, max_concurrency: int = 8) -> Tuple[List[ExposureAuditItem], List[Finding]]:
    """
    Scans base_url asynchronously for exposed sensitive paths.
    """
    semaphore = asyncio.Semaphore(max_concurrency)
    audit_items: List[ExposureAuditItem] = []
    findings: List[Finding] = []

    # Merge core targets with community-contributed signatures
    all_targets = list(EXPOSURE_TARGETS) + load_community_signatures()

    async with httpx.AsyncClient(verify=False) as client:
        tasks = [
            _check_single_path(client, base_url, target, semaphore)
            for target in all_targets
        ]
        results = await asyncio.gather(*tasks)

        for item, finding in results:
            if item:
                audit_items.append(item)
            if finding:
                findings.append(finding)

    # Sort audit items: exposed first, then by risk
    audit_items.sort(key=lambda x: (not x.exposed, x.path))
    return audit_items, findings

