"""
Seed Issues Script for AegisScan.
Automatically populates the repository with roadmap tasks and good-first-issues.
"""

import os
import sys
import time
import httpx

# List of high-value, realistic roadmap issues to seed
ROADMAP_ISSUES = [
    {
        "title": "[NEW-CHECK]: Detect Exposed Symfony Web Profiler (/_profiler/phpinfo)",
        "body": """### Check Name
Exposed Symfony Web Profiler

### Category
Debug & Diagnostics

### Severity
HIGH

### Detection Logic
- Target path: `/_profiler/phpinfo`
- Expected Status: `200`
- Matching pattern: `<title>Symfony Profiler</title>`

### Description
The Symfony Web Profiler and diagnostic toolbar are publicly accessible without authentication, exposing detailed configuration values, environment variables, database query traces, and routing internals.

### Remediation
Disable Symfony WebProfilerBundle on production servers. Ensure `APP_ENV=prod` and `APP_DEBUG=0` in `.env`.
""",
        "labels": ["good first issue", "help wanted", "security-check"],
    },
    {
        "title": "[NEW-CHECK]: Detect Exposed Django Debug Stack Trace & Settings",
        "body": """### Check Name
Django Debug Mode Enabled Leak

### Category
Framework Diagnostics

### Severity
HIGH

### Detection Logic
- Target path: `/nonexistent-test-probe-404-debug`
- Expected Status: `404` or `500`
- Matching pattern: `DisallowedHost at|Traceback \\(most recent call last\\)|Request Method: GET.*Request URL:`

### Description
The Django application is running with `DEBUG = True` in production, displaying interactive stack traces and environment settings.

### Remediation
Set `DEBUG = False` in your Django `settings.py` or `.env` file.
""",
        "labels": ["good first issue", "help wanted", "security-check"],
    },
    {
        "title": "[NEW-CHECK]: Detect Exposed Laravel Horizon Dashboard (/horizon)",
        "body": """### Check Name
Exposed Laravel Horizon Queue Dashboard

### Category
DevOps & Monitoring

### Severity
HIGH

### Detection Logic
- Target path: `/horizon`
- Expected Status: `200`
- Matching pattern: `window.Horizon|<title>Laravel Horizon</title>`

### Description
Laravel Horizon dashboard is exposed anonymously, exposing queue jobs, failed payloads, user IDs, and background worker stats.

### Remediation
Define authorized user emails or IP restrictions in `HorizonServiceProvider.php` using `Horizon::auth()`.
""",
        "labels": ["good first issue", "help wanted", "security-check"],
    },
    {
        "title": "[NEW-CHECK]: Detect Exposed Terraform State File (/terraform.tfstate)",
        "body": """### Check Name
Exposed Terraform Infrastructure State

### Category
Environment & Secrets

### Severity
CRITICAL

### Detection Logic
- Target path: `/terraform.tfstate`
- Expected Status: `200`
- Matching pattern: `"terraform_version"|"resources"|"serial"`

### Description
A raw Terraform state file is accessible in the public web root. Terraform state files contain cleartext database passwords, cloud secret keys, and IAM credentials.

### Remediation
Remove all `.tfstate` files from web servers and migrate to a secure remote backend (AWS S3 with KMS or Terraform Cloud).
""",
        "labels": ["good first issue", "help wanted", "security-check"],
    },
    {
        "title": "[NEW-CHECK]: Detect Exposed Kubernetes Ingress Config (/kubeconfig)",
        "body": """### Check Name
Exposed Kubernetes Configuration File

### Category
DevOps & Infrastructure

### Severity
CRITICAL

### Detection Logic
- Target path: `/kubeconfig`
- Expected Status: `200`
- Matching pattern: `apiVersion: v1.*kind: Config|clusters:.*cluster:`

### Description
A Kubernetes kubeconfig file containing cluster API endpoints and bearer certificates is publicly downloadable.

### Remediation
Delete kubeconfig from the web root and revoke compromised client certificates on the Kubernetes API server.
""",
        "labels": ["good first issue", "help wanted", "security-check"],
    },
    {
        "title": "[NEW-CHECK]: Detect Exposed Apache Server Status (/server-status?auto)",
        "body": """### Check Name
Exposed Apache Mod_Status Diagnostic Page

### Category
Debug & Diagnostics

### Severity
MEDIUM

### Detection Logic
- Target path: `/server-status?auto`
- Expected Status: `200`
- Matching pattern: `Total Accesses:|CPUUsage:|Scoreboard:`

### Description
The Apache server status module discloses current client IP addresses, requested URLs, server uptime, and active worker threads.

### Remediation
Restrict access to `/server-status` using `Require local` or `Require ip 10.0.0.0/8` in your Apache configuration.
""",
        "labels": ["good first issue", "help wanted", "security-check"],
    },
    {
        "title": "[NEW-CHECK]: Detect Exposed Nginx Status Stub (/nginx_status)",
        "body": """### Check Name
Exposed Nginx Stub Status Page

### Category
Debug & Diagnostics

### Severity
LOW

### Detection Logic
- Target path: `/nginx_status`
- Expected Status: `200`
- Matching pattern: `Active connections:\\s*\\d+|server accepts handled requests`

### Description
Nginx status page discloses internal active connection metrics and load statistics without authentication.

### Remediation
Add `allow 127.0.0.1; deny all;` to the `location /nginx_status` block in Nginx.
""",
        "labels": ["good first issue", "help wanted", "security-check"],
    },
    {
        "title": "[NEW-CHECK]: Detect Exposed WordPress Database Backup (/wp-config.php.bak)",
        "body": """### Check Name
Exposed WordPress Configuration Backup File

### Category
Database Backups

### Severity
CRITICAL

### Detection Logic
- Target path: `/wp-config.php.bak`
- Expected Status: `200`
- Matching pattern: `DB_NAME.*DB_USER.*DB_PASSWORD|define\\('DB_`

### Description
A backup copy of wp-config.php is served as plaintext by the web server, disclosing MySQL credentials and secret salts.

### Remediation
Delete all editor backups (`*.bak`, `*.save`, `*~`, `*.swp`) from the web document root.
""",
        "labels": ["good first issue", "help wanted", "security-check"],
    },
    {
        "title": "[NEW-CHECK]: Detect Exposed Drupal Changelog & Version (/CHANGELOG.txt)",
        "body": """### Check Name
Drupal CMS Version Disclosure

### Category
CMS & Framework Specific

### Severity
LOW

### Detection Logic
- Target path: `/CHANGELOG.txt`
- Expected Status: `200`
- Matching pattern: `Drupal\\s+[0-9\\.]+,\\s+\\d{4}-\\d{2}-\\d{2}`

### Description
The Drupal CHANGELOG.txt file exposes the exact CMS version, helping attackers pinpoint version-specific CVEs.

### Remediation
Block access to text documentation files (`*.txt`, `*.md`) in production web server rules.
""",
        "labels": ["good first issue", "help wanted", "security-check"],
    },
    {
        "title": "[NEW-CHECK]: Detect Exposed Node.js NPM Debug Logs (/npm-debug.log)",
        "body": """### Check Name
Exposed NPM Installation Debug Log

### Category
Debug & Diagnostics

### Severity
LOW

### Detection Logic
- Target path: `/npm-debug.log`
- Expected Status: `200`
- Matching pattern: `info it worked if it ends with ok|verbose stack Error:`

### Description
NPM error logs disclose server absolute paths, Node runtime versions, and dependency installation errors.

### Remediation
Ensure `npm-debug.log*` is ignored in `.gitignore` and deleted from production builds.
""",
        "labels": ["good first issue", "help wanted", "security-check"],
    },
    {
        "title": "[NEW-CHECK]: Detect Exposed PHP Composer Lock File (/composer.lock)",
        "body": """### Check Name
Exposed PHP Composer Lock File

### Category
Framework Diagnostics

### Severity
LOW

### Detection Logic
- Target path: `/composer.lock`
- Expected Status: `200`
- Matching pattern: `"packages":\\s*\\[|"packages-dev":\\s*\\[|"hash":`

### Description
Exposes exact versions of all installed PHP packages and vendor libraries, simplifying vulnerability discovery.

### Remediation
Block public access to `composer.json` and `composer.lock` via web server configuration.
""",
        "labels": ["good first issue", "help wanted", "security-check"],
    },
    {
        "title": "[NEW-CHECK]: Detect Dangling DNS & Subdomain Takeover on AWS S3",
        "body": """### Check Name
AWS S3 Dangling Subdomain Takeover

### Category
DNS & Infrastructure

### Severity
HIGH

### Detection Logic
- Check CNAME records pointing to `.s3.amazonaws.com`
- Probe endpoint for AWS error response: `<Code>NoSuchBucket</Code>`

### Description
The domain has a CNAME pointing to an AWS S3 bucket that has been deleted or unclaimed, allowing attackers to claim the bucket and hijack the domain.

### Remediation
Delete the dangling CNAME DNS record or recreate the target S3 bucket in your AWS account.
""",
        "labels": ["help wanted", "security-check"],
    },
    {
        "title": "[NEW-CHECK]: Detect Dangling DNS & Subdomain Takeover on GitHub Pages",
        "body": """### Check Name
GitHub Pages Subdomain Takeover

### Category
DNS & Infrastructure

### Severity
HIGH

### Detection Logic
- Check CNAME records pointing to `.github.io`
- Probe endpoint for error: `There isn't a GitHub Pages site here.`

### Description
A CNAME record points to GitHub Pages, but no corresponding repository or custom domain is configured, allowing an attacker to host malicious content.

### Remediation
Remove the CNAME DNS record or claim the custom domain on your GitHub Pages repository.
""",
        "labels": ["help wanted", "security-check"],
    },
    {
        "title": "[NEW-CHECK]: Detect Unauthenticated GraphQL Introspection (/graphql)",
        "body": """### Check Name
GraphQL Schema Introspection Enabled

### Category
API Security

### Severity
MEDIUM

### Detection Logic
- Send POST to `/graphql` with payload `{"query": "{ __schema { types { name } } }"}`
- Check response contains `"data": { "__schema": { "types":`

### Description
GraphQL introspection is enabled in production, disclosing the entire data graph, private queries, mutations, and object fields.

### Remediation
Disable introspection in production GraphQL servers (e.g., Apollo Server `introspection: false`).
""",
        "labels": ["help wanted", "security-check"],
    },
    {
        "title": "[NEW-CHECK]: Detect Unprotected Spring Boot Jolokia Actuator (/actuator/jolokia)",
        "body": """### Check Name
Spring Boot Jolokia JMX Endpoint Exposed

### Category
Framework Endpoints

### Severity
CRITICAL

### Detection Logic
- Target path: `/actuator/jolokia` or `/jolokia`
- Expected Status: `200`
- Matching pattern: `"status":200.*"request":.*"type":"version"`

### Description
Jolokia JMX bridge allows remote JMX operations, often leading to Remote Code Execution (RCE) via MBean manipulation.

### Remediation
Disable Jolokia actuator endpoint or enforce strong mutual TLS / Spring Security authentication.
""",
        "labels": ["help wanted", "security-check"],
    },
    {
        "title": "[FEATURE]: Implement SARIF Export Format for GitHub Code Scanning",
        "body": """### Motivation
Modern DevSecOps teams use GitHub Code Scanning tab to track security findings across pull requests.

### Proposal
Add `--output-sarif results.sarif` flag to AegisScan.
SARIF (Static Analysis Results Interchange Format) allows GitHub Actions to automatically highlight findings inline in pull requests!

### Tasks
- [ ] Create `aegisscan/reporters/sarif_report.py`
- [ ] Map `Severity` to SARIF severity levels
- [ ] Add CLI flag `--output-sarif`
- [ ] Add unit test in `tests/test_reporters.py`
""",
        "labels": ["enhancement", "help wanted"],
    },
    {
        "title": "[FEATURE]: Add Slack and Discord Webhook Alerts for CI/CD",
        "body": """### Motivation
Security engineers want automated alerts in Slack/Discord channels when a scan finds CRITICAL or HIGH vulnerabilities.

### Proposal
Add `--webhook <URL>` option to send a concise JSON card summary to Slack or Discord webhook endpoints.

### Tasks
- [ ] Add `--webhook` argument to `cli.py`
- [ ] Create payload formatter for Slack and Discord webhooks
- [ ] Test webhook delivery with timeout handling
""",
        "labels": ["enhancement", "help wanted"],
    },
    {
        "title": "[FEATURE]: Add Multi-Target Scanning from Text File (-l targets.txt)",
        "body": """### Motivation
Bug bounty hunters and sysadmins often need to audit multiple domain assets at once.

### Proposal
Support passing a target list via `aegisscan -l targets.txt --concurrency 5`.

### Tasks
- [ ] Add `-l / --list` parameter
- [ ] Asynchronously process targets in queue
- [ ] Aggregate summary table
""",
        "labels": ["enhancement", "help wanted"],
    },
    {
        "title": "[FEATURE]: Add Web Application Firewall (WAF) Detection Module",
        "body": """### Motivation
Knowing what WAF is guarding an asset helps security researchers tailor audit payloads and identify edge proxies.

### Proposal
Create `aegisscan/modules/waf.py` that fingerprints:
- Cloudflare
- AWS WAF
- Akamai
- Imperva / Incapsula
- ModSecurity / NAXSI

### Tasks
- [ ] Inspect headers: `CF-RAY`, `X-Amz-Cf-Id`, `Server: cloudflare`, `X-CDN`
- [ ] Report identified WAF in summary card
""",
        "labels": ["enhancement", "help wanted"],
    },
    {
        "title": "[FEATURE]: Add Technology Stack & CMS Fingerprinter Module",
        "body": """### Motivation
Detecting WordPress, Laravel, Django, Next.js, or Drupal helps prioritize security checks.

### Proposal
Create `aegisscan/modules/fingerprint.py` to identify web framework and CMS from cookies (`XSRF-TOKEN`, `csrftoken`, `PHPSESSID`), HTML meta tags, and header footprints.
""",
        "labels": ["enhancement", "help wanted"],
    },
]


def seed_issues(repo: str, token: str) -> None:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "AegisScan-Issue-Seeder",
    }
    api_url = f"https://api.github.com/repos/{repo}/issues"

    print(f"[*] Starting to seed {len(ROADMAP_ISSUES)} issues to {repo}...")
    created = 0

    with httpx.Client(headers=headers, timeout=15.0) as client:
        for idx, item in enumerate(ROADMAP_ISSUES, 1):
            payload = {
                "title": item["title"],
                "body": item["body"],
                "labels": item["labels"],
            }
            try:
                resp = client.post(api_url, json=payload)
                if resp.status_code in [200, 201]:
                    issue_num = resp.json().get("number")
                    print(f"[{idx}/{len(ROADMAP_ISSUES)}] ✔ Created Issue #{issue_num}: {item['title'][:50]}...")
                    created += 1
                else:
                    print(f"[{idx}/{len(ROADMAP_ISSUES)}] ❌ Failed ({resp.status_code}): {resp.text[:100]}")
            except Exception as e:
                print(f"[{idx}/{len(ROADMAP_ISSUES)}] ❌ Error: {e}")

            # Sleep briefly to respect GitHub secondary rate limits
            time.sleep(1.5)

    print(f"\n[✔] Completed! Successfully created {created}/{len(ROADMAP_ISSUES)} issues in {repo}.")


if __name__ == "__main__":
    repo = os.getenv("REPO_NAME", "RobsHs/AegisScan")
    token = os.getenv("GITHUB_TOKEN")

    if not token and len(sys.argv) > 1:
        token = sys.argv[1]

    if not token:
        print("[!] GITHUB_TOKEN environment variable or argument is required.")
        print("Usage: python scripts/seed_issues.py <GITHUB_TOKEN>")
        sys.exit(1)

    seed_issues(repo, token)
