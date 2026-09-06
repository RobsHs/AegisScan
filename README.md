<div align="center">

# 🛡️ AegisScan

**Modern, Blazingly Fast Web Security Posture & Sensitive Exposure Audit Tool**

[![CI](https://github.com/RobsHs/AegisScan/actions/workflows/ci.yml/badge.svg)](https://github.com/RobsHs/AegisScan/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![OWASP](https://img.shields.io/badge/Compliance-OWASP%20Top%2010-orange.svg)](https://owasp.org/)
[![Code style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

<p align="center">
  <a href="#-key-features">Key Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-ci-cd-integration">DevSecOps & CI/CD</a> •
  <a href="#-html-executive-report">Reports</a> •
  <a href="#-contributing">Contributing</a>
</p>

```
     _    _____ ____ ___ ____  ____   ____    _    _   _
    / \  | ____/ ___|_ _/ ___|/ ___| / ___|  / \  | \ | |
   / _ \ |  _|| |  _ | |\___ \\___ \| |     / _ \ |  \| |
  / ___ \| |__| |_| || | ___) |___) | |___ / ___ \| |\  |
 /_/   \_\_____\____|___|____/|____/ \____//_/   \_\_| \_|
  Modern Web Security Posture & Exposure Audit Tool v1.0.0
```

</div>

---

## 📖 Overview

**AegisScan** is a modern, lightweight, and asynchronous cybersecurity auditing tool engineered for developers, sysadmins, DevOps engineers, and bug bounty hunters.

Modern applications frequently suffer from missing defense-in-depth security headers, exposed `.env` or `.git` repositories, weak cookie configurations, unmanaged TLS expirations, and missing anti-spoofing email records (SPF/DMARC). **AegisScan** audits all these attack vectors in seconds, computing an executive **Security Grade (A+ to F)** and generating actionable remediation guides.

---

## ✨ Key Features

| Capability                       | Description                                                                                                                                                                                                                       |
| :------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **⚡ Asynchronous Core**         | Concurrently checks headers, SSL/TLS, DNS records, and exposures in parallel (< 3 seconds total runtime).                                                                                                                         |
| **🛡️ OWASP Secure Headers**      | Evaluates CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy with remediation guidance.                                                                                                  |
| **🍪 Cookie Flag Inspector**     | Audits session tokens for missing `Secure`, `HttpOnly`, and `SameSite` flags, plus cookie prefixes (`__Host-`, `__Secure-`).                                                                                                      |
| **🔍 Sensitive Exposure Hunter** | Scans for exposed `.env`, `.git/HEAD`, AWS credentials, Dockerfiles, database backups (`.sql`, `.sqlite3`), and debug endpoints (`phpinfo`, Spring Actuators) with **smart signature verification** to eliminate false positives. |
| **🔒 SSL/TLS Health Analysis**   | Inspects certificate expiration, issuer, legacy protocols (TLS 1.0/1.1), and self-signed certificate alerts.                                                                                                                      |
| **📧 DNS & Email Defense**       | Validates SPF (`v=spf1`), DMARC (`p=reject`/`p=quarantine`/`p=none`), and MX records to prevent domain spoofing and spear-phishing.                                                                                               |
| **🌐 CORS Misconfiguration**     | Detects dangerous origin reflection and credential exposure (CWE-942).                                                                                                                                                            |
| **📊 Multi-Format Reporting**    | Gorgeous terminal output (via Rich), structured JSON for pipelines, and interactive standalone HTML dashboards.                                                                                                                   |
| **🚦 DevSecOps Gatekeeper**      | Native `--fail-on <severity>` flag to automatically fail CI/CD build pipelines if security vulnerabilities are found.                                                                                                             |

---

## 🚀 Installation

### Using pip (from GitHub)

```bash
pip install git+https://github.com/RobsHs/AegisScan.git
```

### From Source (Development Mode)

```bash
# Clone the repository
git clone https://github.com/RobsHs/AegisScan.git
cd AegisScan

# Install in editable mode
pip install -e .
```

---

## 💻 Quick Start

### 1. Basic Scan

Scan a target website or API:

```bash
aegisscan https://example.com
```

### 2. Generate Interactive HTML & JSON Reports

Generate an executive dark-mode HTML report and machine-readable JSON:

```bash
aegisscan https://example.com -o security-report.html -j security-report.json
```

### 3. Fail on High Severity in CI/CD

Block builds if any **HIGH** or **CRITICAL** issues exist:

```bash
aegisscan https://staging.mycompany.com --fail-on high
```

### 4. Fast Scan (Skip DNS or Exposure)

For internal host testing where DNS records or exposure checks are not applicable:

```bash
aegisscan https://10.0.0.15:8443 --skip-dns
```

---

## 📊 HTML Executive Report

AegisScan generates standalone, interactive, dark-themed HTML security reports requiring zero external dependencies:

- **Security Posture Grade & Metric Cards** (Score / 100, Critical, High, Med, Low)
- **Filterable & Searchable Vulnerability Cards** with impact descriptions and copyable remediation code
- **Interactive Checklists** for HTTP Security Headers and Exposed Paths
- **Print & Share Ready** for executive briefings or audit documentation

```bash
aegisscan https://target.com -o report.html
# Open in your browser:
start report.html   # Windows
open report.html    # macOS
xdg-open report.html # Linux
```

---

## 🔄 DevSecOps & CI/CD Integration

Integrate AegisScan into your **GitHub Actions** workflow to catch security regressions before deploying to production:

```yaml
# .github/workflows/security-scan.yml
name: Web Security Audit

on:
  push:
    branches: [main]
  schedule:
    - cron: "0 0 * * 1" # Weekly scan

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install AegisScan
        run: pip install git+https://github.com/RobsHs/AegisScan.git

      - name: Run AegisScan Security Gate
        run: |
          aegisscan https://staging.example.com \
            --output-html report.html \
            --output-json report.json \
            --fail-on high

      - name: Upload Security Report Artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: aegisscan-report
          path: report.html
```

---

## 🛠️ CLI Reference

```
usage: aegisscan [-h] [-u TARGET_FLAG] [-o FILE] [-j FILE]
                 [--fail-on {critical,high,medium,low}] [--timeout TIMEOUT]
                 [--concurrency CONCURRENCY] [--skip-exposure] [--skip-dns]
                 [-q] [-v]
                 [target]

AegisScan - Modern Web Security Posture & Sensitive Exposure Audit Tool

positional arguments:
  target                Target URL or domain to audit (e.g. https://example.com)

options:
  -h, --help            Show this help message and exit
  -u, --url TARGET_FLAG Target URL (alternative to positional argument)
  -o, --output-html FILE
                        Path to save modern interactive HTML security report
  -j, --output-json FILE
                        Path to export raw structured JSON findings for CI/CD
  --fail-on {critical,high,medium,low}
                        Fail with exit code 1 if findings meet or exceed severity
  --timeout TIMEOUT     Request timeout in seconds (default: 8.0)
  --concurrency CONCURRENCY
                        Max concurrent asynchronous exposure checks (default: 10)
  --skip-exposure       Skip sensitive file and directory exposure scanning
  --skip-dns            Skip DNS, SPF, and DMARC inspection
  -q, --quiet           Suppress terminal UI dashboard output
  -v, --version         Show program's version number and exit
```

---

## 🧪 Running Tests

To run the automated test suite locally:

```bash
python -m unittest discover -s tests -v
```

All 13 unit tests test models, header audits, cookie security, exposure signature verification, and report generators.

---

## 🤝 Contributing

Contributions are warmly welcomed! Please read our [Contributing Guide](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).

1. Fork the repo (`https://github.com/RobsHs/AegisScan/fork`)
2. Create your feature branch (`git checkout -b feat/amazing-feature`)
3. Commit your changes (`git commit -m "feat: add Subdomain Takeover checker"`)
4. Push to the branch (`git push origin feat/amazing-feature`)
5. Open a Pull Request

---

## ⚖️ License & Ethical Use

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.

> **Disclaimer**: AegisScan is developed for authorized defense, security auditing, and educational research. Always obtain authorization before scanning networks or web assets you do not own.

---

<div align="center">

Crafted with dedication by **[RobsHs](https://github.com/RobsHs)** &bull; Open Source Cybersecurity Community

⭐ If you find AegisScan useful, please consider giving it a star on GitHub! ⭐

</div>
