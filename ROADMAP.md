# 🗺️ AegisScan Community Roadmap & Contribution Wishlist

Welcome to the **AegisScan Roadmap**! This document outlines planned features, audit modules, and detection signatures.

If you are looking to contribute, feel free to **claim any task below** by opening an issue using our [Propose New Security Check Template](https://github.com/RobsHs/AegisScan/issues/new?template=03_new_security_check.yml) and submitting a Pull Request!

---

## 🏷️ Contribution Labels Guide

- `[good first issue]`: Suitable for beginners or first-time open-source contributors (typically 1 signature file in `signatures/`).
- `[help wanted]`: Medium complexity; involves expanding core audit modules or adding new protocol checks.
- `[hacktoberfest]`: Active tasks eligible for community recognition and Hacktoberfest participation.

---

## 🎯 Phase 1: Community Signatures (Quick PRs - Good First Issues)

These checks can be implemented by simply adding a new `.json` rule to the [`signatures/`](signatures/) directory:

- [ ] `[good first issue]` **Laravel Horizon Dashboard** (`/horizon`) - Detect unauthenticated queue monitoring.
- [ ] `[good first issue]` **Symfony Profiler** (`/_profiler/phpinfo`) - Detect exposed debugging profiler.
- [ ] `[good first issue]` **Django Debug Toolbar** - Detect active `DEBUG=True` stack trace exposures.
- [ ] `[good first issue]` **Ruby on Rails Web Console** (`/console`) - Detect interactive Rails web consoles.
- [ ] `[good first issue]` **GitLab Secrets & Pipelines** (`/.gitlab-ci.yml`) - Detect exposed CI/CD configurations.
- [ ] `[good first issue]` **Travis CI Config** (`/.travis.yml`) - Detect exposed deployment keys.
- [ ] `[good first issue]` **Terraform State Files** (`/terraform.tfstate`) - Detect leaked cloud infrastructure secrets and credentials.
- [ ] `[good first issue]` **Kubernetes Ingress Secrets** (`/kubeconfig`) - Detect cluster credential leaks.
- [ ] `[good first issue]` **Elasticsearch Unauthenticated Nodes** (`:9200/_cat/indices`) - Detect unprotected cluster indices.
- [ ] `[good first issue]` **Redis Unauthenticated CLI** (`:6379`) - Detect exposed caching servers.
- [ ] `[good first issue]` **MongoDB HTTP Status** (`:28017`) - Detect legacy diagnostic web consoles.
- [ ] `[good first issue]` **WordPress Configuration Backup** (`/wp-config.php~`, `/wp-config.php.save`) - Detect database password leaks.
- [ ] `[good first issue]` **Drupal Changelog & Status** (`/CHANGELOG.txt`) - Detect outdated CMS core versions.
- [ ] `[good first issue]` **Joomla Configuration Backup** (`/configuration.php.bak`).
- [ ] `[good first issue]` **Apache Server Status** (`/server-status?auto`) - Detect exposed traffic metrics and client IPs.
- [ ] `[good first issue]` **Nginx Status Stub** (`/nginx_status`) - Detect internal active connection counts.
- [ ] `[good first issue]` **cPanel Diagnostic Logs** (`/cpanel_access_log`).
- [ ] `[good first issue]` **AWS S3 Bucket Takeover Heuristic** - Check if custom CNAME points to deleted S3 bucket.
- [ ] `[good first issue]` **Node.js Package Lock** (`/package-lock.json`, `/npm-debug.log`) - Detect dependency trees and versions.
- [ ] `[good first issue]` **Composer Lock File** (`/composer.lock`) - Detect PHP package versions.

---

## 🛡️ Phase 2: Advanced Core Audit Modules

These features require Python changes in `aegisscan/modules/`:

- [ ] `[help wanted]` **Subdomain Takeover Detector** (`aegisscan/modules/subdomain_takeover.py`)
  - Check CNAME records for dangling services (GitHub Pages, AWS S3, Heroku, Azure, Cloudfront).
- [ ] `[help wanted]` **HTTP Request Smuggling Probe** (`aegisscan/modules/smuggling.py`)
  - Heuristic detection for TE.CL / CL.TE desync misconfigurations.
- [ ] `[help wanted]` **GraphQL Introspection & Batching Audit** (`aegisscan/modules/graphql.py`)
  - Probe `/graphql` for enabled schema introspection and unthrottled batch query vulnerabilities.
- [ ] `[help wanted]` **WebSocket Security (WSS) Analyzer** (`aegisscan/modules/websocket.py`)
  - Test origin header validation for cross-site WebSocket hijacking (CSWSH).
- [ ] `[help wanted]` **Web Application Firewall (WAF) Fingerprinting** (`aegisscan/modules/waf.py`)
  - Detect Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity.
- [ ] `[help wanted]` **Technology Stack Fingerprinter** (`aegisscan/modules/tech_stack.py`)
  - Identify front-end frameworks (Next.js, Vue, Nuxt) and back-ends from unique DOM/header signatures.

---

## 📊 Phase 3: Reporting & DevOps Enhancements

- [ ] `[help wanted]` **SARIF Output Format** (`--output-sarif results.sarif`)
  - Native integration with GitHub Code Scanning alerts tab.
- [ ] `[help wanted]` **PDF Report Generation**
  - Export printable audit reports via headless browser or WeasyPrint.
- [ ] `[help wanted]` **Slack & Discord Webhook Alerts** (`--webhook <url>`)
  - Send instant executive summary alerts upon vulnerability discovery in CI/CD pipelines.
- [ ] `[help wanted]` **Multi-Target Bulk Scanning** (`-l targets.txt`)
  - Scan lists of domains concurrently with worker pools.

---

## 💡 Proposing a New Idea?

Have an idea that isn't listed here? Open a [Feature Request](https://github.com/RobsHs/AegisScan/issues/new?template=02_feature_request.yml) or start a discussion!
