# 🔍 AegisScan Community Signatures

Welcome to the **AegisScan Community Signature Repository**!

This directory allows anyone in the cybersecurity community to contribute new vulnerability checks and sensitive path exposure rules **without touching the core Python codebase**.

---

## 🎯 How to Add a New Signature (1 File = 1 Pull Request!)

Adding a new check takes under 2 minutes:

1. **Create a new `.json` file** in this `signatures/` directory (e.g. `signatures/my_vulnerability_check.json`).
2. **Use the following JSON schema**:

```json
{
  "id": "SIG-UNIQUE-ID",
  "name": "Human readable name of the check",
  "path": "/path-to-test",
  "category": "One of: Environment & Secrets, Version Control, Framework Endpoints, DevOps & Monitoring, Database Backups, Cryptographic Keys, Debug & Diagnostics",
  "severity": "CRITICAL, HIGH, MEDIUM, LOW, or INFO",
  "pattern": "Regular expression that uniquely identifies positive vulnerability content (prevents false positives)",
  "title": "Title of the vulnerability finding",
  "description": "Clear explanation of what is exposed or vulnerable",
  "remediation": "Concrete mitigation or configuration fix for developers"
}
```

3. **Verify locally**:
   ```bash
   python -m unittest discover tests
   ```
4. **Submit your Pull Request** on GitHub! We review and merge community signatures promptly.
