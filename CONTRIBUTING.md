# Contributing to AegisScan

Thank you for your interest in contributing to **AegisScan**! We welcome contributions from developers, cybersecurity researchers, and community enthusiasts.

## How to Contribute

### 1. Reporting Bugs
- Search existing issues to ensure the bug hasn't already been reported.
- Open a new issue with a clear title, environment details (OS, Python version), steps to reproduce, and actual vs expected behavior.

### 2. Suggesting Enhancements & New Modules
- We love new audit modules! Ideas:
  - Subdomain takeover detection
  - HTTP request smuggling heuristics
  - Specific cloud bucket exposure checks
- Open an issue describing your proposed feature and how it benefits the security community.

### 3. Submitting Pull Requests
1. Fork the repository on GitHub.
2. Clone your fork locally:
   ```bash
   git clone https://github.com/RobsHs/AegisScan.git
   cd AegisScan
   ```
3. Create a descriptive feature branch:
   ```bash
   git checkout -b feat/new-audit-module
   ```
4. Install editable development mode:
   ```bash
   pip install -e .
   ```
5. Write your code and add corresponding unit tests in `tests/`.
6. Run tests to ensure everything passes:
   ```bash
   python -m unittest discover tests
   ```
7. Commit your changes using semantic commits:
   ```bash
   git commit -m "feat(modules): add GraphQL introspection security check"
   ```
8. Push to your branch and submit a Pull Request!

## Code Style & Ethics
- Write clean, type-annotated Python 3.9+ code.
- Keep defensive and audit tools safe, ethical, and aligned with standard security research practices.
