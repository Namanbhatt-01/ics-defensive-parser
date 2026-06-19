# Contributing to ICS Compliance Auditor

Thank you for contributing to the ICS Compliance Auditor! We value your help in strengthening Critical Information Infrastructure (CII) defense tools.

## Code of Conduct

By participating in this project, you agree to maintain a professional, secure, and respectful environment.

## How to Contribute

### 1. Propose Changes
* For bug fixes or minor parser logic updates, please open an issue first to discuss the context.
* For adding new protocol parsers (e.g. S7Comm, BACnet, Profinet), describe the target CII guidelines mapping in your proposal.

### 2. Set Up Development Environment
* Clone the repository.
* Write clean, PEP 8 compliant Python 3 code.
* Keep the tool dependent on the **Python Standard Library only** (no external pip packages) to preserve zero-trust integrity and avoid supply-chain vulnerability vectors.

### 3. Running Tests
Before opening a pull request, run the test runner to ensure all compliance checks pass:
```bash
python3 tests/run_compliance_tests.py
```

### 4. Commit Guidelines
* Write meaningful, declarative git commit messages.
* Example: `feat: add support for BACnet telemetry logs validation`
