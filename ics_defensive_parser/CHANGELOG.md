# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-06-19
### Added
- Created a fourth protocol parser supporting **IEC 60870-5-104 (IEC 104)**.
- Added automated zone-based unit testing suite in `tests/run_compliance_tests.py`.
- Integrated `.github/workflows/test.yml` for automated CI build, linting, and Bandit security scans.
- Added standard issue templates for bug reporting and feature requests.
- Integrated a `Dockerfile` to support containerized runs.
- Added static code validations and sanitizations (IPv4, hex check rules) in `main.py`.

### Changed
- Refactored folder architecture, separating parsers and tests.
- Rewrote the main engine parser flow in `main.py` to support dynamic multi-protocol log routing.

## [1.0.0] - 2026-06-19
### Added
- Initial release containing passive Modbus TCP and DNP3 log parsers.
- Implemented declarative compliance baseline mapping guidelines matching **CII Sec 6** constraints.
- Integrated persistent reporting logs generation (`audit_report.txt`).
