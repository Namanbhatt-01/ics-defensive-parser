# ICS Compliance Auditor Makefile

.PHONY: run test lint security docker-build docker-run clean help

# Default rule displays help options
help:
	@echo "================================================================="
	@echo "        ICS MULTI-PROTOCOL COMPLIANCE AUDITOR COMMANDS           "
	@echo "================================================================="
	@echo "Available Make rules:"
	@echo "  make run          - Execute the passive log auditing engine locally"
	@echo "  make test         - Run the automated unit test validation suite"
	@echo "  make lint         - Scan source directory using flake8 formatting checks"
	@echo "  make security     - Audit code structures for vulnerabilities using Bandit"
	@echo "  make docker-build - Compile the Docker container image"
	@echo "  make docker-run   - Run the auditor inside an isolated Docker container"
	@echo "  make clean        - Remove python compilation bytecodes and caches"
	@echo "================================================================="

run:
	python3 ics_defensive_parser/main.py

test:
	python3 tests/run_compliance_tests.py

lint:
	flake8 ics_defensive_parser tests --count --select=E9,F63,F7,F82 --show-source --statistics
	flake8 ics_defensive_parser tests --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

security:
	bandit -r ics_defensive_parser/ tests/ -ll -ii

docker-build:
	docker build -t ics-auditor ./ics_defensive_parser

docker-run:
	docker run --rm ics-auditor

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
