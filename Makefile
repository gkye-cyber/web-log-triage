VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest
CLI := $(PYTHON) -m web-log-triage

.PHONY: help install test run html json clean

help:
	@echo "Available commands:"
	@echo "  make install  - Create .venv and install all dependencies in editable mode"
	@echo "  make test     -  Run test suite with pytest"
	@echo "  make run      -  Run CLI console summary on sample log"
	@echo "  make html     -  Generate HTML forensic report"
	@echo "  make json     -  Generate JSON forensic report"
	@echo "  make clean    -  Remove virtualenv, caches, and report files"

install:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	$(PIP) install -e .

test:
	$(PYTEST)

run:
	$(CLI) sample_data/access_sample.log

html:
	$(CLI) sample_data/access_sample.log --format html --output report.html
	@echo "[+] Generated report.html"

json:
	$(CLI) sample_data/access_sample.log --format json --output report.json
	@echo "[+] Generated report.json"

clean:
	rm -rf $(VENV) .pytest_cache dist/ src/*.egg-info report.html report.json