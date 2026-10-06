# Developer and demo commands. See CONTRIBUTING.md.
#   make install   create .venv with hhc-report and dev tools
#   make test      Lua unit + reporter + integration tests
#   make demo      Docker lab: start, scan, render reports into lab/docker/out/

PYTHON  ?= python3
VENV    := .venv
BIN     := $(VENV)/bin
LUA     ?= $(shell command -v lua5.4 || command -v lua)
LUACHECK ?= luacheck
COMPOSE := docker compose -f lab/docker/docker-compose.yml
export HHC_UID := $(shell id -u)
export HHC_GID := $(shell id -g)

.PHONY: install lint lint-lua lint-python unit reporter-test integration stress test check \
        lab-up scan report lab-down demo clean

install: $(BIN)/hhc-report

$(BIN)/hhc-report: reporter/pyproject.toml
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --quiet --upgrade pip
	$(BIN)/pip install --quiet -e "reporter[dev]"

lint: lint-lua lint-python

lint-lua:
	$(LUACHECK) http-hardening-check.nse tests/unit

lint-python: install
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .
	$(BIN)/mypy reporter/src

unit:
	$(LUA) tests/unit/test_engine.lua

reporter-test: install
	cd reporter && ../$(BIN)/pytest -q

integration: install
	$(BIN)/pytest -q tests/integration tests/test_action_and_policies.py

stress: install
	$(BIN)/pytest -q tests/stress

test: unit reporter-test integration

check: lint test stress

lab-up:
	$(COMPOSE) up -d --build --wait

scan:
	$(COMPOSE) run --rm --build scanner

report:
	$(COMPOSE) run --rm --build scanner report

lab-down:
	$(COMPOSE) down --remove-orphans

demo: lab-up scan
	@echo "Reports: lab/docker/out/report.{html,json,csv,md,sarif}"

clean:
	rm -rf $(VENV) reporter/build reporter/dist reporter/src/*.egg-info .pytest_cache reporter/.pytest_cache \
	       .mypy_cache .ruff_cache
	find lab/docker/out -type f ! -name .gitignore -delete
