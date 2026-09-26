ifeq ($(OS),Windows_NT)
SHELL := bash.exe
else
SHELL := /bin/bash
endif
.SHELLFLAGS := -eu -o pipefail -c

PY ?= python
GO ?= go
SCENARIO ?= all
DURATION ?= 400
SPEED ?= 30
API ?= http://127.0.0.1:8000

.DEFAULT_GOAL := help
.PHONY: help demo api ui bench bench-rules bench-realtime test train scenarios verify train-candidate audit-data capture-local native-check gateway-check stack-check prepare-deployment

help:
	@echo "make demo             start the api and open the dashboard"
	@echo "make bench            throughput and latency, rules plus model, constraint C-d"
	@echo "make bench-rules      the same run with the model layer off, the ablation"
	@echo "make bench-realtime   the same corpus at true wire timing, $(SPEED)x speed"
	@echo "make train            rebuild the dataset and retrain tier 1"
	@echo "make test             the whole test suite"
	@echo "make scenarios        regenerate the eleven scenario captures"
	@echo "make verify           check the alert ledger hash chain, once a demo has written one"
	@echo ""
	@echo "vars: SCENARIO=$(SCENARIO) DURATION=$(DURATION) SPEED=$(SPEED) PY=$(PY)"
	@echo "the measured numbers and the exact commands are in bench/RESULTS.md"
	@echo "on windows there is no gnu make, run mingw32-make instead of make"

demo:
	@echo "starting the api on $(API)"
	@$(PY) -m api.main > api.log 2>&1 & echo $$! > .demo.pid
	@for i in $$(seq 60); do curl -sf -o /dev/null $(API)/api/status && break || sleep 0.5; done
	@curl -sf -o /dev/null $(API)/api/status || { echo "the api did not come up, see api.log"; exit 1; }
	@echo "api is up, opening the dashboard"
	@cd ui && npx vite --open || true
	@kill $$(cat .demo.pid) 2>/dev/null || true
	@rm -f .demo.pid

api:
	$(PY) -m api.main

ui:
	cd ui && npx vite --open

bench:
	$(PY) bench/throughput.py --scenario $(SCENARIO) --duration $(DURATION) --bucket 0.5 --warmup 2

bench-rules:
	$(PY) bench/throughput.py --scenario $(SCENARIO) --duration $(DURATION) --bucket 0.5 --warmup 2 --rules-only

bench-realtime:
	$(PY) bench/throughput.py --scenario $(SCENARIO) --mode realtime --speed $(SPEED) \
	  --duration $(DURATION) --bucket 0.5 --warmup 2

test:
	$(PY) -m pytest -q tests

train:
	$(PY) training/build_dataset.py
	$(PY) training/train_tier1.py

train-candidate:
	$(PY) -m api.training_jobs

audit-data:
	$(PY) -m training.inventory

capture-local:
	$(PY) -m tools.capture_loopback

native-check:
	cargo test --offline --manifest-path native/pcap-audit/Cargo.toml
	cargo build --offline --release --manifest-path native/pcap-audit/Cargo.toml

gateway-check:
	cd gateway && $(GO) test -race ./... && $(GO) vet ./... && $(GO) build -trimpath -o sih-gateway .

stack-check:
	SIH_STACK_TEST=1 SIH_BROWSER_TEST=1 $(PY) -m pytest -q tests/test_stack_integration.py -s --tb=short

prepare-deployment:
	$(PY) -m tools.prepare_deployment .runtime

scenarios:
	$(PY) training/generate_scenarios.py

verify:
	$(PY) -m engine.alerts.verify data/alerts.jsonl
