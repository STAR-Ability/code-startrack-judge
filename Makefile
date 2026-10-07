PYTHON ?= python3

.PHONY: help check bootstrap infra-up infra-down db-version migration-status upstream-fetch upstream-verify sandbox-preflight

help:
	@printf '%s\n' 'bootstrap        Check tools and create a private local .env' 'infra-up         Start PostgreSQL and wait for its health check' 'infra-down       Stop development infrastructure; retain database volume' 'db-version       Show the running PostgreSQL server version' 'migration-status Report repository migration level (Phase 0: no SQL)' 'upstream-fetch   Fetch exact locked upstream commits without executing them' 'upstream-verify  Verify cached commits and license evidence offline' 'check            Validate repository foundation' 'sandbox-preflight Check Linux prerequisites; does not certify isolation'

check:
	$(PYTHON) scripts/check-foundation.py

bootstrap:
	$(PYTHON) scripts/bootstrap.py bootstrap

infra-up:
	$(PYTHON) scripts/bootstrap.py up

infra-down:
	$(PYTHON) scripts/bootstrap.py down

db-version:
	$(PYTHON) scripts/bootstrap.py db-version

migration-status:
	$(PYTHON) scripts/bootstrap.py migration-status

upstream-fetch:
	$(PYTHON) scripts/upstream.py fetch

upstream-verify:
	$(PYTHON) scripts/upstream.py verify

sandbox-preflight:
	bash scripts/sandbox-preflight.sh
