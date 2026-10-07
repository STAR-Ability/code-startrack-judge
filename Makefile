PYTHON ?= python3
GO := .local/toolchains/go1.26.8/go/bin/go
export GOTOOLCHAIN := local

.PHONY: help check native-check toolchain contract-test-setup build run bootstrap infra-up infra-down db-version migration-status migration-up database-status upstream-fetch upstream-verify upstream-patch-check sandbox-preflight

help:
	@printf '%s\n' 'bootstrap        Check tools and create a private local .env' 'toolchain        Install the exact checksum-verified Go SDK' 'contract-test-setup Install hash-locked schema test dependencies' 'check            Run foundation, contract and native checks' 'build            Build service and forward migration binaries' 'run              Start the configured API service' 'infra-up         Start development PostgreSQL' 'infra-down       Stop infrastructure; retain its database volume' 'db-version       Show the running PostgreSQL server version' 'migration-status Report available repository migration files' 'database-status  Verify applied migration state and checksums' 'migration-up     Apply pending forward migrations with the owner role' 'upstream-fetch   Fetch exact locked upstream commits' 'upstream-verify  Verify cached commits and legal evidence' 'upstream-patch-check Verify patch provenance and exclusions' 'sandbox-preflight Check Linux prerequisites; does not certify isolation'

check:
	$(PYTHON) scripts/check-foundation.py
	$(PYTHON) scripts/check-native.py

native-check:
	$(PYTHON) scripts/check-native.py

toolchain:
	$(PYTHON) scripts/toolchain.py install

contract-test-setup:
	$(PYTHON) -m venv .local/contract-schema-tests
	.local/contract-schema-tests/bin/python -m pip install --require-hashes --only-binary=:all: -r scripts/requirements-contract-tests.txt

build:
	$(PYTHON) scripts/toolchain.py verify
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -o build/judge-service ./cmd/judge-service
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -o build/judge-migrate ./cmd/judge-migrate
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -o build/judge-admin ./cmd/judge-admin
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -o build/judge-outbox ./cmd/judge-outbox
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -o build/startrack-judger ./cmd/startrack-judger
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -o build/startrack-runtime-init ./cmd/startrack-runtime-init
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -o build/startrack-runtime-matrix ./cmd/startrack-runtime-matrix
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -o build/startrack-supervisor ./cmd/startrack-supervisor

run:
	$(PYTHON) scripts/toolchain.py verify
	$(GO) run ./cmd/judge-service

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

migration-up:
	$(PYTHON) scripts/toolchain.py verify
	$(GO) run -mod=readonly ./cmd/judge-migrate up

database-status:
	$(PYTHON) scripts/toolchain.py verify
	$(GO) run -mod=readonly ./cmd/judge-migrate status

upstream-fetch:
	$(PYTHON) scripts/upstream.py fetch

upstream-verify:
	$(PYTHON) scripts/upstream.py verify

upstream-patch-check:
	$(PYTHON) -m unittest discover -s tests -p 'test_upstream_patches.py' -v

sandbox-preflight:
	bash scripts/sandbox-preflight.sh
