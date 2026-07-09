.PHONY: check check-strict lint test vet fmt fmt-check mutation up down seed demo test-integration

# Compose stack (TASK-001-14).
COMPOSE      := docker compose -f deployments/docker-compose.yml
API_URL      ?= http://localhost:8088
TOKEN_URL    ?= http://localhost:8080/realms/chainbind/protocol/openid-connect/token
SECRETS_DIR  := deployments/secrets
EXAMPLES_DIR := examples

# `./...` matches no packages until the module has at least one .go file, which
# makes vet, lint and test exit non-zero. Skip them while the module is empty.
GO_FILES := $(shell find . -type f -name '*.go' -not -path './vendor/*' -print -quit)

fmt:
	gofumpt -w .

fmt-check:
	@test -z "$$(gofumpt -l .)" || { echo "not gofumpt-formatted:"; gofumpt -l .; exit 1; }

lint:
ifeq ($(GO_FILES),)
	@echo "lint: no Go files yet, skipping"
else
	golangci-lint run ./...
endif

vet:
ifeq ($(GO_FILES),)
	@echo "vet: no Go files yet, skipping"
else
	go vet ./...
endif

test:
ifeq ($(GO_FILES),)
	@echo "test: no Go files yet, skipping"
else
	go test ./...
endif

check: fmt-check lint test

check-strict: fmt-check lint vet
ifeq ($(GO_FILES),)
	@echo "test: no Go files yet, skipping"
else
	go test -race -count=1 -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1
endif

# Optional. Not part of check/check-strict — too slow for a gate.
mutation:
	@command -v gremlins >/dev/null 2>&1 || { echo "gremlins not installed. Install: go install github.com/go-gremlins/gremlins/cmd/gremlins@latest"; exit 1; }
	gremlins unleash

# --- Compose stack (TASK-001-14) ---------------------------------------------
# up: build and start the whole stack, then block until chainbind-api's /ready
# returns 200. The init/bootstrap services provision Vault, Keycloak and the key
# seed with no manual step; `up` is the single documented command of PRD Story 6.
up:
	$(COMPOSE) up --build -d
	@echo "waiting for chainbind-api /ready at $(API_URL) ..."
	@for i in $$(seq 1 60); do \
		code=$$(curl -s -o /dev/null -w '%{http_code}' $(API_URL)/ready || true); \
		if [ "$$code" = "200" ]; then echo "chainbind-api ready (200)"; exit 0; fi; \
		sleep 2; \
	done; \
	echo "chainbind-api did not become ready; recent logs:"; \
	$(COMPOSE) logs --tail=50 chainbind-api; exit 1

down:
	$(COMPOSE) down -v

# seed: bootstrap is run automatically by the init containers `make up` starts.
# This target re-runs them against a live stack (idempotent) for the rare case
# of re-seeding without a full restart.
seed:
	$(COMPOSE) up --build --no-deps bootstrap bootstrap-keycloak

# demo: drive a full seal -> verify -> open through the API + CLI against the
# running stack, writing the six artifacts TASK-001-15 consumes into examples/.
demo:
	@mkdir -p $(EXAMPLES_DIR)
	@cp testdata/checkout-payload.json $(EXAMPLES_DIR)/payload.json
	@echo "demo: obtaining token"
	@TOKEN=$$(curl -s -d grant_type=password -d client_id=chainbind-api \
		-d username=issuer -d password=issuer $(TOKEN_URL) | jq -r .access_token); \
	if [ -z "$$TOKEN" ] || [ "$$TOKEN" = "null" ]; then echo "demo: could not obtain token"; exit 1; fi; \
	echo "demo: sealing"; \
	curl -sf -X POST $(API_URL)/v1/packages/seal \
		-H "Authorization: Bearer $$TOKEN" -H 'Content-Type: application/json' \
		--data @$(EXAMPLES_DIR)/payload.json | jq . > $(EXAMPLES_DIR)/package.json; \
	echo "demo: verifying"; \
	curl -sf -X POST $(API_URL)/v1/packages/verify \
		-H 'Content-Type: application/json' \
		--data @$(EXAMPLES_DIR)/package.json | jq . > $(EXAMPLES_DIR)/verification-report.json
	@echo "demo: opening each segment with its seeded key"
	@for aud in user merchant gateway; do \
		go run ./cmd/chainbind open \
			--package $(EXAMPLES_DIR)/package.json \
			--key $(SECRETS_DIR)/keys/$$aud.key \
			--issuer-key $(SECRETS_DIR)/issuer.pub \
			--out $(EXAMPLES_DIR)/segment-$$aud.json || exit 1; \
	done
	@echo "demo: wrote artifacts:"; ls -1 $(EXAMPLES_DIR)

# test-integration: run the //go:build integration test against the live stack.
test-integration:
	go test -tags=integration -count=1 -v ./test/integration/...
