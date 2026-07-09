.PHONY: check check-strict lint test vet fmt fmt-check mutation

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
