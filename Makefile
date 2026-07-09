.PHONY: check check-strict lint test fmt fmt-check mutation

fmt:
	gofumpt -w .

fmt-check:
	@test -z "$$(gofumpt -l .)" || { echo "not gofumpt-formatted:"; gofumpt -l .; exit 1; }

lint:
	golangci-lint run ./...

test:
	go test ./...

check: fmt-check lint test

check-strict: fmt-check lint
	go vet ./...
	go test -race -count=1 -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1

# Optional. Not part of check/check-strict — too slow for a gate.
mutation:
	@command -v gremlins >/dev/null 2>&1 || { echo "gremlins not installed. Install: go install github.com/go-gremlins/gremlins/cmd/gremlins@latest"; exit 1; }
	gremlins unleash
