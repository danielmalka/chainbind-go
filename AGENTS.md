# AGENTS.md — chainbind-go

## Stack

Go 1.26

## Verification commands

- `make check` — fmt-check + lint + test (mandatory before any commit)
- `make check-strict` — fmt-check + lint + vet + race detector + coverage

A pre-commit hook enforces the gate plus a branch guard, a 10MB file-size limit,
and a secrets scan. Direct commits to `main` are rejected.

## Conventions

- Commits: Conventional Commits in English
- Tests: `go test`, test file alongside the code (`*_test.go`)
- Interfaces: defined in the consumer package, not the producer
- Errors: always wrapped with context — `fmt.Errorf("op: %w", err)`

## What NOT to do

- Do not add dependencies without asking
- Do not create abstractions for a single use case (YAGNI)
- Do not ignore errors with `_` without a justifying comment
- Do not use `panic()` outside `main()` or `init()`

## Extended instructions

Working conventions, architecture invariants, and the delivery workflow live in
`AGENTS.local.md`, which is not published. Agents with access to this working
copy MUST read `AGENTS.local.md` before implementing anything; it takes
precedence over this file where the two overlap.
