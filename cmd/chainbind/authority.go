package main

import (
	"errors"
	"fmt"
	"time"

	authhttp "github.com/danielmalka/chainbind-go/internal/adapters/intent/http"
	"github.com/danielmalka/chainbind-go/internal/adapters/intent/mock"
	"github.com/danielmalka/chainbind-go/pkg/chainbind"
)

// errBothAuthorityFlags is returned when both --authority-seed-dir and
// --authority-url are given: exactly one, or neither where neither is
// allowed, is the whole contract.
var errBothAuthorityFlags = errors.New("chainbind: specify at most one of --authority-seed-dir or --authority-url")

// authorityTimeout bounds every call the HTTP intent verifier makes. A
// standalone CLI invocation has no request deadline of its own to inherit,
// so it sets one itself rather than letting a hung authority hang forever.
const authorityTimeout = 10 * time.Second

// resolveAuthority builds the chainbind.IntentVerifier named by seedDir or
// authorityURL. Both set is a usage error. Neither set returns (nil, nil) —
// a valid, deliberate answer for verify (Level 2 stays unevaluated, D-011)
// and a usage error for seal, which the caller of resolveAuthority in
// seal.go checks for separately since seal requires exactly one.
func resolveAuthority(seedDir, authorityURL string) (chainbind.IntentVerifier, error) {
	if seedDir != "" && authorityURL != "" {
		return nil, errBothAuthorityFlags
	}
	if seedDir != "" {
		v, err := mock.New(seedDir)
		if err != nil {
			return nil, fmt.Errorf("load mock intent authority from %q: %w", seedDir, err)
		}
		return v, nil
	}
	if authorityURL != "" {
		return authhttp.New(authorityURL, nil, authorityTimeout), nil
	}
	return nil, nil
}

// authorityLabel is what seal records verbatim in intent.authority: an
// informational identifier for which authority IntentRef was checked
// against (TECHSPEC-001 §5, SealRequest.Authority doc). chainbind itself
// never dials it.
func authorityLabel(seedDir, authorityURL string) string {
	if authorityURL != "" {
		return authorityURL
	}
	if seedDir != "" {
		return "seed:" + seedDir
	}
	return ""
}
