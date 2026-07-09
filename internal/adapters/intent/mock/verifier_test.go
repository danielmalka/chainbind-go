package mock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// seedDir is the repo-root fixture directory make demo (TASK-001-14) also
// seeds the authority from. New takes a caller-supplied path, so this is the
// only place the location is named.
const seedDir = "../../../../testdata/authorizations"

type allowProjection struct {
	Region string  `json:"region"`
	Limit  float64 `json:"limit"`
}

func TestNew_ReproducibleAcrossInstances(t *testing.T) {
	v1, err := New(seedDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v2, err := New(seedDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	h1, err := v1.ConstraintsHash(context.Background(), "intent:allow-example")
	if err != nil {
		t.Fatalf("ConstraintsHash: %v", err)
	}
	h2, err := v2.ConstraintsHash(context.Background(), "intent:allow-example")
	if err != nil {
		t.Fatalf("ConstraintsHash: %v", err)
	}

	if h1 != h2 {
		t.Fatalf("constraints_hash not reproducible across instances: %q != %q", h1, h2)
	}
}

// TestConstraintsHash_StableAcrossConsumption is one half of the D-012 proof:
// mutating a consumption counter must never change constraints_hash.
func TestConstraintsHash_StableAcrossConsumption(t *testing.T) {
	v, err := New(seedDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	before, err := v.ConstraintsHash(context.Background(), "intent:allow-example")
	if err != nil {
		t.Fatalf("ConstraintsHash: %v", err)
	}

	v.recordUse("intent:allow-example")
	v.recordUse("intent:allow-example")
	v.recordUse("intent:allow-example")

	after, err := v.ConstraintsHash(context.Background(), "intent:allow-example")
	if err != nil {
		t.Fatalf("ConstraintsHash: %v", err)
	}

	if before != after {
		t.Fatalf("D-012 violated: constraints_hash changed after consumption: %q -> %q", before, after)
	}
}

// TestConstraintsHash_AmendingAnAuthorizationDoesNotChangeAnEarlierRef is the
// other half of the D-012 proof: intent_ref pins one immutable version, so an
// amendment (a new ref B) can never move the hash of a prior ref A. A package
// sealed under A stays intent-verifiable forever.
func TestConstraintsHash_AmendingAnAuthorizationDoesNotChangeAnEarlierRef(t *testing.T) {
	const (
		refA = "intent:amendable-v1" // granted at T0
		refB = "intent:amendable-v2" // amendment of the same authorization
	)

	v, err := New(seedDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	hashA, err := v.ConstraintsHash(context.Background(), refA)
	if err != nil {
		t.Fatalf("ConstraintsHash(A): %v", err)
	}
	hashB, err := v.ConstraintsHash(context.Background(), refB)
	if err != nil {
		t.Fatalf("ConstraintsHash(B): %v", err)
	}

	if hashA == hashB {
		t.Fatalf("amendment did not change constraints_hash: A and B both %q", hashA)
	}

	// Re-fetch A after touching B: still identical, byte for byte.
	hashAAgain, err := v.ConstraintsHash(context.Background(), refA)
	if err != nil {
		t.Fatalf("ConstraintsHash(A) again: %v", err)
	}
	if hashA != hashAAgain {
		t.Fatalf("D-012 violated: A's hash moved after B was consulted: %q -> %q", hashA, hashAAgain)
	}
}

func TestConstraintsHash_UnknownRefErrors(t *testing.T) {
	v, err := New(seedDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = v.ConstraintsHash(context.Background(), "intent:does-not-exist")
	if !errors.Is(err, ErrUnknownIntentRef) {
		t.Fatalf("ConstraintsHash(unknown) error = %v, want ErrUnknownIntentRef", err)
	}
}

func TestCheck_AllowsWithinConstraints(t *testing.T) {
	v, err := New(seedDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	decision, err := v.Check(context.Background(), "intent:allow-example", allowProjection{Region: "us", Limit: 100})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("Check: got Allowed=false, reason %q, want allowed", decision.Reason)
	}
}

func TestCheck_DeniesWithAuthorityReason(t *testing.T) {
	v, err := New(seedDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	decision, err := v.Check(context.Background(), "intent:deny-example", map[string]any{"region": "eu"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if decision.Allowed {
		t.Fatal("Check: got Allowed=true, want denied")
	}
	if decision.Reason == "" {
		t.Fatal("Check: denial carries no reason")
	}
}

func TestCheck_UnknownRefErrors(t *testing.T) {
	v, err := New(seedDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = v.Check(context.Background(), "intent:does-not-exist", map[string]any{})
	if !errors.Is(err, ErrUnknownIntentRef) {
		t.Fatalf("Check(unknown) error = %v, want ErrUnknownIntentRef", err)
	}
}

func TestCheck_ExpiredContextErrors(t *testing.T) {
	v, err := New(seedDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)

	decision, err := v.Check(ctx, "intent:allow-example", map[string]any{"region": "us", "limit": 1})
	if err == nil {
		t.Fatal("Check with expired context: got nil error, want an error")
	}
	if decision.Allowed {
		t.Fatal("Check with expired context: got Allowed=true, must never fail open")
	}
}

func TestNew_MissingSeedDirErrors(t *testing.T) {
	_, err := New("testdata/does-not-exist")
	if err == nil {
		t.Fatal("New with missing seed dir: got nil error, want an error")
	}
}

// TestNew_EmptyIntentRefErrors proves a seed file with no ref is rejected
// at construction rather than silently indexed under the empty string,
// where it would be indistinguishable from "no ref given" everywhere else
// in this package.
func TestNew_EmptyIntentRefErrors(t *testing.T) {
	dir := t.TempDir()
	writeSeedFile(t, dir, "empty-ref.json", `{"ref":"","version":1,"rules":{}}`)

	_, err := New(dir)
	if !errors.Is(err, ErrUnknownIntentRef) {
		t.Fatalf("New with an empty intent_ref: error = %v, want ErrUnknownIntentRef", err)
	}
}

// TestNew_DuplicateIntentRefErrors proves two seed files declaring the same
// intent_ref fail construction instead of one silently shadowing the
// other's constraints — last-write-wins here would let one seed file
// silently override another's rules, keyed on file iteration order.
func TestNew_DuplicateIntentRefErrors(t *testing.T) {
	dir := t.TempDir()
	writeSeedFile(t, dir, "a.json", `{"ref":"intent:dup","version":1,"rules":{}}`)
	writeSeedFile(t, dir, "b.json", `{"ref":"intent:dup","version":2,"rules":{}}`)

	_, err := New(dir)
	if !errors.Is(err, ErrDuplicateIntentRef) {
		t.Fatalf("New with a duplicate intent_ref: error = %v, want ErrDuplicateIntentRef", err)
	}
}

func writeSeedFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write seed file %q: %v", name, err)
	}
}

func TestPing_ReturnsContextErr(t *testing.T) {
	v, err := New(seedDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := v.Ping(context.Background()); err != nil {
		t.Fatalf("Ping with a live context: %v, want nil", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := v.Ping(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Ping with a cancelled context: %v, want context.Canceled", err)
	}
}
