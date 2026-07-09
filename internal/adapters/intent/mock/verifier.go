// Package mock implements chainbind.IntentVerifier as a self-contained POC
// authority. It seeds authorizations from a directory of JSON documents at
// construction and answers every call from memory afterward, so a restart
// reproduces the same constraints_hash per intent_ref (TECHSPEC-001 §10 open
// question 2).
//
// intent_ref pins one immutable authorization version. It is an opaque
// handle the library never parses. Amending an authorization mints a new
// intent_ref with its own document; the authority never resolves "latest"
// and has no code path that selects a version. That is what keeps a package
// sealed under an earlier ref verifiable forever: ConstraintsHash is a pure
// function of the ref, and an amendment cannot move a prior ref's hash
// (D-012).
//
// The mock does not evaluate constraints for real, and does not model every
// constraint type a production authority might support (D-005): it only
// needs to be self-consistent and reproducible. It supports two rule kinds —
// an allowed-value equality check and a numeric bound — against whatever
// fields a projection happens to supply. It invents no domain vocabulary: a
// projection is opaque data, inspected only by the field names its own seed
// data names.
package mock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/danielmalka/chainbind-go/pkg/chainbind"
)

// Sentinel errors. Static strings only — no projection value, no payload
// data, ever appears in one of these (AGENTS.local.md invariant 10).
var (
	// ErrUnknownIntentRef is returned by Check and ConstraintsHash when no
	// seeded authorization matches the given intent_ref, and by New when a
	// seed file declares an empty ref.
	ErrUnknownIntentRef = errors.New("mock: unknown intent_ref")

	// ErrDuplicateIntentRef is returned by New when two seed files declare
	// the same intent_ref — malformed seed data, since a ref pins exactly
	// one immutable version.
	ErrDuplicateIntentRef = errors.New("mock: duplicate intent_ref in seed data")
)

// Rule is one field-level constraint. Equals checks the field for exact
// equality against an allowed set of values; Max and Min bound a numeric
// field. A field with no rule is not projected on.
type Rule struct {
	Equals []any    `json:"equals,omitempty"`
	Max    *float64 `json:"max,omitempty"`
	Min    *float64 `json:"min,omitempty"`
}

// constraints is the immutable, versioned authorization document D-012
// requires: the constraints as granted, and nothing else. Its JSON encoding
// is exactly what ConstraintsHash hashes over. Version distinguishes two
// amendments even if their rules happened to coincide; consumption state
// (uses consumed, remaining budget, last-used timestamp) is deliberately a
// separate, unhashed field on authorization below, never here.
type constraints struct {
	Version int             `json:"version"`
	Rules   map[string]Rule `json:"rules"`
}

// seedDoc is one seed file: an opaque intent_ref that pins exactly one
// immutable authorization version. The Version and Rules are embedded so a
// seed file is flat: {"ref": ..., "version": ..., "rules": {...}}.
type seedDoc struct {
	Ref         string `json:"ref"`
	constraints        // Version + Rules
}

// authorization pairs an immutable document with mutable consumption state
// that D-012 forbids from ever entering constraints_hash. consumed exists
// only so tests can prove that mutating it does not change the hash; the
// mock's evaluation logic never reads it.
type authorization struct {
	doc      constraints
	consumed int
}

// Verifier is the mock Intent Authority. It implements
// chainbind.IntentVerifier.
type Verifier struct {
	mu    sync.RWMutex
	auths map[string]*authorization // keyed by intent_ref
}

// New loads every *.json file in dir as an authorization document, indexed
// by its intent_ref, and returns a Verifier ready to serve Check and
// ConstraintsHash. Two Verifier instances loaded from the same dir answer
// ConstraintsHash identically for a given ref (TECHSPEC-001 §10 Q2).
func New(dir string) (*Verifier, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("mock: read seed dir: %w", err)
	}

	auths := make(map[string]*authorization, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		raw, err := os.ReadFile(path) //nolint:gosec // dir is operator-supplied seed config, not untrusted input
		if err != nil {
			return nil, fmt.Errorf("mock: read seed file %q: %w", entry.Name(), err)
		}

		var doc seedDoc
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("mock: parse seed file %q: %w", entry.Name(), err)
		}
		if doc.Ref == "" {
			return nil, fmt.Errorf("mock: seed file %q: %w", entry.Name(), ErrUnknownIntentRef)
		}
		if _, dup := auths[doc.Ref]; dup {
			return nil, fmt.Errorf("mock: seed file %q: %w", entry.Name(), ErrDuplicateIntentRef)
		}

		auths[doc.Ref] = &authorization{doc: doc.constraints}
	}

	return &Verifier{auths: auths}, nil
}

// Check implements chainbind.IntentVerifier. It evaluates the pinned
// authorization's rules against projection and reports the mock's own
// verdict; it never consults or mutates consumption state.
func (v *Verifier) Check(ctx context.Context, intentRef string, projection any) (chainbind.IntentDecision, error) {
	if err := ctx.Err(); err != nil {
		return chainbind.IntentDecision{}, fmt.Errorf("mock: check: %w", err)
	}

	doc, err := v.lookup(intentRef)
	if err != nil {
		return chainbind.IntentDecision{}, err
	}

	fields, err := projectionFields(projection)
	if err != nil {
		return chainbind.IntentDecision{}, fmt.Errorf("mock: check: %w", err)
	}

	for field, rule := range doc.Rules {
		val, present := fields[field]
		if !present {
			return chainbind.IntentDecision{
				Allowed: false,
				Reason:  fmt.Sprintf("required field %q not present in projection", field),
			}, nil
		}
		if reason, ok := rule.evaluate(field, val); !ok {
			return chainbind.IntentDecision{Allowed: false, Reason: reason}, nil
		}
	}

	return chainbind.IntentDecision{Allowed: true}, nil
}

// ConstraintsHash implements chainbind.IntentVerifier. It is a pure function
// of intentRef: it hashes only the pinned immutable document, never
// authorization.consumed and never a "latest" version. The same ref yields
// the same hash forever, which is what keeps previously sealed packages
// verifiable after the underlying authorization is amended (D-012).
func (v *Verifier) ConstraintsHash(ctx context.Context, intentRef string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("mock: constraints hash: %w", err)
	}

	doc, err := v.lookup(intentRef)
	if err != nil {
		return "", err
	}
	return hashConstraints(doc)
}

// Ping implements the HTTP shell's Prober port. The mock authority is
// in-memory — there is no network dependency to probe — so Ping only
// reports whether ctx is already done, and is otherwise always ready.
func (v *Verifier) Ping(ctx context.Context) error {
	return ctx.Err()
}

// lookup returns the immutable document pinned by intentRef. There is no
// version selection here or anywhere: the ref is the whole key.
func (v *Verifier) lookup(intentRef string) (constraints, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	auth, ok := v.auths[intentRef]
	if !ok {
		return constraints{}, fmt.Errorf("mock: %w", ErrUnknownIntentRef)
	}
	return auth.doc, nil
}

// recordUse increments the consumption counter for intentRef. Nothing in
// Check or ConstraintsHash reads it; it exists so tests can exercise D-012.
func (v *Verifier) recordUse(intentRef string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if auth, ok := v.auths[intentRef]; ok {
		auth.consumed++
	}
}

// hashConstraints computes constraints_hash = H(JCS(doc)) over the immutable
// authorization document alone (D-012).
func hashConstraints(doc constraints) (string, error) {
	canon, err := chainbind.JCS(doc)
	if err != nil {
		return "", fmt.Errorf("mock: hash constraints: %w", err)
	}
	return chainbind.H(canon), nil
}

// projectionFields normalizes an opaque projection into field->value by
// round-tripping it through JSON, so evaluation never assumes a concrete Go
// type for the profile-supplied projection.
func projectionFields(projection any) (map[string]any, error) {
	raw, err := json.Marshal(projection)
	if err != nil {
		return nil, fmt.Errorf("encode projection: %w", err)
	}

	fields := make(map[string]any)
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("decode projection: %w", err)
	}
	return fields, nil
}

// evaluate reports whether val satisfies rule, and a human-readable reason
// when it does not. The reason names field and val: both are the caller's
// own authorization data, which the IntentVerifier contract allows to be
// surfaced verbatim (never another party's secret).
func (r Rule) evaluate(field string, val any) (reason string, ok bool) {
	if len(r.Equals) > 0 {
		for _, allowed := range r.Equals {
			if allowed == val {
				return "", true
			}
		}
		return fmt.Sprintf("field %q: value %v is not in the allowed set", field, val), false
	}

	if r.Max != nil || r.Min != nil {
		num, isNum := val.(float64)
		if !isNum {
			return fmt.Sprintf("field %q: expected a numeric value", field), false
		}
		if r.Max != nil && num > *r.Max {
			return fmt.Sprintf("field %q: value %v exceeds maximum %v", field, num, *r.Max), false
		}
		if r.Min != nil && num < *r.Min {
			return fmt.Sprintf("field %q: value %v is below minimum %v", field, num, *r.Min), false
		}
	}

	return "", true
}
