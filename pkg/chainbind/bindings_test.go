package chainbind

import (
	"errors"
	"strings"
	"testing"
)

func TestSegmentsRoot_ChangesWithPlainHash(t *testing.T) {
	order := []string{"a", "b"}
	base := map[string]string{"a": "sha256:aaaa", "b": "sha256:bbbb"}
	changed := map[string]string{"a": "sha256:aaaa", "b": "sha256:cccc"}

	want, err := SegmentsRoot(order, base)
	if err != nil {
		t.Fatalf("SegmentsRoot(base): %v", err)
	}
	got, err := SegmentsRoot(order, changed)
	if err != nil {
		t.Fatalf("SegmentsRoot(changed): %v", err)
	}
	if want == got {
		t.Fatalf("segments_root did not change when a plain_hash changed: both %q", want)
	}
}

// TestSegmentsRoot_CommitsToOrder is the interesting test: two calls with
// identical hashes but a permuted segment_order must produce different
// roots, proving order is part of what segments_root commits to
// (TECHSPEC-001 §6.1).
func TestSegmentsRoot_CommitsToOrder(t *testing.T) {
	hashes := map[string]string{"a": "sha256:aaaa", "b": "sha256:bbbb"}

	forward, err := SegmentsRoot([]string{"a", "b"}, hashes)
	if err != nil {
		t.Fatalf("SegmentsRoot(a,b): %v", err)
	}
	reversed, err := SegmentsRoot([]string{"b", "a"}, hashes)
	if err != nil {
		t.Fatalf("SegmentsRoot(b,a): %v", err)
	}
	if forward == reversed {
		t.Fatalf("segments_root is stable under permuting segment_order: both %q", forward)
	}
}

func TestSegmentsRoot_Deterministic(t *testing.T) {
	order := []string{"a", "b"}
	hashes := map[string]string{"a": "sha256:aaaa", "b": "sha256:bbbb"}

	first, err := SegmentsRoot(order, hashes)
	if err != nil {
		t.Fatalf("SegmentsRoot: %v", err)
	}
	second, err := SegmentsRoot(order, hashes)
	if err != nil {
		t.Fatalf("SegmentsRoot: %v", err)
	}
	if first != second {
		t.Fatalf("segments_root not deterministic: %q vs %q", first, second)
	}
}

// TestSegmentsRoot_RejectsAsymmetricInput proves segment_order and plain_hash
// must describe the same set of audiences, in both directions. The uncommitted
// case is the one that matters: a segment carried in the package whose
// plaintext hash never enters the root is a segment nothing commits to, and
// it must not be possible to compute a root that quietly omits it.
func TestSegmentsRoot_RejectsAsymmetricInput(t *testing.T) {
	tests := []struct {
		name         string
		order        []string
		plainHash    map[string]string
		whyItMatters string
	}{
		{
			name:         "audience in segment_order has no plain_hash",
			order:        []string{"a", "missing"},
			plainHash:    map[string]string{"a": "sha256:aaaa"},
			whyItMatters: "would hash an empty plaintext hash",
		},
		{
			name:         "audience has a plain_hash but is absent from segment_order",
			order:        []string{"a"},
			plainHash:    map[string]string{"a": "sha256:aaaa", "uncommitted": "sha256:bbbb"},
			whyItMatters: "segment would exist in the package but not in segments_root",
		},
		{
			name:         "audience listed twice in segment_order",
			order:        []string{"a", "a"},
			plainHash:    map[string]string{"a": "sha256:aaaa"},
			whyItMatters: "a map holds one segment per audience; a duplicate entry is malformed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SegmentsRoot(tt.order, tt.plainHash)
			if err == nil {
				t.Fatalf("SegmentsRoot: got nil error, want one (%s)", tt.whyItMatters)
			}
			if !errors.Is(err, ErrMalformedPackage) {
				t.Fatalf("SegmentsRoot: got %v, want errors.Is ErrMalformedPackage", err)
			}
		})
	}
}

// TestIntentCommitment_ThreeAttackTable proves the D-008 claim: each of the
// three named attacks changes intent_commitment relative to a genuine
// baseline, because each attack moves exactly one of the three inputs.
func TestIntentCommitment_ThreeAttackTable(t *testing.T) {
	const (
		intentRef       = "intent-ref-1"
		constraintsHash = "sha256:constraints-v1"
		segmentsRoot    = "sha256:segments-v1"
	)

	baseline, err := IntentCommitment(intentRef, constraintsHash, segmentsRoot)
	if err != nil {
		t.Fatalf("IntentCommitment(baseline): %v", err)
	}

	tests := []struct {
		name            string
		intentRef       string
		constraintsHash string
		segmentsRoot    string
	}{
		{
			name:            "payload swapped under a valid authorization reference",
			intentRef:       intentRef,
			constraintsHash: constraintsHash,
			segmentsRoot:    "sha256:segments-v2-swapped-payload",
		},
		{
			name:            "authorization reference swapped for a different one",
			intentRef:       "intent-ref-2-swapped",
			constraintsHash: constraintsHash,
			segmentsRoot:    segmentsRoot,
		},
		{
			name:            "constraints mutated at the authority after sealing",
			intentRef:       intentRef,
			constraintsHash: "sha256:constraints-v2-mutated",
			segmentsRoot:    segmentsRoot,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attacked, err := IntentCommitment(tt.intentRef, tt.constraintsHash, tt.segmentsRoot)
			if err != nil {
				t.Fatalf("IntentCommitment(attack): %v", err)
			}
			if attacked == baseline {
				t.Fatalf("intent_commitment did not change under %q: both %q", tt.name, baseline)
			}
		})
	}
}

func TestIntentCommitment_HasCtxSha256Prefix(t *testing.T) {
	got, err := IntentCommitment("intent-ref-1", "sha256:constraints", "sha256:segments")
	if err != nil {
		t.Fatalf("IntentCommitment: %v", err)
	}
	if !strings.HasPrefix(got, "ctx:sha256:") {
		t.Fatalf("intent_commitment = %q, want prefix %q", got, "ctx:sha256:")
	}
}

func TestComputeBindings_RunsEverySpecAsData(t *testing.T) {
	specs := []BindingSpec{
		{
			Name: "profile_alias",
			Compute: func(ctx BindingContext) (string, error) {
				return ctx.SegmentsRoot, nil
			},
		},
		{
			Name: "profile_intent_ref_echo",
			Compute: func(ctx BindingContext) (string, error) {
				return ctx.IntentRef, nil
			},
		},
	}

	got, err := ComputeBindings(BindingContext{
		SegmentsRoot: "sha256:root",
		IntentRef:    "intent-ref-1",
	}, specs)
	if err != nil {
		t.Fatalf("ComputeBindings: %v", err)
	}

	if got["profile_alias"] != "sha256:root" {
		t.Fatalf("profile_alias = %q, want %q", got["profile_alias"], "sha256:root")
	}
	if got["profile_intent_ref_echo"] != "intent-ref-1" {
		t.Fatalf("profile_intent_ref_echo = %q, want %q", got["profile_intent_ref_echo"], "intent-ref-1")
	}
}

func TestComputeBindings_PropagatesSpecError(t *testing.T) {
	sentinel := errors.New("boom")
	specs := []BindingSpec{
		{
			Name: "broken",
			Compute: func(BindingContext) (string, error) {
				return "", sentinel
			},
		},
	}

	_, err := ComputeBindings(BindingContext{}, specs)
	if !errors.Is(err, sentinel) {
		t.Fatalf("ComputeBindings error = %v, want errors.Is sentinel", err)
	}
}

func TestBindingsMarshalJSON_RejectsExtraCollisionWithSegmentsRoot(t *testing.T) {
	b := Bindings{
		SegmentsRoot:     "sha256:root",
		IntentCommitment: "ctx:sha256:commit",
		Extra:            map[string]string{"segments_root": "sha256:forged"},
	}

	_, err := b.MarshalJSON()
	if !errors.Is(err, ErrBindingCollision) {
		t.Fatalf("MarshalJSON with Extra[segments_root] = %v, want errors.Is ErrBindingCollision", err)
	}
}

func TestBindingsMarshalJSON_RejectsExtraCollisionWithIntentCommitment(t *testing.T) {
	b := Bindings{
		SegmentsRoot:     "sha256:root",
		IntentCommitment: "ctx:sha256:commit",
		Extra:            map[string]string{"intent_commitment": "ctx:sha256:forged"},
	}

	_, err := b.MarshalJSON()
	if !errors.Is(err, ErrBindingCollision) {
		t.Fatalf("MarshalJSON with Extra[intent_commitment] = %v, want errors.Is ErrBindingCollision", err)
	}
}

func TestBindingsMarshalJSON_AcceptsNonCollidingExtraKey(t *testing.T) {
	b := Bindings{
		SegmentsRoot:     "sha256:root",
		IntentCommitment: "ctx:sha256:commit",
		Extra:            map[string]string{"profile_alias": "sha256:alias"},
	}

	out, err := b.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if !strings.Contains(string(out), `"profile_alias":"sha256:alias"`) {
		t.Fatalf("marshaled bindings = %s, want it to contain the non-colliding Extra key", out)
	}
}
