package chainbind

import "fmt"

// segmentRootEntry is one element of the ordered list segments_root commits
// to. The struct (not a map) is what makes the JSON key order predictable
// without relying on json.Marshal's map-key sort, and audience naming keeps
// the position of each entry driven by manifest.segment_order rather than
// by insertion order into plainHash (TECHSPEC-001 §6.1).
type segmentRootEntry struct {
	Audience  string `json:"audience"`
	PlainHash string `json:"plain_hash"`
}

// SegmentsRoot computes segments_root = H(JCS([{"audience": a, "plain_hash":
// plain_hash[a]} for a in segmentOrder])) per TECHSPEC-001 §6.1. The result
// commits to both which segments exist and the order they are listed in:
// permuting segmentOrder with identical hashes changes the value.
//
// segmentOrder and plainHash must describe exactly the same set of
// audiences, and segmentOrder must name each one once. The correspondence is
// enforced in both directions on purpose. An audience listed in segmentOrder
// but absent from plainHash would hash an empty string; an audience present
// in plainHash but absent from segmentOrder would be a segment that exists in
// the package, encrypted and openable, whose plaintext hash never enters the
// root — a segment nothing commits to. Both are malformed input, and neither
// is this function's to paper over.
//
// TECHSPEC-001 §6.5 L1.1 also checks the manifest for one entry per declared
// segment. That check and this one are independent, and this function does
// not rely on it having run.
func SegmentsRoot(segmentOrder []string, plainHash map[string]string) (string, error) {
	entries := make([]segmentRootEntry, 0, len(segmentOrder))
	seen := make(map[string]struct{}, len(segmentOrder))

	for _, a := range segmentOrder {
		if _, dup := seen[a]; dup {
			return "", fmt.Errorf("%w: audience %q listed twice in segment_order", ErrMalformedPackage, a)
		}
		seen[a] = struct{}{}

		ph, ok := plainHash[a]
		if !ok {
			return "", fmt.Errorf("%w: missing plain_hash for audience %q", ErrMalformedPackage, a)
		}
		entries = append(entries, segmentRootEntry{Audience: a, PlainHash: ph})
	}

	for a := range plainHash {
		if _, ok := seen[a]; !ok {
			return "", fmt.Errorf("%w: audience %q has a plain_hash but is absent from segment_order", ErrMalformedPackage, a)
		}
	}

	canon, err := JCS(entries)
	if err != nil {
		return "", fmt.Errorf("chainbind: segments root: %w", err)
	}
	return H(canon), nil
}

// intentCommitmentInput is the object intent_commitment hashes over. Field
// names match the wire vocabulary in TECHSPEC-001 §6.1, not Go convention,
// because they are part of what gets canonicalized and signed.
type intentCommitmentInput struct {
	IntentRef       string `json:"intent_ref"`
	ConstraintsHash string `json:"constraints_hash"`
	SegmentsRoot    string `json:"segments_root"`
}

// IntentCommitment computes intent_commitment = "ctx:" + H(JCS({intent_ref,
// constraints_hash, segments_root})) per TECHSPEC-001 §6.1 and D-008. The
// "ctx:" literal is prepended in front of the "sha256:" prefix H already
// adds, so the result begins "ctx:sha256:". It changes independently for
// each of its three inputs, which is what lets a keyless verifier detect
// each of the three attacks in D-008's table (payload swap, authorization
// swap, constraints mutated after sealing).
func IntentCommitment(intentRef, constraintsHash, segmentsRoot string) (string, error) {
	canon, err := JCS(intentCommitmentInput{
		IntentRef:       intentRef,
		ConstraintsHash: constraintsHash,
		SegmentsRoot:    segmentsRoot,
	})
	if err != nil {
		return "", fmt.Errorf("chainbind: intent commitment: %w", err)
	}
	return "ctx:" + H(canon), nil
}

// BindingContext carries the core values a profile-supplied binding may
// need to compute its own commitment, without the core knowing what the
// binding means (D-004, PRD Story 5 AC-2). The core populates this once per
// Seal/Verify call; a BindingSpec reads whichever fields its formula needs.
type BindingContext struct {
	PlainHash       map[string]string
	IntentRef       string
	ConstraintsHash string
	SegmentsRoot    string
}

// BindingSpec is one named, profile-supplied binding: a formula expressed
// as data (a name plus a pure function of BindingContext), not as a core
// type the library has to know the meaning of. This is the entirety of the
// binding engine — the core ships no plugin framework, only this.
type BindingSpec struct {
	Name    string
	Compute func(BindingContext) (string, error)
}

// ComputeBindings runs every spec against ctx and returns name -> value,
// suitable for Bindings.Extra. It stops at the first error, wrapped with
// the binding's name so a caller can tell which profile binding failed.
func ComputeBindings(ctx BindingContext, specs []BindingSpec) (map[string]string, error) {
	if len(specs) == 0 {
		return nil, nil
	}

	out := make(map[string]string, len(specs))
	for _, spec := range specs {
		v, err := spec.Compute(ctx)
		if err != nil {
			return nil, fmt.Errorf("chainbind: compute binding %q: %w", spec.Name, err)
		}
		out[spec.Name] = v
	}
	return out, nil
}
