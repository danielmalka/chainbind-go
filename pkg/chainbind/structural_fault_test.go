package chainbind_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/danielmalka/chainbind-go/pkg/chainbind"
)

// This file holds TASK-001-16's tests for StructuralFault and its effect on
// Report — split out of verify_test.go, which already exceeded the
// project's 500-line-per-file convention before this task touched it, so
// adding here rather than there avoids making that pre-existing overrun
// worse.

// TestVerify_MalformedSignedFields_IsNotAForgedSignature and
// TestVerify_ForgedSignature_IsNotMalformed are the pair TASK-001-16 exists
// to make distinguishable. Before that task, both a garbage signed_fields
// list and a genuinely forged signature left report.Signature == false and
// nothing else to tell them apart — Signature == false was overloaded to
// mean "malformed" and "forged" simultaneously. Now Structural carries the
// distinction: FaultSignedFieldsInvalid for the first, FaultNone for the
// second.
func TestVerify_MalformedSignedFields_IsNotAForgedSignature(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	p, pub := sealTestPackage(t, aud)

	p.Signature.SignedFields = []string{"not_a_real_field"}

	report, err := chainbind.Verify(context.Background(), p, verifyOpts(pub, newTestVerifier(t)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Signature {
		t.Fatal("Signature = true with a garbage signed_fields list")
	}
	// Signature == false is not the distinguishing signal — a forged
	// signature also leaves it false. Structural is what tells this case
	// apart from a forgery.
	if report.Structural != chainbind.FaultSignedFieldsInvalid {
		t.Fatalf("Structural = %v, want FaultSignedFieldsInvalid", report.Structural)
	}
	if report.Structural == chainbind.FaultNone {
		t.Fatal("Structural = FaultNone for a garbage signed_fields list")
	}
}

func TestVerify_ForgedSignature_IsNotMalformed(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	p, pub := sealTestPackage(t, aud)

	// The package itself is structurally perfect; only the signature bytes
	// are wrong. Flip a bit in the decoded signature and re-encode, so
	// signature.value still decodes cleanly as base64url — this must not
	// parse as malformed, only fail to verify.
	sig, err := chainbind.DecodeSignatureValue(p.Signature.Value)
	if err != nil {
		t.Fatalf("DecodeSignatureValue: %v", err)
	}
	sig = bytes.Clone(sig)
	sig[0] ^= 0xFF
	p.Signature.Value = chainbind.EncodeSignatureValue(sig)

	report, err := chainbind.Verify(context.Background(), p, verifyOpts(pub, newTestVerifier(t)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Signature {
		t.Fatal("Signature = true for a forged signature")
	}
	if report.Structural != chainbind.FaultNone {
		t.Fatalf("Structural = %v, want FaultNone: a forged signature is not a structural fault", report.Structural)
	}
}

// TestVerify_UnbuildableSigningView_IsNotInvalidSignedFields is the third
// member of the family above. A package whose bindings.Extra shadows a core
// binding name cannot be canonicalized — Bindings.MarshalJSON refuses — even
// though its signature.signed_fields is perfectly well formed. Reporting that
// as FaultSignedFieldsInvalid would be a false statement about a field that
// is not at fault.
//
// It is reachable only from a caller-constructed Package: decoding one from
// JSON runs Bindings.UnmarshalJSON, which rejects the collision on the way
// in. Verify takes a *Package, so the caller can hand it exactly this.
func TestVerify_UnbuildableSigningView_IsNotInvalidSignedFields(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	p, pub := sealTestPackage(t, aud)

	p.Bindings.Extra = map[string]string{"segments_root": "sha256:deadbeef"}

	report, err := chainbind.Verify(context.Background(), p, verifyOpts(pub, newTestVerifier(t)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Structural != chainbind.FaultSigningViewUnbuildable {
		t.Fatalf("Structural = %v, want FaultSigningViewUnbuildable", report.Structural)
	}
	if report.Level1() {
		t.Fatal("Level1() = true for a package whose signing view cannot be built")
	}

	// The signed_fields list itself is untouched and valid; blaming it
	// would be the conflation this fault exists to prevent.
	if report.Structural == chainbind.FaultSignedFieldsInvalid {
		t.Fatal("Structural = FaultSignedFieldsInvalid, but signature.signed_fields is well formed")
	}
}

// TestReport_Level1_FalseWhenStructuralFaultSet proves level1Passed's added
// requirement actually gates: a report where every other field claims
// success must still fail Level1() and OK() once Structural names a fault.
//
// The Report below is hand-built on purpose, and no Verify call can produce
// it: a structural fault makes Verify return before CipherHashes is
// allocated, so the nil-map check would already answer. The guard exists for
// exactly this shape — Report's fields are exported, and a caller can
// assemble one — which is why the only way to test it is to assemble one.
func TestReport_Level1_FalseWhenStructuralFaultSet(t *testing.T) {
	r := &chainbind.Report{
		Structural:           chainbind.FaultEmptySegmentOrder,
		SpecVersionSupported: true,
		Signature:            true,
		AADContextConsistent: true,
		CipherHashes:         map[string]bool{"alpha": true},
		SegmentsRoot:         true,
		ProfileBindings:      map[string]bool{"binding": true},
		Intent:               chainbind.IntentResult{Evaluated: true, Valid: true},
	}
	if r.Level1() {
		t.Fatal("Level1() = true despite a non-FaultNone Structural value")
	}
	if r.OK() {
		t.Fatal("OK() = true despite a non-FaultNone Structural value")
	}
}

// TestStructuralFault_StringIsStaticForEveryValue proves every StructuralFault
// value — including one outside the declared range — renders as a non-empty,
// static string with no digits, so %+v on a Report never leaks the raw
// numeric fault value (architecture invariant 10).
func TestStructuralFault_StringIsStaticForEveryValue(t *testing.T) {
	faults := []chainbind.StructuralFault{
		chainbind.FaultNone,
		chainbind.FaultEmptySignedFields,
		chainbind.FaultEmptySegmentOrder,
		chainbind.FaultSegmentCountMismatch,
		chainbind.FaultDuplicateAudience,
		chainbind.FaultManifestSegmentMissing,
		chainbind.FaultSealedSegmentMissing,
		chainbind.FaultSignedFieldsInvalid,
		chainbind.FaultSigningViewUnbuildable,
		chainbind.FaultSignatureUndecodable,
		chainbind.StructuralFault(255), // out of range: exercises the default branch
	}

	// Every declared fault must render distinctly: two faults sharing a
	// string would make them indistinguishable in a log, which is the
	// conflation this whole type exists to remove.
	seen := make(map[string]chainbind.StructuralFault, len(faults))
	for _, f := range faults {
		if prev, dup := seen[f.String()]; dup {
			t.Fatalf("StructuralFault(%d) and StructuralFault(%d) share the string %q", uint8(prev), uint8(f), f.String())
		}
		seen[f.String()] = f
	}

	for _, f := range faults {
		s := f.String()
		if s == "" {
			t.Fatalf("StructuralFault(%d).String() is empty", uint8(f))
		}
		if strings.ContainsAny(s, "0123456789") {
			t.Fatalf("StructuralFault(%d).String() = %q contains a digit — the numeric value leaked", uint8(f), s)
		}
	}
}

// TestStructuralFault_MarshalsAsText pins the JSON contract. encoding/json
// does not consult fmt.Stringer, so without MarshalJSON a Report serialized
// to a client carries "structural": 4 — an ordinal that is an implementation
// detail of the iota block and shifts the day a fault is inserted. Both the
// HTTP shell's /v1/packages/verify and the CLI's `verify --json` hand a
// Report to someone else; both would have shipped the integer.
func TestStructuralFault_MarshalsAsText(t *testing.T) {
	for _, f := range []chainbind.StructuralFault{
		chainbind.FaultNone,
		chainbind.FaultDuplicateAudience,
		chainbind.FaultSignatureUndecodable,
		chainbind.StructuralFault(255),
	} {
		raw, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshal %v: %v", f, err)
		}
		var got string
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("StructuralFault(%d) marshalled to non-string %s", uint8(f), raw)
		}
		if got != f.String() {
			t.Fatalf("marshalled %q, want %q", got, f.String())
		}
	}

	// The whole Report, as a client receives it.
	raw, err := json.Marshal(&chainbind.Report{Structural: chainbind.FaultEmptySegmentOrder})
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if _, isNumber := rec["Structural"].(float64); isNumber {
		t.Fatalf("Report.Structural serialized as a number: %s", raw)
	}
	if rec["Structural"] != chainbind.FaultEmptySegmentOrder.String() {
		t.Fatalf("Report.Structural = %v, want %q", rec["Structural"], chainbind.FaultEmptySegmentOrder.String())
	}
}

// TestStructuralFault_JSONRoundTrips pins that a StructuralFault, and a whole
// Report, survive a marshal→unmarshal cycle as text. The HTTP shell returns a
// Report as the body of /v1/packages/verify and a Go client decodes it back
// into a chainbind.Report; MarshalJSON without UnmarshalJSON breaks exactly
// that, because Structural marshals to a string but is a uint8 in the struct.
func TestStructuralFault_JSONRoundTrips(t *testing.T) {
	for _, want := range []chainbind.StructuralFault{
		chainbind.FaultNone,
		chainbind.FaultEmptySegmentOrder,
		chainbind.FaultSigningViewUnbuildable,
		chainbind.FaultSignatureUndecodable,
	} {
		raw, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("marshal %v: %v", want, err)
		}
		var got chainbind.StructuralFault
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", raw, err)
		}
		if got != want {
			t.Fatalf("round trip: got %v, want %v", got, want)
		}
	}

	// The whole Report a verify client receives and decodes.
	in := &chainbind.Report{Structural: chainbind.FaultDuplicateAudience, SpecVersionSupported: true}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var out chainbind.Report
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if out.Structural != chainbind.FaultDuplicateAudience {
		t.Fatalf("report round trip: Structural = %v, want FaultDuplicateAudience", out.Structural)
	}

	// An unrecognised fault string is rejected, not silently read as FaultNone
	// — a garbled Report must not decode as a clean one.
	var bad chainbind.StructuralFault
	if err := json.Unmarshal([]byte(`"not a real fault"`), &bad); err == nil {
		t.Fatal("unmarshalling an unknown fault string succeeded; want an error")
	}
}
