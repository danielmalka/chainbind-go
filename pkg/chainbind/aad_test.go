package chainbind

import (
	"bytes"
	"testing"
)

func baseAADContext() AADContext {
	return AADContext{
		PackageID:   "pkg-1",
		TenantID:    "tenant-1",
		Environment: "prod",
	}
}

func TestAAD_DiffersBySegmentName(t *testing.T) {
	ctx := baseAADContext()

	a, err := AAD(ctx, "audience-a", SupportedSpecVersion)
	if err != nil {
		t.Fatalf("AAD(audience-a): %v", err)
	}
	b, err := AAD(ctx, "audience-b", SupportedSpecVersion)
	if err != nil {
		t.Fatalf("AAD(audience-b): %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatalf("AAD identical for two different segment names: %s", a)
	}
}

func TestAAD_DiffersByPackageID(t *testing.T) {
	ctxA := baseAADContext()
	ctxB := baseAADContext()
	ctxB.PackageID = "pkg-2"

	a, err := AAD(ctxA, "audience-a", SupportedSpecVersion)
	if err != nil {
		t.Fatalf("AAD(pkg-1): %v", err)
	}
	b, err := AAD(ctxB, "audience-a", SupportedSpecVersion)
	if err != nil {
		t.Fatalf("AAD(pkg-2): %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatalf("AAD identical for the same segment name across two different package_ids: %s", a)
	}
}

func TestAAD_DeterministicForSameInputs(t *testing.T) {
	ctx := baseAADContext()

	first, err := AAD(ctx, "audience-a", SupportedSpecVersion)
	if err != nil {
		t.Fatalf("AAD (first call): %v", err)
	}
	second, err := AAD(ctx, "audience-a", SupportedSpecVersion)
	if err != nil {
		t.Fatalf("AAD (second call): %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("AAD not byte-identical across two calls with the same inputs: %s vs %s", first, second)
	}
}

func TestAAD_ExcludesCipherHash(t *testing.T) {
	// AAD is a JCS object over exactly five fields (package_id, segment,
	// spec_version, tenant_id, environment). cipher_hash is computed
	// after encryption, so including it here would be circular
	// (TECHSPEC-001 §6.3). This test guards against a future edit
	// accidentally threading cipher_hash into AADContext or AAD's inputs.
	out, err := AAD(baseAADContext(), "audience-a", SupportedSpecVersion)
	if err != nil {
		t.Fatalf("AAD: %v", err)
	}
	if bytes.Contains(out, []byte("cipher_hash")) {
		t.Fatalf("AAD output contains cipher_hash, which must never be part of the AAD: %s", out)
	}
}
