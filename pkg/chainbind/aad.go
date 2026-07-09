package chainbind

import "fmt"

// aadInput is the object AAD hashes over. Field names and order match the
// wire vocabulary in TECHSPEC-001 §6.3; JCS canonicalizes the object so Go
// struct field order does not matter to the result.
//
// It deliberately excludes cipher_hash: cipher_hash is computed *after*
// encryption (it hashes the ciphertext AES-256-GCM produces), so including
// it in the AAD fed to that same encryption call would be circular.
type aadInput struct {
	PackageID   string `json:"package_id"`
	Segment     string `json:"segment"`
	SpecVersion string `json:"spec_version"`
	TenantID    string `json:"tenant_id"`
	Environment string `json:"environment"`
}

// AAD computes AAD_a = JCS({"package_id", "segment": a, "spec_version",
// "tenant_id", "environment"}) per TECHSPEC-001 §6.3. The returned bytes are
// the additional authenticated data a later task feeds to
// AES-256-GCM.Seal/Open: GCM authentication fails if a segment is moved to
// another package_id or renamed to another segment, which is the anti-
// splicing control behind PRD Story 1 AC-8 (architecture invariant 11).
func AAD(ctx AADContext, segment, specVersion string) ([]byte, error) {
	canon, err := JCS(aadInput{
		PackageID:   ctx.PackageID,
		Segment:     segment,
		SpecVersion: specVersion,
		TenantID:    ctx.TenantID,
		Environment: ctx.Environment,
	})
	if err != nil {
		return nil, fmt.Errorf("chainbind: aad: %w", err)
	}
	return canon, nil
}
