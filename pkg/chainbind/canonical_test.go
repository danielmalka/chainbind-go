package chainbind

import (
	"bytes"
	"testing"
)

func TestJCS_StableAcrossKeyReordering(t *testing.T) {
	tests := []struct {
		name string
		a    map[string]any
		b    map[string]any
	}{
		{
			name: "flat object, reversed insertion order",
			a:    map[string]any{"z": 1, "a": 2, "m": 3},
			b:    map[string]any{"m": 3, "a": 2, "z": 1},
		},
		{
			name: "nested object",
			a: map[string]any{
				"outer": map[string]any{"b": 1, "a": 2},
				"list":  []any{1, 2, 3},
			},
			b: map[string]any{
				"list":  []any{1, 2, 3},
				"outer": map[string]any{"a": 2, "b": 1},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotA, err := JCS(tt.a)
			if err != nil {
				t.Fatalf("JCS(a): %v", err)
			}
			gotB, err := JCS(tt.b)
			if err != nil {
				t.Fatalf("JCS(b): %v", err)
			}
			if !bytes.Equal(gotA, gotB) {
				t.Fatalf("JCS output differs across key order:\na=%s\nb=%s", gotA, gotB)
			}
		})
	}
}

func TestJCS_ErrorsOnUnsupportedValue(t *testing.T) {
	if _, err := JCS(func() {}); err == nil {
		t.Fatal("expected an error marshaling a func value, got nil")
	}
}

func TestH_DeterministicAndPrefixed(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{name: "empty", in: []byte{}},
		{name: "ascii", in: []byte("chainbind")},
		{name: "binary", in: []byte{0x00, 0xff, 0x10, 0x02}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h1 := H(tt.in)
			h2 := H(tt.in)
			if h1 != h2 {
				t.Fatalf("H is not deterministic: %q != %q", h1, h2)
			}
			const prefix = "sha256:"
			if len(h1) <= len(prefix) || h1[:len(prefix)] != prefix {
				t.Fatalf("H(%q) = %q, want %q prefix", tt.in, h1, prefix)
			}
			// sha256 hex digest is 64 chars.
			if len(h1) != len(prefix)+64 {
				t.Fatalf("H(%q) = %q, want %d chars after prefix", tt.in, h1, 64)
			}
		})
	}
}

func TestH_DifferentInputsDifferentHashes(t *testing.T) {
	if H([]byte("a")) == H([]byte("b")) {
		t.Fatal("H produced the same digest for different inputs")
	}
}
