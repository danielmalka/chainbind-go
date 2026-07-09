package chainbind

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestCheckSpecVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantErr bool
	}{
		{name: "supported version", version: SupportedSpecVersion, wantErr: false},
		{name: "unknown version", version: "0.9.0", wantErr: true},
		{name: "empty version", version: "", wantErr: true},
		{name: "future version", version: "2.0.0", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckSpecVersion(tt.version)
			if tt.wantErr && err == nil {
				t.Fatalf("CheckSpecVersion(%q) = nil, want an error", tt.version)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("CheckSpecVersion(%q) = %v, want nil", tt.version, err)
			}
			if tt.wantErr && !errors.Is(err, ErrUnsupportedSpecVersion) {
				t.Fatalf("CheckSpecVersion(%q) = %v, want errors.Is ErrUnsupportedSpecVersion", tt.version, err)
			}
		})
	}
}

// TestPackage_RoundTripsExampleWireShape unmarshals the authoritative wire
// example, marshals it back, and checks the top-level and nested key sets
// are exactly preserved (D-001). It does not assert on illustrative values.
func TestPackage_RoundTripsExampleWireShape(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "package-example-v1.json"))
	if err != nil {
		t.Fatalf("reading example: %v", err)
	}

	var original map[string]any
	if err := json.Unmarshal(raw, &original); err != nil {
		t.Fatalf("unmarshal example into map: %v", err)
	}
	delete(original, "_comment")

	var p Package
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("unmarshal example into Package: %v", err)
	}

	out, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal Package: %v", err)
	}

	var roundTripped map[string]any
	if err := json.Unmarshal(out, &roundTripped); err != nil {
		t.Fatalf("unmarshal round-tripped bytes: %v", err)
	}

	assertSameKeys(t, "$", original, roundTripped)
}

// assertSameKeys walks two decoded JSON values in lockstep and fails if any
// object at any depth has a different key set.
func assertSameKeys(t *testing.T, path string, a, b any) {
	t.Helper()

	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			t.Fatalf("%s: expected object, got %T", path, b)
			return
		}
		if !reflect.DeepEqual(sortedKeys(av), sortedKeys(bv)) {
			t.Fatalf("%s: key sets differ\nwant: %v\ngot:  %v", path, sortedKeys(av), sortedKeys(bv))
		}
		for k, v := range av {
			assertSameKeys(t, path+"."+k, v, bv[k])
		}
	case []any:
		bv, ok := b.([]any)
		if !ok {
			t.Fatalf("%s: expected array, got %T", path, b)
			return
		}
		if len(av) != len(bv) {
			t.Fatalf("%s: array length differs: want %d, got %d", path, len(av), len(bv))
		}
		for i := range av {
			assertSameKeys(t, path+"[]", av[i], bv[i])
		}
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestManifest_DisclosuresMarshalsAsEmptyArray(t *testing.T) {
	var m Manifest // zero value: Disclosures is nil

	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	disclosures, ok := decoded["disclosures"].([]any)
	if !ok {
		t.Fatalf("disclosures = %#v (%T), want []any", decoded["disclosures"], decoded["disclosures"])
	}
	if len(disclosures) != 0 {
		t.Fatalf("disclosures = %v, want empty", disclosures)
	}
}

func TestBindings_ExtraFieldsFlattenIntoSameObject(t *testing.T) {
	b := Bindings{
		SegmentsRoot:     "sha256:aaa",
		IntentCommitment: "ctx:sha256:bbb",
		Extra: map[string]string{
			"alias_one": "ctx:sha256:bbb",
			"alias_two": "sha256:ccc",
		},
	}

	out, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]string
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(decoded) != 4 {
		t.Fatalf("flattened bindings = %v, want 4 keys", decoded)
	}

	var roundTripped Bindings
	if err := json.Unmarshal(out, &roundTripped); err != nil {
		t.Fatalf("unmarshal into Bindings: %v", err)
	}
	if roundTripped.SegmentsRoot != b.SegmentsRoot || roundTripped.IntentCommitment != b.IntentCommitment {
		t.Fatalf("round-tripped core fields = %+v, want %+v", roundTripped, b)
	}
	if !reflect.DeepEqual(roundTripped.Extra, b.Extra) {
		t.Fatalf("round-tripped Extra = %v, want %v", roundTripped.Extra, b.Extra)
	}
}
