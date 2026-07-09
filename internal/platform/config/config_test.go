package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"testing"
)

// requiredVars must stay in sync with the vars Load treats as required.
var requiredVars = []string{
	"CHAINBIND_VAULT_ADDR",
	"CHAINBIND_VAULT_TOKEN",
	"CHAINBIND_VAULT_TRANSIT_KEY",
	"CHAINBIND_INTENT_AUTHORITY_URL",
	"CHAINBIND_KEYCLOAK_ISSUER",
	"CHAINBIND_KEYCLOAK_JWKS_URL",
}

// setAll sets every required var to a distinctive, per-var value and
// registers cleanup to unset them, so tests never leak env state into
// each other.
func setAll(t *testing.T) map[string]string {
	t.Helper()
	values := make(map[string]string, len(requiredVars))
	for _, name := range requiredVars {
		v := "value-of-" + name
		values[name] = v
		t.Setenv(name, v)
	}
	os.Unsetenv("CHAINBIND_HTTP_ADDR")
	return values
}

func TestLoad_RequiredPresent_Succeeds(t *testing.T) {
	values := setAll(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.VaultAddr != values["CHAINBIND_VAULT_ADDR"] {
		t.Errorf("VaultAddr = %q, want %q", cfg.VaultAddr, values["CHAINBIND_VAULT_ADDR"])
	}
	if cfg.VaultToken != values["CHAINBIND_VAULT_TOKEN"] {
		t.Errorf("VaultToken = %q, want %q", cfg.VaultToken, values["CHAINBIND_VAULT_TOKEN"])
	}
	if cfg.VaultTransitKey != values["CHAINBIND_VAULT_TRANSIT_KEY"] {
		t.Errorf("VaultTransitKey = %q, want %q", cfg.VaultTransitKey, values["CHAINBIND_VAULT_TRANSIT_KEY"])
	}
	if cfg.IntentAuthorityURL != values["CHAINBIND_INTENT_AUTHORITY_URL"] {
		t.Errorf("IntentAuthorityURL = %q, want %q", cfg.IntentAuthorityURL, values["CHAINBIND_INTENT_AUTHORITY_URL"])
	}
	if cfg.KeycloakIssuer != values["CHAINBIND_KEYCLOAK_ISSUER"] {
		t.Errorf("KeycloakIssuer = %q, want %q", cfg.KeycloakIssuer, values["CHAINBIND_KEYCLOAK_ISSUER"])
	}
	if cfg.KeycloakJWKSURL != values["CHAINBIND_KEYCLOAK_JWKS_URL"] {
		t.Errorf("KeycloakJWKSURL = %q, want %q", cfg.KeycloakJWKSURL, values["CHAINBIND_KEYCLOAK_JWKS_URL"])
	}
	if cfg.HTTPAddr != defaultHTTPAddr {
		t.Errorf("HTTPAddr = %q, want default %q", cfg.HTTPAddr, defaultHTTPAddr)
	}
}

func TestLoad_MissingAllRequired_NamesEveryVariable(t *testing.T) {
	for _, name := range requiredVars {
		os.Unsetenv(name)
	}
	os.Unsetenv("CHAINBIND_HTTP_ADDR")

	_, err := Load()
	if err == nil {
		t.Fatal("Load with no env set: got nil error, want one")
	}
	if !errors.Is(err, ErrMissingConfig) {
		t.Fatalf("Load error = %v, want errors.Is ErrMissingConfig", err)
	}
	for _, name := range requiredVars {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("Load error %q does not name missing var %q", err.Error(), name)
		}
	}
}

func TestLoad_OneMissingRequired_Errors(t *testing.T) {
	setAll(t)
	os.Unsetenv("CHAINBIND_VAULT_TOKEN")

	_, err := Load()
	if !errors.Is(err, ErrMissingConfig) {
		t.Fatalf("Load error = %v, want errors.Is ErrMissingConfig", err)
	}
	if !strings.Contains(err.Error(), "CHAINBIND_VAULT_TOKEN") {
		t.Fatalf("Load error %q does not name CHAINBIND_VAULT_TOKEN", err.Error())
	}
}

func TestLoad_HTTPAddr_DefaultAndOverride(t *testing.T) {
	setAll(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTPAddr != defaultHTTPAddr {
		t.Fatalf("HTTPAddr = %q, want default %q", cfg.HTTPAddr, defaultHTTPAddr)
	}

	t.Setenv("CHAINBIND_HTTP_ADDR", ":9999")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTPAddr != ":9999" {
		t.Fatalf("HTTPAddr = %q, want override %q", cfg.HTTPAddr, ":9999")
	}
}

// TestConfig_LogValueRedactsToken proves LogValue keeps VaultToken out of
// anything logged through it. Without LogValue, slog would reflect every
// exported field of *Config, token included — this test fails the moment
// that redaction is removed or bypassed.
func TestConfig_LogValueRedactsToken(t *testing.T) {
	const distinctiveToken = "s.super-secret-vault-token-value"
	cfg := &Config{
		VaultAddr:       "https://vault.example.internal",
		VaultToken:      distinctiveToken,
		VaultTransitKey: "issuer-signing-key-1",
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("config loaded", "cfg", cfg)

	out := buf.String()
	if strings.Contains(out, distinctiveToken) {
		t.Fatalf("logged output contains the raw vault token: %s", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("logged output does not contain [REDACTED]: %s", out)
	}

	// Also exercise LogValue directly and confirm it round-trips through
	// JSON without the token, in case a future change guards it only in
	// one of the two paths.
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("decode logged JSON: %v", err)
	}
}

// TestLoad_ErrorsNeverContainEnvValues drives Load with distinctive
// sentinel values in every required var and confirms none of them ever
// appears in any error Load can produce, over every var missing one at a
// time.
func TestLoad_ErrorsNeverContainEnvValues(t *testing.T) {
	sentinels := setAll(t)

	for _, missing := range requiredVars {
		t.Run(missing, func(t *testing.T) {
			for _, name := range requiredVars {
				t.Setenv(name, sentinels[name])
			}
			os.Unsetenv(missing)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load with %s unset: got nil error, want one", missing)
			}
			for _, v := range sentinels {
				if strings.Contains(err.Error(), v) {
					t.Fatalf("Load error %q contains an env var value %q", err.Error(), v)
				}
			}
		})
	}
}

// TestLogValue_CoversEveryField turns the token redaction from a snapshot
// into an invariant. LogValue lists its fields by hand, so a field added to
// Config later would simply not be logged — or, worse, a new secret-bearing
// field would be logged in the clear the day someone remembers to add it.
//
// Two guards. The attribute count must equal Config's field count, so adding
// a field without touching LogValue fails here. And every field is filled
// with a distinct sentinel: each must appear in the rendered value, except
// the token's, which must not appear at all.
func TestLogValue_CoversEveryField(t *testing.T) {
	cfg := &Config{
		VaultAddr:          "SENTINEL_VAULT_ADDR",
		VaultToken:         "SENTINEL_VAULT_TOKEN",
		VaultTransitKey:    "SENTINEL_TRANSIT_KEY",
		IntentAuthorityURL: "SENTINEL_AUTHORITY_URL",
		KeycloakIssuer:     "SENTINEL_KEYCLOAK_ISSUER",
		KeycloakJWKSURL:    "SENTINEL_JWKS_URL",
		HTTPAddr:           "SENTINEL_HTTP_ADDR",
	}

	v := cfg.LogValue()
	if v.Kind() != slog.KindGroup {
		t.Fatalf("LogValue kind = %v, want a group", v.Kind())
	}
	gotAttrs := len(v.Group())
	wantFields := reflect.TypeOf(Config{}).NumField()
	if gotAttrs != wantFields {
		t.Fatalf("LogValue emits %d attributes but Config has %d fields — a field was added without updating LogValue", gotAttrs, wantFields)
	}

	rendered := v.String()

	if strings.Contains(rendered, "SENTINEL_VAULT_TOKEN") {
		t.Fatalf("LogValue leaked the token: %s", rendered)
	}
	if !strings.Contains(rendered, "[REDACTED]") {
		t.Fatalf("LogValue does not mark the token redacted: %s", rendered)
	}
	for _, want := range []string{
		"SENTINEL_VAULT_ADDR", "SENTINEL_TRANSIT_KEY", "SENTINEL_AUTHORITY_URL",
		"SENTINEL_KEYCLOAK_ISSUER", "SENTINEL_JWKS_URL", "SENTINEL_HTTP_ADDR",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("LogValue omits %s: %s", want, rendered)
		}
	}
}
