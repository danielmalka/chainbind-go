// Package config loads the deployed shell's configuration from the
// environment only (TECHSPEC-001 §6.6 decision 6: os.Getenv, no
// viper/flag framework — nothing here needs one). Load is the single
// place that reads os.Getenv so every other component can depend on a
// typed Config instead of scattering lookups.
//
// A missing required variable is a startup error, never a silent zero
// value: an empty VaultToken that reaches the Vault signer adapter would
// fail far from here, with a confusing symptom. Load reports every
// missing variable at once so a developer does not have to run the
// binary once per missing var.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// ErrMissingConfig is the sentinel Load wraps when one or more required
// environment variables are unset. The wrapping error names every missing
// variable; it never names or carries a value (AGENTS.local.md invariant
// 10 — this applies to env var values exactly as it does to plaintext).
var ErrMissingConfig = errors.New("config: missing required environment variables")

const defaultHTTPAddr = ":8080"

// Config holds the deployed shell's settings. It is safe to log: LogValue
// redacts VaultToken. That safety is the reason this type exists instead
// of components calling os.Getenv directly — a raw token is one careless
// slog.Info away from an aggregator.
type Config struct {
	// VaultAddr is the base URL of the Vault server the Transit signer
	// adapter calls. Required: the adapter cannot sign without it.
	VaultAddr string

	// VaultToken authenticates to Vault. Required. Never logged, never
	// placed in an error string.
	VaultToken string

	// VaultTransitKey names the Transit key the issuer signs with.
	// Required.
	VaultTransitKey string

	// IntentAuthorityURL is the base URL of the Intent Authority the HTTP
	// IntentVerifier adapter calls. Required: Seal fails closed without a
	// reachable authority (D-006), so a shell that cannot even locate one
	// should not start.
	IntentAuthorityURL string

	// KeycloakIssuer is the expected `iss` claim on tokens the shell
	// accepts. Required once the shell authenticates callers (TASK-001-12).
	KeycloakIssuer string

	// KeycloakJWKSURL is where the shell fetches Keycloak's signing keys.
	// Required for the same reason as KeycloakIssuer.
	KeycloakJWKSURL string

	// HTTPAddr is the shell's listen address. Optional: defaults to
	// ":8080" when unset, since a demo/dev deployment has no reason to
	// fail startup over a listen address it can reasonably default.
	HTTPAddr string
}

// envSpec names an environment variable and the Config field it fills.
type envSpec struct {
	name string
	dst  *string
}

// Load reads Config from the environment. It returns an error wrapping
// ErrMissingConfig, naming every unset required variable, if any required
// variable is unset. HTTPAddr defaults to ":8080" when unset.
func Load() (*Config, error) {
	cfg := &Config{}

	required := []envSpec{
		{"CHAINBIND_VAULT_ADDR", &cfg.VaultAddr},
		{"CHAINBIND_VAULT_TOKEN", &cfg.VaultToken},
		{"CHAINBIND_VAULT_TRANSIT_KEY", &cfg.VaultTransitKey},
		{"CHAINBIND_INTENT_AUTHORITY_URL", &cfg.IntentAuthorityURL},
		{"CHAINBIND_KEYCLOAK_ISSUER", &cfg.KeycloakIssuer},
		{"CHAINBIND_KEYCLOAK_JWKS_URL", &cfg.KeycloakJWKSURL},
	}

	var missing []string
	for _, spec := range required {
		v := os.Getenv(spec.name)
		if v == "" {
			missing = append(missing, spec.name)
			continue
		}
		*spec.dst = v
	}

	cfg.HTTPAddr = os.Getenv("CHAINBIND_HTTP_ADDR")
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = defaultHTTPAddr
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrMissingConfig, strings.Join(missing, ", "))
	}

	return cfg, nil
}

// LogValue implements slog.LogValuer so a Config can be passed straight
// to slog without leaking VaultToken. This is the control that makes
// "safe to log" true rather than aspirational: without it, slog would
// reflect every exported field, token included.
func (c *Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("vault_addr", c.VaultAddr),
		slog.String("vault_token", "[REDACTED]"),
		slog.String("vault_transit_key", c.VaultTransitKey),
		slog.String("intent_authority_url", c.IntentAuthorityURL),
		slog.String("keycloak_issuer", c.KeycloakIssuer),
		slog.String("keycloak_jwks_url", c.KeycloakJWKSURL),
		slog.String("http_addr", c.HTTPAddr),
	)
}
