package config

import (
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg, err := LoadFrom(nil, func(string) string { return "" })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.WorkloadAPIAddr != "unix:///tmp/spire-agent/public/api.sock" {
		t.Errorf("unexpected WorkloadAPIAddr: %q", cfg.WorkloadAPIAddr)
	}
	if cfg.Port != 80 {
		t.Errorf("unexpected Port: %d", cfg.Port)
	}
	if cfg.JWTAudience != "spiffe-info" {
		t.Errorf("unexpected JWTAudience: %q", cfg.JWTAudience)
	}
}

func TestFlagsOverrideDefaults(t *testing.T) {
	cfg, err := LoadFrom(
		[]string{"--port", "8080", "--jwt-audience", "my-svc", "--workload-api-addr", "unix:///run/spire.sock"},
		func(string) string { return "" },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != 8080 {
		t.Errorf("unexpected Port: %d", cfg.Port)
	}
	if cfg.JWTAudience != "my-svc" {
		t.Errorf("unexpected JWTAudience: %q", cfg.JWTAudience)
	}
	if cfg.WorkloadAPIAddr != "unix:///run/spire.sock" {
		t.Errorf("unexpected WorkloadAPIAddr: %q", cfg.WorkloadAPIAddr)
	}
}

func TestEnvVarsApply(t *testing.T) {
	env := map[string]string{
		"PORT":                   "9090",
		"SPIFFE_ENDPOINT_SOCKET": "unix:///custom.sock",
		"JWT_AUDIENCE":           "env-audience",
	}
	cfg, err := LoadFrom(nil, func(key string) string { return env[key] })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != 9090 {
		t.Errorf("unexpected Port: %d", cfg.Port)
	}
	if cfg.WorkloadAPIAddr != "unix:///custom.sock" {
		t.Errorf("unexpected WorkloadAPIAddr: %q", cfg.WorkloadAPIAddr)
	}
	if cfg.JWTAudience != "env-audience" {
		t.Errorf("unexpected JWTAudience: %q", cfg.JWTAudience)
	}
}

func TestFlagOverridesEnv(t *testing.T) {
	cfg, err := LoadFrom(
		[]string{"--port", "7070"},
		func(key string) string {
			if key == "PORT" {
				return "9090"
			}
			return ""
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != 7070 {
		t.Errorf("flag should override env: got %d", cfg.Port)
	}
}
