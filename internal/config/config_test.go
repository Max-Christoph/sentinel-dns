package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultIsValid(t *testing.T) {
	t.Parallel()
	if err := Default().Validate(); err != nil {
		t.Fatalf("default config must validate, got: %v", err)
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadMergesOverDefaults(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `
listen:
  udp: "127.0.0.1:5353"
provider:
  type: heuristic
  timeout: "1m30s"
blocking:
  ttl: 60
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen.UDP != "127.0.0.1:5353" {
		t.Errorf("udp = %q, want 127.0.0.1:5353", cfg.Listen.UDP)
	}
	if cfg.Listen.TCP != Default().Listen.TCP {
		t.Errorf("tcp = %q, want the default %q", cfg.Listen.TCP, Default().Listen.TCP)
	}
	if got := cfg.Provider.Timeout.Std(); got != 90*time.Second {
		t.Errorf("provider timeout = %v, want 1m30s", got)
	}
	if cfg.Blocking.TTL != 60 {
		t.Errorf("blocking ttl = %d, want 60", cfg.Blocking.TTL)
	}
	if len(cfg.Upstream.Addresses) == 0 {
		t.Error("upstream defaults were not preserved")
	}
}

func TestLoadRejectsBareNumberDuration(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, "upstream:\n  timeout: 3\n")
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "invalid duration") {
		t.Fatalf("want a duration parse error, got %v", err)
	}
}

func TestLoadRejectsInvalidYAML(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, "listen: [this is not a mapping\n")
	if _, err := Load(path); err == nil {
		t.Fatal("want parse error for malformed YAML")
	}
}

func TestValidateReportsAllProblems(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.Listen.UDP = "not-an-address"
	cfg.Workers.PoolSize = 0
	cfg.Provider.Type = "magic"
	cfg.Blocking.MinConfidence = 1.5

	err := cfg.Validate()
	if err == nil {
		t.Fatal("want validation error")
	}
	msg := err.Error()
	for _, want := range []string{"listen.udp", "workers.pool_size", "provider.type", "blocking.min_confidence"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message %q does not mention %s", msg, want)
		}
	}
}

func TestValidateRejectsBadBlockAddresses(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.Blocking.IPv4 = "::1"
	cfg.Blocking.IPv6 = "0.0.0.0"
	if err := cfg.Validate(); err == nil {
		t.Fatal("want error for swapped IP families")
	}
}

func TestValidateProviderSpecifics(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.Provider.Type = "ollama"
	cfg.Provider.Ollama.Model = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "provider.ollama.model") {
		t.Fatalf("want missing model error, got %v", err)
	}

	cfg = Default()
	cfg.Provider.Type = "openai"
	cfg.Provider.OpenAI.BaseURL = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "provider.openai.base_url") {
		t.Fatalf("want missing base_url error, got %v", err)
	}

	cfg = Default()
	cfg.Provider.Type = "systemone"
	cfg.Provider.SystemOne.Model = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "provider.systemone.model") {
		t.Fatalf("want missing model error, got %v", err)
	}

	cfg = Default()
	cfg.Provider.Type = "systemone"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("systemone defaults must validate, got %v", err)
	}
}
