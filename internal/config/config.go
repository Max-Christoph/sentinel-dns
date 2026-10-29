// Package config loads and validates the sentinel-dns YAML configuration.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a YAML scalar that accepts Go duration strings ("3s", "1m30s").
type Duration time.Duration

// Std returns the wrapped time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// MarshalYAML renders the duration in Go's canonical string form.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// UnmarshalYAML parses a duration string, rejecting bare numbers so that
// "timeout: 3" cannot silently be interpreted as nanoseconds.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return fmt.Errorf("duration must be a string such as \"3s\": %w", err)
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", raw, err)
	}
	if parsed <= 0 {
		return fmt.Errorf("duration %q must be positive", raw)
	}
	*d = Duration(parsed)
	return nil
}

// Config is the complete runtime configuration.
type Config struct {
	Listen   ListenConfig   `yaml:"listen"`
	Upstream UpstreamConfig `yaml:"upstream"`
	Cache    CacheConfig    `yaml:"cache"`
	Database DatabaseConfig `yaml:"database"`
	Workers  WorkerConfig   `yaml:"workers"`
	Provider ProviderConfig `yaml:"provider"`
	Blocking BlockingConfig `yaml:"blocking"`
	Logging  LoggingConfig  `yaml:"logging"`
}

// ListenConfig holds the DNS listener addresses. An empty TCP address disables
// the TCP listener.
type ListenConfig struct {
	UDP string `yaml:"udp"`
	TCP string `yaml:"tcp"`
}

// UpstreamConfig describes the recursive resolvers used for cache misses and
// allow-listed names. Addresses are tried in order.
type UpstreamConfig struct {
	Addresses []string `yaml:"addresses"`
	Timeout   Duration `yaml:"timeout"`
}

// CacheConfig controls the in-memory decision cache.
type CacheConfig struct {
	BlockedTTL Duration `yaml:"blocked_ttl"`
	AllowedTTL Duration `yaml:"allowed_ttl"`
	MaxEntries int      `yaml:"max_entries"`
}

// DatabaseConfig points at the SQLite file. The directory is created on
// startup.
type DatabaseConfig struct {
	Path string `yaml:"path"`
}

// WorkerConfig sizes the asynchronous classification pool.
type WorkerConfig struct {
	PoolSize   int      `yaml:"pool_size"`
	QueueSize  int      `yaml:"queue_size"`
	JobTimeout Duration `yaml:"job_timeout"`
}

// ProviderConfig selects and configures the classification backend.
type ProviderConfig struct {
	Type      string          `yaml:"type"`
	Timeout   Duration        `yaml:"timeout"`
	Ollama    OllamaConfig    `yaml:"ollama"`
	OpenAI    OpenAIConfig    `yaml:"openai"`
	SystemOne SystemOneConfig `yaml:"systemone"`
	Heuristic HeuristicConfig `yaml:"heuristic"`
}

// OllamaConfig targets a local Ollama daemon.
type OllamaConfig struct {
	Endpoint    string  `yaml:"endpoint"`
	Model       string  `yaml:"model"`
	Temperature float64 `yaml:"temperature"`
	NumPredict  int     `yaml:"num_predict"`
}

// OpenAIConfig targets any OpenAI-compatible /v1/chat/completions endpoint.
type OpenAIConfig struct {
	BaseURL     string            `yaml:"base_url"`
	Model       string            `yaml:"model"`
	APIKey      string            `yaml:"api_key"`
	APIKeyEnv   string            `yaml:"api_key_env"`
	JSONMode    bool              `yaml:"json_mode"`
	Temperature float64           `yaml:"temperature"`
	Headers     map[string]string `yaml:"headers"`
}

// SystemOneConfig targets a decision model served through Ollama's
// /v1/systemone endpoint (Clef, Clef-flash, Jev). Unlike chat models these
// answer typed questions and return probabilities.
type SystemOneConfig struct {
	BaseURL   string `yaml:"base_url"`
	Model     string `yaml:"model"`
	APIKey    string `yaml:"api_key"`
	APIKeyEnv string `yaml:"api_key_env"`
	// Questions selects the request shape. Clef scores every question in one
	// joint pass, so asking for the category changes the tracking probability:
	// "tracking" (default) is the measured, well-separated variant;
	// "tracking_category" also fills device_category, at the cost of noisier
	// borderline scores; "category" asks only the label question and is used
	// for the post-block enrichment call.
	Questions string `yaml:"questions"`
	// EnrichCategory runs a second, category-only request for blocked domains
	// so the first-line decision stays on the well-separated prompt.
	EnrichCategory bool `yaml:"enrich_category"`
}

// HeuristicConfig configures the zero-AI fallback provider.
type HeuristicConfig struct {
	ExtraPatterns []string `yaml:"extra_patterns"`
}

// BlockingConfig controls the sinkhole answers and the decision threshold.
type BlockingConfig struct {
	IPv4                   string  `yaml:"ipv4"`
	IPv6                   string  `yaml:"ipv6"`
	TTL                    uint32  `yaml:"ttl"`
	MinConfidence          float64 `yaml:"min_confidence"`
	CategoryMinProbability float64 `yaml:"category_min_probability"`
	// Allowlist entries are never sinkholed: exact names or suffix matches
	// ("google.com" covers "gemini.google.com"). Critical infrastructure goes
	// here because a false positive on a core endpoint looks like a broken
	// internet connection, not like a blocked tracker.
	Allowlist []string `yaml:"allowlist"`
	// FilterAAAA answers every AAAA query with an empty NOERROR. Use it on
	// networks where the router advertises IPv6 without providing a working
	// upstream: clients then stop waiting on unreachable AAAA addresses.
	FilterAAAA bool `yaml:"filter_aaaa"`
}

// LoggingConfig configures slog.
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Default returns a configuration that works on a fresh host with a local
// Ollama-free setup: heuristic provider, loopback database, port 53 listeners.
func Default() Config {
	return Config{
		Listen: ListenConfig{UDP: "0.0.0.0:53", TCP: "0.0.0.0:53"},
		Upstream: UpstreamConfig{
			Addresses: []string{"9.9.9.9:53", "149.112.112.112:53"},
			Timeout:   Duration(2 * time.Second),
		},
		Cache: CacheConfig{
			BlockedTTL: Duration(300 * time.Second),
			AllowedTTL: Duration(600 * time.Second),
			MaxEntries: 50_000,
		},
		Database: DatabaseConfig{Path: "/var/lib/sentinel-dns/sentinel.db"},
		Workers: WorkerConfig{
			PoolSize:   3,
			QueueSize:  1024,
			JobTimeout: Duration(25 * time.Second),
		},
		Provider: ProviderConfig{
			Type:    "heuristic",
			Timeout: Duration(20 * time.Second),
			Ollama: OllamaConfig{
				Endpoint:    "http://127.0.0.1:11434",
				Model:       "d1",
				Temperature: 0.1,
				NumPredict:  128,
			},
			OpenAI: OpenAIConfig{
				BaseURL:     "https://api.openai.com/v1",
				Model:       "gpt-4o-mini",
				APIKeyEnv:   "OPENAI_API_KEY",
				JSONMode:    true,
				Temperature: 0,
			},
			SystemOne: SystemOneConfig{
				BaseURL:        "https://ollama.com/v1",
				Model:          "clef:27b",
				APIKeyEnv:      "OLLAMA_API_KEY",
				Questions:      "tracking",
				EnrichCategory: true,
			},
		},
		Blocking: BlockingConfig{
			IPv4:                   "0.0.0.0",
			IPv6:                   "::",
			TTL:                    300,
			MinConfidence:          0.6,
			CategoryMinProbability: 0.7,
			Allowlist: []string{
				"google.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
				"googlevideo.com", "gvt1.com",
				"msftncsi.com", "msftconnecttest.com", "windowsupdate.com",
				"captive.apple.com", "detectportal.firefox.com",
				"connectivitycheck.gstatic.com", "connectivitycheck.android.com",
				"ocsp.digicert.com", "ocsp.sectigo.com",
			},
		},
		Logging: LoggingConfig{Level: "info", Format: "text"},
	}
}

// Load reads path, applies it over the defaults and validates the result.
func Load(path string) (Config, error) {
	cfg := Default()
	if strings.TrimSpace(path) == "" {
		return cfg, errors.New("config path must not be empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return cfg, nil
}

// Validate reports every problem it finds instead of stopping at the first.
func (c Config) Validate() error {
	var errs []error
	if c.Listen.UDP == "" && c.Listen.TCP == "" {
		errs = append(errs, errors.New("listen.udp and listen.tcp must not both be empty"))
	}
	for name, addr := range map[string]string{"listen.udp": c.Listen.UDP, "listen.tcp": c.Listen.TCP} {
		if addr == "" {
			continue
		}
		if err := validateHostPort(addr); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	if len(c.Upstream.Addresses) == 0 {
		errs = append(errs, errors.New("upstream.addresses must contain at least one resolver"))
	}
	for _, addr := range c.Upstream.Addresses {
		if err := validateHostPort(addr); err != nil {
			errs = append(errs, fmt.Errorf("upstream address %q: %w", addr, err))
		}
	}
	if c.Upstream.Timeout.Std() <= 0 {
		errs = append(errs, errors.New("upstream.timeout must be positive"))
	}
	if c.Cache.BlockedTTL.Std() <= 0 || c.Cache.AllowedTTL.Std() <= 0 {
		errs = append(errs, errors.New("cache.blocked_ttl and cache.allowed_ttl must be positive"))
	}
	if c.Cache.MaxEntries < 0 {
		errs = append(errs, errors.New("cache.max_entries must not be negative"))
	}
	if strings.TrimSpace(c.Database.Path) == "" {
		errs = append(errs, errors.New("database.path must not be empty"))
	}
	if c.Workers.PoolSize < 1 || c.Workers.PoolSize > 32 {
		errs = append(errs, fmt.Errorf("workers.pool_size must be between 1 and 32, got %d", c.Workers.PoolSize))
	}
	if c.Workers.QueueSize < 1 {
		errs = append(errs, errors.New("workers.queue_size must be positive"))
	}
	if c.Workers.JobTimeout.Std() <= 0 {
		errs = append(errs, errors.New("workers.job_timeout must be positive"))
	}
	switch c.Provider.Type {
	case "heuristic":
	case "ollama":
		if strings.TrimSpace(c.Provider.Ollama.Endpoint) == "" {
			errs = append(errs, errors.New("provider.ollama.endpoint must not be empty"))
		}
		if strings.TrimSpace(c.Provider.Ollama.Model) == "" {
			errs = append(errs, errors.New("provider.ollama.model must not be empty"))
		}
	case "openai":
		if strings.TrimSpace(c.Provider.OpenAI.BaseURL) == "" {
			errs = append(errs, errors.New("provider.openai.base_url must not be empty"))
		}
		if strings.TrimSpace(c.Provider.OpenAI.Model) == "" {
			errs = append(errs, errors.New("provider.openai.model must not be empty"))
		}
	case "systemone":
		if strings.TrimSpace(c.Provider.SystemOne.BaseURL) == "" {
			errs = append(errs, errors.New("provider.systemone.base_url must not be empty"))
		}
		if strings.TrimSpace(c.Provider.SystemOne.Model) == "" {
			errs = append(errs, errors.New("provider.systemone.model must not be empty"))
		}
		switch c.Provider.SystemOne.Questions {
		case "tracking", "tracking_category", "category":
		default:
			errs = append(errs, fmt.Errorf("provider.systemone.questions %q must be tracking, tracking_category or category", c.Provider.SystemOne.Questions))
		}
	default:
		errs = append(errs, fmt.Errorf("provider.type %q must be one of heuristic, ollama, openai, systemone", c.Provider.Type))
	}
	if c.Provider.Timeout.Std() <= 0 {
		errs = append(errs, errors.New("provider.timeout must be positive"))
	}
	if net.ParseIP(c.Blocking.IPv4) == nil || net.ParseIP(c.Blocking.IPv4).To4() == nil {
		errs = append(errs, fmt.Errorf("blocking.ipv4 %q is not an IPv4 address", c.Blocking.IPv4))
	}
	if ip := net.ParseIP(c.Blocking.IPv6); ip == nil || ip.To4() != nil {
		errs = append(errs, fmt.Errorf("blocking.ipv6 %q is not an IPv6 address", c.Blocking.IPv6))
	}
	if c.Blocking.TTL == 0 {
		errs = append(errs, errors.New("blocking.ttl must be greater than zero"))
	}
	if c.Blocking.MinConfidence < 0 || c.Blocking.MinConfidence > 1 {
		errs = append(errs, fmt.Errorf("blocking.min_confidence must be within [0,1], got %v", c.Blocking.MinConfidence))
	}
	if c.Blocking.CategoryMinProbability < 0 || c.Blocking.CategoryMinProbability > 1 {
		errs = append(errs, fmt.Errorf("blocking.category_min_probability must be within [0,1], got %v", c.Blocking.CategoryMinProbability))
	}
	switch strings.ToLower(c.Logging.Level) {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("logging.level %q must be debug, info, warn or error", c.Logging.Level))
	}
	switch strings.ToLower(c.Logging.Format) {
	case "text", "json":
	default:
		errs = append(errs, fmt.Errorf("logging.format %q must be text or json", c.Logging.Format))
	}
	return errors.Join(errs...)
}

func validateHostPort(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("expected host:port, got %q: %w", addr, err)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("host must not be empty in %q", addr)
	}
	num, err := strconv.Atoi(port)
	if err != nil || num < 1 || num > 65535 {
		return fmt.Errorf("port must be 1-65535 in %q", addr)
	}
	return nil
}
