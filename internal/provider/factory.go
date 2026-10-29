package provider

import (
	"fmt"
	"log/slog"

	"github.com/Max-Christoph/sentinel-dns/internal/config"
)

// New builds the configured provider. Validation of provider-specific fields
// already happened in config.Validate; this only checks construction-time
// constraints such as a missing API key.
func New(cfg config.ProviderConfig, log *slog.Logger) (DecisionProvider, error) {
	if log == nil {
		log = slog.Default()
	}
	switch cfg.Type {
	case "heuristic":
		return NewHeuristic(cfg.Heuristic.ExtraPatterns), nil
	case "ollama":
		return NewOllama(cfg.Ollama, cfg.Timeout.Std(), log)
	case "openai":
		return NewOpenAI(cfg.OpenAI, cfg.Timeout.Std(), log)
	case "systemone":
		return NewSystemOne(cfg.SystemOne, cfg.Timeout.Std(), log)
	default:
		return nil, fmt.Errorf("provider: unsupported type %q", cfg.Type)
	}
}
