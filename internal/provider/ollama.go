package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Max-Christoph/sentinel-dns/internal/config"
)

// OllamaProvider calls a local Ollama daemon with JSON output mode.
type OllamaProvider struct {
	endpoint    string
	model       string
	temperature float64
	numPredict  int
	client      *http.Client
	log         *slog.Logger
}

// NewOllama validates the endpoint and builds the provider.
func NewOllama(cfg config.OllamaConfig, timeout time.Duration, log *slog.Logger) (*OllamaProvider, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if endpoint == "" {
		return nil, errors.New("ollama: endpoint must not be empty")
	}
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		return nil, fmt.Errorf("ollama: endpoint %q must start with http:// or https://", endpoint)
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return nil, errors.New("ollama: model must not be empty")
	}
	if log == nil {
		log = slog.Default()
	}
	return &OllamaProvider{
		endpoint:    endpoint,
		model:       cfg.Model,
		temperature: cfg.Temperature,
		numPredict:  cfg.NumPredict,
		client:      &http.Client{Timeout: timeout},
		log:         log,
	}, nil
}

// Name implements the optional named-provider interface.
func (o *OllamaProvider) Name() string { return "ollama" }

type ollamaRequest struct {
	Model   string         `json:"model"`
	Prompt  string         `json:"prompt"`
	System  string         `json:"system"`
	Stream  bool           `json:"stream"`
	Format  string         `json:"format"`
	Options map[string]any `json:"options,omitempty"`
}

type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
	Error    string `json:"error"`
}

// Classify sends the prompt to /api/generate and parses the JSON answer.
func (o *OllamaProvider) Classify(ctx context.Context, req DecisionRequest) (*DecisionResponse, error) {
	payload := ollamaRequest{
		Model:  o.model,
		Prompt: fewShotPrompt(req),
		System: systemPrompt,
		Stream: false,
		Format: "json",
		Options: map[string]any{
			"temperature": o.temperature,
			"num_predict": o.numPredict,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("ollama: encode request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.endpoint+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ollama: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: ollama: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: ollama: read body: %v", ErrUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: ollama: status %d: %s", ErrUnavailable, resp.StatusCode, truncate(strings.TrimSpace(string(raw)), 200))
	}
	var out ollamaResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%w: ollama: decode envelope: %v", ErrUnavailable, err)
	}
	if out.Error != "" {
		return nil, fmt.Errorf("%w: ollama: %s", ErrUnavailable, truncate(out.Error, 200))
	}
	decision, err := parseDecision(out.Response)
	if err != nil {
		return nil, fmt.Errorf("ollama model %s: %w", o.model, err)
	}
	o.log.Debug("ollama verdict", "domain", req.Domain, "block", decision.Block, "confidence", decision.Confidence)
	return decision, nil
}

var _ DecisionProvider = (*OllamaProvider)(nil)
