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
	"os"
	"strings"
	"time"

	"github.com/Max-Christoph/sentinel-dns/internal/config"
)

// OpenAIProvider speaks /v1/chat/completions against OpenAI, Cloudflare
// Workers AI, vLLM, llama.cpp server or any other compatible endpoint.
type OpenAIProvider struct {
	baseURL     string
	model       string
	apiKey      string
	jsonMode    bool
	temperature float64
	headers     map[string]string
	client      *http.Client
	log         *slog.Logger
}

// NewOpenAI resolves the API key (config value first, then environment) and
// builds the provider.
func NewOpenAI(cfg config.OpenAIConfig, timeout time.Duration, log *slog.Logger) (*OpenAIProvider, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		return nil, errors.New("openai: base_url must not be empty")
	}
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		return nil, fmt.Errorf("openai: base_url %q must start with http:// or https://", baseURL)
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return nil, errors.New("openai: model must not be empty")
	}
	apiKey := strings.TrimSpace(cfg.APIKey)
	if apiKey == "" && strings.TrimSpace(cfg.APIKeyEnv) != "" {
		apiKey = strings.TrimSpace(os.Getenv(cfg.APIKeyEnv))
	}
	if apiKey == "" {
		return nil, fmt.Errorf("openai: no API key: set api_key or export %s", firstNonEmpty(cfg.APIKeyEnv, "OPENAI_API_KEY"))
	}
	if log == nil {
		log = slog.Default()
	}
	return &OpenAIProvider{
		baseURL:     baseURL,
		model:       cfg.Model,
		apiKey:      apiKey,
		jsonMode:    cfg.JSONMode,
		temperature: cfg.Temperature,
		headers:     cfg.Headers,
		client:      &http.Client{Timeout: timeout},
		log:         log,
	}, nil
}

// Name implements the optional named-provider interface.
func (o *OpenAIProvider) Name() string { return "openai" }

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model          string          `json:"model"`
	Messages       []chatMessage   `json:"messages"`
	Temperature    float64         `json:"temperature"`
	Stream         bool            `json:"stream"`
	ResponseFormat *responseFormat `json:"response_format,omitempty"`
}

type responseFormat struct {
	Type string `json:"type"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// Classify sends a chat completion request and parses the JSON answer.
func (o *OpenAIProvider) Classify(ctx context.Context, req DecisionRequest) (*DecisionResponse, error) {
	payload := chatRequest{
		Model: o.model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt(req)},
		},
		Temperature: o.temperature,
		Stream:      false,
	}
	if o.jsonMode {
		payload.ResponseFormat = &responseFormat{Type: "json_object"}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("openai: encode request: %w", err)
	}
	url := o.baseURL + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("openai: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+o.apiKey)
	for key, value := range o.headers {
		httpReq.Header.Set(key, value)
	}

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: openai: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: openai: read body: %v", ErrUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: openai: status %d: %s", ErrUnavailable, resp.StatusCode, truncate(strings.TrimSpace(string(raw)), 200))
	}
	var out chatResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%w: openai: decode envelope: %v", ErrUnavailable, err)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("%w: openai: %s", ErrUnavailable, truncate(out.Error.Message, 200))
	}
	if len(out.Choices) == 0 {
		return nil, fmt.Errorf("%w: openai: response contains no choices", ErrUnavailable)
	}
	decision, err := parseDecision(out.Choices[0].Message.Content)
	if err != nil {
		return nil, fmt.Errorf("openai model %s: %w", o.model, err)
	}
	o.log.Debug("openai verdict", "domain", req.Domain, "block", decision.Block, "confidence", decision.Confidence)
	return decision, nil
}

var _ DecisionProvider = (*OpenAIProvider)(nil)
