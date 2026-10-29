package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Max-Christoph/sentinel-dns/internal/config"
)

// SystemOneProvider talks to a decision model through Ollama's /v1/systemone
// endpoint (Clef, Clef-flash, Jev, Nimble). These models answer typed
// questions in one forward pass instead of generating text, so the verdict is
// a probability, not a parsed sentence.
type SystemOneProvider struct {
	endpoint      string
	wantsTracking bool
	wantsCategory bool
	model         string
	apiKey        string
	client        *http.Client
	log           *slog.Logger
	questions     map[string]systemOneQuestion
}

type systemOneQuestion struct {
	Type         string         `json:"type"`
	Instructions string         `json:"instructions"`
	Criteria     map[string]any `json:"criteria,omitempty"`
}

type systemOneRequest struct {
	Model     string                       `json:"model"`
	State     string                       `json:"state"`
	Questions map[string]systemOneQuestion `json:"questions"`
}

type systemOneAnswer struct {
	Type          string             `json:"type"`
	Noul          *float64           `json:"noul"`
	Choice        string             `json:"choice"`
	Confidence    *float64           `json:"confidence"`
	Probabilities map[string]float64 `json:"probabilities"`
}

type systemOneResponse struct {
	Model   string                     `json:"model"`
	Answers map[string]systemOneAnswer `json:"answers"`
	Usage   struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error any `json:"error"`
}

const (
	trackingQuestion = "tracking"
	categoryQuestion = "category"
)

// NewSystemOne resolves the API key and builds the provider. The question set
// is fixed: one noul for the block decision, one choice for the category.
func NewSystemOne(cfg config.SystemOneConfig, timeout time.Duration, log *slog.Logger) (*SystemOneProvider, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		return nil, errors.New("systemone: base_url must not be empty")
	}
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		return nil, fmt.Errorf("systemone: base_url %q must start with http:// or https://", baseURL)
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return nil, errors.New("systemone: model must not be empty")
	}
	// Accept both the API root ("https://ollama.com/v1") and the full endpoint
	// ("https://ollama.com/v1/systemone").
	endpoint := baseURL
	if !strings.HasSuffix(endpoint, "/systemone") {
		endpoint += "/systemone"
	}
	apiKey := strings.TrimSpace(cfg.APIKey)
	if apiKey == "" && strings.TrimSpace(cfg.APIKeyEnv) != "" {
		apiKey = strings.TrimSpace(os.Getenv(cfg.APIKeyEnv))
	}
	if apiKey == "" {
		return nil, fmt.Errorf("systemone: no API key: set api_key or export %s", firstNonEmpty(cfg.APIKeyEnv, "OLLAMA_API_KEY"))
	}
	if log == nil {
		log = slog.Default()
	}
	mode := cfg.Questions
	if mode == "" {
		mode = "tracking" // zero-value config behaves like the default
	}
	questions := make(map[string]systemOneQuestion, 2)
	wantsTracking := mode != "category"
	wantsCategory := mode != "tracking"

	if wantsTracking {
		questions[trackingQuestion] = systemOneQuestion{
			Type: "noul",
			Instructions: "Does this domain primarily serve tracking, user analytics, ads, crash metrics, " +
				"or behavioural profiling, including vendor-specific CDNs serving tracking scripts? " +
				"Answer false for first-party application APIs, multi-tenant content delivery " +
				"(media/static assets), authentication, and essential OS infrastructure. " +
				"Judge only the DNS name; no page content is available.",
		}
	}
	// The category question is optional: it fills device_category but shifts the
	// joint tracking score by up to ±0.44 on borderline names, so the default
	// keeps it out of the decision request and runs it afterwards.
	if wantsCategory {
		questions[categoryQuestion] = systemOneQuestion{
			Type:         "choice",
			Instructions: "What is the primary function of this domain?",
			Criteria: map[string]any{
				"telemetry": "Crash reporting, diagnostics, performance beacons, or device metrics",
				"analytics": "User tracking, event ingestion, customer data platforms, or behavioral profiling",
				"ads":       "Ad delivery, attribution, affiliate pixels, or conversion tracking",
				"benign":    "Core app functionality, static UI assets, generic CDNs, auth, updates, or email",
			},
		}
	}

	return &SystemOneProvider{
		endpoint:      endpoint,
		model:         cfg.Model,
		apiKey:        apiKey,
		client:        &http.Client{Timeout: timeout},
		log:           log,
		questions:     questions,
		wantsTracking: wantsTracking,
		wantsCategory: wantsCategory,
	}, nil
}

// Name implements the optional named-provider interface.
func (s *SystemOneProvider) Name() string { return "systemone" }

// Classify asks both questions in a single request. Block is the majority
// verdict of the noul probability; Confidence is the certainty of that
// verdict (max(p, 1-p)), so a 0.55 probability does not clear the default
// min_confidence of 0.6.
func (s *SystemOneProvider) Classify(ctx context.Context, req DecisionRequest) (*DecisionResponse, error) {
	domain := normalizeDomain(req.Domain)
	if domain == "" {
		return nil, ErrUnavailable
	}
	// The client IP is deliberately not part of the state: it carries no signal
	// about the domain, it would leave the network, and it measurably perturbs
	// the joint score (facebook.net 0.631 vs 0.398 on the same prompt).
	payload := systemOneRequest{Model: s.model, State: "DNS name: " + domain, Questions: s.questions}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("systemone: encode request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("systemone: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+s.apiKey)

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: systemone: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: systemone: read body: %v", ErrUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: systemone: status %d: %s", ErrUnavailable, resp.StatusCode, truncate(strings.TrimSpace(string(raw)), 200))
	}

	var out systemOneResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%w: systemone: decode response: %v", ErrUnavailable, err)
	}
	var (
		block      bool
		confidence float64
		reason     string
	)
	if s.wantsTracking {
		tracking, ok := out.Answers[trackingQuestion]
		if !ok || tracking.Noul == nil {
			return nil, fmt.Errorf("%w: systemone: response has no %q answer", ErrUnavailable, trackingQuestion)
		}
		p := clampProbability(*tracking.Noul)
		block = p >= 0.5
		confidence = math.Max(p, 1-p)
		reason = fmt.Sprintf("noul p=%.3f", p)
	}
	category := "unknown"
	categoryProb := 0.0
	answer, hasCategory := out.Answers[categoryQuestion]
	if s.wantsCategory && (!hasCategory || answer.Choice == "") {
		return nil, fmt.Errorf("%w: systemone: response has no %q answer", ErrUnavailable, categoryQuestion)
	}
	if hasCategory && answer.Choice != "" {
		category = answer.Choice
		categoryProb = clampProbability(answer.Probabilities[category])
		if categoryProb > 0 {
			reason += fmt.Sprintf("; category=%s (%.3f)", category, categoryProb)
		} else {
			reason += "; category=" + category
		}
		if !s.wantsTracking {
			// Category-only mode exists for post-block enrichment.
			confidence = categoryProb
		}
	}

	s.log.Debug("systemone verdict", "domain", domain, "block", block,
		"confidence", confidence, "category", category,
		"input_tokens", out.Usage.InputTokens)
	return &DecisionResponse{
		Block:        block,
		Confidence:   confidence,
		Reason:       reason,
		Category:     category,
		CategoryProb: categoryProb,
	}, nil
}

func clampProbability(p float64) float64 {
	switch {
	case math.IsNaN(p), p < 0:
		return 0
	case p > 1:
		return 1
	default:
		return p
	}
}

var _ DecisionProvider = (*SystemOneProvider)(nil)
