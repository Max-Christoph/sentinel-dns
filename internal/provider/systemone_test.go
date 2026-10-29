package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Max-Christoph/sentinel-dns/internal/config"
)

func systemOneServer(t *testing.T, domain string, tracking float64, choice string, choiceProb float64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/systemone" {
			t.Errorf("path = %q, want /v1/systemone", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("authorization = %q", got)
		}
		var body struct {
			Model     string `json:"model"`
			State     string `json:"state"`
			Questions map[string]struct {
				Type         string         `json:"type"`
				Instructions string         `json:"instructions"`
				Criteria     map[string]any `json:"criteria"`
			} `json:"questions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if body.Model != "clef:27b" {
			t.Errorf("model = %q", body.Model)
		}
		if !strings.Contains(body.State, domain) {
			t.Errorf("state does not carry the domain: %q", body.State)
		}
		if body.Questions["tracking"].Type != "noul" {
			t.Errorf("tracking question type = %q, want noul", body.Questions["tracking"].Type)
		}
		if body.Questions["tracking"].Instructions == "" {
			t.Error("tracking question has no instructions")
		}
		cat, ok := body.Questions["category"]
		if !ok || cat.Type != "choice" || len(cat.Criteria) != 4 {
			t.Errorf("category question malformed: %+v", cat)
		}
		for _, want := range []string{"telemetry", "analytics", "ads", "benign"} {
			if _, ok := cat.Criteria[want]; !ok {
				t.Errorf("category criteria missing %q: %+v", want, cat.Criteria)
			}
		}

		answers := map[string]any{
			"tracking": map[string]any{"type": "noul", "noul": tracking},
			"category": map[string]any{
				"type":          "choice",
				"choice":        choice,
				"probabilities": map[string]float64{choice: choiceProb, "benign": 1 - choiceProb},
				"confidence":    choiceProb,
			},
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":   "clef:27b",
			"answers": answers,
			"usage":   map[string]int{"input_tokens": 120, "output_tokens": 3},
		})
	}))
}

func newTestSystemOne(t *testing.T, url string, timeout time.Duration) *SystemOneProvider {
	t.Helper()
	p, err := NewSystemOne(config.SystemOneConfig{
		BaseURL: url + "/v1", Model: "clef:27b", APIKey: "test-key", Questions: "tracking_category",
	}, timeout, discardLogger())
	if err != nil {
		t.Fatalf("NewSystemOne: %v", err)
	}
	return p
}

func TestSystemOneClassify(t *testing.T) {
	t.Parallel()
	srv := systemOneServer(t, "metrics.vendor.example", 0.93, "telemetry", 0.88)
	defer srv.Close()
	p := newTestSystemOne(t, srv.URL, 2*time.Second)

	got, err := p.Classify(context.Background(), DecisionRequest{Domain: "metrics.vendor.example", ClientIP: "10.0.0.5"})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if !got.Block {
		t.Error("p=0.93 must block")
	}
	if got.Confidence != 0.93 {
		t.Errorf("confidence = %v, want 0.93", got.Confidence)
	}
	if got.Category != "telemetry" {
		t.Errorf("category = %q, want telemetry", got.Category)
	}
	if got.CategoryProb != 0.88 {
		t.Errorf("category probability = %v, want 0.88", got.CategoryProb)
	}
	if !strings.Contains(got.Reason, "noul p=0.930") || !strings.Contains(got.Reason, "category=telemetry") {
		t.Errorf("reason does not document the probabilities: %q", got.Reason)
	}
}

func TestSystemOneLowProbabilityDoesNotBlock(t *testing.T) {
	t.Parallel()
	srv := systemOneServer(t, "api.github.com", 0.18, "benign", 0.9)
	defer srv.Close()
	p := newTestSystemOne(t, srv.URL, 2*time.Second)

	got, err := p.Classify(context.Background(), DecisionRequest{Domain: "api.github.com"})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got.Block {
		t.Error("p=0.18 must not block")
	}
	if math.Abs(got.Confidence-0.82) > 1e-9 {
		t.Errorf("confidence = %v, want 0.82", got.Confidence)
	}
	if got.Category != "benign" {
		t.Errorf("category = %q, want benign", got.Category)
	}
}

func TestSystemOneBorderlineIsLowConfidence(t *testing.T) {
	t.Parallel()
	srv := systemOneServer(t, "borderline.example", 0.55, "analytics", 0.5)
	defer srv.Close()
	p := newTestSystemOne(t, srv.URL, 2*time.Second)

	got, err := p.Classify(context.Background(), DecisionRequest{Domain: "borderline.example"})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if !got.Block {
		t.Error("p=0.55 is a (weak) block vote")
	}
	if got.Confidence > 0.6 {
		t.Errorf("confidence = %v, want below the default 0.6 threshold", got.Confidence)
	}
}

func TestSystemOneRejectsMissingAnswer(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"model":"clef:27b","answers":{"category":{"type":"choice","choice":"benign"}}}`)
	}))
	defer srv.Close()
	p := newTestSystemOne(t, srv.URL, 2*time.Second)

	if _, err := p.Classify(context.Background(), DecisionRequest{Domain: "x.example"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

func TestSystemOneSurfacesHTTPError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"message":"state must be a nonempty string, object, or array"}}`)
	}))
	defer srv.Close()
	p := newTestSystemOne(t, srv.URL, 2*time.Second)

	_, err := p.Classify(context.Background(), DecisionRequest{Domain: "x.example"})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
	if !strings.Contains(err.Error(), "state must be") {
		t.Errorf("error lost the body: %v", err)
	}
}

func TestSystemOneHonoursTimeout(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()
	p := newTestSystemOne(t, srv.URL, 50*time.Millisecond)

	start := time.Now()
	if _, err := p.Classify(context.Background(), DecisionRequest{Domain: "x.example"}); err == nil {
		t.Fatal("want timeout error")
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("classify blocked for %v", elapsed)
	}
}

func TestSystemOneTrackingOnlyOmitsCategory(t *testing.T) {
	t.Parallel()
	var questions []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Questions map[string]json.RawMessage `json:"questions"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		for name := range body.Questions {
			questions = append(questions, name)
		}
		_, _ = io.WriteString(w, `{"answers":{"tracking":{"type":"noul","noul":0.93}}}`)
	}))
	defer srv.Close()

	p, err := NewSystemOne(config.SystemOneConfig{BaseURL: srv.URL + "/v1", Model: "clef:27b", APIKey: "k"}, time.Second, discardLogger())
	if err != nil {
		t.Fatalf("NewSystemOne: %v", err)
	}
	got, err := p.Classify(context.Background(), DecisionRequest{Domain: "metrics.vendor.example"})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if len(questions) != 1 || questions[0] != "tracking" {
		t.Fatalf("questions = %v, want only [tracking]", questions)
	}
	if !got.Block || got.Confidence != 0.93 {
		t.Fatalf("unexpected decision: %+v", got)
	}
	if got.Category != "unknown" || got.CategoryProb != 0 {
		t.Fatalf("category must stay empty in tracking-only mode: %+v", got)
	}
}

func TestSystemOneAcceptsFullEndpoint(t *testing.T) {
	t.Parallel()
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, `{"answers":{"tracking":{"type":"noul","noul":0.9},"category":{"type":"choice","choice":"telemetry"}}}`)
	}))
	defer srv.Close()

	p, err := NewSystemOne(config.SystemOneConfig{
		BaseURL: srv.URL + "/v1/systemone",
		Model:   "clef:27b",
		APIKey:  "test-key",
	}, time.Second, discardLogger())
	if err != nil {
		t.Fatalf("NewSystemOne: %v", err)
	}
	if _, err := p.Classify(context.Background(), DecisionRequest{Domain: "x.example"}); err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if gotPath != "/v1/systemone" {
		t.Fatalf("path = %q, want /v1/systemone (no doubled suffix)", gotPath)
	}
}

func TestNewSystemOneRequiresKeyAndURL(t *testing.T) {
	t.Setenv("SENTINEL_ONLINE_KEY", "")
	if _, err := NewSystemOne(config.SystemOneConfig{BaseURL: "https://ollama.com/v1", Model: "clef:27b", APIKeyEnv: "SENTINEL_ONLINE_KEY"}, time.Second, nil); err == nil {
		t.Error("want error when no API key is available")
	}
	if _, err := NewSystemOne(config.SystemOneConfig{BaseURL: "ollama.com", Model: "clef:27b", APIKey: "k"}, time.Second, nil); err == nil {
		t.Error("want error for base_url without scheme")
	}
	if _, err := NewSystemOne(config.SystemOneConfig{BaseURL: "https://ollama.com/v1", APIKey: "k"}, time.Second, nil); err == nil {
		t.Error("want error for missing model")
	}
}
