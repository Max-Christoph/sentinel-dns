package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Max-Christoph/sentinel-dns/internal/config"
)

func TestOpenAIClassify(t *testing.T) {
	t.Parallel()
	var (
		authHeader   string
		gotFormat    string
		gotModel     string
		customHeader string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("path = %q, want /v1/chat/completions", r.URL.Path)
		}
		authHeader = r.Header.Get("Authorization")
		customHeader = r.Header.Get("cf-aig-authorization")
		var body struct {
			Model          string `json:"model"`
			ResponseFormat *struct {
				Type string `json:"type"`
			} `json:"response_format"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode: %v", err)
		}
		gotModel = body.Model
		if body.ResponseFormat != nil {
			gotFormat = body.ResponseFormat.Type
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"{\"block\":false,\"confidence\":0.3,\"reason\":\"developer API\"}"},"finish_reason":"stop"}]}`)
	}))
	defer srv.Close()

	cfg := config.OpenAIConfig{
		BaseURL:     srv.URL + "/v1",
		Model:       "test-model",
		APIKey:      "sk-test",
		JSONMode:    true,
		Temperature: 0,
		Headers:     map[string]string{"cf-aig-authorization": "Bearer extra"},
	}
	p, err := NewOpenAI(cfg, 2*time.Second, discardLogger())
	if err != nil {
		t.Fatalf("NewOpenAI: %v", err)
	}
	got, err := p.Classify(context.Background(), DecisionRequest{Domain: "api.github.com"})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got.Block || got.Confidence != 0.3 {
		t.Fatalf("unexpected decision: %+v", got)
	}
	if authHeader != "Bearer sk-test" {
		t.Errorf("authorization = %q", authHeader)
	}
	if customHeader != "Bearer extra" {
		t.Errorf("custom header = %q", customHeader)
	}
	if gotFormat != "json_object" {
		t.Errorf("response_format = %q, want json_object", gotFormat)
	}
	if gotModel != "test-model" {
		t.Errorf("model = %q", gotModel)
	}
}

func TestOpenAIRequiresAPIKey(t *testing.T) {
	t.Setenv("SENTINEL_TEST_KEY", "")
	cfg := config.OpenAIConfig{BaseURL: "https://example.invalid/v1", Model: "m", APIKeyEnv: "SENTINEL_TEST_KEY"}
	if _, err := NewOpenAI(cfg, time.Second, nil); err == nil {
		t.Fatal("want error when no API key is available")
	}
	t.Setenv("SENTINEL_TEST_KEY", "from-env")
	if _, err := NewOpenAI(cfg, time.Second, nil); err != nil {
		t.Fatalf("env key was not picked up: %v", err)
	}
}

func TestOpenAIErrorPaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		status  int
		payload string
	}{
		{"http error", http.StatusUnauthorized, `{"error":{"message":"bad key","type":"auth"}}`},
		{"empty choices", http.StatusOK, `{"choices":[]}`},
		{"garbled content", http.StatusOK, `{"choices":[{"message":{"content":"no json"}}]}`},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.payload)
			}))
			defer srv.Close()
			p, err := NewOpenAI(config.OpenAIConfig{BaseURL: srv.URL, Model: "m", APIKey: "k"}, time.Second, discardLogger())
			if err != nil {
				t.Fatalf("NewOpenAI: %v", err)
			}
			_, err = p.Classify(context.Background(), DecisionRequest{Domain: "x.example"})
			if err == nil {
				t.Fatal("want error")
			}
			if tc.status != http.StatusOK && !errors.Is(err, ErrUnavailable) {
				t.Fatalf("HTTP failures must wrap ErrUnavailable, got %v", err)
			}
		})
	}
}

func TestFactory(t *testing.T) {
	t.Parallel()
	p, err := New(config.ProviderConfig{Type: "heuristic"}, discardLogger())
	if err != nil {
		t.Fatalf("New(heuristic): %v", err)
	}
	if Name(p) != "heuristic" {
		t.Fatalf("name = %q, want heuristic", Name(p))
	}
	if _, err := New(config.ProviderConfig{Type: "bogus"}, discardLogger()); err == nil {
		t.Fatal("want error for unknown provider type")
	}
}
