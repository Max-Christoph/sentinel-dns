package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Max-Christoph/sentinel-dns/internal/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestOllamaClassify(t *testing.T) {
	t.Parallel()
	var gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request: %v", err)
		}
		_, _ = io.WriteString(w, `{"response":"{\"block\":true,\"confidence\":0.93,\"reason\":\"metrics label\",\"category\":\"telemetry\"}","done":true}`)
	}))
	defer srv.Close()

	p, err := NewOllama(config.OllamaConfig{Endpoint: srv.URL, Model: "d1", Temperature: 0.1, NumPredict: 96}, 2*time.Second, discardLogger())
	if err != nil {
		t.Fatalf("NewOllama: %v", err)
	}
	got, err := p.Classify(context.Background(), DecisionRequest{Domain: "metrics.vendor.example", ClientIP: "10.0.0.5"})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if !got.Block || got.Confidence != 0.93 || got.Category != "telemetry" {
		t.Fatalf("unexpected decision: %+v", got)
	}
	if gotPath != "/api/generate" {
		t.Errorf("path = %q, want /api/generate", gotPath)
	}
	if gotBody["format"] != "json" || gotBody["stream"] != false {
		t.Errorf("request must force JSON mode and disable streaming: %v", gotBody)
	}
	if !strings.Contains(gotBody["prompt"].(string), "metrics.vendor.example") {
		t.Errorf("prompt does not carry the domain: %v", gotBody["prompt"])
	}
}

func TestOllamaSurfacesBackendErrors(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "model not found", http.StatusNotFound)
	}))
	defer srv.Close()

	p, err := NewOllama(config.OllamaConfig{Endpoint: srv.URL, Model: "nope"}, time.Second, discardLogger())
	if err != nil {
		t.Fatalf("NewOllama: %v", err)
	}
	_, err = p.Classify(context.Background(), DecisionRequest{Domain: "x.example"})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

func TestOllamaHonoursTimeout(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(w, `{"response":"{}"}`)
	}))
	defer srv.Close()

	p, err := NewOllama(config.OllamaConfig{Endpoint: srv.URL, Model: "slow"}, 50*time.Millisecond, discardLogger())
	if err != nil {
		t.Fatalf("NewOllama: %v", err)
	}
	start := time.Now()
	if _, err := p.Classify(context.Background(), DecisionRequest{Domain: "x.example"}); err == nil {
		t.Fatal("want timeout error")
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("classify blocked for %v, want ~50ms", elapsed)
	}
}

func TestOllamaRejectsInvalidJSONPayload(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"response":"not json at all","done":true}`)
	}))
	defer srv.Close()
	p, err := NewOllama(config.OllamaConfig{Endpoint: srv.URL, Model: "small"}, time.Second, discardLogger())
	if err != nil {
		t.Fatalf("NewOllama: %v", err)
	}
	if _, err := p.Classify(context.Background(), DecisionRequest{Domain: "x.example"}); err == nil {
		t.Fatal("want parse error")
	}
}

func TestNewOllamaValidatesConfig(t *testing.T) {
	t.Parallel()
	if _, err := NewOllama(config.OllamaConfig{Endpoint: "127.0.0.1:11434", Model: "d1"}, time.Second, nil); err == nil {
		t.Error("want error for endpoint without scheme")
	}
	if _, err := NewOllama(config.OllamaConfig{Endpoint: "http://localhost:11434"}, time.Second, nil); err == nil {
		t.Error("want error for missing model")
	}
}
