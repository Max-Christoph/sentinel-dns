package provider

import (
	"context"
	"testing"
)

func TestHeuristicClassification(t *testing.T) {
	t.Parallel()
	p := NewHeuristic(nil)
	tests := []struct {
		domain       string
		wantBlock    bool
		wantCategory string
	}{
		{"metrics.vendor.example", true, "telemetry"},
		{"app-measurement.com", true, "analytics"},
		{"telemetry-eu.corp.example", true, "telemetry"},
		{"log-ingest.example.net", true, "telemetry"},
		{"ads.doubleclick.net", true, "ads"},
		{"api.github.com", false, "unknown"},
		{"acrobat.com", false, "unknown"},            // "acr" must not match inside a label
		{"logs.example.com", false, "unknown"},       // "log-" prefix only
		{"notmetrics.example.com", false, "unknown"}, // no substring matching for label rules
		{"cdn.example.com", false, "unknown"},
	}
	for _, tc := range tests {
		got, err := p.Classify(context.Background(), DecisionRequest{Domain: tc.domain})
		if err != nil {
			t.Fatalf("%s: unexpected error %v", tc.domain, err)
		}
		if got.Block != tc.wantBlock {
			t.Errorf("%s: block = %v, want %v (reason %q)", tc.domain, got.Block, tc.wantBlock, got.Reason)
		}
		if got.Category != tc.wantCategory {
			t.Errorf("%s: category = %q, want %q", tc.domain, got.Category, tc.wantCategory)
		}
		if got.Confidence < 0 || got.Confidence > 1 {
			t.Errorf("%s: confidence out of range: %v", tc.domain, got.Confidence)
		}
	}
}

func TestHeuristicNormalizesDomain(t *testing.T) {
	t.Parallel()
	p := NewHeuristic(nil)
	got, err := p.Classify(context.Background(), DecisionRequest{Domain: "  METRICS.Vendor.Example. "})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if !got.Block {
		t.Fatalf("upper-case trailing-dot domain was not blocked: %+v", got)
	}
}

func TestHeuristicExtraPatterns(t *testing.T) {
	t.Parallel()
	p := NewHeuristic([]string{"  Track.Vendor.Example. ", ""})
	got, err := p.Classify(context.Background(), DecisionRequest{Domain: "cdn.track.vendor.example"})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if !got.Block || got.Category != "custom" {
		t.Fatalf("extra pattern did not apply: %+v", got)
	}
	if got.Confidence < 0.9 {
		t.Fatalf("confidence = %v, want >= 0.9", got.Confidence)
	}
}

func TestHeuristicCombinesMatches(t *testing.T) {
	t.Parallel()
	p := NewHeuristic(nil)
	got, err := p.Classify(context.Background(), DecisionRequest{Domain: "metrics.analytics.vendor.example"})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if !got.Block {
		t.Fatal("want block")
	}
	if got.Confidence <= 0.85 {
		t.Fatalf("confidence = %v, want multiple matches to add up", got.Confidence)
	}
	if got.Reason == "" {
		t.Fatal("reason must not be empty")
	}
}

func TestHeuristicEmptyDomainIsUnavailable(t *testing.T) {
	t.Parallel()
	if _, err := NewHeuristic(nil).Classify(context.Background(), DecisionRequest{Domain: "  "}); err == nil {
		t.Fatal("want ErrUnavailable for an empty domain")
	}
}
