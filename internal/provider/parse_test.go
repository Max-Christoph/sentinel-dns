package provider

import (
	"errors"
	"strings"
	"testing"
)

func TestParseDecisionAcceptsModelVariants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		raw        string
		wantBlock  bool
		wantConf   float64
		wantReason string
	}{
		{
			name:       "clean json",
			raw:        `{"block":true,"confidence":0.91,"reason":"telemetry endpoint"}`,
			wantBlock:  true,
			wantConf:   0.91,
			wantReason: "telemetry endpoint",
		},
		{
			name:       "code fence",
			raw:        "```json\n{\"block\": false, \"confidence\": 0.4, \"reason\": \"cdn\"}\n```",
			wantBlock:  false,
			wantConf:   0.4,
			wantReason: "cdn",
		},
		{
			name:       "prose around json",
			raw:        `Sure. {"block": true, "confidence": 0.8, "reason": "ads"} Hope that helps.`,
			wantBlock:  true,
			wantConf:   0.8,
			wantReason: "ads",
		},
		{
			name:       "brace inside string",
			raw:        `{"block":true,"confidence":0.7,"reason":"pattern {acr} in host"}`,
			wantBlock:  true,
			wantConf:   0.7,
			wantReason: "pattern {acr} in host",
		},
		{
			name:       "confidence as percent string",
			raw:        `{"block":true,"confidence":"82%","reason":"metrics"}`,
			wantBlock:  true,
			wantConf:   0.82,
			wantReason: "metrics",
		},
		{
			name:       "zero to hundred scale",
			raw:        `{"block":true,"confidence":95,"reason":"firebase"}`,
			wantBlock:  true,
			wantConf:   0.95,
			wantReason: "firebase",
		},
		{
			name:       "is_telemetry alias",
			raw:        `{"is_telemetry":true,"confidence":0.75,"reasoning":"vendor collector"}`,
			wantBlock:  true,
			wantConf:   0.75,
			wantReason: "vendor collector",
		},
		{
			name:       "missing confidence fails safe",
			raw:        `{"block":true,"reason":"guess"}`,
			wantBlock:  true,
			wantConf:   0,
			wantReason: "guess",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseDecision(tc.raw)
			if err != nil {
				t.Fatalf("parseDecision: %v", err)
			}
			if got.Block != tc.wantBlock {
				t.Errorf("block = %v, want %v", got.Block, tc.wantBlock)
			}
			if got.Confidence != tc.wantConf {
				t.Errorf("confidence = %v, want %v", got.Confidence, tc.wantConf)
			}
			if got.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", got.Reason, tc.wantReason)
			}
		})
	}
}

func TestParseDecisionRejectsUnusableOutput(t *testing.T) {
	t.Parallel()
	for name, raw := range map[string]string{
		"empty":        "",
		"prose only":   "I cannot help with that.",
		"no block key": `{"confidence":0.9,"reason":"telemetry"}`,
		"broken json":  `{"block":tru`,
	} {
		raw := raw
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseDecision(raw); err == nil {
				t.Fatalf("want error for %q", raw)
			} else if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("error must wrap ErrUnavailable, got %v", err)
			}
		})
	}
}

func TestParseDecisionCategoryAlias(t *testing.T) {
	t.Parallel()
	got, err := parseDecision(`{"block":true,"confidence":0.9,"reason":"x","device_category":"smart-tv"}`)
	if err != nil {
		t.Fatalf("parseDecision: %v", err)
	}
	if got.Category != "smart-tv" {
		t.Fatalf("category = %q, want smart-tv", got.Category)
	}
}

func TestJSONObjectsIgnoresNestedNoise(t *testing.T) {
	t.Parallel()
	payload := `prefix {"a": {"b": "}"}} suffix {"c":1}`
	got := jsonObjects(payload)
	if len(got) != 2 {
		t.Fatalf("got %d objects (%v), want 2", len(got), got)
	}
	if got[0] != `{"a": {"b": "}"}}` || got[1] != `{"c":1}` {
		t.Fatalf("unexpected objects: %#v", got)
	}
}

func TestStripCodeFenceWithoutNewline(t *testing.T) {
	t.Parallel()
	if got := stripCodeFence("```json"); got != "" {
		t.Fatalf("stripCodeFence = %q, want empty", got)
	}
	if got := stripCodeFence(strings.Repeat(" ", 3) + `{"block":false}`); got != `{"block":false}` {
		t.Fatalf("plain json was modified: %q", got)
	}
}
