package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// parseDecision extracts a DecisionResponse from arbitrary model output.
// Small models wrap JSON in prose or code fences, so the parser scans for the
// first balanced JSON object instead of assuming a clean payload.
func parseDecision(raw string) (*DecisionResponse, error) {
	trimmed := strings.TrimSpace(stripCodeFence(raw))
	if trimmed == "" {
		return nil, fmt.Errorf("%w: empty model response", ErrUnavailable)
	}
	candidates := jsonObjects(trimmed)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("%w: no JSON object in response %q", ErrUnavailable, truncate(trimmed, 200))
	}
	var lastErr error
	for _, candidate := range candidates {
		decision, err := decodeDecision(candidate)
		if err != nil {
			lastErr = err
			continue
		}
		return decision, nil
	}
	return nil, fmt.Errorf("%w: %v", ErrUnavailable, lastErr)
}

type wireDecision struct {
	Block          *bool           `json:"block"`
	ShouldBlock    *bool           `json:"should_block"`
	IsTelemetry    *bool           `json:"is_telemetry"`
	Confidence     json.RawMessage `json:"confidence"`
	Reason         string          `json:"reason"`
	Reasoning      string          `json:"reasoning"`
	Category       string          `json:"category"`
	DeviceCategory string          `json:"device_category"`
}

func decodeDecision(payload string) (*DecisionResponse, error) {
	var wire wireDecision
	if err := json.Unmarshal([]byte(payload), &wire); err != nil {
		return nil, fmt.Errorf("decode decision: %w", err)
	}

	block, ok := firstBool(wire.Block, wire.ShouldBlock, wire.IsTelemetry)
	if !ok {
		return nil, errors.New(`decision lacks a boolean "block" field`)
	}
	confidence := 0.0
	if v, ok := parseConfidence(wire.Confidence); ok {
		confidence = v
	}
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 1 {
		// Models occasionally answer on a 0-100 scale.
		if confidence <= 100 {
			confidence /= 100
		} else {
			confidence = 1
		}
	}
	reason := strings.TrimSpace(firstNonEmpty(wire.Reason, wire.Reasoning))
	if reason == "" {
		reason = "model returned no reasoning"
	}
	category := strings.TrimSpace(firstNonEmpty(wire.Category, wire.DeviceCategory))
	return &DecisionResponse{
		Block:      block,
		Confidence: confidence,
		Reason:     reason,
		Category:   category,
	}, nil
}

// stripCodeFence removes a leading ```json / ``` fence and the closing fence.
func stripCodeFence(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		s = s[idx+1:]
	} else {
		return ""
	}
	if idx := strings.LastIndex(s, "```"); idx >= 0 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

// jsonObjects returns every balanced {...} block, outermost first, skipping
// braces inside JSON strings.
func jsonObjects(s string) []string {
	var (
		out     []string
		depth   int
		start   = -1
		inStr   bool
		escaped bool
	)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			if depth == 0 {
				continue
			}
			depth--
			if depth == 0 && start >= 0 {
				out = append(out, s[start:i+1])
				start = -1
			}
		}
	}
	return out
}

func firstBool(values ...*bool) (bool, bool) {
	for _, v := range values {
		if v != nil {
			return *v, true
		}
	}
	return false, false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// parseConfidence accepts a JSON number or a string ("0.82", "82%").
func parseConfidence(raw json.RawMessage) (float64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return f, true
	}
	return numericString(raw)
}

// numericString accepts a confidence value that was serialized as a string
// ("0.82", "82%").
func numericString(raw json.RawMessage) (float64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, false
	}
	s = strings.TrimSpace(s)
	scale := 1.0
	if strings.HasSuffix(s, "%") {
		scale = 100
		s = strings.TrimSpace(strings.TrimSuffix(s, "%"))
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v / scale, true
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
