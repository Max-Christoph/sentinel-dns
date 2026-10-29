package provider

import (
	"context"
	"strings"
)

// matchKind describes how a heuristic pattern is compared with the domain.
type matchKind int

const (
	// matchLabel matches a complete DNS label ("metrics.example.com").
	matchLabel matchKind = iota
	// matchLabelPrefix matches a label prefix ("log-", "acr").
	matchLabelPrefix
	// matchSuffix matches the registrable suffix ("doubleclick.net").
	matchSuffix
)

type heuristicRule struct {
	pattern  string
	kind     matchKind
	category string
	weight   float64
	reason   string
}

// defaultRules is a deliberately small, auditable baseline. It is the
// zero-AI fallback and must stay predictable: no fuzzy matching, no scoring
// surprises.
var defaultRules = []heuristicRule{
	{pattern: "metrics", kind: matchLabel, category: "telemetry", weight: 0.80, reason: "metrics endpoint label"},
	{pattern: "telemetry", kind: matchLabel, category: "telemetry", weight: 0.90, reason: "explicit telemetry label"},
	{pattern: "analytics", kind: matchLabel, category: "analytics", weight: 0.85, reason: "analytics label"},
	{pattern: "tracking", kind: matchLabel, category: "tracking", weight: 0.88, reason: "tracking label"},
	{pattern: "tracker", kind: matchLabel, category: "tracking", weight: 0.88, reason: "tracker label"},
	{pattern: "stats", kind: matchLabel, category: "analytics", weight: 0.78, reason: "statistics label"},
	{pattern: "collector", kind: matchLabel, category: "telemetry", weight: 0.82, reason: "collector label"},
	{pattern: "beacon", kind: matchLabel, category: "telemetry", weight: 0.80, reason: "beacon label"},
	{pattern: "pixel", kind: matchLabel, category: "ads", weight: 0.78, reason: "tracking pixel label"},
	{pattern: "acr", kind: matchLabel, category: "telemetry", weight: 0.75, reason: "Samsung ACR label"},
	{pattern: "app-measurement", kind: matchLabel, category: "analytics", weight: 0.95, reason: "Firebase app-measurement label"},
	{pattern: "crashlytics", kind: matchLabel, category: "crash", weight: 0.95, reason: "Crashlytics label"},
	{pattern: "sentry", kind: matchLabel, category: "crash", weight: 0.85, reason: "Sentry label"},
	{pattern: "amplitude", kind: matchLabel, category: "analytics", weight: 0.92, reason: "Amplitude label"},
	{pattern: "mixpanel", kind: matchLabel, category: "analytics", weight: 0.92, reason: "Mixpanel label"},
	{pattern: "adjust", kind: matchLabel, category: "tracking", weight: 0.82, reason: "Adjust attribution label"},
	{pattern: "appsflyer", kind: matchLabel, category: "tracking", weight: 0.92, reason: "AppsFlyer label"},
	{pattern: "log-", kind: matchLabelPrefix, category: "telemetry", weight: 0.70, reason: "log ingest prefix"},
	{pattern: "telemetry-", kind: matchLabelPrefix, category: "telemetry", weight: 0.88, reason: "telemetry ingest prefix"},
	{pattern: "metrics-", kind: matchLabelPrefix, category: "telemetry", weight: 0.80, reason: "metrics ingest prefix"},
	{pattern: "stats-", kind: matchLabelPrefix, category: "analytics", weight: 0.75, reason: "stats ingest prefix"},
	{pattern: "doubleclick.net", kind: matchSuffix, category: "ads", weight: 0.97, reason: "Google ad network"},
	{pattern: "google-analytics.com", kind: matchSuffix, category: "analytics", weight: 0.97, reason: "Google Analytics"},
	{pattern: "googletagmanager.com", kind: matchSuffix, category: "analytics", weight: 0.93, reason: "Google Tag Manager"},
	{pattern: "segment.io", kind: matchSuffix, category: "analytics", weight: 0.93, reason: "Segment CDP"},
	{pattern: "segment.com", kind: matchSuffix, category: "analytics", weight: 0.85, reason: "Segment CDP"},
	{pattern: "scorecardresearch.com", kind: matchSuffix, category: "analytics", weight: 0.95, reason: "Comscore audience measurement"},
	{pattern: "hotjar.com", kind: matchSuffix, category: "analytics", weight: 0.90, reason: "Hotjar session recording"},
	{pattern: "clarity.ms", kind: matchSuffix, category: "analytics", weight: 0.90, reason: "Microsoft Clarity"},
	{pattern: "branch.io", kind: matchSuffix, category: "tracking", weight: 0.90, reason: "Branch deep-link attribution"},
	{pattern: "bugsnag.com", kind: matchSuffix, category: "crash", weight: 0.90, reason: "Bugsnag crash reporting"},
}

// HeuristicProvider is the deterministic fallback: keyword rules, no network,
// no model, stable output for tests.
type HeuristicProvider struct {
	rules []heuristicRule
}

// NewHeuristic builds the fallback provider. extraPatterns are treated as
// suffix matches so operators can add vendor domains without recompiling.
func NewHeuristic(extraPatterns []string) *HeuristicProvider {
	rules := make([]heuristicRule, 0, len(defaultRules)+len(extraPatterns))
	rules = append(rules, defaultRules...)
	for _, raw := range extraPatterns {
		pattern := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if pattern == "" {
			continue
		}
		rules = append(rules, heuristicRule{
			pattern:  pattern,
			kind:     matchSuffix,
			category: "custom",
			weight:   0.90,
			reason:   "operator-defined pattern " + pattern,
		})
	}
	return &HeuristicProvider{rules: rules}
}

// Name implements the optional named-provider interface.
func (h *HeuristicProvider) Name() string { return "heuristic" }

// Classify applies the first matching rule with the highest weight.
func (h *HeuristicProvider) Classify(_ context.Context, req DecisionRequest) (*DecisionResponse, error) {
	domain := normalizeDomain(req.Domain)
	if domain == "" {
		return nil, ErrUnavailable
	}
	var matches []heuristicRule
	for _, rule := range h.rules {
		if rule.matches(domain) {
			matches = append(matches, rule)
		}
	}
	if len(matches) == 0 {
		return &DecisionResponse{
			Block:      false,
			Confidence: 0.4,
			Reason:     "no telemetry signature matched",
			Category:   "unknown",
		}, nil
	}
	best := matches[0]
	for _, m := range matches[1:] {
		if m.weight > best.weight {
			best = m
		}
	}
	confidence := best.weight + 0.02*float64(len(matches)-1)
	if confidence > 0.99 {
		confidence = 0.99
	}
	reasons := make([]string, 0, len(matches))
	for _, m := range matches {
		reasons = append(reasons, m.reason)
	}
	return &DecisionResponse{
		Block:      true,
		Confidence: confidence,
		Reason:     strings.Join(reasons, "; "),
		Category:   best.category,
	}, nil
}

func (r heuristicRule) matches(domain string) bool {
	switch r.kind {
	case matchSuffix:
		return domain == r.pattern || strings.HasSuffix(domain, "."+r.pattern)
	case matchLabel:
		for _, label := range strings.Split(domain, ".") {
			if label == r.pattern {
				return true
			}
		}
		return false
	case matchLabelPrefix:
		for _, label := range strings.Split(domain, ".") {
			if strings.HasPrefix(label, r.pattern) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func normalizeDomain(raw string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(raw), ".")))
}
