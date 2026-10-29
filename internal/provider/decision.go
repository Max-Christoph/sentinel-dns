package provider

import "math"

// Policy turns a provider verdict into the effective decision. It lives in one
// place so the thresholds are applied exactly once: a second gate inside a
// provider would silently discard decisions the policy just made.
type Policy struct {
	// MinConfidence is the certainty a verdict needs before it blocks.
	MinConfidence float64
	// CategoryMinProbability lets a confident category label block even when
	// the yes/no question hesitated (vendor CDNs, borderline trackers).
	CategoryMinProbability float64
}

// Decision is the effective verdict after the policy ran.
type Decision struct {
	Block      bool
	Confidence float64 // certainty of the effective decision
	Reason     string  // "noul" or "category:analytics"
}

// trackingCategories are the labels that justify a block when the model is
// confident about them. "benign", "unknown" and operator rules never qualify.
var trackingCategories = map[string]bool{
	"telemetry": true,
	"analytics": true,
	"ads":       true,
	"crash":     true,
}

// Decide applies the policy to a provider verdict.
func (p Policy) Decide(resp *DecisionResponse) Decision {
	if resp == nil {
		return Decision{}
	}
	block := resp.Block && resp.Confidence >= p.MinConfidence
	confidence := resp.Confidence
	reason := "noul"

	if !block && resp.CategoryProb >= p.CategoryMinProbability && trackingCategories[resp.Category] {
		block = true
		confidence = math.Max(resp.Confidence, resp.CategoryProb)
		reason = "category:" + resp.Category
	}
	return Decision{Block: block, Confidence: confidence, Reason: reason}
}
