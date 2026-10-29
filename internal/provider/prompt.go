package provider

import (
	"fmt"
	"strings"
)

const systemPrompt = `You are a DNS telemetry classifier.
Decide whether the given DNS name is used by device telemetry, analytics,
crash reporting, advertising or tracking infrastructure.
Reply with a single JSON object and nothing else:
{"block": true|false, "confidence": 0.0-1.0, "reason": "short justification", "category": "telemetry|analytics|ads|crash|unknown"}
Block only when the domain itself shows a tracking or telemetry purpose.
Never block mail, update, CDN, payment, login or plain API domains.`

// userPrompt renders the per-request question.
func userPrompt(req DecisionRequest) string {
	domain := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(req.Domain, ".")))
	if req.ClientIP == "" {
		return fmt.Sprintf("Domain: %s", domain)
	}
	return fmt.Sprintf("Domain: %s\nClient IP: %s", domain, req.ClientIP)
}

// fewShotPrompt is the compact prompt used for small models that follow
// examples better than instructions.
func fewShotPrompt(req DecisionRequest) string {
	return `Classify DNS names for telemetry tracking. JSON only.

Domain: metrics.vendor.example
{"block": true, "confidence": 0.94, "reason": "metrics subdomain of a device vendor", "category": "telemetry"}
Domain: api.github.com
{"block": false, "confidence": 0.9, "reason": "developer API, not tracking", "category": "unknown"}
Domain: app-measurement.com
{"block": true, "confidence": 0.97, "reason": "Google Firebase analytics endpoint", "category": "analytics"}
Domain: ` + userPrompt(req)
}
