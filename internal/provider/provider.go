// Package provider contains the pluggable classification backends. Every
// backend turns a (domain, client IP) pair into a block/allow decision and is
// called exclusively from the asynchronous worker pool.
package provider

import (
	"context"
	"errors"
)

// DecisionRequest is the classifier input.
type DecisionRequest struct {
	Domain   string `json:"domain"`
	ClientIP string `json:"client_ip"`
}

// DecisionResponse is the classifier output. Category is optional metadata for
// the device_category column (e.g. "smart-tv", "mobile-sdk"); providers that
// cannot infer it leave it empty.
type DecisionResponse struct {
	Block      bool    `json:"block"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
	Category   string  `json:"category,omitempty"`
}

// DecisionProvider classifies a domain. Implementations must honour the
// context deadline and never block indefinitely.
type DecisionProvider interface {
	Classify(ctx context.Context, req DecisionRequest) (*DecisionResponse, error)
}

// ErrUnavailable signals that the backend could not produce a verdict so the
// caller may keep the domain unclassified instead of caching a guess.
var ErrUnavailable = errors.New("provider unavailable")

// Name returns the provider type for logging.
func Name(p DecisionProvider) string {
	if named, ok := p.(interface{ Name() string }); ok {
		return named.Name()
	}
	return "unknown"
}
