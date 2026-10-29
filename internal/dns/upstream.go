package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	mdns "github.com/miekg/dns"
)

// Forwarder resolves a query on the upstream path.
type Forwarder interface {
	Forward(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error)
}

// Upstream forwards queries to one or more recursive resolvers, failing over
// in the configured order and retrying over TCP when a UDP answer is
// truncated.
type Upstream struct {
	addresses []string
	timeout   time.Duration
	log       *slog.Logger
}

// NewUpstream validates the resolver list.
func NewUpstream(addresses []string, timeout time.Duration, log *slog.Logger) (*Upstream, error) {
	if len(addresses) == 0 {
		return nil, errors.New("dns: at least one upstream resolver is required")
	}
	if timeout <= 0 {
		return nil, errors.New("dns: upstream timeout must be positive")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Upstream{addresses: append([]string(nil), addresses...), timeout: timeout, log: log}, nil
}

// Addresses returns the configured resolvers.
func (u *Upstream) Addresses() []string { return append([]string(nil), u.addresses...) }

// Timeout returns the per-attempt timeout.
func (u *Upstream) Timeout() time.Duration { return u.timeout }

// Forward tries every resolver until one answers.
func (u *Upstream) Forward(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error) {
	if req == nil {
		return nil, errors.New("dns: nil query")
	}
	var errs []error
	for _, addr := range u.addresses {
		resp, err := u.exchange(ctx, addr, req, "udp")
		if err != nil {
			errs = append(errs, fmt.Errorf("udp %s: %w", addr, err))
			u.log.Debug("upstream attempt failed", "resolver", addr, "network", "udp", "error", err)
			continue
		}
		if resp.Truncated {
			full, tcpErr := u.exchange(ctx, addr, req, "tcp")
			if tcpErr != nil {
				// A truncated answer is still better than SERVFAIL; the client
				// may retry over TCP itself.
				errs = append(errs, fmt.Errorf("tcp %s: %w", addr, tcpErr))
				u.log.Debug("tcp retry failed, returning truncated answer", "resolver", addr, "error", tcpErr)
				resp.Compress = true
				return resp, nil
			}
			resp = full
		}
		if resp.Rcode == mdns.RcodeServerFailure {
			errs = append(errs, fmt.Errorf("%s: upstream returned SERVFAIL", addr))
			continue
		}
		resp.Compress = true
		return resp, nil
	}
	return nil, fmt.Errorf("dns: all upstream resolvers failed: %w", errors.Join(errs...))
}

func (u *Upstream) exchange(ctx context.Context, addr string, req *mdns.Msg, network string) (*mdns.Msg, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, u.timeout)
	defer cancel()
	client := &mdns.Client{Net: network, Timeout: u.timeout}
	resp, _, err := client.ExchangeContext(attemptCtx, req.Copy(), addr)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("empty upstream response")
	}
	return resp, nil
}

var _ Forwarder = (*Upstream)(nil)
