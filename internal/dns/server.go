// Package dnsserver implements the synchronous DNS path: answer blocked names
// from the in-memory cache, forward everything else upstream and enqueue cache
// misses for asynchronous classification.
package dnsserver

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	mdns "github.com/miekg/dns"
)

// SubmitFunc hands a cache miss to the worker pool. It must not block.
type SubmitFunc func(domain, clientIP string) bool

// Options configures a Server.
type Options struct {
	Cache          *Cache
	Forwarder      Forwarder
	Submit         SubmitFunc
	IPv4           net.IP
	IPv6           net.IP
	TTL            uint32
	ForwardTimeout time.Duration
	Allowlist      []string
	Logger         *slog.Logger
}

// Server implements mdns.Handler.
type Server struct {
	cache          *Cache
	forwarder      Forwarder
	submit         SubmitFunc
	ipv4           net.IP
	ipv6           net.IP
	ttl            uint32
	forwardTimeout time.Duration
	allowlist      []string
	log            *slog.Logger

	queries          atomic.Uint64
	blocked          atomic.Uint64
	forwarded        atomic.Uint64
	upstreamFailures atomic.Uint64
	enqueued         atomic.Uint64
	enqueueRejected  atomic.Uint64
	writeErrors      atomic.Uint64
	allowlisted      atomic.Uint64
}

// Snapshot is a consistent-ish view of the DNS counters.
type Snapshot struct {
	Queries          uint64 `json:"queries"`
	Blocked          uint64 `json:"blocked"`
	Forwarded        uint64 `json:"forwarded"`
	UpstreamFailures uint64 `json:"upstream_failures"`
	Enqueued         uint64 `json:"enqueued"`
	EnqueueRejected  uint64 `json:"enqueue_rejected"`
	WriteErrors      uint64 `json:"write_errors"`
	Allowlisted      uint64 `json:"allowlisted"`
}

// New validates the wiring and returns the handler.
func New(opts Options) (*Server, error) {
	if opts.Cache == nil {
		return nil, errors.New("dns: cache must not be nil")
	}
	if opts.Forwarder == nil {
		return nil, errors.New("dns: forwarder must not be nil")
	}
	if opts.IPv4 == nil || opts.IPv4.To4() == nil {
		return nil, errors.New("dns: blocking IPv4 address is invalid")
	}
	if opts.IPv6 == nil || opts.IPv6.To4() != nil || len(opts.IPv6) != net.IPv6len {
		return nil, errors.New("dns: blocking IPv6 address is invalid")
	}
	if opts.TTL == 0 {
		return nil, errors.New("dns: blocking TTL must be greater than zero")
	}
	if opts.ForwardTimeout <= 0 {
		opts.ForwardTimeout = 5 * time.Second
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	allow := make([]string, 0, len(opts.Allowlist))
	for _, entry := range opts.Allowlist {
		if normalized := NormalizeName(entry); normalized != "" {
			allow = append(allow, normalized)
		}
	}
	return &Server{
		allowlist:      allow,
		cache:          opts.Cache,
		forwarder:      opts.Forwarder,
		submit:         opts.Submit,
		ipv4:           opts.IPv4.To4(),
		ipv6:           opts.IPv6.To16(),
		ttl:            opts.TTL,
		forwardTimeout: opts.ForwardTimeout,
		log:            opts.Logger,
	}, nil
}

// ServeDNS handles one DNS message.
func (s *Server) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	s.queries.Add(1)
	if req == nil || len(req.Question) != 1 {
		s.replyRcode(w, req, mdns.RcodeFormatError)
		return
	}
	q := req.Question[0]
	domain := NormalizeName(q.Name)

	onlyAddress := q.Qclass == mdns.ClassINET && (q.Qtype == mdns.TypeA || q.Qtype == mdns.TypeAAAA)
	if domain == "" || !onlyAddress {
		s.forward(w, req)
		return
	}

	// Infrastructure is never sinkholed, regardless of what the model said.
	if s.isAllowlisted(domain) {
		s.allowlisted.Add(1)
		s.forward(w, req)
		return
	}

	entry, cached := s.cache.Get(domain)
	if cached && entry.Blocked {
		s.blocked.Add(1)
		s.write(w, req, s.blockResponse(req, q))
		return
	}

	s.forward(w, req)

	if !cached && s.submit != nil {
		if s.submit(domain, clientIP(w.RemoteAddr())) {
			s.enqueued.Add(1)
		} else {
			s.enqueueRejected.Add(1)
		}
	}
}

// blockResponse builds the sinkhole answer for A and AAAA queries.
func (s *Server) blockResponse(req *mdns.Msg, q mdns.Question) *mdns.Msg {
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.RecursionAvailable = true

	hdr := mdns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: mdns.ClassINET, Ttl: s.ttl}
	switch q.Qtype {
	case mdns.TypeA:
		resp.Answer = append(resp.Answer, &mdns.A{Hdr: hdr, A: s.ipv4})
	case mdns.TypeAAAA:
		resp.Answer = append(resp.Answer, &mdns.AAAA{Hdr: hdr, AAAA: s.ipv6})
	}
	if opt := req.IsEdns0(); opt != nil {
		resp.SetEdns0(1232, opt.Do())
	}
	return resp
}

func (s *Server) forward(w mdns.ResponseWriter, req *mdns.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), s.forwardTimeout)
	defer cancel()

	resp, err := s.forwarder.Forward(ctx, req)
	if err != nil {
		s.upstreamFailures.Add(1)
		s.log.Warn("upstream lookup failed", "qname", questionName(req), "error", err)
		s.replyRcode(w, req, mdns.RcodeServerFailure)
		return
	}
	s.forwarded.Add(1)
	s.write(w, req, resp)
}

func (s *Server) replyRcode(w mdns.ResponseWriter, req *mdns.Msg, rcode int) {
	resp := new(mdns.Msg)
	if req != nil {
		resp.SetRcode(req, rcode)
	} else {
		resp.Rcode = rcode
	}
	s.write(w, req, resp)
}

func (s *Server) write(w mdns.ResponseWriter, req *mdns.Msg, resp *mdns.Msg) {
	if resp == nil {
		return
	}
	if err := w.WriteMsg(resp); err != nil {
		s.writeErrors.Add(1)
		remote := ""
		if w != nil {
			remote = w.RemoteAddr().String()
		}
		s.log.Debug("write DNS response failed", "remote", remote, "qname", questionName(req), "error", err)
	}
}

// isAllowlisted reports whether the name matches an allowlist entry exactly or
// as a subdomain.
func (s *Server) isAllowlisted(domain string) bool {
	for _, entry := range s.allowlist {
		if domain == entry || strings.HasSuffix(domain, "."+entry) {
			return true
		}
	}
	return false
}

// Stats returns the DNS path counters.
func (s *Server) Stats() Snapshot {
	return Snapshot{
		Queries:          s.queries.Load(),
		Blocked:          s.blocked.Load(),
		Forwarded:        s.forwarded.Load(),
		UpstreamFailures: s.upstreamFailures.Load(),
		Enqueued:         s.enqueued.Load(),
		EnqueueRejected:  s.enqueueRejected.Load(),
		WriteErrors:      s.writeErrors.Load(),
		Allowlisted:      s.allowlisted.Load(),
	}
}

// Cache exposes the decision cache for statistics and pipeline updates.
func (s *Server) Cache() *Cache { return s.cache }

func questionName(req *mdns.Msg) string {
	if req == nil || len(req.Question) == 0 {
		return ""
	}
	return req.Question[0].Name
}

// clientIP extracts the peer address that mdns reports for a query.
func clientIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

var _ mdns.Handler = (*Server)(nil)
