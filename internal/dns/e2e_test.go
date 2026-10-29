package dnsserver

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

// TestEndToEndSinkholeFlow exercises the real UDP wiring: an unknown domain is
// forwarded to a stub resolver and enqueued, then the worker's verdict turns
// the same domain into a sinkhole answer without touching the resolver again.
func TestEndToEndSinkholeFlow(t *testing.T) {
	t.Parallel()

	var upstreamQueries atomic.Int64
	upstreamAddr := startUDPServer(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		upstreamQueries.Add(1)
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.Answer = append(resp.Answer, &mdns.A{
			Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
			A:   net.ParseIP("198.51.100.10").To4(),
		})
		_ = w.WriteMsg(resp)
	}))

	upstream, err := NewUpstream([]string{upstreamAddr.String()}, time.Second, testLogger())
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}

	cache := NewCache(64)
	var enqueued atomic.Int64
	handler, err := New(Options{
		Cache:          cache,
		Forwarder:      upstream,
		Submit:         func(domain, clientIP string) bool { enqueued.Add(1); return true },
		IPv4:           net.ParseIP("0.0.0.0"),
		IPv6:           net.ParseIP("::"),
		TTL:            120,
		ForwardTimeout: time.Second,
		Logger:         testLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &mdns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()
	addr := pc.LocalAddr().String()

	client := &mdns.Client{Net: "udp", Timeout: 2 * time.Second}
	ask := func() *mdns.Msg {
		t.Helper()
		resp, _, err := client.Exchange(query("tracker.vendor.example", mdns.TypeA), addr)
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		return resp
	}

	first := ask()
	if got := first.Answer[0].(*mdns.A).A.String(); got != "198.51.100.10" {
		t.Fatalf("first answer = %s, want the upstream address", got)
	}
	if enqueued.Load() != 1 {
		t.Fatalf("enqueued = %d, want 1", enqueued.Load())
	}

	// The worker persists and caches the verdict.
	cache.Put("tracker.vendor.example", Entry{Blocked: true, Confidence: 0.95, Reason: "test", Expires: time.Now().Add(time.Minute)})

	second := ask()
	if len(second.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(second.Answer))
	}
	if got := second.Answer[0].(*mdns.A).A.String(); got != "0.0.0.0" {
		t.Fatalf("second answer = %s, want the sinkhole address", got)
	}
	if ttl := second.Answer[0].Header().Ttl; ttl != 120 {
		t.Fatalf("ttl = %d, want 120", ttl)
	}
	if upstreamQueries.Load() != 1 {
		t.Fatalf("upstream queries = %d, want 1 (second lookup must not leave the box)", upstreamQueries.Load())
	}
	if enqueued.Load() != 1 {
		t.Fatalf("enqueued = %d, want 1 (a cache hit must not be re-queued)", enqueued.Load())
	}

	stats := handler.Stats()
	if stats.Blocked != 1 || stats.Forwarded != 1 {
		t.Fatalf("stats = %+v, want 1 blocked and 1 forwarded", stats)
	}
}
