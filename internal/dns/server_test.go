package dnsserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

type captureWriter struct {
	remote net.Addr
	msg    *mdns.Msg
	err    error
}

func (w *captureWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (w *captureWriter) RemoteAddr() net.Addr        { return w.remote }
func (w *captureWriter) WriteMsg(m *mdns.Msg) error  { w.msg = m.Copy(); return nil }
func (w *captureWriter) Write(b []byte) (int, error) { return 0, errors.New("not implemented") }
func (w *captureWriter) Close() error                { return nil }
func (w *captureWriter) TsigStatus() error           { return nil }
func (w *captureWriter) TsigTimersOnly(bool)         {}
func (w *captureWriter) Hijack()                     {}

type stubForwarder struct {
	mu    sync.Mutex
	calls int
	resp  *mdns.Msg
	err   error
}

func (f *stubForwarder) Forward(_ context.Context, req *mdns.Msg) (*mdns.Msg, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if f.resp != nil {
		resp := f.resp.Copy()
		resp.SetReply(req)
		return resp, nil
	}
	out := new(mdns.Msg)
	out.SetReply(req)
	return out, nil
}

func (f *stubForwarder) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type submitRecorder struct {
	mu      sync.Mutex
	domains []string
	ips     []string
}

func (s *submitRecorder) submit(domain, ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.domains = append(s.domains, domain)
	s.ips = append(s.ips, ip)
	return true
}

func (s *submitRecorder) snapshot() ([]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.domains...), append([]string(nil), s.ips...)
}

func newTestServer(t *testing.T, cache *Cache, fwd Forwarder, submit SubmitFunc) *Server {
	t.Helper()
	srv, err := New(Options{
		Cache:          cache,
		Forwarder:      fwd,
		Submit:         submit,
		IPv4:           net.ParseIP("0.0.0.0"),
		IPv6:           net.ParseIP("::"),
		TTL:            300,
		ForwardTimeout: time.Second,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

func query(name string, qtype uint16) *mdns.Msg {
	req := new(mdns.Msg)
	req.SetQuestion(mdns.Fqdn(name), qtype)
	return req
}

func TestBlockedAnswersFromCache(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		qtype  uint16
		want   string
		answer func(mdns.RR) string
	}{
		{"A", mdns.TypeA, "0.0.0.0", func(rr mdns.RR) string { return rr.(*mdns.A).A.String() }},
		{"AAAA", mdns.TypeAAAA, "::", func(rr mdns.RR) string { return rr.(*mdns.AAAA).AAAA.String() }},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cache := NewCache(10)
			cache.Put("ads.example", Entry{Blocked: true, Expires: time.Now().Add(time.Minute)})
			fwd := &stubForwarder{}
			recorder := &submitRecorder{}
			srv := newTestServer(t, cache, fwd, recorder.submit)

			w := &captureWriter{remote: &net.UDPAddr{IP: net.ParseIP("192.168.88.50"), Port: 4242}}
			srv.ServeDNS(w, query("ads.example", tc.qtype))

			if w.msg == nil {
				t.Fatal("no response written")
			}
			if w.msg.Rcode != mdns.RcodeSuccess {
				t.Fatalf("rcode = %v, want success", w.msg.Rcode)
			}
			if len(w.msg.Answer) != 1 {
				t.Fatalf("answers = %d, want 1", len(w.msg.Answer))
			}
			if got := tc.answer(w.msg.Answer[0]); got != tc.want {
				t.Errorf("answer = %s, want %s", got, tc.want)
			}
			if ttl := w.msg.Answer[0].Header().Ttl; ttl != 300 {
				t.Errorf("ttl = %d, want 300", ttl)
			}
			if fwd.callCount() != 0 {
				t.Error("blocked query was forwarded upstream")
			}
			if domains, _ := recorder.snapshot(); len(domains) != 0 {
				t.Errorf("blocked cache hit was enqueued again: %v", domains)
			}
			if srv.Stats().Blocked != 1 {
				t.Errorf("blocked counter = %d, want 1", srv.Stats().Blocked)
			}
		})
	}
}

func TestCacheMissForwardsAndEnqueues(t *testing.T) {
	t.Parallel()
	cache := NewCache(10)
	upstreamResp := new(mdns.Msg)
	upstreamResp.Answer = []mdns.RR{&mdns.A{
		Hdr: mdns.RR_Header{Name: "api.example.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
		A:   net.ParseIP("1.2.3.4").To4(),
	}}
	fwd := &stubForwarder{resp: upstreamResp}
	recorder := &submitRecorder{}
	srv := newTestServer(t, cache, fwd, recorder.submit)

	w := &captureWriter{remote: &net.UDPAddr{IP: net.ParseIP("10.0.0.7"), Port: 5555}}
	srv.ServeDNS(w, query("api.example", mdns.TypeA))

	if fwd.callCount() != 1 {
		t.Fatalf("forward calls = %d, want 1", fwd.callCount())
	}
	if w.msg == nil || len(w.msg.Answer) != 1 {
		t.Fatalf("upstream answer not returned: %+v", w.msg)
	}
	if got := w.msg.Answer[0].(*mdns.A).A.String(); got != "1.2.3.4" {
		t.Fatalf("answer = %s, want 1.2.3.4", got)
	}
	domains, ips := recorder.snapshot()
	if len(domains) != 1 || domains[0] != "api.example" {
		t.Fatalf("enqueued domains = %v, want [api.example]", domains)
	}
	if len(ips) != 1 || ips[0] != "10.0.0.7" {
		t.Fatalf("client IPs = %v, want [10.0.0.7]", ips)
	}
}

func TestCachedAllowStillForwardsWithoutEnqueue(t *testing.T) {
	t.Parallel()
	cache := NewCache(10)
	cache.Put("cdn.example", Entry{Blocked: false, Expires: time.Now().Add(time.Minute)})
	fwd := &stubForwarder{}
	recorder := &submitRecorder{}
	srv := newTestServer(t, cache, fwd, recorder.submit)

	w := &captureWriter{remote: &net.UDPAddr{IP: net.ParseIP("10.0.0.7"), Port: 5555}}
	srv.ServeDNS(w, query("cdn.example", mdns.TypeA))

	if fwd.callCount() != 1 {
		t.Fatalf("forward calls = %d, want 1", fwd.callCount())
	}
	if domains, _ := recorder.snapshot(); len(domains) != 0 {
		t.Fatalf("cached allow was re-enqueued: %v", domains)
	}
}

func TestUpstreamFailureReturnsServfail(t *testing.T) {
	t.Parallel()
	fwd := &stubForwarder{err: errors.New("no route to host")}
	srv := newTestServer(t, NewCache(10), fwd, func(string, string) bool { return true })

	w := &captureWriter{remote: &net.UDPAddr{IP: net.ParseIP("10.0.0.7"), Port: 5555}}
	srv.ServeDNS(w, query("api.example", mdns.TypeA))

	if w.msg == nil || w.msg.Rcode != mdns.RcodeServerFailure {
		t.Fatalf("want SERVFAIL, got %+v", w.msg)
	}
	if srv.Stats().UpstreamFailures != 1 {
		t.Fatalf("upstream failures = %d, want 1", srv.Stats().UpstreamFailures)
	}
}

func TestAllowlistedDomainsAreNeverSinkholed(t *testing.T) {
	t.Parallel()
	cache := NewCache(10)
	cache.Put("signaler-pa.clients6.google.com", Entry{Blocked: true, Expires: time.Now().Add(time.Minute)})

	fwd := &stubForwarder{}
	recorder := &submitRecorder{}
	srv, err := New(Options{
		Cache: cache, Forwarder: fwd, Submit: recorder.submit,
		IPv4: net.ParseIP("0.0.0.0"), IPv6: net.ParseIP("::"), TTL: 300,
		ForwardTimeout: time.Second, Allowlist: []string{"google.com", "msftncsi.com"},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	w := &captureWriter{remote: &net.UDPAddr{IP: net.ParseIP("10.0.0.7"), Port: 5555}}
	srv.ServeDNS(w, query("signaler-pa.clients6.google.com", mdns.TypeA))
	if fwd.callCount() != 1 {
		t.Fatalf("allowlisted domain was not forwarded (calls=%d)", fwd.callCount())
	}
	if w.msg == nil || len(w.msg.Answer) != 0 {
		t.Fatalf("allowlisted domain got a sinkhole answer: %+v", w.msg)
	}
	if domains, _ := recorder.snapshot(); len(domains) != 0 {
		t.Fatalf("allowlisted domain was enqueued for classification: %v", domains)
	}
	if srv.Stats().Allowlisted != 1 {
		t.Errorf("allowlisted counter = %d, want 1", srv.Stats().Allowlisted)
	}

	// A name that only looks similar must still be cache-checked.
	w2 := &captureWriter{remote: &net.UDPAddr{IP: net.ParseIP("10.0.0.7"), Port: 5555}}
	cache.Put("notgoogle.com.example", Entry{Blocked: true, Expires: time.Now().Add(time.Minute)})
	srv.ServeDNS(w2, query("notgoogle.com.example", mdns.TypeA))
	if w2.msg == nil || len(w2.msg.Answer) != 1 {
		t.Fatalf("non-allowlisted domain was not sinkholed: %+v", w2.msg)
	}
}

func TestNonAddressQueriesAreForwardedEvenWhenBlocked(t *testing.T) {
	t.Parallel()
	cache := NewCache(10)
	cache.Put("ads.example", Entry{Blocked: true, Expires: time.Now().Add(time.Minute)})
	fwd := &stubForwarder{}
	recorder := &submitRecorder{}
	srv := newTestServer(t, cache, fwd, recorder.submit)

	w := &captureWriter{remote: &net.UDPAddr{IP: net.ParseIP("10.0.0.7"), Port: 5555}}
	srv.ServeDNS(w, query("ads.example", mdns.TypeTXT))

	if fwd.callCount() != 1 {
		t.Fatalf("TXT query was not forwarded, calls = %d", fwd.callCount())
	}
	if domains, _ := recorder.snapshot(); len(domains) != 0 {
		t.Fatalf("non-address query was enqueued: %v", domains)
	}
}

func TestMalformedRequestGetsFormErr(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, NewCache(10), &stubForwarder{}, nil)
	w := &captureWriter{remote: &net.UDPAddr{IP: net.ParseIP("10.0.0.7"), Port: 5555}}

	req := new(mdns.Msg)
	req.Id = 4711
	srv.ServeDNS(w, req)

	if w.msg == nil || w.msg.Rcode != mdns.RcodeFormatError {
		t.Fatalf("want FORMERR, got %+v", w.msg)
	}
	if w.msg.Id != 4711 {
		t.Fatalf("response id = %d, want 4711", w.msg.Id)
	}
}

func TestBlockedResponseCarriesEDNS(t *testing.T) {
	t.Parallel()
	cache := NewCache(10)
	cache.Put("ads.example", Entry{Blocked: true, Expires: time.Now().Add(time.Minute)})
	srv := newTestServer(t, cache, &stubForwarder{}, nil)

	req := query("ads.example", mdns.TypeA)
	req.SetEdns0(4096, true)
	w := &captureWriter{remote: &net.UDPAddr{IP: net.ParseIP("10.0.0.7"), Port: 5555}}
	srv.ServeDNS(w, req)

	if opt := w.msg.IsEdns0(); opt == nil {
		t.Fatal("blocked response dropped the EDNS0 record")
	} else if opt.UDPSize() != 1232 {
		t.Errorf("advertised UDP size = %d, want 1232", opt.UDPSize())
	}
}

func TestNewRejectsInvalidOptions(t *testing.T) {
	t.Parallel()
	base := Options{
		Cache:          NewCache(1),
		Forwarder:      &stubForwarder{},
		IPv4:           net.ParseIP("0.0.0.0"),
		IPv6:           net.ParseIP("::"),
		TTL:            30,
		ForwardTimeout: time.Second,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	bad := base
	bad.Cache = nil
	if _, err := New(bad); err == nil {
		t.Error("want error for nil cache")
	}
	bad = base
	bad.Forwarder = nil
	if _, err := New(bad); err == nil {
		t.Error("want error for nil forwarder")
	}
	bad = base
	bad.IPv6 = net.ParseIP("0.0.0.0")
	if _, err := New(bad); err == nil {
		t.Error("want error for IPv4 address in the IPv6 slot")
	}
	bad = base
	bad.TTL = 0
	if _, err := New(bad); err == nil {
		t.Error("want error for zero TTL")
	}
}
