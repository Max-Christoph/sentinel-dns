package dnsserver

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func startUDPServer(t *testing.T, handler mdns.Handler) net.Addr {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	srv := &mdns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr()
}

func answerWith(ip string) mdns.Handler {
	return mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.Answer = append(resp.Answer, &mdns.A{
			Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
			A:   net.ParseIP(ip).To4(),
		})
		_ = w.WriteMsg(resp)
	})
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestUpstreamForwardResolves(t *testing.T) {
	t.Parallel()
	addr := startUDPServer(t, answerWith("198.51.100.9"))
	up, err := NewUpstream([]string{addr.String()}, time.Second, testLogger())
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	resp, err := up.Forward(context.Background(), query("example.com", mdns.TypeA))
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(resp.Answer))
	}
	if got := resp.Answer[0].(*mdns.A).A.String(); got != "198.51.100.9" {
		t.Fatalf("answer = %s", got)
	}
}

func TestUpstreamFailoverToSecondResolver(t *testing.T) {
	t.Parallel()
	addr := startUDPServer(t, answerWith("203.0.113.5"))
	up, err := NewUpstream([]string{"127.0.0.1:1", addr.String()}, 500*time.Millisecond, testLogger())
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	resp, err := up.Forward(context.Background(), query("example.com", mdns.TypeA))
	if err != nil {
		t.Fatalf("Forward with failover: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(resp.Answer))
	}
}

func TestUpstreamRetriesOverTCPWhenTruncated(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	addr := listener.Addr().String()

	udpConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("listen udp on %s: %v", addr, err)
	}

	udpSrv := &mdns.Server{PacketConn: udpConn, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.Truncated = true
		_ = w.WriteMsg(resp)
	})}
	tcpSrv := &mdns.Server{Listener: listener, Handler: answerWith("203.0.113.77")}
	go func() { _ = udpSrv.ActivateAndServe() }()
	go func() { _ = tcpSrv.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udpSrv.Shutdown()
		_ = tcpSrv.Shutdown()
	})

	up, err := NewUpstream([]string{addr}, time.Second, testLogger())
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	resp, err := up.Forward(context.Background(), query("big.example", mdns.TypeA))
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if resp.Truncated {
		t.Fatal("truncated answer was not completed over TCP")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(resp.Answer))
	}
	if got := resp.Answer[0].(*mdns.A).A.String(); got != "203.0.113.77" {
		t.Fatalf("answer = %s, want 203.0.113.77", got)
	}
}

// TestUpstreamFallsBackToTCPOnMalformedUDP covers the field failure where a
// datagram larger than the read buffer was cut mid-record: the parse error must
// trigger a TCP retry instead of a SERVFAIL.
func TestUpstreamFallsBackToTCPOnMalformedUDP(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	addr := listener.Addr().String()
	udpConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("listen udp on %s: %v", addr, err)
	}

	udpSrv := &mdns.Server{PacketConn: udpConn, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		// Three bytes: too short to unpack, exactly what a truncated datagram
		// looks like to the parser.
		_, _ = w.Write([]byte{0x01, 0x02, 0x03})
	})}
	tcpSrv := &mdns.Server{Listener: listener, Handler: answerWith("203.0.113.99")}
	go func() { _ = udpSrv.ActivateAndServe() }()
	go func() { _ = tcpSrv.ActivateAndServe() }()
	t.Cleanup(func() { _ = udpSrv.Shutdown(); _ = tcpSrv.Shutdown() })

	up, err := NewUpstream([]string{addr}, time.Second, testLogger())
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	resp, err := up.Forward(context.Background(), query("www.tagesschau.de", mdns.TypeA))
	if err != nil {
		t.Fatalf("Forward: %v (want a TCP retry, not a failure)", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(resp.Answer))
	}
	if got := resp.Answer[0].(*mdns.A).A.String(); got != "203.0.113.99" {
		t.Fatalf("answer = %s, want the TCP answer", got)
	}
}

func TestUpstreamAllResolversFail(t *testing.T) {
	t.Parallel()
	up, err := NewUpstream([]string{"127.0.0.1:1"}, 300*time.Millisecond, testLogger())
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	_, err = up.Forward(context.Background(), query("example.com", mdns.TypeA))
	if err == nil {
		t.Fatal("want error when every resolver fails")
	}
	if !strings.Contains(err.Error(), "all upstream resolvers failed") {
		t.Fatalf("error = %v, want a summary of all attempts", err)
	}
}

func TestUpstreamRejectsNilQuery(t *testing.T) {
	t.Parallel()
	up, err := NewUpstream([]string{"127.0.0.1:53"}, time.Second, testLogger())
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	if _, err := up.Forward(context.Background(), nil); err == nil {
		t.Fatal("want error for nil query")
	}
}

func TestNewUpstreamValidates(t *testing.T) {
	t.Parallel()
	if _, err := NewUpstream(nil, time.Second, nil); err == nil {
		t.Error("want error for empty address list")
	}
	if _, err := NewUpstream([]string{"127.0.0.1:53"}, 0, nil); err == nil {
		t.Error("want error for zero timeout")
	}
}
