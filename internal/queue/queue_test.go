package queue

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Max-Christoph/sentinel-dns/internal/provider"
)

type stubClassifier struct {
	calls atomic.Int64
	fn    func(ctx context.Context, req provider.DecisionRequest) (*provider.DecisionResponse, error)
}

func (s *stubClassifier) Classify(ctx context.Context, req provider.DecisionRequest) (*provider.DecisionResponse, error) {
	s.calls.Add(1)
	return s.fn(ctx, req)
}

func newTestPool(t *testing.T, opts Options) *Pool {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	pool, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return pool
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestPoolDeduplicatesInFlightDomains(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	classifier := &stubClassifier{fn: func(ctx context.Context, req provider.DecisionRequest) (*provider.DecisionResponse, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return &provider.DecisionResponse{Block: true, Confidence: 0.9, Reason: "test"}, nil
	}}

	var (
		mu      sync.Mutex
		results []string
	)
	pool := newTestPool(t, Options{
		Workers: 2, Buffer: 8, JobTimeout: time.Second, Classifier: classifier,
		OnResult: func(_ context.Context, job Job, _ *provider.DecisionResponse) {
			mu.Lock()
			results = append(results, job.Domain)
			mu.Unlock()
		},
	})
	pool.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = pool.Stop(ctx)
	}()

	if !pool.Submit(Job{Domain: "tracker.example", ClientIP: "10.0.0.1"}) {
		t.Fatal("first submit was rejected")
	}
	<-started
	if pool.Submit(Job{Domain: "tracker.example", ClientIP: "10.0.0.2"}) {
		t.Fatal("duplicate submit was accepted while the domain is in flight")
	}
	close(release)

	waitFor(t, "result", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(results) == 1
	})
	stats := pool.Stats()
	if stats.Duplicates != 1 {
		t.Errorf("duplicates = %d, want 1", stats.Duplicates)
	}
	if stats.Submitted != 1 || stats.Processed != 1 {
		t.Errorf("stats = %+v, want 1 submitted and 1 processed", stats)
	}
	if classifier.calls.Load() != 1 {
		t.Errorf("classifier calls = %d, want 1", classifier.calls.Load())
	}
	// A finished domain may be queued again.
	waitFor(t, "inflight cleanup", func() bool { return pool.Stats().Pending == 0 })
}

func TestPoolDropsWhenFullWithoutBlocking(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	classifier := &stubClassifier{fn: func(ctx context.Context, req provider.DecisionRequest) (*provider.DecisionResponse, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return &provider.DecisionResponse{Block: false, Confidence: 0.2}, nil
	}}
	pool := newTestPool(t, Options{Workers: 1, Buffer: 1, JobTimeout: time.Second, Classifier: classifier})
	pool.Start()

	if !pool.Submit(Job{Domain: "a.example"}) {
		t.Fatal("first submit rejected")
	}
	<-started // worker is busy, buffer is free again
	if !pool.Submit(Job{Domain: "b.example"}) {
		t.Fatal("second submit rejected, buffer should accept one job")
	}

	done := make(chan bool, 1)
	go func() { done <- pool.Submit(Job{Domain: "c.example"}) }()
	select {
	case accepted := <-done:
		if accepted {
			t.Fatal("third submit was accepted but the queue was full")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Submit blocked on a full queue")
	}
	if got := pool.Stats().Dropped; got != 1 {
		t.Errorf("dropped = %d, want 1", got)
	}
	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := pool.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestPoolReportsErrorsAndKeepsRunning(t *testing.T) {
	t.Parallel()
	var failures atomic.Int64
	classifier := &stubClassifier{fn: func(ctx context.Context, req provider.DecisionRequest) (*provider.DecisionResponse, error) {
		if req.Domain == "bad.example" {
			return nil, errors.New("backend down")
		}
		return &provider.DecisionResponse{Block: true, Confidence: 0.8}, nil
	}}
	var processed atomic.Int64
	pool := newTestPool(t, Options{
		Workers: 1, Buffer: 4, JobTimeout: time.Second, Classifier: classifier,
		OnError:  func(context.Context, Job, error) { failures.Add(1) },
		OnResult: func(context.Context, Job, *provider.DecisionResponse) { processed.Add(1) },
	})
	pool.Start()
	if !pool.Submit(Job{Domain: "bad.example"}) || !pool.Submit(Job{Domain: "good.example"}) {
		t.Fatal("submit rejected")
	}
	waitFor(t, "both jobs", func() bool { return failures.Load() == 1 && processed.Load() == 1 })
	stats := pool.Stats()
	if stats.Failed != 1 || stats.Processed != 1 || stats.Pending != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := pool.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if pool.Submit(Job{Domain: "late.example"}) {
		t.Fatal("Submit after Stop must be rejected")
	}
}

func TestPoolStopWaitsForInFlightWork(t *testing.T) {
	t.Parallel()
	classifier := &stubClassifier{fn: func(ctx context.Context, req provider.DecisionRequest) (*provider.DecisionResponse, error) {
		time.Sleep(60 * time.Millisecond)
		return &provider.DecisionResponse{Block: false, Confidence: 0.5}, nil
	}}
	var processed atomic.Int64
	pool := newTestPool(t, Options{
		Workers: 2, Buffer: 4, JobTimeout: time.Second, Classifier: classifier,
		OnResult: func(context.Context, Job, *provider.DecisionResponse) { processed.Add(1) },
	})
	pool.Start()
	pool.Submit(Job{Domain: "a.example"})
	pool.Submit(Job{Domain: "b.example"})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := pool.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if processed.Load() != 2 {
		t.Fatalf("processed = %d, want both jobs finished before Stop returned", processed.Load())
	}
}

func TestNewRejectsInvalidOptions(t *testing.T) {
	t.Parallel()
	if _, err := New(Options{}); err == nil {
		t.Error("want error for nil classifier")
	}
	if _, err := New(Options{Classifier: &stubClassifier{}}); err == nil {
		t.Error("want error for zero workers")
	}
	if _, err := New(Options{Classifier: &stubClassifier{}, Workers: 1, Buffer: 0, JobTimeout: time.Second}); err == nil {
		t.Error("want error for zero buffer")
	}
	if _, err := New(Options{Classifier: &stubClassifier{}, Workers: 1, Buffer: 1}); err == nil {
		t.Error("want error for zero job timeout")
	}
}
