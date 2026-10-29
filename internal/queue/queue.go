// Package queue implements the bounded, non-blocking worker pool that
// decouples DNS answering from AI classification.
package queue

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Max-Christoph/sentinel-dns/internal/provider"
)

// Job is one classification task.
type Job struct {
	Domain   string
	ClientIP string
}

// Classifier is the subset of provider.DecisionProvider the pool needs.
type Classifier interface {
	Classify(ctx context.Context, req provider.DecisionRequest) (*provider.DecisionResponse, error)
}

// ResultFunc persists and caches a successful verdict.
type ResultFunc func(ctx context.Context, job Job, resp *provider.DecisionResponse)

// ErrorFunc observes failed classifications.
type ErrorFunc func(ctx context.Context, job Job, err error)

// Options configures a Pool.
type Options struct {
	Workers    int
	Buffer     int
	JobTimeout time.Duration
	Classifier Classifier
	OnResult   ResultFunc
	OnError    ErrorFunc
	Logger     *slog.Logger
}

// Stats is a snapshot of pool counters.
type Stats struct {
	Submitted  uint64 `json:"submitted"`
	Processed  uint64 `json:"processed"`
	Failed     uint64 `json:"failed"`
	Dropped    uint64 `json:"dropped"`    // queue full, never queued
	Duplicates uint64 `json:"duplicates"` // already in flight
	Pending    int64  `json:"pending"`    // queued or being classified
}

// Pool runs a fixed number of classification workers.
type Pool struct {
	opts Options
	jobs chan Job

	inflight sync.Map // domain -> struct{}
	wg       sync.WaitGroup

	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.RWMutex
	closed bool

	submitted  atomic.Uint64
	processed  atomic.Uint64
	failed     atomic.Uint64
	dropped    atomic.Uint64
	duplicates atomic.Uint64
	pending    atomic.Int64
}

// New validates the options and returns a pool that has not started yet.
func New(opts Options) (*Pool, error) {
	if opts.Classifier == nil {
		return nil, errors.New("queue: classifier must not be nil")
	}
	if opts.Workers < 1 {
		return nil, fmt.Errorf("queue: workers must be >= 1, got %d", opts.Workers)
	}
	if opts.Buffer < 1 {
		return nil, fmt.Errorf("queue: buffer must be >= 1, got %d", opts.Buffer)
	}
	if opts.JobTimeout <= 0 {
		return nil, errors.New("queue: job timeout must be positive")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Pool{
		opts:   opts,
		jobs:   make(chan Job, opts.Buffer),
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// Start launches the workers.
func (p *Pool) Start() {
	for i := 0; i < p.opts.Workers; i++ {
		p.wg.Add(1)
		go p.worker(i)
	}
}

func (p *Pool) worker(id int) {
	defer p.wg.Done()
	log := p.opts.Logger.With("worker", id)
	for job := range p.jobs {
		p.classify(job, log)
	}
}

func (p *Pool) classify(job Job, log *slog.Logger) {
	defer func() {
		p.inflight.Delete(job.Domain)
		p.pending.Add(-1)
	}()

	ctx, cancel := context.WithTimeout(p.ctx, p.opts.JobTimeout)
	defer cancel()

	resp, err := p.opts.Classifier.Classify(ctx, provider.DecisionRequest{
		Domain:   job.Domain,
		ClientIP: job.ClientIP,
	})
	if err != nil {
		p.failed.Add(1)
		if p.opts.OnError != nil {
			p.opts.OnError(ctx, job, err)
		} else {
			log.Warn("classification failed", "domain", job.Domain, "error", err)
		}
		return
	}
	if resp == nil {
		p.failed.Add(1)
		if p.opts.OnError != nil {
			p.opts.OnError(ctx, job, errors.New("queue: classifier returned nil response"))
		}
		return
	}
	p.processed.Add(1)
	if p.opts.OnResult != nil {
		p.opts.OnResult(ctx, job, resp)
	}
}

// Submit enqueues a job without ever blocking the DNS path. It returns false
// when the job was dropped (queue full), deduplicated, invalid or the pool is
// shutting down.
func (p *Pool) Submit(job Job) bool {
	if job.Domain == "" {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return false
	}
	if _, loaded := p.inflight.LoadOrStore(job.Domain, struct{}{}); loaded {
		p.duplicates.Add(1)
		return false
	}
	select {
	case p.jobs <- job:
		p.submitted.Add(1)
		p.pending.Add(1)
		return true
	default:
		p.inflight.Delete(job.Domain)
		p.dropped.Add(1)
		return false
	}
}

// Stop closes the queue and waits for in-flight classifications. Workers keep
// using their own context so a store write is not cancelled mid-flight.
func (p *Pool) Stop(ctx context.Context) error {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.jobs)
	}
	p.mu.Unlock()

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		p.cancel()
		return nil
	case <-ctx.Done():
		p.cancel()
		return fmt.Errorf("queue: shutdown incomplete, %d jobs pending: %w", p.pending.Load(), ctx.Err())
	}
}

// Stats returns a consistent-enough snapshot for logging and tests.
func (p *Pool) Stats() Stats {
	return Stats{
		Submitted:  p.submitted.Load(),
		Processed:  p.processed.Load(),
		Failed:     p.failed.Load(),
		Dropped:    p.dropped.Load(),
		Duplicates: p.duplicates.Load(),
		Pending:    p.pending.Load(),
	}
}
