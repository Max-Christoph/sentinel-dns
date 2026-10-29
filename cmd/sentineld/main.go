// Command sentineld runs the sentinel-dns sinkhole daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/Max-Christoph/sentinel-dns/internal/config"
	dnsserver "github.com/Max-Christoph/sentinel-dns/internal/dns"
	"github.com/Max-Christoph/sentinel-dns/internal/provider"
	"github.com/Max-Christoph/sentinel-dns/internal/queue"
	"github.com/Max-Christoph/sentinel-dns/internal/store"
)

// version is injected at build time via
// -ldflags "-X main.version=$(git describe --tags --always)".
var version = "dev"

const (
	shutdownGrace    = 10 * time.Second
	retrySuppression = 90 * time.Second
	statsInterval    = 5 * time.Minute
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sentineld: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "config.yaml", "path to the YAML configuration")
	showVersion := flag.Bool("version", false, "print the version and exit")
	pruneDays := flag.Int("prune-days", 0, "delete decisions not updated for N days at startup (0 disables)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("sentineld %s\n", version)
		return nil
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	log := newLogger(cfg.Logging)
	slog.SetDefault(log)
	log.Info("starting sentinel-dns", "version", version, "provider", cfg.Provider.Type,
		"upstream", strings.Join(cfg.Upstream.Addresses, ","), "database", cfg.Database.Path)

	st, err := store.Open(cfg.Database.Path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := st.Close(); cerr != nil {
			log.Error("closing store", "error", cerr)
		}
	}()

	cache := dnsserver.NewCache(cfg.Cache.MaxEntries)
	if err := warmCache(context.Background(), st, cache, cfg, log); err != nil {
		return err
	}
	if *pruneDays > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -*pruneDays)
		removed, err := st.PruneBefore(context.Background(), cutoff)
		if err != nil {
			log.Warn("pruning old decisions failed", "error", err)
		} else {
			log.Info("pruned old decisions", "rows", removed, "older_than", cutoff)
		}
	}

	classifier, err := provider.New(cfg.Provider, log)
	if err != nil {
		return err
	}
	log.Info("decision provider ready", "provider", provider.Name(classifier))

	limiter := newErrorLimiter(30 * time.Second)
	onError := func(ctx context.Context, job queue.Job, classifyErr error) {
		// Suppress immediate retries so a broken backend does not get one
		// request per client lookup.
		cache.Put(job.Domain, dnsserver.Entry{
			Source:  "error",
			Expires: time.Now().Add(retrySuppression),
		})
		if count, ok := limiter.observe(); ok {
			log.Warn("classification failed", "domain", job.Domain, "error", classifyErr, "failures_since_last_log", count)
		}
	}

	// Post-block enrichment: a second, category-only request for blocked
	// domains. It runs on its own single-worker pool so it can never occupy a
	// first-line worker, and it only backfills metadata.
	var enrichPool *queue.Pool
	if cfg.Provider.Type == "systemone" && cfg.Provider.SystemOne.EnrichCategory &&
		cfg.Provider.SystemOne.Questions == "tracking" {
		enrichCfg := cfg.Provider
		enrichCfg.SystemOne.Questions = "category"
		enricher, err := provider.New(enrichCfg, log)
		if err != nil {
			return err
		}
		enrichPool, err = queue.New(queue.Options{
			Workers:    1,
			Buffer:     cfg.Workers.QueueSize,
			JobTimeout: cfg.Workers.JobTimeout.Std(),
			Classifier: enricher,
			OnError: func(_ context.Context, job queue.Job, enrichErr error) {
				log.Debug("category enrichment failed", "domain", job.Domain, "error", enrichErr)
			},
			OnResult: func(ctx context.Context, job queue.Job, resp *provider.DecisionResponse) {
				if resp.Category == "" || resp.Category == "unknown" {
					return
				}
				// A label below the decision threshold is not written: an empty
				// column is honest, a guessed category in a dashboard is not.
				if resp.CategoryProb < cfg.Blocking.MinConfidence {
					log.Debug("category label below threshold, not stored", "domain", job.Domain,
						"category", resp.Category, "category_probability", resp.CategoryProb)
					return
				}
				if _, err := st.UpdateCategory(ctx, job.Domain, resp.Category); err != nil {
					log.Warn("store category failed", "domain", job.Domain, "error", err)
				}
				cache.UpdateCategory(job.Domain, resp.Category)
				log.Info("category enriched", "domain", job.Domain,
					"category", resp.Category, "category_probability", resp.CategoryProb)
			},
			Logger: log,
		})
		if err != nil {
			return err
		}
		enrichPool.Start()
		log.Info("post-block category enrichment enabled", "workers", 1)
	}

	policy := provider.Policy{
		MinConfidence:          cfg.Blocking.MinConfidence,
		CategoryMinProbability: cfg.Blocking.CategoryMinProbability,
	}
	onResult := func(ctx context.Context, job queue.Job, resp *provider.DecisionResponse) {
		decision := policy.Decide(resp)
		block, confidence := decision.Block, decision.Confidence
		now := time.Now().UTC()
		record := store.Decision{
			Domain:         job.Domain,
			DeviceCategory: resp.Category,
			IsTelemetry:    resp.Block,
			Blocked:        block,
			Confidence:     confidence,
			Reasoning:      resp.Reason,
			ClientIP:       job.ClientIP,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		if err := st.RecordDecision(ctx, record); err != nil {
			log.Error("persist decision failed", "domain", job.Domain, "error", err)
		}
		ttl := cfg.Cache.AllowedTTL.Std()
		if block {
			ttl = cfg.Cache.BlockedTTL.Std()
		}
		entry := dnsserver.Entry{
			Blocked:     block,
			Confidence:  confidence,
			Reason:      resp.Reason,
			Category:    resp.Category,
			IsTelemetry: resp.Block,
			Source:      "provider",
			Expires:     now.Add(ttl),
		}
		if !cache.Put(job.Domain, entry) {
			log.Debug("cache full, decision not cached", "domain", job.Domain)
		}
		if block && enrichPool != nil {
			if !enrichPool.Submit(queue.Job{Domain: job.Domain}) {
				log.Debug("enrichment queue full, category skipped", "domain", job.Domain)
			}
		}
		log.Info("classified", "domain", job.Domain, "client_ip", job.ClientIP,
			"block", block, "confidence", confidence, "decided_by", decision.Reason,
			"category", resp.Category, "reason", resp.Reason)
	}

	pool, err := queue.New(queue.Options{
		Workers:    cfg.Workers.PoolSize,
		Buffer:     cfg.Workers.QueueSize,
		JobTimeout: cfg.Workers.JobTimeout.Std(),
		Classifier: classifier,
		OnResult:   onResult,
		OnError:    onError,
		Logger:     log,
	})
	if err != nil {
		return err
	}
	pool.Start()

	upstream, err := dnsserver.NewUpstream(cfg.Upstream.Addresses, cfg.Upstream.Timeout.Std(), log)
	if err != nil {
		return err
	}
	handler, err := dnsserver.New(dnsserver.Options{
		Cache:          cache,
		Forwarder:      upstream,
		Submit:         func(domain, clientIP string) bool { return pool.Submit(queue.Job{Domain: domain, ClientIP: clientIP}) },
		IPv4:           net.ParseIP(cfg.Blocking.IPv4),
		IPv6:           net.ParseIP(cfg.Blocking.IPv6),
		TTL:            cfg.Blocking.TTL,
		ForwardTimeout: cfg.Upstream.Timeout.Std()*time.Duration(len(cfg.Upstream.Addresses)) + time.Second,
		Allowlist:      cfg.Blocking.Allowlist,
		Logger:         log,
	})
	if err != nil {
		return err
	}

	runtime, serveErrs, err := startDNS(cfg, handler, log)
	if err != nil {
		return err
	}

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	statsCtx, stopStats := context.WithCancel(context.Background())
	defer stopStats()
	go logStats(statsCtx, handler, pool, log)

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case serveErr := <-serveErrs:
		log.Error("dns listener failed", "error", serveErr)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	runtime.shutdown(shutdownCtx, log)
	if err := pool.Stop(shutdownCtx); err != nil {
		log.Warn("worker pool shutdown", "error", err)
	}
	if enrichPool != nil {
		if err := enrichPool.Stop(shutdownCtx); err != nil {
			log.Warn("enrichment pool shutdown", "error", err)
		}
	}
	if err := st.Close(); err != nil {
		log.Error("closing store", "error", err)
	}
	log.Info("stopped", "dns", handler.Stats(), "queue", pool.Stats(), "cache", cache.Stats())
	return nil
}

// warmCache loads every persisted decision into the in-memory cache so a
// restart does not re-classify known domains.
func warmCache(ctx context.Context, st *store.Store, cache *dnsserver.Cache, cfg config.Config, log *slog.Logger) error {
	decisions, err := st.All(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	for _, d := range decisions {
		ttl := cfg.Cache.AllowedTTL.Std()
		if d.Blocked {
			ttl = cfg.Cache.BlockedTTL.Std()
		}
		cache.Put(d.Domain, dnsserver.Entry{
			Blocked:     d.Blocked,
			Confidence:  d.Confidence,
			Reason:      d.Reasoning,
			Category:    d.DeviceCategory,
			IsTelemetry: d.IsTelemetry,
			Source:      "preload",
			Expires:     now.Add(ttl),
		})
	}
	log.Info("cache warmed", "domains", len(decisions), "entries", cache.Len())
	return nil
}

type dnsRuntime struct {
	udp *mdns.Server
	tcp *mdns.Server
}

func startDNS(cfg config.Config, handler mdns.Handler, log *slog.Logger) (*dnsRuntime, <-chan error, error) {
	errCh := make(chan error, 2)
	rt := &dnsRuntime{}

	if cfg.Listen.UDP != "" {
		pc, err := net.ListenPacket("udp", cfg.Listen.UDP)
		if err != nil {
			return nil, nil, fmt.Errorf("listen udp %s: %w", cfg.Listen.UDP, err)
		}
		rt.udp = &mdns.Server{PacketConn: pc, Handler: handler, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
		go func() {
			if serveErr := rt.udp.ActivateAndServe(); serveErr != nil {
				errCh <- fmt.Errorf("udp %s: %w", cfg.Listen.UDP, serveErr)
			}
		}()
		log.Info("dns listener started", "network", "udp", "addr", pc.LocalAddr().String())
	}

	if cfg.Listen.TCP != "" {
		listener, err := net.Listen("tcp", cfg.Listen.TCP)
		if err != nil {
			if rt.udp != nil {
				_ = rt.udp.Shutdown()
			}
			return nil, nil, fmt.Errorf("listen tcp %s: %w", cfg.Listen.TCP, err)
		}
		rt.tcp = &mdns.Server{Listener: listener, Handler: handler, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
		go func() {
			if serveErr := rt.tcp.ActivateAndServe(); serveErr != nil {
				errCh <- fmt.Errorf("tcp %s: %w", cfg.Listen.TCP, serveErr)
			}
		}()
		log.Info("dns listener started", "network", "tcp", "addr", listener.Addr().String())
	}

	return rt, errCh, nil
}

func (r *dnsRuntime) shutdown(ctx context.Context, log *slog.Logger) {
	if r == nil {
		return
	}
	if r.udp != nil {
		if err := r.udp.ShutdownContext(ctx); err != nil {
			log.Warn("udp shutdown", "error", err)
		}
	}
	if r.tcp != nil {
		if err := r.tcp.ShutdownContext(ctx); err != nil {
			log.Warn("tcp shutdown", "error", err)
		}
	}
}

func logStats(ctx context.Context, handler *dnsserver.Server, pool *queue.Pool, log *slog.Logger) {
	ticker := time.NewTicker(statsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Info("stats", "dns", handler.Stats(), "queue", pool.Stats(), "cache", handler.Cache().Stats())
		}
	}
}

func newLogger(cfg config.LoggingConfig) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if strings.EqualFold(cfg.Format, "json") {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(handler)
}

// errorLimiter collapses a storm of provider failures into periodic warnings.
type errorLimiter struct {
	mu      sync.Mutex
	every   time.Duration
	count   uint64
	lastLog time.Time
}

func newErrorLimiter(every time.Duration) *errorLimiter {
	return &errorLimiter{every: every}
}

func (l *errorLimiter) observe() (uint64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.count++
	if time.Since(l.lastLog) < l.every {
		return 0, false
	}
	count := l.count
	l.count = 0
	l.lastLog = time.Now()
	return count, true
}
