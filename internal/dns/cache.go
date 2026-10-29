package dnsserver

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Entry is a cached verdict for one domain.
type Entry struct {
	Blocked     bool
	Confidence  float64
	Reason      string
	Category    string
	IsTelemetry bool
	Source      string // preload, provider, error
	Expires     time.Time
}

// Cache is a thread-safe, TTL-bounded decision cache. It is a hint only:
// an evicted or expired entry degrades to an upstream lookup plus a fresh
// classification, never to a wrong answer.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]Entry
	max     int
	now     func() time.Time

	hits    atomic.Uint64
	misses  atomic.Uint64
	expired atomic.Uint64
	evicted atomic.Uint64
	rejects atomic.Uint64
}

// CacheStats is a snapshot of cache counters.
type CacheStats struct {
	Entries int    `json:"entries"`
	Hits    uint64 `json:"hits"`
	Misses  uint64 `json:"misses"`
	Expired uint64 `json:"expired"`
	Evicted uint64 `json:"evicted"`
	Rejects uint64 `json:"rejects"`
}

// NewCache returns a cache holding at most max entries (0 means unbounded).
func NewCache(max int) *Cache {
	if max < 0 {
		max = 0
	}
	return &Cache{
		entries: make(map[string]Entry, 1024),
		max:     max,
		now:     time.Now,
	}
}

// NormalizeName lower-cases a DNS name and strips the trailing dot.
func NormalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// Get returns a live entry. Expired entries are removed lazily.
func (c *Cache) Get(domain string) (Entry, bool) {
	key := NormalizeName(domain)
	if key == "" {
		return Entry{}, false
	}
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		c.misses.Add(1)
		return Entry{}, false
	}
	if !entry.Expires.IsZero() && c.now().After(entry.Expires) {
		c.mu.Lock()
		if current, still := c.entries[key]; still && current.Expires.Equal(entry.Expires) {
			delete(c.entries, key)
		}
		c.mu.Unlock()
		c.expired.Add(1)
		c.misses.Add(1)
		return Entry{}, false
	}
	c.hits.Add(1)
	return entry, true
}

// Put stores an entry. It returns false when the cache is full and no expired
// entry could be reclaimed; callers may log that at debug level.
func (c *Cache) Put(domain string, entry Entry) bool {
	key := NormalizeName(domain)
	if key == "" || entry.Expires.IsZero() {
		c.rejects.Add(1)
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists && c.max > 0 && len(c.entries) >= c.max {
		c.evictExpiredLocked(c.now())
		if len(c.entries) >= c.max {
			c.rejects.Add(1)
			return false
		}
	}
	c.entries[key] = entry
	return true
}

// UpdateCategory backfills the label of an existing entry and reports whether
// the domain was present. Blocked state and expiry are untouched: the label is
// metadata, the decision stands.
func (c *Cache) UpdateCategory(domain, category string) bool {
	key := NormalizeName(domain)
	if key == "" || category == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return false
	}
	entry.Category = category
	c.entries[key] = entry
	return true
}

// Delete removes a domain from the cache.
func (c *Cache) Delete(domain string) {
	c.mu.Lock()
	delete(c.entries, NormalizeName(domain))
	c.mu.Unlock()
}

// Len returns the current number of entries, including not-yet-evicted
// expired ones.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// EvictExpired drops expired entries and returns how many were removed.
func (c *Cache) EvictExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.evictExpiredLocked(c.now())
}

func (c *Cache) evictExpiredLocked(now time.Time) int {
	removed := 0
	for key, entry := range c.entries {
		if !entry.Expires.IsZero() && now.After(entry.Expires) {
			delete(c.entries, key)
			removed++
		}
	}
	c.evicted.Add(uint64(removed))
	return removed
}

// Stats returns the cache counters.
func (c *Cache) Stats() CacheStats {
	return CacheStats{
		Entries: c.Len(),
		Hits:    c.hits.Load(),
		Misses:  c.misses.Load(),
		Expired: c.expired.Load(),
		Evicted: c.evicted.Load(),
		Rejects: c.rejects.Load(),
	}
}
