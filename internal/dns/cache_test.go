package dnsserver

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCachePutGetAndExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	cache := NewCache(10)
	cache.now = func() time.Time { return now }

	entry := Entry{Blocked: true, Confidence: 0.9, Reason: "metrics", Expires: now.Add(time.Minute)}
	if !cache.Put("Ads.Example.", entry) {
		t.Fatal("Put rejected a valid entry")
	}
	got, ok := cache.Get("ads.example")
	if !ok {
		t.Fatal("expected a cache hit")
	}
	if !got.Blocked || got.Reason != "metrics" {
		t.Fatalf("unexpected entry: %+v", got)
	}

	now = now.Add(2 * time.Minute)
	if _, ok := cache.Get("ads.example"); ok {
		t.Fatal("expired entry was returned")
	}
	if cache.Len() != 0 {
		t.Fatalf("expired entry was not removed, len = %d", cache.Len())
	}
	stats := cache.Stats()
	if stats.Hits != 1 || stats.Expired != 1 {
		t.Fatalf("stats = %+v, want 1 hit and 1 expired", stats)
	}
}

func TestCacheRejectsInvalidEntries(t *testing.T) {
	t.Parallel()
	cache := NewCache(2)
	if cache.Put("", Entry{Expires: time.Now().Add(time.Minute)}) {
		t.Error("empty domain was accepted")
	}
	if cache.Put("x.example", Entry{}) {
		t.Error("entry without expiry was accepted")
	}
	if _, ok := cache.Get(""); ok {
		t.Error("empty domain lookup must miss")
	}
}

func TestCacheCapacityBound(t *testing.T) {
	t.Parallel()
	now := time.Now()
	cache := NewCache(2)
	cache.now = func() time.Time { return now }
	for _, domain := range []string{"a.example", "b.example"} {
		if !cache.Put(domain, Entry{Expires: now.Add(time.Minute)}) {
			t.Fatalf("Put(%s) rejected below capacity", domain)
		}
	}
	if cache.Put("c.example", Entry{Expires: now.Add(time.Minute)}) {
		t.Fatal("Put accepted an entry above capacity")
	}
	if cache.Len() != 2 {
		t.Fatalf("len = %d, want 2", cache.Len())
	}
	// Expired entries free capacity.
	now = now.Add(2 * time.Minute)
	if !cache.Put("c.example", Entry{Expires: now.Add(time.Minute)}) {
		t.Fatal("Put did not reclaim expired entries")
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	t.Parallel()
	cache := NewCache(1000)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				domain := fmt.Sprintf("d%d.example", j%50)
				cache.Put(domain, Entry{Blocked: j%2 == 0, Expires: time.Now().Add(time.Minute)})
				_, _ = cache.Get(domain)
			}
		}(i)
	}
	wg.Wait()
	if cache.Len() == 0 {
		t.Fatal("cache is empty after concurrent writes")
	}
}

func TestCacheUpdateCategoryKeepsBlock(t *testing.T) {
	t.Parallel()
	now := time.Now()
	cache := NewCache(4)
	cache.now = func() time.Time { return now }
	cache.Put("ads.example", Entry{Blocked: true, Confidence: 0.9, Reason: "noul", Expires: now.Add(time.Minute)})

	if !cache.UpdateCategory("ADS.example", "analytics") {
		t.Fatal("UpdateCategory missed an existing entry")
	}
	entry, ok := cache.Get("ads.example")
	if !ok {
		t.Fatal("entry disappeared")
	}
	if entry.Category != "analytics" {
		t.Errorf("category = %q, want analytics", entry.Category)
	}
	if !entry.Blocked || entry.Confidence != 0.9 || entry.Reason != "noul" {
		t.Errorf("category backfill altered the decision: %+v", entry)
	}

	if cache.UpdateCategory("missing.example", "ads") {
		t.Error("UpdateCategory reported success for an unknown domain")
	}
	if cache.UpdateCategory("ads.example", "") {
		t.Error("empty category must be rejected")
	}
}

func TestNormalizeName(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]string{
		"Ads.Example.COM.": "ads.example.com",
		"  plain.example ": "plain.example",
		"":                 "",
	} {
		if got := NormalizeName(input); got != want {
			t.Errorf("NormalizeName(%q) = %q, want %q", input, got, want)
		}
	}
}
