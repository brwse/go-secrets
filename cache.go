package secrets

import (
	"context"
	"io"
	"sync"
	"time"
)

// CachedProvider wraps a Provider with TTL-based caching.
// Successful results are stored in memory and reused until they expire.
// This is useful for cloud providers (AWS SM, GCP SM, Vault, etc.)
// to avoid redundant API calls and potential rate limiting.
//
// CachedProvider is safe for concurrent use.
type CachedProvider struct {
	provider Provider
	ttl      time.Duration
	mu       sync.RWMutex
	entries  map[string]*cacheEntry
}

type cacheEntry struct {
	data    []byte
	expires time.Time
}

// NewCachedProvider wraps p with a cache that holds results for ttl.
// Only successful results (err == nil) are cached.
func NewCachedProvider(p Provider, ttl time.Duration) *CachedProvider {
	return &CachedProvider{
		provider: p,
		ttl:      ttl,
		entries:  make(map[string]*cacheEntry),
	}
}

// Get retrieves the secret for key, returning a cached value if fresh.
func (c *CachedProvider) Get(ctx context.Context, key string) ([]byte, error) {
	if data, ok := c.get(key); ok {
		return data, nil
	}
	data, err := c.provider.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	c.set(key, data)
	return data, nil
}

// GetVersion retrieves a versioned secret, returning a cached value if fresh.
// The underlying provider must implement VersionedProvider; otherwise an
// ErrVersioningNotSupported error is returned.
func (c *CachedProvider) GetVersion(ctx context.Context, key, version string) ([]byte, error) {
	vp, ok := c.provider.(VersionedProvider)
	if !ok {
		return nil, &ErrVersioningNotSupported{Provider: "cached"}
	}
	cacheKey := key + "\x00" + version
	if data, ok := c.get(cacheKey); ok {
		return data, nil
	}
	data, err := vp.GetVersion(ctx, key, version)
	if err != nil {
		return nil, err
	}
	c.set(cacheKey, data)
	return data, nil
}

// Clear removes all entries from the cache.
func (c *CachedProvider) Clear() {
	c.mu.Lock()
	c.entries = make(map[string]*cacheEntry)
	c.mu.Unlock()
}

// Close clears the cache and, if the underlying provider implements
// io.Closer, closes it.
func (c *CachedProvider) Close() error {
	c.Clear()
	if cl, ok := c.provider.(io.Closer); ok {
		return cl.Close()
	}
	return nil
}

func (c *CachedProvider) get(key string) ([]byte, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	return entry.data, true
}

func (c *CachedProvider) set(key string, data []byte) {
	c.mu.Lock()
	c.entries[key] = &cacheEntry{
		data:    data,
		expires: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
}
