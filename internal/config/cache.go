package config

import (
	"sync"
	"time"
)

// CacheEntry represents a cached ConfigSource value
type CacheEntry struct {
	Value      string
	ExpiresAt  time.Time
	Exists     bool
	LastError  error
}

// ConfigSourceCache provides TTL-based caching for resolved ConfigSource values
type ConfigSourceCache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	ttl     time.Duration
}

// NewConfigSourceCache creates a new cache with the specified TTL
func NewConfigSourceCache(ttl time.Duration) *ConfigSourceCache {
	return &ConfigSourceCache{
		entries: make(map[string]*CacheEntry),
		ttl:     ttl,
	}
}

// Get retrieves a cached value if it exists and hasn't expired
func (c *ConfigSourceCache) Get(key string) (string, bool, error, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, found := c.entries[key]
	if !found {
		return "", false, nil, false // Not in cache
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		return "", false, nil, false // Expired
	}

	return entry.Value, entry.Exists, entry.LastError, true // Valid cache hit
}

// Set stores a value in the cache with TTL
func (c *ConfigSourceCache) Set(key string, value string, exists bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &CacheEntry{
		Value:     value,
		ExpiresAt: time.Now().Add(c.ttl),
		Exists:    exists,
		LastError: err,
	}
}

// Clear removes all entries from the cache
func (c *ConfigSourceCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*CacheEntry)
}

// SetTTL updates the cache TTL
func (c *ConfigSourceCache) SetTTL(ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ttl = ttl
}

// GetCacheKey generates a unique key for a ConfigSource
func GetCacheKey(namespace string, source ConfigSource) string {
	resourceName := source.Ref
	if resourceName == "" {
		resourceName = source.RefName
	}
	
	keyName := source.RefName
	if keyName == "" || keyName == resourceName {
		keyName = "value"
	}
	
	return string(source.Type) + ":" + namespace + ":" + resourceName + ":" + keyName
}

