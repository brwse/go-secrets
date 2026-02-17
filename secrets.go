package secrets

import (
	"context"
	"errors"
	"io"
)

// ErrNotFound indicates the requested secret does not exist.
// Providers should wrap this error with context:
//
//	fmt.Errorf("awssm: secret %q: %w", key, secrets.ErrNotFound)
var ErrNotFound = errors.New("secret not found")

// Provider retrieves secret values by key.
// Implementations must be safe for concurrent use.
type Provider interface {
	// Get retrieves the raw secret bytes for the given key.
	// Returns ErrNotFound (wrapped) if the key does not exist.
	Get(ctx context.Context, key string) ([]byte, error)
}

// VersionedProvider is implemented by providers that support secret versioning.
// The resolver uses this for Versioned[T] fields and version= tag options.
type VersionedProvider interface {
	Provider
	GetVersion(ctx context.Context, key string, version string) ([]byte, error)
}

// Versioned holds current and previous values for key rotation.
// When used as a field type, the resolver fetches both versions.
// Requires the provider to implement VersionedProvider.
type Versioned[T any] struct {
	Current  T
	Previous T
}

// ChangeEvent is emitted by a Watcher when a secret value changes.
type ChangeEvent struct {
	// Field is the struct field name (e.g. "EncKey").
	Field string
	// Key is the secret key (e.g. "prod/encryption-key").
	Key string
	// Provider is the provider scheme (e.g. "awssm").
	Provider string
	// OldValue is the previous raw value.
	OldValue []byte
	// NewValue is the new raw value.
	NewValue []byte
}

// Option configures a Resolver.
type Option func(*resolverConfig)

type resolverConfig struct {
	defaultProvider Provider
	providers       map[string]Provider
	parallelism     int
}

// WithDefault sets the provider used for bare keys (no URI scheme).
func WithDefault(p Provider) Option {
	return func(c *resolverConfig) {
		c.defaultProvider = p
	}
}

// WithProvider registers a provider for the given URI scheme.
func WithProvider(scheme string, p Provider) Option {
	return func(c *resolverConfig) {
		if c.providers == nil {
			c.providers = make(map[string]Provider)
		}
		c.providers[scheme] = p
	}
}

// WithParallelism sets the maximum number of concurrent secret fetches.
// Defaults to 10. Set to 1 for sequential fetching. n must be >= 1.
func WithParallelism(n int) Option {
	return func(c *resolverConfig) {
		if n < 1 {
			n = 1
		}
		c.parallelism = n
	}
}

// closeProviders closes all providers that implement io.Closer.
func closeProviders(cfg *resolverConfig) error {
	var errs []error
	seen := make(map[Provider]bool)
	if cfg.defaultProvider != nil {
		if c, ok := cfg.defaultProvider.(io.Closer); ok {
			seen[cfg.defaultProvider] = true
			if err := c.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for _, p := range cfg.providers {
		if seen[p] {
			continue
		}
		seen[p] = true
		if c, ok := p.(io.Closer); ok {
			if err := c.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
