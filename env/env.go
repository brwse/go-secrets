// Package env provides a secret provider that reads from environment variables.
package env

import (
	"context"
	"fmt"
	"os"

	"github.com/brwse/go-secrets"
)

// ProviderOption configures the env Provider.
type ProviderOption func(*Provider)

// WithPrefix configures a prefix that is prepended to all key lookups.
// For example, WithPrefix("MYAPP_") causes Get(ctx, "DB_PASS") to look up
// the environment variable "MYAPP_DB_PASS".
func WithPrefix(prefix string) ProviderOption {
	return func(p *Provider) {
		p.prefix = prefix
	}
}

// Provider reads secrets from environment variables.
// It implements secrets.Provider.
type Provider struct {
	prefix string
}

// New creates a new env Provider with the given options.
func New(opts ...ProviderOption) *Provider {
	p := &Provider{}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Get retrieves the secret value from the environment variable named by key
// (with any configured prefix prepended).
// Returns secrets.ErrNotFound (wrapped) if the environment variable is not set.
func (p *Provider) Get(_ context.Context, key string) ([]byte, error) {
	name := p.prefix + key
	val, ok := os.LookupEnv(name)
	if !ok {
		return nil, fmt.Errorf("env: %q: %w", name, secrets.ErrNotFound)
	}
	return []byte(val), nil
}
