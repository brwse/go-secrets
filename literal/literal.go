// Package literal provides a map-based secret provider for testing.
package literal

import (
	"context"
	"fmt"

	"github.com/jrandolf/secrets"
)

// ProviderOption configures the literal Provider.
type ProviderOption func(*Provider)

// WithVersions configures versioned secret data.
// The outer map key is the secret key, the inner map key is the version identifier,
// and the value is the secret bytes for that version.
func WithVersions(versions map[string]map[string][]byte) ProviderOption {
	return func(p *Provider) {
		p.versions = versions
	}
}

// Provider is a map-based secrets.Provider intended for testing.
// It supports both Get and GetVersion (implements secrets.VersionedProvider).
type Provider struct {
	data     map[string][]byte
	versions map[string]map[string][]byte // key -> version -> value
}

// New creates a literal Provider with the given static data.
func New(data map[string][]byte, opts ...ProviderOption) *Provider {
	p := &Provider{
		data: data,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Get retrieves the secret value for the given key.
// Returns secrets.ErrNotFound (wrapped) if the key does not exist.
func (p *Provider) Get(_ context.Context, key string) ([]byte, error) {
	v, ok := p.data[key]
	if !ok {
		return nil, fmt.Errorf("literal: %q: %w", key, secrets.ErrNotFound)
	}
	return v, nil
}

// GetVersion retrieves a specific version of the secret value.
// Returns secrets.ErrNotFound (wrapped) if the key or version does not exist.
func (p *Provider) GetVersion(_ context.Context, key string, version string) ([]byte, error) {
	if p.versions == nil {
		return nil, fmt.Errorf("literal: %q version %q: %w", key, version, secrets.ErrNotFound)
	}
	vmap, ok := p.versions[key]
	if !ok {
		return nil, fmt.Errorf("literal: %q version %q: %w", key, version, secrets.ErrNotFound)
	}
	v, ok := vmap[version]
	if !ok {
		return nil, fmt.Errorf("literal: %q version %q: %w", key, version, secrets.ErrNotFound)
	}
	return v, nil
}
