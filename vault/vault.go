// Package vault provides a secret provider that reads from HashiCorp Vault (KV v2).
package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/jrandolf/secrets"
)

// Client abstracts the HashiCorp Vault KV v2 API.
type Client interface {
	// Get retrieves the latest version of the secret at the given path.
	// Returns the secret data map.
	Get(ctx context.Context, path string) (map[string]any, error)
	// GetVersion retrieves a specific version of the secret at the given path.
	GetVersion(ctx context.Context, path string, version int) (map[string]any, error)
}

// ProviderOption configures the vault Provider.
type ProviderOption func(*Provider)

// WithAddress configures the Vault server address.
func WithAddress(addr string) ProviderOption {
	return func(p *Provider) {
		p.address = addr
	}
}

// WithToken configures the Vault authentication token.
func WithToken(token string) ProviderOption {
	return func(p *Provider) {
		p.token = token
	}
}

// WithMount configures the KV v2 mount path. Defaults to "secret".
func WithMount(mount string) ProviderOption {
	return func(p *Provider) {
		p.mount = mount
	}
}

// WithDataKey configures which key from the Vault data map to return.
// Defaults to "value". If the secret data contains {"value": "s3cret"},
// Get returns "s3cret".
func WithDataKey(key string) ProviderOption {
	return func(p *Provider) {
		p.dataKey = key
	}
}

// WithClient injects a custom Client implementation.
func WithClient(c Client) ProviderOption {
	return func(p *Provider) {
		p.client = c
	}
}

// Provider reads secrets from HashiCorp Vault's KV v2 engine.
// It implements secrets.Provider and secrets.VersionedProvider.
type Provider struct {
	address string
	token   string
	mount   string
	dataKey string
	client  Client
}

// New creates a new HashiCorp Vault Provider with the given options.
// If no Client is provided via WithClient, a real Vault SDK client is created
// using DefaultConfig (reads VAULT_ADDR and VAULT_TOKEN from environment).
func New(opts ...ProviderOption) (*Provider, error) {
	p := &Provider{
		mount:   "secret",
		dataKey: "value",
	}
	for _, opt := range opts {
		opt(p)
	}
	if p.client == nil {
		cfg := vaultapi.DefaultConfig()
		if p.address != "" {
			cfg.Address = p.address
		}
		c, err := vaultapi.NewClient(cfg)
		if err != nil {
			return nil, fmt.Errorf("vault: create Vault client: %w", err)
		}
		if p.token != "" {
			c.SetToken(p.token)
		}
		p.client = &sdkClient{kv: c.KVv2(p.mount)}
	}
	return p, nil
}

// extractValue extracts the configured data key from the Vault data map.
func (p *Provider) extractValue(key string, data map[string]any) ([]byte, error) {
	if data == nil {
		return nil, fmt.Errorf("vault: secret %q: %w", key, secrets.ErrNotFound)
	}
	val, ok := data[p.dataKey]
	if !ok {
		return nil, fmt.Errorf("vault: secret %q: data key %q not found", key, p.dataKey)
	}
	switch v := val.(type) {
	case string:
		return []byte(v), nil
	case []byte:
		return v, nil
	default:
		return fmt.Appendf(nil, "%v", v), nil
	}
}

// Get retrieves the latest version of the secret.
// Returns secrets.ErrNotFound (wrapped) if the secret does not exist.
func (p *Provider) Get(ctx context.Context, key string) ([]byte, error) {
	data, err := p.client.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("vault: secret %q: %w", key, err)
	}
	return p.extractValue(key, data)
}

// GetVersion retrieves a specific version of the secret.
// The version string is parsed as an integer (Vault KV v2 version numbers).
// "current" retrieves the latest version.
// Returns secrets.ErrNotFound (wrapped) if the secret or version does not exist.
func (p *Provider) GetVersion(ctx context.Context, key string, version string) ([]byte, error) {
	if version == "current" {
		return p.Get(ctx, key)
	}
	v, err := strconv.Atoi(version)
	if err != nil {
		return nil, fmt.Errorf("vault: secret %q: invalid version %q: must be integer or \"current\"", key, version)
	}
	data, err := p.client.GetVersion(ctx, key, v)
	if err != nil {
		return nil, fmt.Errorf("vault: secret %q: %w", key, err)
	}
	return p.extractValue(key, data)
}

// sdkClient wraps the real HashiCorp Vault KV v2 SDK.
type sdkClient struct {
	kv *vaultapi.KVv2
}

func (c *sdkClient) Get(ctx context.Context, path string) (map[string]any, error) {
	s, err := c.kv.Get(ctx, path)
	if err != nil {
		var re *vaultapi.ResponseError
		if errors.As(err, &re) && re.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%w", secrets.ErrNotFound)
		}
		return nil, err
	}
	return s.Data, nil
}

func (c *sdkClient) GetVersion(ctx context.Context, path string, version int) (map[string]any, error) {
	s, err := c.kv.GetVersion(ctx, path, version)
	if err != nil {
		var re *vaultapi.ResponseError
		if errors.As(err, &re) && re.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%w", secrets.ErrNotFound)
		}
		return nil, err
	}
	return s.Data, nil
}
