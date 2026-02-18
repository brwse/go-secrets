// Package azkv provides a secret provider that reads from Azure Key Vault.
package azkv

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/brwse/go-secrets"
)

// Client abstracts the Azure Key Vault secrets API.
type Client interface {
	GetSecret(ctx context.Context, name string, version string) (string, error)
}

// ProviderOption configures the azkv Provider.
type ProviderOption func(*Provider)

// WithVaultURL configures the Azure Key Vault URL. Required.
func WithVaultURL(url string) ProviderOption {
	return func(p *Provider) {
		p.vaultURL = url
	}
}

// WithClient injects a custom Client implementation.
func WithClient(c Client) ProviderOption {
	return func(p *Provider) {
		p.client = c
	}
}

// Provider reads secrets from Azure Key Vault.
type Provider struct {
	vaultURL string
	client   Client
}

// New creates a new Azure Key Vault Provider.
// WithVaultURL is required when not providing a custom Client via WithClient.
// If no Client is provided, a real Azure SDK client is created
// using DefaultAzureCredential.
func New(opts ...ProviderOption) (*Provider, error) {
	p := &Provider{}
	for _, opt := range opts {
		opt(p)
	}
	if p.client == nil {
		if p.vaultURL == "" {
			return nil, fmt.Errorf("azkv: vault URL is required (use WithVaultURL)")
		}
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("azkv: create Azure credential: %w", err)
		}
		azClient, err := azsecrets.NewClient(p.vaultURL, cred, nil)
		if err != nil {
			return nil, fmt.Errorf("azkv: create Key Vault client: %w", err)
		}
		p.client = &sdkClient{kv: azClient}
	}
	return p, nil
}

// Get retrieves the current version of the secret.
func (p *Provider) Get(ctx context.Context, key string) ([]byte, error) {
	return p.GetVersion(ctx, key, "current")
}

// GetVersion retrieves a specific version of the secret.
func (p *Provider) GetVersion(ctx context.Context, key string, version string) ([]byte, error) {
	v := version
	if v == "current" {
		v = ""
	}
	val, err := p.client.GetSecret(ctx, key, v)
	if err != nil {
		return nil, fmt.Errorf("azkv: secret %q: %w", key, err)
	}
	return []byte(val), nil
}

// sdkClient wraps the real Azure Key Vault SDK.
type sdkClient struct {
	kv *azsecrets.Client
}

func (c *sdkClient) GetSecret(ctx context.Context, name string, version string) (string, error) {
	resp, err := c.kv.GetSecret(ctx, name, version, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
			return "", fmt.Errorf("%w", secrets.ErrNotFound)
		}
		return "", err
	}
	if resp.Value == nil {
		return "", fmt.Errorf("%w", secrets.ErrNotFound)
	}
	return *resp.Value, nil
}
