// Package gcpsm provides a secret provider that reads from GCP Secret Manager.
package gcpsm

import (
	"context"
	"fmt"
	"os"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/jrandolf/secrets"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Client abstracts the GCP Secret Manager API.
type Client interface {
	AccessSecretVersion(ctx context.Context, name string) ([]byte, error)
	Close() error
}

// ProviderOption configures the gcpsm Provider.
type ProviderOption func(*Provider)

// WithProject configures the GCP project ID. Required.
func WithProject(project string) ProviderOption {
	return func(p *Provider) {
		p.project = project
	}
}

// WithClient injects a custom Client implementation.
func WithClient(c Client) ProviderOption {
	return func(p *Provider) {
		p.client = c
	}
}

// Provider reads secrets from GCP Secret Manager.
type Provider struct {
	project string
	client  Client
}

func (p *Provider) resourceName(key string, version string) string {
	return fmt.Sprintf("projects/%s/secrets/%s/versions/%s", p.project, key, version)
}

// New creates a new GCP Secret Manager Provider.
// The project ID is resolved in order: WithProject option, GOOGLE_CLOUD_PROJECT
// env var, GCLOUD_PROJECT env var. Returns an error if no project is found.
// If no Client is provided via WithClient, a real GCP SDK client is created
// using Application Default Credentials.
func New(opts ...ProviderOption) (*Provider, error) {
	p := &Provider{}
	for _, opt := range opts {
		opt(p)
	}
	if p.project == "" {
		p.project = os.Getenv("GOOGLE_CLOUD_PROJECT")
	}
	if p.project == "" {
		p.project = os.Getenv("GCLOUD_PROJECT")
	}
	if p.project == "" {
		return nil, fmt.Errorf("gcpsm: project is required (use WithProject or set GOOGLE_CLOUD_PROJECT)")
	}
	if p.client == nil {
		c, err := secretmanager.NewClient(context.Background())
		if err != nil {
			return nil, fmt.Errorf("gcpsm: create Secret Manager client: %w", err)
		}
		p.client = &sdkClient{sm: c}
	}
	return p, nil
}

// Get retrieves the latest version of the secret.
func (p *Provider) Get(ctx context.Context, key string) ([]byte, error) {
	return p.GetVersion(ctx, key, "current")
}

// GetVersion retrieves a specific version of the secret.
func (p *Provider) GetVersion(ctx context.Context, key string, version string) ([]byte, error) {
	v := version
	if v == "current" {
		v = "latest"
	}
	name := p.resourceName(key, v)
	data, err := p.client.AccessSecretVersion(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("gcpsm: secret %q version %q: %w", key, version, err)
	}
	return data, nil
}

// Close releases resources held by the provider.
func (p *Provider) Close() error {
	return p.client.Close()
}

// sdkClient wraps the real GCP Secret Manager SDK.
type sdkClient struct {
	sm *secretmanager.Client
}

func (c *sdkClient) AccessSecretVersion(ctx context.Context, name string) ([]byte, error) {
	resp, err := c.sm.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	})
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			return nil, fmt.Errorf("%w", secrets.ErrNotFound)
		}
		return nil, err
	}
	return resp.Payload.Data, nil
}

func (c *sdkClient) Close() error {
	return c.sm.Close()
}
