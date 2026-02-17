// Package awssm provides a secret provider that reads from AWS Secrets Manager.
package awssm

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/jrandolf/secrets"
)

// Client abstracts the AWS Secrets Manager API.
// Implement this interface to provide a custom or pre-configured client.
type Client interface {
	GetSecretValue(ctx context.Context, name string, versionStage string) (string, error)
}

// ProviderOption configures the awssm Provider.
type ProviderOption func(*Provider)

// WithRegion configures the AWS region for the Secrets Manager client.
func WithRegion(region string) ProviderOption {
	return func(p *Provider) {
		p.region = region
	}
}

// WithClient injects a custom Client implementation.
// Use this to provide a pre-configured AWS client or for testing.
func WithClient(c Client) ProviderOption {
	return func(p *Provider) {
		p.client = c
	}
}

// Provider reads secrets from AWS Secrets Manager.
// It implements secrets.Provider and secrets.VersionedProvider.
type Provider struct {
	region string
	client Client
}

// New creates a new AWS Secrets Manager Provider with the given options.
// If no Client is provided via WithClient, a real AWS SDK client is created
// using the default AWS credential chain.
func New(opts ...ProviderOption) (*Provider, error) {
	p := &Provider{}
	for _, opt := range opts {
		opt(p)
	}
	if p.client == nil {
		var cfgOpts []func(*awsconfig.LoadOptions) error
		if p.region != "" {
			cfgOpts = append(cfgOpts, awsconfig.WithRegion(p.region))
		}
		cfg, err := awsconfig.LoadDefaultConfig(context.Background(), cfgOpts...)
		if err != nil {
			return nil, fmt.Errorf("awssm: load AWS config: %w", err)
		}
		p.client = &sdkClient{sm: secretsmanager.NewFromConfig(cfg)}
	}
	return p, nil
}

// versionStage maps user-facing version strings to AWS version stages.
var versionStage = map[string]string{
	"current":  "AWSCURRENT",
	"previous": "AWSPREVIOUS",
	"pending":  "AWSPENDING",
}

// Get retrieves the current version of the secret.
// Returns secrets.ErrNotFound (wrapped) if the secret does not exist.
func (p *Provider) Get(ctx context.Context, key string) ([]byte, error) {
	return p.GetVersion(ctx, key, "current")
}

// GetVersion retrieves a specific version stage of the secret.
// Supported versions: "current" (AWSCURRENT), "previous" (AWSPREVIOUS), "pending" (AWSPENDING).
// Returns secrets.ErrNotFound (wrapped) if the secret or version does not exist.
func (p *Provider) GetVersion(ctx context.Context, key string, version string) ([]byte, error) {
	stage, ok := versionStage[version]
	if !ok {
		return nil, fmt.Errorf("awssm: secret %q: unsupported version %q", key, version)
	}
	val, err := p.client.GetSecretValue(ctx, key, stage)
	if err != nil {
		return nil, fmt.Errorf("awssm: secret %q: %w", key, err)
	}
	return []byte(val), nil
}

// sdkClient wraps the real AWS Secrets Manager SDK.
type sdkClient struct {
	sm *secretsmanager.Client
}

func (c *sdkClient) GetSecretValue(ctx context.Context, name string, versionStage string) (string, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(name),
		VersionStage: aws.String(versionStage),
	}
	out, err := c.sm.GetSecretValue(ctx, input)
	if err != nil {
		var rnf *smtypes.ResourceNotFoundException
		if errors.As(err, &rnf) {
			return "", fmt.Errorf("%w", secrets.ErrNotFound)
		}
		return "", err
	}
	if out.SecretString != nil {
		return *out.SecretString, nil
	}
	return string(out.SecretBinary), nil
}
