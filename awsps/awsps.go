// Package awsps provides a secret provider that reads from AWS Systems Manager Parameter Store.
package awsps

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/jrandolf/secrets"
)

// Client abstracts the AWS SSM Parameter Store API.
type Client interface {
	GetParameter(ctx context.Context, name string, decrypt bool) (string, error)
}

// ProviderOption configures the awsps Provider.
type ProviderOption func(*Provider)

// WithRegion configures the AWS region for the SSM client.
func WithRegion(region string) ProviderOption {
	return func(p *Provider) {
		p.region = region
	}
}

// WithDecryption configures whether SecureString parameters are decrypted.
// Defaults to true.
func WithDecryption(decrypt bool) ProviderOption {
	return func(p *Provider) {
		p.decrypt = decrypt
	}
}

// WithClient injects a custom Client implementation.
func WithClient(c Client) ProviderOption {
	return func(p *Provider) {
		p.client = c
	}
}

// Provider reads secrets from AWS Systems Manager Parameter Store.
// It implements secrets.Provider.
type Provider struct {
	region  string
	decrypt bool
	client  Client
}

// New creates a new AWS Parameter Store Provider with the given options.
// If no Client is provided via WithClient, a real AWS SDK client is created
// using the default AWS credential chain.
func New(opts ...ProviderOption) (*Provider, error) {
	p := &Provider{
		decrypt: true, // default: decrypt SecureString parameters
	}
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
			return nil, fmt.Errorf("awsps: load AWS config: %w", err)
		}
		p.client = &sdkClient{ssm: ssm.NewFromConfig(cfg)}
	}
	return p, nil
}

// Get retrieves the parameter value for the given key.
// Returns secrets.ErrNotFound (wrapped) if the parameter does not exist.
func (p *Provider) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := p.client.GetParameter(ctx, key, p.decrypt)
	if err != nil {
		return nil, fmt.Errorf("awsps: parameter %q: %w", key, err)
	}
	return []byte(val), nil
}

// sdkClient wraps the real AWS SSM SDK.
type sdkClient struct {
	ssm *ssm.Client
}

func (c *sdkClient) GetParameter(ctx context.Context, name string, decrypt bool) (string, error) {
	out, err := c.ssm.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(decrypt),
	})
	if err != nil {
		var pnf *ssmtypes.ParameterNotFound
		if errors.As(err, &pnf) {
			return "", fmt.Errorf("%w", secrets.ErrNotFound)
		}
		return "", err
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", fmt.Errorf("%w", secrets.ErrNotFound)
	}
	return *out.Parameter.Value, nil
}
