// Package onepassword provides a secret provider that reads from 1Password
// using the 1Password CLI (op).
package onepassword

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/jrandolf/secrets"
)

// Client abstracts the 1Password CLI for retrieving secrets.
type Client interface {
	GetItem(ctx context.Context, reference string) (string, error)
}

// ProviderOption configures the onepassword Provider.
type ProviderOption func(*Provider)

// WithServiceAccountToken configures the 1Password service account token.
// This is used for authentication with the 1Password CLI.
func WithServiceAccountToken(token string) ProviderOption {
	return func(p *Provider) {
		p.serviceAccountToken = token
	}
}

// WithClient injects a custom Client implementation.
func WithClient(c Client) ProviderOption {
	return func(p *Provider) {
		p.client = c
	}
}

// Provider reads secrets from 1Password using the CLI.
// It implements secrets.Provider.
//
// Keys are in the format "vault/item/field", which maps to the
// 1Password reference "op://vault/item/field".
type Provider struct {
	serviceAccountToken string
	client              Client
}

// New creates a new 1Password Provider with the given options.
func New(opts ...ProviderOption) *Provider {
	p := &Provider{}
	for _, opt := range opts {
		opt(p)
	}
	if p.client == nil {
		p.client = &cliClient{serviceAccountToken: p.serviceAccountToken}
	}
	return p
}

// Get retrieves the secret value for the given key.
// The key should be in the format "vault/item/field".
// Returns secrets.ErrNotFound (wrapped) if the secret does not exist.
func (p *Provider) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := p.client.GetItem(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("onepassword: %q: %w", key, err)
	}
	return []byte(val), nil
}

// cliClient shells out to the 1Password CLI.
type cliClient struct {
	serviceAccountToken string
}

func (c *cliClient) GetItem(ctx context.Context, reference string) (string, error) {
	ref := "op://" + reference
	cmd := exec.CommandContext(ctx, "op", "read", ref)
	if c.serviceAccountToken != "" {
		cmd.Env = append(cmd.Environ(), "OP_SERVICE_ACCOUNT_TOKEN="+c.serviceAccountToken)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if strings.Contains(strings.ToLower(errMsg), "not found") ||
			strings.Contains(strings.ToLower(errMsg), "isn't an item") {
			return "", fmt.Errorf("%s: %w", errMsg, secrets.ErrNotFound)
		}
		if errMsg != "" {
			return "", fmt.Errorf("%s", errMsg)
		}
		return "", err
	}
	return strings.TrimRight(stdout.String(), "\n"), nil
}
