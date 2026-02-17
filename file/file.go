// Package file provides a secret provider that reads from filesystem files.
package file

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jrandolf/secrets"
)

// ProviderOption configures the file Provider.
type ProviderOption func(*Provider)

// WithBaseDir configures a base directory that is prepended to all key lookups.
// For example, WithBaseDir("/run/secrets") causes Get(ctx, "db-pass") to read
// the file "/run/secrets/db-pass".
func WithBaseDir(dir string) ProviderOption {
	return func(p *Provider) {
		p.baseDir = dir
	}
}

// WithTrimNewline configures whether trailing newlines (\n and \r\n) are
// trimmed from the file contents. This is useful for secret files that
// contain a trailing newline added by editors or tooling.
func WithTrimNewline(trim bool) ProviderOption {
	return func(p *Provider) {
		p.trimNewline = trim
	}
}

// Provider reads secrets from filesystem files.
// It implements secrets.Provider.
type Provider struct {
	baseDir     string
	trimNewline bool
}

// New creates a new file Provider with the given options.
func New(opts ...ProviderOption) *Provider {
	p := &Provider{}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Get retrieves the secret value by reading the file at the path determined
// by the key (with any configured base directory prepended).
// Returns secrets.ErrNotFound (wrapped) if the file does not exist.
func (p *Provider) Get(_ context.Context, key string) ([]byte, error) {
	path := key
	if p.baseDir != "" {
		path = filepath.Join(p.baseDir, key)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("file: %q: %w", path, secrets.ErrNotFound)
		}
		return nil, fmt.Errorf("file: %q: %w", path, err)
	}

	if p.trimNewline {
		data = bytes.TrimRight(data, "\r\n")
	}

	return data, nil
}
