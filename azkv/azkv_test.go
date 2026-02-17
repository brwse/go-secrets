package azkv

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jrandolf/secrets"
)

// mockKVClient implements Client for testing.
type mockKVClient struct {
	// secrets maps (name, version) to secret value.
	// version "" means the current/latest version.
	secrets map[string]map[string]string
}

func (m *mockKVClient) GetSecret(_ context.Context, name string, version string) (string, error) {
	versions, ok := m.secrets[name]
	if !ok {
		return "", fmt.Errorf("%w", secrets.ErrNotFound)
	}
	val, ok := versions[version]
	if !ok {
		return "", fmt.Errorf("%w", secrets.ErrNotFound)
	}
	return val, nil
}

func TestGet_Existing(t *testing.T) {
	mock := &mockKVClient{
		secrets: map[string]map[string]string{
			"db-password": {
				"": "s3cret", // current/latest
			},
		},
	}
	p, err := New(WithVaultURL("https://my-vault.vault.azure.net"), WithClient(mock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	val, err := p.Get(context.Background(), "db-password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "s3cret" {
		t.Errorf("Get = %q, want %q", val, "s3cret")
	}
}

func TestGet_Missing(t *testing.T) {
	mock := &mockKVClient{
		secrets: map[string]map[string]string{},
	}
	p, err := New(WithVaultURL("https://my-vault.vault.azure.net"), WithClient(mock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = p.Get(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestGetVersion_Specific(t *testing.T) {
	mock := &mockKVClient{
		secrets: map[string]map[string]string{
			"api-key": {
				"":       "new-key",
				"abc123": "old-key",
			},
		},
	}
	p, err := New(WithVaultURL("https://my-vault.vault.azure.net"), WithClient(mock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	val, err := p.GetVersion(context.Background(), "api-key", "abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "old-key" {
		t.Errorf("GetVersion = %q, want %q", val, "old-key")
	}
}
