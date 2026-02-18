package vault

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/brwse/go-secrets"
)

// mockVaultClient implements Client for testing.
type mockVaultClient struct {
	// secrets maps path to version to data map.
	// version 0 means the latest version.
	secrets map[string]map[int]map[string]any
}

func (m *mockVaultClient) Get(_ context.Context, path string) (map[string]any, error) {
	versions, ok := m.secrets[path]
	if !ok {
		return nil, fmt.Errorf("%w", secrets.ErrNotFound)
	}
	data, ok := versions[0]
	if !ok {
		return nil, fmt.Errorf("%w", secrets.ErrNotFound)
	}
	return data, nil
}

func (m *mockVaultClient) GetVersion(_ context.Context, path string, version int) (map[string]any, error) {
	versions, ok := m.secrets[path]
	if !ok {
		return nil, fmt.Errorf("%w", secrets.ErrNotFound)
	}
	data, ok := versions[version]
	if !ok {
		return nil, fmt.Errorf("%w", secrets.ErrNotFound)
	}
	return data, nil
}

func TestGet_Existing(t *testing.T) {
	mock := &mockVaultClient{
		secrets: map[string]map[int]map[string]any{
			"db-password": {
				0: {"value": "s3cret"},
			},
		},
	}
	p, err := New(WithClient(mock))
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
	mock := &mockVaultClient{
		secrets: map[string]map[int]map[string]any{},
	}
	p, err := New(WithClient(mock))
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
	mock := &mockVaultClient{
		secrets: map[string]map[int]map[string]any{
			"api-key": {
				0: {"value": "v3-key"},
				1: {"value": "v1-key"},
				2: {"value": "v2-key"},
				3: {"value": "v3-key"},
			},
		},
	}
	p, err := New(WithClient(mock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	val, err := p.GetVersion(context.Background(), "api-key", "1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "v1-key" {
		t.Errorf("GetVersion = %q, want %q", val, "v1-key")
	}
}

func TestGetVersion_Current(t *testing.T) {
	mock := &mockVaultClient{
		secrets: map[string]map[int]map[string]any{
			"api-key": {
				0: {"value": "latest-key"},
			},
		},
	}
	p, err := New(WithClient(mock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	val, err := p.GetVersion(context.Background(), "api-key", "current")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "latest-key" {
		t.Errorf("GetVersion = %q, want %q", val, "latest-key")
	}
}

func TestGetVersion_InvalidVersion(t *testing.T) {
	mock := &mockVaultClient{
		secrets: map[string]map[int]map[string]any{},
	}
	p, err := New(WithClient(mock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = p.GetVersion(context.Background(), "key", "not-a-number")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
