package awssm

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jrandolf/secrets"
)

// mockSMClient implements Client for testing.
type mockSMClient struct {
	// secrets maps (name, versionStage) to secret value.
	secrets map[string]map[string]string
}

func (m *mockSMClient) GetSecretValue(_ context.Context, name string, versionStage string) (string, error) {
	stages, ok := m.secrets[name]
	if !ok {
		return "", fmt.Errorf("%w", secrets.ErrNotFound)
	}
	val, ok := stages[versionStage]
	if !ok {
		return "", fmt.Errorf("%w", secrets.ErrNotFound)
	}
	return val, nil
}

func TestGet_Existing(t *testing.T) {
	mock := &mockSMClient{
		secrets: map[string]map[string]string{
			"prod/db-password": {
				"AWSCURRENT": "s3cret",
			},
		},
	}
	p, err := New(WithClient(mock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	val, err := p.Get(context.Background(), "prod/db-password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "s3cret" {
		t.Errorf("Get = %q, want %q", val, "s3cret")
	}
}

func TestGet_Missing(t *testing.T) {
	mock := &mockSMClient{
		secrets: map[string]map[string]string{},
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

func TestGetVersion_Previous(t *testing.T) {
	mock := &mockSMClient{
		secrets: map[string]map[string]string{
			"prod/api-key": {
				"AWSCURRENT":  "new-key",
				"AWSPREVIOUS": "old-key",
			},
		},
	}
	p, err := New(WithClient(mock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	val, err := p.GetVersion(context.Background(), "prod/api-key", "previous")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "old-key" {
		t.Errorf("GetVersion = %q, want %q", val, "old-key")
	}
}

func TestGetVersion_UnsupportedVersion(t *testing.T) {
	mock := &mockSMClient{
		secrets: map[string]map[string]string{},
	}
	p, err := New(WithClient(mock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = p.GetVersion(context.Background(), "key", "invalid")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
