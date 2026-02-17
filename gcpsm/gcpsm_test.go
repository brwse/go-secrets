package gcpsm

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jrandolf/secrets"
)

// mockSMClient implements Client for testing.
type mockSMClient struct {
	// secrets maps resource name to secret payload.
	secrets map[string][]byte
}

func (m *mockSMClient) AccessSecretVersion(_ context.Context, name string) ([]byte, error) {
	val, ok := m.secrets[name]
	if !ok {
		return nil, fmt.Errorf("%w", secrets.ErrNotFound)
	}
	return val, nil
}

func (m *mockSMClient) Close() error {
	return nil
}

func TestGet_Existing(t *testing.T) {
	mock := &mockSMClient{
		secrets: map[string][]byte{
			"projects/my-project/secrets/db-password/versions/latest": []byte("s3cret"),
		},
	}
	p, err := New(WithProject("my-project"), WithClient(mock))
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
	mock := &mockSMClient{
		secrets: map[string][]byte{},
	}
	p, err := New(WithProject("my-project"), WithClient(mock))
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

func TestGetVersion_Numeric(t *testing.T) {
	mock := &mockSMClient{
		secrets: map[string][]byte{
			"projects/my-project/secrets/api-key/versions/3": []byte("v3-value"),
		},
	}
	p, err := New(WithProject("my-project"), WithClient(mock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	val, err := p.GetVersion(context.Background(), "api-key", "3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "v3-value" {
		t.Errorf("GetVersion = %q, want %q", val, "v3-value")
	}
}

func TestClose(t *testing.T) {
	mock := &mockSMClient{secrets: map[string][]byte{}}
	p, err := New(WithProject("my-project"), WithClient(mock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := p.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNew_MissingProject(t *testing.T) {
	mock := &mockSMClient{secrets: map[string][]byte{}}
	_, err := New(WithClient(mock))
	if err == nil {
		t.Fatal("expected error for missing project, got nil")
	}
}
