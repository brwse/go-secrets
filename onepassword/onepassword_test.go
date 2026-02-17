package onepassword

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jrandolf/secrets"
)

// mockOPClient implements Client for testing.
type mockOPClient struct {
	// items maps reference to secret value.
	items map[string]string
}

func (m *mockOPClient) GetItem(_ context.Context, reference string) (string, error) {
	val, ok := m.items[reference]
	if !ok {
		return "", fmt.Errorf("%w", secrets.ErrNotFound)
	}
	return val, nil
}

func TestGet_Existing(t *testing.T) {
	mock := &mockOPClient{
		items: map[string]string{
			"vault/item/password": "s3cret",
		},
	}
	p := New(WithClient(mock))

	val, err := p.Get(context.Background(), "vault/item/password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "s3cret" {
		t.Errorf("Get = %q, want %q", val, "s3cret")
	}
}

func TestGet_Missing(t *testing.T) {
	mock := &mockOPClient{
		items: map[string]string{},
	}
	p := New(WithClient(mock))

	_, err := p.Get(context.Background(), "vault/item/nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestGet_WithServiceAccountToken(t *testing.T) {
	mock := &mockOPClient{
		items: map[string]string{
			"vault/item/field": "value",
		},
	}
	p := New(WithServiceAccountToken("ops_token_123"), WithClient(mock))

	val, err := p.Get(context.Background(), "vault/item/field")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "value" {
		t.Errorf("Get = %q, want %q", val, "value")
	}
}
