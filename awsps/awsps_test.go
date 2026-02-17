package awsps

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jrandolf/secrets"
)

// mockSSMClient implements Client for testing.
type mockSSMClient struct {
	// params maps parameter name to its value.
	params map[string]string
}

func (m *mockSSMClient) GetParameter(_ context.Context, name string, _ bool) (string, error) {
	val, ok := m.params[name]
	if !ok {
		return "", fmt.Errorf("%w", secrets.ErrNotFound)
	}
	return val, nil
}

func TestGet_Existing(t *testing.T) {
	mock := &mockSSMClient{
		params: map[string]string{
			"/prod/db-password": "s3cret",
		},
	}
	p, err := New(WithClient(mock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	val, err := p.Get(context.Background(), "/prod/db-password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "s3cret" {
		t.Errorf("Get = %q, want %q", val, "s3cret")
	}
}

func TestGet_Missing(t *testing.T) {
	mock := &mockSSMClient{
		params: map[string]string{},
	}
	p, err := New(WithClient(mock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = p.Get(context.Background(), "/nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestGet_WithDecryptionDisabled(t *testing.T) {
	var capturedDecrypt bool
	mock := &capturingSSMClient{
		params: map[string]string{"/param": "val"},
		onGetParameter: func(_ context.Context, _ string, decrypt bool) {
			capturedDecrypt = decrypt
		},
	}
	p, err := New(WithDecryption(false), WithClient(mock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = p.Get(context.Background(), "/param")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedDecrypt != false {
		t.Errorf("expected decrypt=false, got %v", capturedDecrypt)
	}
}

// capturingSSMClient captures call parameters for assertion.
type capturingSSMClient struct {
	params         map[string]string
	onGetParameter func(ctx context.Context, name string, decrypt bool)
}

func (m *capturingSSMClient) GetParameter(ctx context.Context, name string, decrypt bool) (string, error) {
	if m.onGetParameter != nil {
		m.onGetParameter(ctx, name, decrypt)
	}
	val, ok := m.params[name]
	if !ok {
		return "", fmt.Errorf("%w", secrets.ErrNotFound)
	}
	return val, nil
}
