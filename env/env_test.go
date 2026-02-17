package env_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jrandolf/secrets"
	"github.com/jrandolf/secrets/env"
)

func TestGet_ExistingVar(t *testing.T) {
	t.Setenv("TEST_SECRET", "s3cret")

	p := env.New()
	val, err := p.Get(context.Background(), "TEST_SECRET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "s3cret" {
		t.Errorf("Get = %q, want %q", val, "s3cret")
	}
}

func TestGet_MissingVar(t *testing.T) {
	p := env.New()
	_, err := p.Get(context.Background(), "DEFINITELY_NOT_SET_12345")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestGet_WithPrefix(t *testing.T) {
	t.Setenv("MYAPP_DB_PASS", "password123")

	p := env.New(env.WithPrefix("MYAPP_"))
	val, err := p.Get(context.Background(), "DB_PASS")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "password123" {
		t.Errorf("Get = %q, want %q", val, "password123")
	}
}
