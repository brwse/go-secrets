package literal_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jrandolf/secrets"
	"github.com/jrandolf/secrets/literal"
)

func TestGet_ExistingKey(t *testing.T) {
	p := literal.New(map[string][]byte{
		"db-pass": []byte("s3cret"),
	})
	val, err := p.Get(context.Background(), "db-pass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "s3cret" {
		t.Errorf("Get = %q, want %q", val, "s3cret")
	}
}

func TestGet_MissingKey(t *testing.T) {
	p := literal.New(map[string][]byte{
		"db-pass": []byte("s3cret"),
	})
	_, err := p.Get(context.Background(), "no-such-key")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestGetVersion(t *testing.T) {
	p := literal.New(
		map[string][]byte{
			"api-key": []byte("current-val"),
		},
		literal.WithVersions(map[string]map[string][]byte{
			"api-key": {
				"current":  []byte("current-val"),
				"previous": []byte("old-val"),
			},
		}),
	)

	val, err := p.GetVersion(context.Background(), "api-key", "previous")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "old-val" {
		t.Errorf("GetVersion = %q, want %q", val, "old-val")
	}
}

func TestGetVersion_MissingKey(t *testing.T) {
	p := literal.New(map[string][]byte{})
	_, err := p.GetVersion(context.Background(), "no-key", "current")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestGetVersion_MissingVersion(t *testing.T) {
	p := literal.New(
		map[string][]byte{},
		literal.WithVersions(map[string]map[string][]byte{
			"api-key": {
				"current": []byte("val"),
			},
		}),
	)
	_, err := p.GetVersion(context.Background(), "api-key", "nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestGetVersion_NoVersionsConfigured(t *testing.T) {
	p := literal.New(map[string][]byte{"key": []byte("val")})
	_, err := p.GetVersion(context.Background(), "key", "current")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}
