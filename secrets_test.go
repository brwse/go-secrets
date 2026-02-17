package secrets

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestErrNotFound(t *testing.T) {
	// Wrapping preserves identity.
	wrapped := fmt.Errorf("awssm: secret %q: %w", "prod/db", ErrNotFound)
	if !errors.Is(wrapped, ErrNotFound) {
		t.Error("wrapped error should match ErrNotFound")
	}
}

func TestVersioned(t *testing.T) {
	v := Versioned[string]{
		Current:  "new-key",
		Previous: "old-key",
	}
	if v.Current != "new-key" {
		t.Errorf("Current = %q, want %q", v.Current, "new-key")
	}
	if v.Previous != "old-key" {
		t.Errorf("Previous = %q, want %q", v.Previous, "old-key")
	}
}

func TestOptions(t *testing.T) {
	mp := &mockProvider{data: map[string][]byte{"a": []byte("1")}}
	fp := &mockProvider{data: map[string][]byte{"b": []byte("2")}}

	cfg := &resolverConfig{}
	WithDefault(mp)(cfg)
	WithProvider("file", fp)(cfg)
	WithParallelism(5)(cfg)

	if cfg.defaultProvider != mp {
		t.Error("default provider not set")
	}
	if cfg.providers["file"] != fp {
		t.Error("file provider not registered")
	}
	if cfg.parallelism != 5 {
		t.Errorf("parallelism = %d, want 5", cfg.parallelism)
	}
}

// mockProvider is a simple map-based Provider for testing.
type mockProvider struct {
	data map[string][]byte
}

func (m *mockProvider) Get(_ context.Context, key string) ([]byte, error) {
	v, ok := m.data[key]
	if !ok {
		return nil, fmt.Errorf("mock: %q: %w", key, ErrNotFound)
	}
	return v, nil
}
