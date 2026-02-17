package secrets

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestWatch_DetectsChange(t *testing.T) {
	store := &syncMapProvider{}
	store.Store("key", []byte("initial"))
	r := NewResolver(WithDefault(store))

	type Config struct {
		Val string `secret:"key"`
	}
	var cfg Config

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	w, err := r.Watch(ctx, &cfg, WatchInterval(50*time.Millisecond))
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	defer w.Stop()

	// Verify initial value.
	w.RLock()
	if cfg.Val != "initial" {
		t.Fatalf("initial Val = %q, want %q", cfg.Val, "initial")
	}
	w.RUnlock()

	// Change the value.
	store.Store("key", []byte("updated"))

	// Wait for a change event.
	select {
	case event := <-w.Changes():
		if event.Field != "Val" {
			t.Errorf("event.Field = %q, want %q", event.Field, "Val")
		}
		if event.Key != "key" {
			t.Errorf("event.Key = %q, want %q", event.Key, "key")
		}
		if string(event.OldValue) != "initial" {
			t.Errorf("event.OldValue = %q, want %q", event.OldValue, "initial")
		}
		if string(event.NewValue) != "updated" {
			t.Errorf("event.NewValue = %q, want %q", event.NewValue, "updated")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for change event")
	}

	// Verify struct was updated.
	w.RLock()
	if cfg.Val != "updated" {
		t.Errorf("after change Val = %q, want %q", cfg.Val, "updated")
	}
	w.RUnlock()
}

func TestWatch_StopClosesChannel(t *testing.T) {
	store := &syncMapProvider{}
	store.Store("key", []byte("val"))
	r := NewResolver(WithDefault(store))

	type Config struct {
		Val string `secret:"key"`
	}
	var cfg Config

	ctx := context.Background()
	w, err := r.Watch(ctx, &cfg, WatchInterval(50*time.Millisecond))
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}

	w.Stop()

	// Changes channel should be closed after Stop.
	select {
	case _, ok := <-w.Changes():
		if ok {
			t.Error("expected channel to be closed, got a value")
		}
		// ok == false means channel is closed, which is correct.
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for channel close")
	}
}

func TestWatch_ContextCancellationClosesChannel(t *testing.T) {
	store := &syncMapProvider{}
	store.Store("key", []byte("val"))
	r := NewResolver(WithDefault(store))

	type Config struct {
		Val string `secret:"key"`
	}
	var cfg Config

	ctx, cancel := context.WithCancel(context.Background())
	w, err := r.Watch(ctx, &cfg, WatchInterval(50*time.Millisecond))
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}

	// Cancel the context.
	cancel()

	// Changes channel should be closed.
	select {
	case _, ok := <-w.Changes():
		if ok {
			t.Error("expected channel to be closed, got a value")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for channel close after context cancellation")
	}
}

func TestWatch_PreservesNonSecretFields(t *testing.T) {
	store := &syncMapProvider{}
	store.Store("key", []byte("initial"))
	r := NewResolver(WithDefault(store))

	type Config struct {
		Val  string `secret:"key"`
		Port int    // not a secret field
	}
	cfg := Config{Port: 8080}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	w, err := r.Watch(ctx, &cfg, WatchInterval(50*time.Millisecond))
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	defer w.Stop()

	// Change the secret value.
	store.Store("key", []byte("updated"))

	// Wait for a change event.
	select {
	case <-w.Changes():
	case <-ctx.Done():
		t.Fatal("timed out waiting for change event")
	}

	// Verify non-secret field was preserved.
	w.RLock()
	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want 8080 (non-secret field was overwritten)", cfg.Port)
	}
	if cfg.Val != "updated" {
		t.Errorf("Val = %q, want %q", cfg.Val, "updated")
	}
	w.RUnlock()
}

// --- helpers ---

// syncMapProvider is a thread-safe map-based Provider for watcher testing.
type syncMapProvider struct {
	data sync.Map
}

func (p *syncMapProvider) Store(key string, val []byte) {
	p.data.Store(key, val)
}

func (p *syncMapProvider) Get(_ context.Context, key string) ([]byte, error) {
	v, ok := p.data.Load(key)
	if !ok {
		return nil, fmt.Errorf("syncmap: %q: %w", key, ErrNotFound)
	}
	return v.([]byte), nil
}
