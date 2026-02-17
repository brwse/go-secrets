package secrets

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type cacheTestProvider struct {
	data  map[string][]byte
	calls int
	mu    sync.Mutex
}

func (p *cacheTestProvider) Get(_ context.Context, key string) ([]byte, error) {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	v, ok := p.data[key]
	if !ok {
		return nil, ErrNotFound
	}
	return v, nil
}

type cacheTestVersionedProvider struct {
	cacheTestProvider
	versions map[string][]byte // key is "key\x00version"
}

func (p *cacheTestVersionedProvider) GetVersion(_ context.Context, key, version string) ([]byte, error) {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	v, ok := p.versions[key+"\x00"+version]
	if !ok {
		return nil, ErrNotFound
	}
	return v, nil
}

func TestCachedProvider_Hit(t *testing.T) {
	p := &cacheTestProvider{data: map[string][]byte{"k": []byte("v")}}
	cp := NewCachedProvider(p, time.Minute)

	ctx := context.Background()
	got1, err := cp.Get(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	got2, err := cp.Get(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}

	if string(got1) != "v" || string(got2) != "v" {
		t.Fatalf("unexpected values: %q, %q", got1, got2)
	}
	if p.calls != 1 {
		t.Fatalf("expected 1 provider call, got %d", p.calls)
	}
}

func TestCachedProvider_Miss(t *testing.T) {
	p := &cacheTestProvider{data: map[string][]byte{"k": []byte("v")}}
	cp := NewCachedProvider(p, time.Minute)

	ctx := context.Background()
	got, err := cp.Get(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v" {
		t.Fatalf("expected %q, got %q", "v", got)
	}
	if p.calls != 1 {
		t.Fatalf("expected 1 provider call, got %d", p.calls)
	}
}

func TestCachedProvider_Expired(t *testing.T) {
	p := &cacheTestProvider{data: map[string][]byte{"k": []byte("v1")}}
	cp := NewCachedProvider(p, time.Nanosecond)

	ctx := context.Background()
	if _, err := cp.Get(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)

	p.data["k"] = []byte("v2")
	got, err := cp.Get(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v2" {
		t.Fatalf("expected %q after expiry, got %q", "v2", got)
	}
	if p.calls != 2 {
		t.Fatalf("expected 2 provider calls, got %d", p.calls)
	}
}

func TestCachedProvider_ErrorNotCached(t *testing.T) {
	p := &cacheTestProvider{data: map[string][]byte{}}
	cp := NewCachedProvider(p, time.Minute)

	ctx := context.Background()
	_, err := cp.Get(ctx, "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	// Add the key and fetch again — should call provider again.
	p.data["missing"] = []byte("found")
	got, err := cp.Get(ctx, "missing")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "found" {
		t.Fatalf("expected %q, got %q", "found", got)
	}
	if p.calls != 2 {
		t.Fatalf("expected 2 provider calls, got %d", p.calls)
	}
}

func TestCachedProvider_GetVersion(t *testing.T) {
	p := &cacheTestVersionedProvider{
		cacheTestProvider: cacheTestProvider{data: map[string][]byte{"k": []byte("current")}},
		versions:          map[string][]byte{"k\x00prev": []byte("previous")},
	}
	cp := NewCachedProvider(p, time.Minute)

	ctx := context.Background()
	// Get and GetVersion should cache separately.
	got, err := cp.Get(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "current" {
		t.Fatalf("expected %q, got %q", "current", got)
	}

	ver, err := cp.GetVersion(ctx, "k", "prev")
	if err != nil {
		t.Fatal(err)
	}
	if string(ver) != "previous" {
		t.Fatalf("expected %q, got %q", "previous", ver)
	}

	// Second call should be cached.
	ver2, err := cp.GetVersion(ctx, "k", "prev")
	if err != nil {
		t.Fatal(err)
	}
	if string(ver2) != "previous" {
		t.Fatalf("expected %q, got %q", "previous", ver2)
	}
	if p.calls != 2 {
		t.Fatalf("expected 2 provider calls (1 Get + 1 GetVersion), got %d", p.calls)
	}
}

func TestCachedProvider_GetVersionNotSupported(t *testing.T) {
	p := &cacheTestProvider{data: map[string][]byte{"k": []byte("v")}}
	cp := NewCachedProvider(p, time.Minute)

	_, err := cp.GetVersion(context.Background(), "k", "v1")
	var target *ErrVersioningNotSupported
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrVersioningNotSupported, got %v", err)
	}
}

func TestCachedProvider_Clear(t *testing.T) {
	p := &cacheTestProvider{data: map[string][]byte{"k": []byte("v")}}
	cp := NewCachedProvider(p, time.Minute)

	ctx := context.Background()
	if _, err := cp.Get(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	cp.Clear()
	if _, err := cp.Get(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if p.calls != 2 {
		t.Fatalf("expected 2 provider calls after Clear, got %d", p.calls)
	}
}

func TestCachedProvider_Close(t *testing.T) {
	closed := false
	p := &cacheTestClosableProvider{
		cacheTestProvider: cacheTestProvider{data: map[string][]byte{"k": []byte("v")}},
		onClose:           func() { closed = true },
	}
	cp := NewCachedProvider(p, time.Minute)

	ctx := context.Background()
	if _, err := cp.Get(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if err := cp.Close(); err != nil {
		t.Fatal(err)
	}
	if !closed {
		t.Fatal("expected underlying provider to be closed")
	}
	// Cache should be cleared.
	cp.mu.RLock()
	n := len(cp.entries)
	cp.mu.RUnlock()
	if n != 0 {
		t.Fatalf("expected empty cache after Close, got %d entries", n)
	}
}

type cacheTestClosableProvider struct {
	cacheTestProvider
	onClose func()
}

func (p *cacheTestClosableProvider) Close() error {
	p.onClose()
	return nil
}

func TestCachedProvider_Concurrent(t *testing.T) {
	p := &cacheTestProvider{data: map[string][]byte{
		"a": []byte("1"),
		"b": []byte("2"),
	}}
	cp := NewCachedProvider(p, time.Minute)

	ctx := context.Background()
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := "a"
			if i%2 == 0 {
				key = "b"
			}
			if _, err := cp.Get(ctx, key); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
}
