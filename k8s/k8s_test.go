package k8s_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/jrandolf/secrets"
	"github.com/jrandolf/secrets/k8s"
)

// mockClient implements k8s.Client for testing.
type mockClient struct {
	secrets map[string]map[string]map[string][]byte // namespace -> name -> data
}

func (m *mockClient) GetSecret(_ context.Context, namespace, name string) (map[string][]byte, error) {
	ns, ok := m.secrets[namespace]
	if !ok {
		return nil, fmt.Errorf("%w", secrets.ErrNotFound)
	}
	data, ok := ns[name]
	if !ok {
		return nil, fmt.Errorf("%w", secrets.ErrNotFound)
	}
	return data, nil
}

func TestGet_Existing(t *testing.T) {
	mock := &mockClient{
		secrets: map[string]map[string]map[string][]byte{
			"prod": {
				"db-creds": {
					"password": []byte("s3cret"),
					"host":     []byte("db.example.com"),
				},
			},
		},
	}
	p, err := k8s.New(k8s.WithClient(mock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	val, err := p.Get(context.Background(), "prod/db-creds")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got map[string]string
	if err := json.Unmarshal(val, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got["password"] != "s3cret" {
		t.Errorf("password = %q, want %q", got["password"], "s3cret")
	}
	if got["host"] != "db.example.com" {
		t.Errorf("host = %q, want %q", got["host"], "db.example.com")
	}
}

func TestGet_Missing(t *testing.T) {
	mock := &mockClient{
		secrets: map[string]map[string]map[string][]byte{},
	}
	p, err := k8s.New(k8s.WithClient(mock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = p.Get(context.Background(), "default/nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestGet_InvalidKey(t *testing.T) {
	mock := &mockClient{
		secrets: map[string]map[string]map[string][]byte{},
	}
	p, err := k8s.New(k8s.WithClient(mock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = p.Get(context.Background(), "no-slash")
	if err == nil {
		t.Fatal("expected error for invalid key, got nil")
	}
}

func TestGet_JSONEncoding(t *testing.T) {
	mock := &mockClient{
		secrets: map[string]map[string]map[string][]byte{
			"default": {
				"my-secret": {
					"key1": []byte("value1"),
					"key2": []byte("value2"),
				},
			},
		},
	}
	p, err := k8s.New(k8s.WithClient(mock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	val, err := p.Get(context.Background(), "default/my-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got map[string]string
	if err := json.Unmarshal(val, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	want := map[string]string{"key1": "value1", "key2": "value2"}
	for k, wv := range want {
		if gv := got[k]; gv != wv {
			t.Errorf("key %q = %q, want %q", k, gv, wv)
		}
	}
}
