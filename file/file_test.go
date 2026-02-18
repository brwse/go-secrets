package file_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/brwse/go-secrets"
	"github.com/brwse/go-secrets/file"
)

func TestGet_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db-pass")
	if err := os.WriteFile(path, []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}

	p := file.New()
	val, err := p.Get(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "s3cret" {
		t.Errorf("Get = %q, want %q", val, "s3cret")
	}
}

func TestGet_MissingFile(t *testing.T) {
	p := file.New()
	_, err := p.Get(context.Background(), "/nonexistent/path/to/secret")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestGet_TrimNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "api-key")
	if err := os.WriteFile(path, []byte("my-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	p := file.New(file.WithTrimNewline(true))
	val, err := p.Get(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "my-key" {
		t.Errorf("Get = %q, want %q", val, "my-key")
	}
}

func TestGet_TrimNewline_CRLF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "api-key")
	if err := os.WriteFile(path, []byte("my-key\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	p := file.New(file.WithTrimNewline(true))
	val, err := p.Get(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "my-key" {
		t.Errorf("Get = %q, want %q", val, "my-key")
	}
}

func TestGet_WithBaseDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("tok123"), 0o600); err != nil {
		t.Fatal(err)
	}

	p := file.New(file.WithBaseDir(dir))
	val, err := p.Get(context.Background(), "token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "tok123" {
		t.Errorf("Get = %q, want %q", val, "tok123")
	}
}
