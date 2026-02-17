package secrets

import "testing"

func TestParseTag_BareKey(t *testing.T) {
	tag, err := parseTag("db-password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tag.Scheme != "" {
		t.Errorf("Scheme = %q, want empty", tag.Scheme)
	}
	if tag.Key != "db-password" {
		t.Errorf("Key = %q, want %q", tag.Key, "db-password")
	}
	if tag.Fragment != "" {
		t.Errorf("Fragment = %q, want empty", tag.Fragment)
	}
	if tag.Optional {
		t.Error("Optional = true, want false")
	}
	if tag.Version != "" {
		t.Errorf("Version = %q, want empty", tag.Version)
	}
}

func TestParseTag_URIWithScheme(t *testing.T) {
	tag, err := parseTag("awssm://prod/db#password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tag.Scheme != "awssm" {
		t.Errorf("Scheme = %q, want %q", tag.Scheme, "awssm")
	}
	if tag.Key != "prod/db" {
		t.Errorf("Key = %q, want %q", tag.Key, "prod/db")
	}
	if tag.Fragment != "password" {
		t.Errorf("Fragment = %q, want %q", tag.Fragment, "password")
	}
}

func TestParseTag_Fragment(t *testing.T) {
	tag, err := parseTag("awssm://prod/db#host")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tag.Fragment != "host" {
		t.Errorf("Fragment = %q, want %q", tag.Fragment, "host")
	}
}

func TestParseTag_NestedFragment(t *testing.T) {
	tag, err := parseTag("awssm://prod/config#db.host")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tag.Fragment != "db.host" {
		t.Errorf("Fragment = %q, want %q", tag.Fragment, "db.host")
	}
}

func TestParseTag_FileURI(t *testing.T) {
	tag, err := parseTag("file:///etc/tls/cert.pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tag.Scheme != "file" {
		t.Errorf("Scheme = %q, want %q", tag.Scheme, "file")
	}
	if tag.Key != "/etc/tls/cert.pem" {
		t.Errorf("Key = %q, want %q", tag.Key, "/etc/tls/cert.pem")
	}
}

func TestParseTag_Optional(t *testing.T) {
	tag, err := parseTag("debug,optional")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tag.Key != "debug" {
		t.Errorf("Key = %q, want %q", tag.Key, "debug")
	}
	if !tag.Optional {
		t.Error("Optional = false, want true")
	}
}

func TestParseTag_Version(t *testing.T) {
	tag, err := parseTag("key,version=previous")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tag.Key != "key" {
		t.Errorf("Key = %q, want %q", tag.Key, "key")
	}
	if tag.Version != "previous" {
		t.Errorf("Version = %q, want %q", tag.Version, "previous")
	}
}

func TestParseTag_AllOptions(t *testing.T) {
	tag, err := parseTag("awssm://prod/db#password,optional,version=2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tag.Scheme != "awssm" {
		t.Errorf("Scheme = %q, want %q", tag.Scheme, "awssm")
	}
	if tag.Key != "prod/db" {
		t.Errorf("Key = %q, want %q", tag.Key, "prod/db")
	}
	if tag.Fragment != "password" {
		t.Errorf("Fragment = %q, want %q", tag.Fragment, "password")
	}
	if !tag.Optional {
		t.Error("Optional = false, want true")
	}
	if tag.Version != "2" {
		t.Errorf("Version = %q, want %q", tag.Version, "2")
	}
}

func TestParseTag_EmptyTag(t *testing.T) {
	_, err := parseTag("")
	if err == nil {
		t.Error("expected error for empty tag, got nil")
	}
}

func TestParsedTag_URI_BareKey(t *testing.T) {
	tag := parsedTag{Key: "my-key"}
	if got := tag.URI(); got != "my-key" {
		t.Errorf("URI() = %q, want %q", got, "my-key")
	}
}

func TestParsedTag_URI_WithScheme(t *testing.T) {
	tag := parsedTag{Scheme: "awssm", Key: "prod/db"}
	if got := tag.URI(); got != "awssm://prod/db" {
		t.Errorf("URI() = %q, want %q", got, "awssm://prod/db")
	}
}

func TestParsedTag_URI_FileScheme(t *testing.T) {
	tag := parsedTag{Scheme: "file", Key: "/etc/tls/cert.pem"}
	if got := tag.URI(); got != "file:///etc/tls/cert.pem" {
		t.Errorf("URI() = %q, want %q", got, "file:///etc/tls/cert.pem")
	}
}

func TestParseTag_UnknownOption(t *testing.T) {
	_, err := parseTag("key,bogus")
	if err == nil {
		t.Fatal("expected error for unknown option, got nil")
	}
}

func TestParseTag_EmptyKey(t *testing.T) {
	_, err := parseTag(",optional")
	if err == nil {
		t.Fatal("expected error for empty key, got nil")
	}
}

func TestParseTag_EmptyKeyWithScheme(t *testing.T) {
	_, err := parseTag("awssm://")
	if err == nil {
		t.Fatal("expected error for empty key with scheme, got nil")
	}
}

func TestParseTag_BareKeyWithFragment(t *testing.T) {
	tag, err := parseTag("my-secret#field")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tag.Scheme != "" {
		t.Errorf("Scheme = %q, want empty", tag.Scheme)
	}
	if tag.Key != "my-secret" {
		t.Errorf("Key = %q, want %q", tag.Key, "my-secret")
	}
	if tag.Fragment != "field" {
		t.Errorf("Fragment = %q, want %q", tag.Fragment, "field")
	}
}
