package secrets

import "testing"

func TestExtractFragment_StringField(t *testing.T) {
	data := []byte(`{"host":"localhost","port":5432,"password":"s3cret"}`)
	val, err := extractFragment(data, "password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "s3cret" {
		t.Errorf("got %q, want %q", val, "s3cret")
	}
}

func TestExtractFragment_NumberField(t *testing.T) {
	data := []byte(`{"host":"localhost","port":5432}`)
	val, err := extractFragment(data, "port")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "5432" {
		t.Errorf("got %q, want %q", val, "5432")
	}
}

func TestExtractFragment_BoolField(t *testing.T) {
	data := []byte(`{"enabled":true}`)
	val, err := extractFragment(data, "enabled")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "true" {
		t.Errorf("got %q, want %q", val, "true")
	}
}

func TestExtractFragment_MissingField(t *testing.T) {
	data := []byte(`{"host":"localhost"}`)
	_, err := extractFragment(data, "password")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestExtractFragment_InvalidJSON(t *testing.T) {
	data := []byte(`not json`)
	_, err := extractFragment(data, "key")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestExtractFragment_NestedField(t *testing.T) {
	data := []byte(`{"db":{"host":"localhost","port":3306}}`)
	val, err := extractFragment(data, "db.host")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "localhost" {
		t.Errorf("got %q, want %q", val, "localhost")
	}
}

func TestExtractFragment_ArrayIndex(t *testing.T) {
	data := []byte(`{"items":[{"name":"first"},{"name":"second"}]}`)
	val, err := extractFragment(data, "items.1.name")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "second" {
		t.Errorf("got %q, want %q", val, "second")
	}
}

func TestExtractFragment_NullField(t *testing.T) {
	data := []byte(`{"value":null}`)
	val, err := extractFragment(data, "value")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "null" {
		t.Errorf("got %q, want %q", val, "null")
	}
}

func TestExtractFragment_NestedObject(t *testing.T) {
	data := []byte(`{"db":{"host":"localhost","port":3306}}`)
	val, err := extractFragment(data, "db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return re-marshaled JSON.
	expected := `{"host":"localhost","port":3306}`
	if string(val) != expected {
		t.Errorf("got %q, want %q", val, expected)
	}
}

func TestExtractFragment_FloatField(t *testing.T) {
	data := []byte(`{"rate":3.14}`)
	val, err := extractFragment(data, "rate")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "3.14" {
		t.Errorf("got %q, want %q", val, "3.14")
	}
}
