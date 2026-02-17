package secrets

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestResolve_BasicString(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"db-pass": []byte("s3cret"),
	}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		DBPass string `secret:"db-pass"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DBPass != "s3cret" {
		t.Errorf("DBPass = %q, want %q", cfg.DBPass, "s3cret")
	}
}

func TestResolve_NoSecretTagSkipped(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"key": []byte("val"),
	}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Secret string `secret:"key"`
		Normal string // no secret tag
	}
	cfg := Config{Normal: "unchanged"}
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Secret != "val" {
		t.Errorf("Secret = %q, want %q", cfg.Secret, "val")
	}
	if cfg.Normal != "unchanged" {
		t.Errorf("Normal = %q, want %q", cfg.Normal, "unchanged")
	}
}

func TestResolve_NonPointerError(t *testing.T) {
	r := NewResolver()
	type Config struct{}
	err := r.Resolve(context.Background(), Config{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got == "" {
		t.Error("expected non-empty error message")
	}
}

func TestResolve_NilPointerError(t *testing.T) {
	r := NewResolver()
	err := r.Resolve(context.Background(), (*struct{})(nil))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestResolve_NonStructError(t *testing.T) {
	r := NewResolver()
	s := "not a struct"
	err := r.Resolve(context.Background(), &s)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestResolve_MissingSecret(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Missing string `secret:"no-such-key"`
	}
	var cfg Config
	err := r.Resolve(context.Background(), &cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound in chain, got: %v", err)
	}
}

func TestResolve_NoDefaultProvider(t *testing.T) {
	r := NewResolver() // no default provider
	type Config struct {
		Key string `secret:"bare-key"`
	}
	var cfg Config
	err := r.Resolve(context.Background(), &cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var target *ErrNoDefaultProvider
	if !errors.As(err, &target) {
		t.Errorf("expected ErrNoDefaultProvider, got: %v", err)
	}
}

func TestResolve_UnknownProvider(t *testing.T) {
	r := NewResolver()
	type Config struct {
		Key string `secret:"unknown://some/key"`
	}
	var cfg Config
	err := r.Resolve(context.Background(), &cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var target *ErrUnknownProvider
	if !errors.As(err, &target) {
		t.Errorf("expected ErrUnknownProvider, got: %v", err)
	}
}

func TestResolve_URIRouting(t *testing.T) {
	defProvider := &mockProvider{data: map[string][]byte{
		"default-key": []byte("default-val"),
	}}
	customProvider := &mockProvider{data: map[string][]byte{
		"custom/key": []byte("custom-val"),
	}}
	r := NewResolver(WithDefault(defProvider), WithProvider("custom", customProvider))

	type Config struct {
		DefKey    string `secret:"default-key"`
		CustomKey string `secret:"custom://custom/key"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DefKey != "default-val" {
		t.Errorf("DefKey = %q, want %q", cfg.DefKey, "default-val")
	}
	if cfg.CustomKey != "custom-val" {
		t.Errorf("CustomKey = %q, want %q", cfg.CustomKey, "custom-val")
	}
}

func TestResolve_ByteSlice(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"cert": []byte("cert-data"),
	}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Cert []byte `secret:"cert"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(cfg.Cert) != "cert-data" {
		t.Errorf("Cert = %q, want %q", cfg.Cert, "cert-data")
	}
}

func TestResolve_Bool(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"debug": []byte("true"),
	}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Debug bool `secret:"debug"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Debug {
		t.Error("Debug = false, want true")
	}
}

func TestResolve_IntTypes(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"port": []byte("8080"),
	}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Port   int   `secret:"port"`
		Port16 int16 `secret:"port"`
		Port32 int32 `secret:"port"`
		Port64 int64 `secret:"port"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want 8080", cfg.Port)
	}
	if cfg.Port16 != 8080 {
		t.Errorf("Port16 = %d, want 8080", cfg.Port16)
	}
	if cfg.Port32 != 8080 {
		t.Errorf("Port32 = %d, want 8080", cfg.Port32)
	}
	if cfg.Port64 != 8080 {
		t.Errorf("Port64 = %d, want 8080", cfg.Port64)
	}
}

func TestResolve_UintTypes(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"count": []byte("42"),
	}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Count   uint   `secret:"count"`
		Count32 uint32 `secret:"count"`
		Count64 uint64 `secret:"count"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Count != 42 {
		t.Errorf("Count = %d, want 42", cfg.Count)
	}
}

func TestResolve_FloatTypes(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"rate": []byte("3.14"),
	}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Rate32 float32 `secret:"rate"`
		Rate64 float64 `secret:"rate"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Rate64 != 3.14 {
		t.Errorf("Rate64 = %f, want 3.14", cfg.Rate64)
	}
}

func TestResolve_Duration(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"timeout": []byte("5s"),
	}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Timeout time.Duration `secret:"timeout"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", cfg.Timeout)
	}
}

func TestResolve_Optional(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Missing string `secret:"no-key,optional"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Missing != "" {
		t.Errorf("Missing = %q, want empty", cfg.Missing)
	}
}

func TestResolve_JSONFragment(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"prod/db": []byte(`{"host":"localhost","port":5432,"password":"s3cret"}`),
	}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Host string `secret:"prod/db#host"`
		Port int    `secret:"prod/db#port"`
		Pass string `secret:"prod/db#password"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Host != "localhost" {
		t.Errorf("Host = %q, want %q", cfg.Host, "localhost")
	}
	if cfg.Port != 5432 {
		t.Errorf("Port = %d, want 5432", cfg.Port)
	}
	if cfg.Pass != "s3cret" {
		t.Errorf("Pass = %q, want %q", cfg.Pass, "s3cret")
	}
}

func TestResolve_Deduplication(t *testing.T) {
	var callCount atomic.Int64
	p := &countingProvider{
		data: map[string][]byte{
			"shared": []byte(`{"a":"1","b":"2"}`),
		},
		count: &callCount,
	}
	r := NewResolver(WithDefault(p))

	type Config struct {
		A string `secret:"shared#a"`
		B string `secret:"shared#b"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount.Load() != 1 {
		t.Errorf("provider was called %d times, want 1 (deduplication)", callCount.Load())
	}
	if cfg.A != "1" {
		t.Errorf("A = %q, want %q", cfg.A, "1")
	}
	if cfg.B != "2" {
		t.Errorf("B = %q, want %q", cfg.B, "2")
	}
}

func TestResolve_PointerField(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"key": []byte("value"),
	}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Val *string `secret:"key"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Val == nil {
		t.Fatal("Val is nil, want non-nil")
	}
	if *cfg.Val != "value" {
		t.Errorf("*Val = %q, want %q", *cfg.Val, "value")
	}
}

func TestResolve_TextUnmarshaler(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"ip": []byte("192.168.1.1"),
	}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		IP net.IP `secret:"ip"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := net.ParseIP("192.168.1.1")
	if !cfg.IP.Equal(expected) {
		t.Errorf("IP = %v, want %v", cfg.IP, expected)
	}
}

func TestResolve_NestedStruct(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"db-host": []byte("localhost"),
		"db-port": []byte("5432"),
	}}
	r := NewResolver(WithDefault(p))

	type DB struct {
		Host string `secret:"db-host"`
		Port int    `secret:"db-port"`
	}
	type Config struct {
		Database DB
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Database.Host != "localhost" {
		t.Errorf("Database.Host = %q, want %q", cfg.Database.Host, "localhost")
	}
	if cfg.Database.Port != 5432 {
		t.Errorf("Database.Port = %d, want 5432", cfg.Database.Port)
	}
}

func TestResolve_EmbeddedStruct(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"base-key": []byte("base-val"),
		"ext-key":  []byte("ext-val"),
	}}
	r := NewResolver(WithDefault(p))

	type Base struct {
		BaseKey string `secret:"base-key"`
	}
	type Config struct {
		Base
		ExtKey string `secret:"ext-key"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BaseKey != "base-val" {
		t.Errorf("BaseKey = %q, want %q", cfg.BaseKey, "base-val")
	}
	if cfg.ExtKey != "ext-val" {
		t.Errorf("ExtKey = %q, want %q", cfg.ExtKey, "ext-val")
	}
}

func TestResolve_ConversionError(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"port": []byte("not-a-number"),
	}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Port int `secret:"port"`
	}
	var cfg Config
	err := r.Resolve(context.Background(), &cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var target *ErrConversion
	if !errors.As(err, &target) {
		t.Errorf("expected ErrConversion, got: %v", err)
	}
}

func TestResolve_UnsupportedType(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"key": []byte("val"),
	}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Unsupported complex128 `secret:"key"`
	}
	var cfg Config
	err := r.Resolve(context.Background(), &cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var target *ErrUnsupportedType
	if !errors.As(err, &target) {
		t.Errorf("expected ErrUnsupportedType, got: %v", err)
	}
}

func TestResolve_MultipleErrors(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		A string `secret:"missing-a"`
		B string `secret:"missing-b"`
	}
	var cfg Config
	err := r.Resolve(context.Background(), &cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// errors.Join produces a multi-error.
	unwrapped := errors.Unwrap(err)
	// Check that both missing keys are reported.
	errStr := err.Error()
	if !containsSubstring(errStr, "missing-a") || !containsSubstring(errStr, "missing-b") {
		t.Errorf("expected both missing-a and missing-b in error, got: %v", err)
	}
	_ = unwrapped
}

// --- Task 6: URI routing, fragment extraction through resolver, deduplication ---

func TestResolve_MultiProviderRouting(t *testing.T) {
	awssm := &mockProvider{data: map[string][]byte{
		"prod/db": []byte(`{"host":"rds.aws.com","password":"aws-pass"}`),
	}}
	vault := &mockProvider{data: map[string][]byte{
		"secret/data/api": []byte("vault-token-123"),
	}}
	defProv := &mockProvider{data: map[string][]byte{
		"local-key": []byte("local-val"),
	}}
	r := NewResolver(
		WithDefault(defProv),
		WithProvider("awssm", awssm),
		WithProvider("vault", vault),
	)

	type Config struct {
		DBHost   string `secret:"awssm://prod/db#host"`
		DBPass   string `secret:"awssm://prod/db#password"`
		APIToken string `secret:"vault://secret/data/api"`
		LocalKey string `secret:"local-key"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DBHost != "rds.aws.com" {
		t.Errorf("DBHost = %q, want %q", cfg.DBHost, "rds.aws.com")
	}
	if cfg.DBPass != "aws-pass" {
		t.Errorf("DBPass = %q, want %q", cfg.DBPass, "aws-pass")
	}
	if cfg.APIToken != "vault-token-123" {
		t.Errorf("APIToken = %q, want %q", cfg.APIToken, "vault-token-123")
	}
	if cfg.LocalKey != "local-val" {
		t.Errorf("LocalKey = %q, want %q", cfg.LocalKey, "local-val")
	}
}

func TestResolve_FragmentExtractionThroughURIProvider(t *testing.T) {
	awssm := &mockProvider{data: map[string][]byte{
		"prod/db": []byte(`{"host":"db.example.com","port":5432,"password":"s3cret","ssl":true}`),
	}}
	r := NewResolver(WithProvider("awssm", awssm))

	type Config struct {
		Host string `secret:"awssm://prod/db#host"`
		Port int    `secret:"awssm://prod/db#port"`
		Pass string `secret:"awssm://prod/db#password"`
		SSL  bool   `secret:"awssm://prod/db#ssl"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Host != "db.example.com" {
		t.Errorf("Host = %q, want %q", cfg.Host, "db.example.com")
	}
	if cfg.Port != 5432 {
		t.Errorf("Port = %d, want 5432", cfg.Port)
	}
	if cfg.Pass != "s3cret" {
		t.Errorf("Pass = %q, want %q", cfg.Pass, "s3cret")
	}
	if !cfg.SSL {
		t.Error("SSL = false, want true")
	}
}

func TestResolve_DeduplicationWithURIProvider(t *testing.T) {
	var awssmCount atomic.Int64
	awssm := &countingProvider{
		data: map[string][]byte{
			"prod/db": []byte(`{"user":"admin","password":"s3cret"}`),
		},
		count: &awssmCount,
	}
	var vaultCount atomic.Int64
	vault := &countingProvider{
		data: map[string][]byte{
			"api/key": []byte("token-abc"),
		},
		count: &vaultCount,
	}
	r := NewResolver(
		WithProvider("awssm", awssm),
		WithProvider("vault", vault),
	)

	type Config struct {
		DBUser string `secret:"awssm://prod/db#user"`
		DBPass string `secret:"awssm://prod/db#password"`
		Token1 string `secret:"vault://api/key"`
		Token2 string `secret:"vault://api/key"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if awssmCount.Load() != 1 {
		t.Errorf("awssm provider called %d times, want 1 (deduplication)", awssmCount.Load())
	}
	if vaultCount.Load() != 1 {
		t.Errorf("vault provider called %d times, want 1 (deduplication)", vaultCount.Load())
	}
	if cfg.DBUser != "admin" {
		t.Errorf("DBUser = %q, want %q", cfg.DBUser, "admin")
	}
	if cfg.DBPass != "s3cret" {
		t.Errorf("DBPass = %q, want %q", cfg.DBPass, "s3cret")
	}
	if cfg.Token1 != "token-abc" {
		t.Errorf("Token1 = %q, want %q", cfg.Token1, "token-abc")
	}
	if cfg.Token2 != "token-abc" {
		t.Errorf("Token2 = %q, want %q", cfg.Token2, "token-abc")
	}
}

// --- Task 7: Types, optional, pointers, nested structs, error collection ---

func TestResolve_OptionalPointerNilWhenAbsent(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Val *string `secret:"no-key,optional"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Val != nil {
		t.Errorf("Val = %v, want nil", cfg.Val)
	}
}

func TestResolve_OptionalIntZeroWhenAbsent(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Port int `secret:"no-port,optional"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != 0 {
		t.Errorf("Port = %d, want 0", cfg.Port)
	}
}

func TestResolve_OptionalBoolZeroWhenAbsent(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Debug bool `secret:"no-debug,optional"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Debug {
		t.Error("Debug = true, want false")
	}
}

func TestResolve_OptionalBytesNilWhenAbsent(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Data []byte `secret:"no-data,optional"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Data != nil {
		t.Errorf("Data = %v, want nil", cfg.Data)
	}
}

func TestResolve_AllTypeConversions(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"b":    []byte("true"),
		"i":    []byte("42"),
		"i64":  []byte("-99"),
		"u":    []byte("7"),
		"f64":  []byte("2.718"),
		"dur":  []byte("1m30s"),
		"raw":  []byte("binary-data"),
		"str":  []byte("hello"),
	}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		B   bool          `secret:"b"`
		I   int           `secret:"i"`
		I64 int64         `secret:"i64"`
		U   uint          `secret:"u"`
		F64 float64       `secret:"f64"`
		Dur time.Duration `secret:"dur"`
		Raw []byte        `secret:"raw"`
		Str string        `secret:"str"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.B {
		t.Error("B = false, want true")
	}
	if cfg.I != 42 {
		t.Errorf("I = %d, want 42", cfg.I)
	}
	if cfg.I64 != -99 {
		t.Errorf("I64 = %d, want -99", cfg.I64)
	}
	if cfg.U != 7 {
		t.Errorf("U = %d, want 7", cfg.U)
	}
	if cfg.F64 != 2.718 {
		t.Errorf("F64 = %f, want 2.718", cfg.F64)
	}
	if cfg.Dur != 90*time.Second {
		t.Errorf("Dur = %v, want 1m30s", cfg.Dur)
	}
	if string(cfg.Raw) != "binary-data" {
		t.Errorf("Raw = %q, want %q", cfg.Raw, "binary-data")
	}
	if cfg.Str != "hello" {
		t.Errorf("Str = %q, want %q", cfg.Str, "hello")
	}
}

func TestResolve_PointerFieldNilWhenOptionalAbsent(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"present": []byte("here"),
	}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Present *string `secret:"present"`
		Absent  *string `secret:"missing,optional"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Present == nil {
		t.Fatal("Present is nil, want non-nil")
	}
	if *cfg.Present != "here" {
		t.Errorf("*Present = %q, want %q", *cfg.Present, "here")
	}
	if cfg.Absent != nil {
		t.Errorf("Absent = %v, want nil", cfg.Absent)
	}
}

func TestResolve_NestedStructPointer(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"inner-val": []byte("nested"),
	}}
	r := NewResolver(WithDefault(p))

	type Inner struct {
		Val string `secret:"inner-val"`
	}
	type Config struct {
		Inner *Inner
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Inner == nil {
		t.Fatal("Inner is nil, want non-nil")
	}
	if cfg.Inner.Val != "nested" {
		t.Errorf("Inner.Val = %q, want %q", cfg.Inner.Val, "nested")
	}
}

type customText struct {
	Value string
}

func (c *customText) UnmarshalText(text []byte) error {
	c.Value = "custom:" + string(text)
	return nil
}

func TestResolve_CustomTextUnmarshaler(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"key": []byte("input"),
	}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Field customText `secret:"key"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Field.Value != "custom:input" {
		t.Errorf("Field.Value = %q, want %q", cfg.Field.Value, "custom:input")
	}
}

func TestResolve_ErrorCollectionAllFieldNames(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Alpha   string `secret:"key-a"`
		Beta    string `secret:"key-b"`
		Gamma   string `secret:"key-c"`
	}
	var cfg Config
	err := r.Resolve(context.Background(), &cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	errStr := err.Error()
	for _, field := range []string{"Alpha", "Beta", "Gamma"} {
		if !containsSubstring(errStr, field) {
			t.Errorf("error should mention field %q, got: %v", field, err)
		}
	}
	for _, key := range []string{"key-a", "key-b", "key-c"} {
		if !containsSubstring(errStr, key) {
			t.Errorf("error should mention key %q, got: %v", key, err)
		}
	}
}

func TestResolve_EmbeddedStructWithNestedAndOuter(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"base":  []byte("base-val"),
		"mid":   []byte("mid-val"),
		"outer": []byte("outer-val"),
	}}
	r := NewResolver(WithDefault(p))

	type Base struct {
		BaseField string `secret:"base"`
	}
	type Mid struct {
		Base
		MidField string `secret:"mid"`
	}
	type Config struct {
		Mid
		OuterField string `secret:"outer"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BaseField != "base-val" {
		t.Errorf("BaseField = %q, want %q", cfg.BaseField, "base-val")
	}
	if cfg.MidField != "mid-val" {
		t.Errorf("MidField = %q, want %q", cfg.MidField, "mid-val")
	}
	if cfg.OuterField != "outer-val" {
		t.Errorf("OuterField = %q, want %q", cfg.OuterField, "outer-val")
	}
}

// --- Task 8: Parallel fetching ---

func TestResolve_ParallelFetching(t *testing.T) {
	const n = 3
	p := &barrierProvider{
		data: map[string][]byte{
			"key-a": []byte("val-a"),
			"key-b": []byte("val-b"),
			"key-c": []byte("val-c"),
		},
		required: n,
	}
	// Parallelism must be >= n so all goroutines can run concurrently.
	r := NewResolver(WithDefault(p), WithParallelism(n))

	type Config struct {
		A string `secret:"key-a"`
		B string `secret:"key-b"`
		C string `secret:"key-c"`
	}

	done := make(chan error, 1)
	var cfg Config
	go func() {
		done <- r.Resolve(context.Background(), &cfg)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Resolve deadlocked — fetches are not running in parallel")
	}

	if cfg.A != "val-a" {
		t.Errorf("A = %q, want %q", cfg.A, "val-a")
	}
	if cfg.B != "val-b" {
		t.Errorf("B = %q, want %q", cfg.B, "val-b")
	}
	if cfg.C != "val-c" {
		t.Errorf("C = %q, want %q", cfg.C, "val-c")
	}
}

// --- Task 9: Validate method ---

func TestValidate_ValidStruct(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{}}
	r := NewResolver(WithDefault(p), WithProvider("awssm", p))

	type Config struct {
		Name    string        `secret:"name"`
		Host    string        `secret:"awssm://prod/db#host"`
		Port    int           `secret:"port"`
		Debug   bool          `secret:"debug"`
		Timeout time.Duration `secret:"timeout"`
		Cert    []byte        `secret:"cert"`
		Rate    float64       `secret:"rate"`
		Count   uint          `secret:"count"`
		Opt     string        `secret:"opt,optional"`
	}
	var cfg Config
	if err := r.Validate(&cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_MissingDefaultProvider(t *testing.T) {
	r := NewResolver() // no default
	type Config struct {
		Key string `secret:"bare-key"`
	}
	var cfg Config
	err := r.Validate(&cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var target *ErrNoDefaultProvider
	if !errors.As(err, &target) {
		t.Errorf("expected ErrNoDefaultProvider, got: %v", err)
	}
}

func TestValidate_UnknownScheme(t *testing.T) {
	r := NewResolver() // no providers
	type Config struct {
		Key string `secret:"unknown://some/key"`
	}
	var cfg Config
	err := r.Validate(&cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var target *ErrUnknownProvider
	if !errors.As(err, &target) {
		t.Errorf("expected ErrUnknownProvider, got: %v", err)
	}
}

func TestValidate_UnsupportedType(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Bad map[string]string `secret:"key"`
	}
	var cfg Config
	err := r.Validate(&cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var target *ErrUnsupportedType
	if !errors.As(err, &target) {
		t.Errorf("expected ErrUnsupportedType, got: %v", err)
	}
}

func TestValidate_BadTag(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Bad string `secret:""`
	}
	var cfg Config
	err := r.Validate(&cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !containsSubstring(err.Error(), "empty tag") {
		t.Errorf("expected 'empty tag' in error, got: %v", err)
	}
}

func TestValidate_NonPointerError(t *testing.T) {
	r := NewResolver()
	type Config struct{}
	err := r.Validate(Config{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestValidate_NestedStruct(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{}}
	r := NewResolver(WithDefault(p))

	type Inner struct {
		Key string `secret:"inner-key"`
	}
	type Config struct {
		Inner Inner
	}
	var cfg Config
	if err := r.Validate(&cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Task 10: Versioned[T] resolution ---

func TestResolve_VersionedString(t *testing.T) {
	p := &mockVersionedProvider{
		data: map[string][]byte{
			"api-key": []byte("current-key"),
		},
		versions: map[string]map[string][]byte{
			"api-key": {
				"previous": []byte("old-key"),
			},
		},
	}
	r := NewResolver(WithDefault(p))

	type Config struct {
		APIKey Versioned[string] `secret:"api-key"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.APIKey.Current != "current-key" {
		t.Errorf("Current = %q, want %q", cfg.APIKey.Current, "current-key")
	}
	if cfg.APIKey.Previous != "old-key" {
		t.Errorf("Previous = %q, want %q", cfg.APIKey.Previous, "old-key")
	}
}

func TestResolve_VersionedBytes(t *testing.T) {
	p := &mockVersionedProvider{
		data: map[string][]byte{
			"cert": []byte("new-cert"),
		},
		versions: map[string]map[string][]byte{
			"cert": {
				"previous": []byte("old-cert"),
			},
		},
	}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Cert Versioned[[]byte] `secret:"cert"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(cfg.Cert.Current) != "new-cert" {
		t.Errorf("Current = %q, want %q", cfg.Cert.Current, "new-cert")
	}
	if string(cfg.Cert.Previous) != "old-cert" {
		t.Errorf("Previous = %q, want %q", cfg.Cert.Previous, "old-cert")
	}
}

func TestResolve_VersionedPreviousNotFound(t *testing.T) {
	p := &mockVersionedProvider{
		data: map[string][]byte{
			"api-key": []byte("current-key"),
		},
		versions: map[string]map[string][]byte{}, // no previous version
	}
	r := NewResolver(WithDefault(p))

	type Config struct {
		APIKey Versioned[string] `secret:"api-key"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.APIKey.Current != "current-key" {
		t.Errorf("Current = %q, want %q", cfg.APIKey.Current, "current-key")
	}
	if cfg.APIKey.Previous != "" {
		t.Errorf("Previous = %q, want empty (not found)", cfg.APIKey.Previous)
	}
}

func TestResolve_VersionTagPrevious(t *testing.T) {
	p := &mockVersionedProvider{
		data: map[string][]byte{
			"api-key": []byte("current-key"),
		},
		versions: map[string]map[string][]byte{
			"api-key": {
				"previous": []byte("old-key"),
			},
		},
	}
	r := NewResolver(WithDefault(p))

	type Config struct {
		OldKey string `secret:"api-key,version=previous"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.OldKey != "old-key" {
		t.Errorf("OldKey = %q, want %q", cfg.OldKey, "old-key")
	}
}

func TestResolve_VersionedNonVersionedProviderError(t *testing.T) {
	p := &mockProvider{data: map[string][]byte{
		"key": []byte("val"),
	}}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Key Versioned[string] `secret:"key"`
	}
	var cfg Config
	err := r.Resolve(context.Background(), &cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var target *ErrVersioningNotSupported
	if !errors.As(err, &target) {
		t.Errorf("expected ErrVersioningNotSupported, got: %v", err)
	}
}

func TestResolve_VersionedWithFragment(t *testing.T) {
	p := &mockVersionedProvider{
		data: map[string][]byte{
			"db": []byte(`{"password":"new-pass","host":"db.example.com"}`),
		},
		versions: map[string]map[string][]byte{
			"db": {
				"previous": []byte(`{"password":"old-pass","host":"db-old.example.com"}`),
			},
		},
	}
	r := NewResolver(WithDefault(p))

	type Config struct {
		Password Versioned[string] `secret:"db#password"`
	}
	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Password.Current != "new-pass" {
		t.Errorf("Current = %q, want %q", cfg.Password.Current, "new-pass")
	}
	if cfg.Password.Previous != "old-pass" {
		t.Errorf("Previous = %q, want %q", cfg.Password.Previous, "old-pass")
	}
}

func TestResolve_Close(t *testing.T) {
	cp := &closableProvider{closed: false}
	r := NewResolver(WithDefault(cp))
	if err := r.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cp.closed {
		t.Error("provider was not closed")
	}
}

// --- helpers ---

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

type countingProvider struct {
	data  map[string][]byte
	count *atomic.Int64
}

func (p *countingProvider) Get(_ context.Context, key string) ([]byte, error) {
	p.count.Add(1)
	v, ok := p.data[key]
	if !ok {
		return nil, fmt.Errorf("counting: %q: %w", key, ErrNotFound)
	}
	return v, nil
}

type closableProvider struct {
	closed bool
}

func (p *closableProvider) Get(_ context.Context, key string) ([]byte, error) {
	return nil, fmt.Errorf("closable: %q: %w", key, ErrNotFound)
}

func (p *closableProvider) Close() error {
	p.closed = true
	return nil
}

// barrierProvider blocks each Get call until `required` concurrent calls are active.
// If fetching is sequential, the test will deadlock.
type barrierProvider struct {
	data     map[string][]byte
	required int
	active   atomic.Int32
	barrier  sync.WaitGroup
	once     sync.Once
}

func (p *barrierProvider) init() {
	p.once.Do(func() {
		p.barrier.Add(p.required)
	})
}

func (p *barrierProvider) Get(_ context.Context, key string) ([]byte, error) {
	p.init()
	p.active.Add(1)
	p.barrier.Done()
	p.barrier.Wait() // Block until all required goroutines have arrived.

	v, ok := p.data[key]
	if !ok {
		return nil, fmt.Errorf("barrier: %q: %w", key, ErrNotFound)
	}
	return v, nil
}

// mockVersionedProvider is a map-based VersionedProvider for testing.
type mockVersionedProvider struct {
	data     map[string][]byte
	versions map[string]map[string][]byte // key -> version -> value
}

func (p *mockVersionedProvider) Get(_ context.Context, key string) ([]byte, error) {
	v, ok := p.data[key]
	if !ok {
		return nil, fmt.Errorf("mock-versioned: %q: %w", key, ErrNotFound)
	}
	return v, nil
}

func (p *mockVersionedProvider) GetVersion(_ context.Context, key string, version string) ([]byte, error) {
	vmap, ok := p.versions[key]
	if !ok {
		return nil, fmt.Errorf("mock-versioned: %q version %q: %w", key, version, ErrNotFound)
	}
	v, ok := vmap[version]
	if !ok {
		return nil, fmt.Errorf("mock-versioned: %q version %q: %w", key, version, ErrNotFound)
	}
	return v, nil
}
