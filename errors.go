package secrets

import "fmt"

// ErrNoDefaultProvider indicates a bare key was encountered but no default provider is configured.
type ErrNoDefaultProvider struct {
	Field string // struct field name
	Key   string // the bare key from the tag
}

func (e *ErrNoDefaultProvider) Error() string {
	return fmt.Sprintf("secrets: field %s: no default provider for bare key %q", e.Field, e.Key)
}

// ErrUnknownProvider indicates a URI scheme was not registered with the resolver.
type ErrUnknownProvider struct {
	Field  string // struct field name
	Scheme string // the URI scheme
	URI    string // the full URI
}

func (e *ErrUnknownProvider) Error() string {
	return fmt.Sprintf("secrets: field %s: unknown provider %q for URI %q", e.Field, e.Scheme, e.URI)
}

// ErrConversion indicates that a raw secret value could not be converted to the target field type.
type ErrConversion struct {
	Field    string // struct field name
	TypeName string // target Go type name
	Raw      string // the raw string value that failed conversion
	Err      error  // the underlying conversion error
}

func (e *ErrConversion) Error() string {
	return fmt.Sprintf("secrets: field %s: cannot convert %q to %s: %v", e.Field, e.Raw, e.TypeName, e.Err)
}

func (e *ErrConversion) Unwrap() error {
	return e.Err
}

// ErrUnsupportedType indicates that the field type is not supported by the resolver.
type ErrUnsupportedType struct {
	Field    string // struct field name
	TypeName string // the unsupported Go type name
}

func (e *ErrUnsupportedType) Error() string {
	return fmt.Sprintf("secrets: field %s: unsupported type %s", e.Field, e.TypeName)
}

// ErrVersioningNotSupported indicates that a version was requested but the provider
// does not implement VersionedProvider.
type ErrVersioningNotSupported struct {
	Field    string // struct field name
	Provider string // the provider scheme or "default"
}

func (e *ErrVersioningNotSupported) Error() string {
	return fmt.Sprintf("secrets: field %s: provider %q does not support versioning", e.Field, e.Provider)
}
