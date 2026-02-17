package secrets

import (
	"context"
	"encoding"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Resolver populates struct fields annotated with `secret` tags from configured providers.
type Resolver struct {
	cfg resolverConfig
}

// NewResolver creates a Resolver with the given options.
func NewResolver(opts ...Option) *Resolver {
	r := &Resolver{}
	for _, opt := range opts {
		opt(&r.cfg)
	}
	if r.cfg.parallelism == 0 {
		r.cfg.parallelism = 10
	}
	return r
}

// Close closes all providers that implement io.Closer.
func (r *Resolver) Close() error {
	return closeProviders(&r.cfg)
}

// Validate checks that dst is a valid target for Resolve without contacting any provider.
// It verifies:
//   - dst is a non-nil pointer to a struct
//   - all `secret` tags are syntactically valid
//   - all referenced schemes have registered providers (or a default exists for bare keys)
//   - all field types are supported for conversion
func (r *Resolver) Validate(dst any) error {
	rv := reflect.ValueOf(dst)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("secrets: dst must be a non-nil pointer, got %T", dst)
	}
	elem := rv.Elem()
	if elem.Kind() != reflect.Struct {
		return fmt.Errorf("secrets: dst must point to a struct, got pointer to %s", elem.Kind())
	}

	var errs []error
	r.validateStruct(elem.Type(), &errs)
	return errors.Join(errs...)
}

// validateStruct walks a struct type recursively and validates all tagged fields.
func (r *Resolver) validateStruct(st reflect.Type, errs *[]error) {
	for i := range st.NumField() {
		field := st.Field(i)

		// Handle embedded/anonymous structs: recurse into them.
		if field.Anonymous {
			ft := field.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				r.validateStruct(ft, errs)
			}
			continue
		}

		// Skip unexported fields.
		if !field.IsExported() {
			continue
		}

		tagStr, ok := field.Tag.Lookup("secret")
		if !ok {
			// Check for nested struct without tag.
			ft := field.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct && hasSecretTags(ft) {
				r.validateStruct(ft, errs)
			}
			continue
		}

		tag, err := parseTag(tagStr)
		if err != nil {
			*errs = append(*errs, fmt.Errorf("secrets: field %s: %w", field.Name, err))
			continue
		}

		// Validate provider availability.
		if tag.Scheme != "" {
			if _, found := r.cfg.providers[tag.Scheme]; !found {
				*errs = append(*errs, &ErrUnknownProvider{
					Field:  field.Name,
					Scheme: tag.Scheme,
					URI:    tag.URI(),
				})
			}
		} else {
			if r.cfg.defaultProvider == nil {
				*errs = append(*errs, &ErrNoDefaultProvider{
					Field: field.Name,
					Key:   tag.Key,
				})
			}
		}

		// Validate field type is supported.
		ft := field.Type
		if isVersionedType(ft) {
			// For Versioned[T], validate the inner type T (Current field type).
			innerType := ft.Field(0).Type
			if !isSupportedType(innerType) {
				*errs = append(*errs, &ErrUnsupportedType{
					Field:    field.Name,
					TypeName: ft.String(),
				})
			}
		} else if !isSupportedType(ft) {
			*errs = append(*errs, &ErrUnsupportedType{
				Field:    field.Name,
				TypeName: ft.String(),
			})
		}
	}
}

// isSupportedType checks if the given type can be set by setField.
func isSupportedType(t reflect.Type) bool {
	// Dereference pointer.
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	// Check for encoding.TextUnmarshaler via pointer receiver.
	if reflect.PointerTo(t).Implements(reflect.TypeFor[encoding.TextUnmarshaler]()) {
		return true
	}

	switch t.Kind() {
	case reflect.String:
		return true
	case reflect.Bool:
		return true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	case reflect.Float32, reflect.Float64:
		return true
	case reflect.Slice:
		return t.Elem().Kind() == reflect.Uint8 // []byte
	default:
		return false
	}
}

// isVersionedType returns true if the given type matches the Versioned[T] pattern:
// a struct with exactly 2 fields named "Current" and "Previous" of the same type.
func isVersionedType(t reflect.Type) bool {
	if t.Kind() != reflect.Struct {
		return false
	}
	if t.NumField() != 2 {
		return false
	}
	f0 := t.Field(0)
	f1 := t.Field(1)
	return f0.Name == "Current" && f1.Name == "Previous" && f0.Type == f1.Type
}

// fieldInfo holds metadata for a single tagged field to be resolved.
type fieldInfo struct {
	fieldName    string
	fieldValue   reflect.Value
	tag          parsedTag
	provider     Provider
	providerName string
	isVersioned  bool // true if the field is a Versioned[T] type
}

// fetchKey uniquely identifies a fetch operation including version.
type fetchKey struct {
	uri     string
	version string // empty for current, "previous" for previous, or explicit version
}

func (fk fetchKey) String() string {
	if fk.version != "" {
		return fk.uri + "@" + fk.version
	}
	return fk.uri
}

// Resolve walks dst (which must be a non-nil pointer to a struct) and populates
// fields annotated with `secret` struct tags from the configured providers.
//
// Secrets are fetched concurrently with a configurable parallelism limit.
// Secrets are deduplicated by URI so the same secret is only fetched once.
// All errors are collected and returned via errors.Join.
func (r *Resolver) Resolve(ctx context.Context, dst any) error {
	rv := reflect.ValueOf(dst)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("secrets: dst must be a non-nil pointer, got %T", dst)
	}
	elem := rv.Elem()
	if elem.Kind() != reflect.Struct {
		return fmt.Errorf("secrets: dst must point to a struct, got pointer to %s", elem.Kind())
	}

	// Phase 1: Collect all fields that need resolution.
	var fields []fieldInfo
	var collectErrs []error
	r.collectFields(elem, &fields, &collectErrs)
	if len(collectErrs) > 0 && len(fields) == 0 {
		return errors.Join(collectErrs...)
	}

	// Phase 2: Determine unique fetch keys and fetch them concurrently.
	type fetchResult struct {
		data []byte
		err  error
	}

	// Build the set of unique fetch keys.
	type fetchSpec struct {
		key      fetchKey
		fi       *fieldInfo
		version  string // version to request (empty = use Get, non-empty = use GetVersion)
	}

	seen := make(map[string]bool) // fetchKey.String() -> true
	var specs []fetchSpec

	for i := range fields {
		fi := &fields[i]
		uri := fi.tag.URI()

		if fi.isVersioned {
			// Versioned fields need two fetches: current and previous.
			currentKey := fetchKey{uri: uri, version: ""}
			previousKey := fetchKey{uri: uri, version: "previous"}

			if !seen[currentKey.String()] {
				seen[currentKey.String()] = true
				specs = append(specs, fetchSpec{key: currentKey, fi: fi, version: ""})
			}
			if !seen[previousKey.String()] {
				seen[previousKey.String()] = true
				specs = append(specs, fetchSpec{key: previousKey, fi: fi, version: "previous"})
			}
		} else {
			fk := fetchKey{uri: uri, version: fi.tag.Version}
			if !seen[fk.String()] {
				seen[fk.String()] = true
				specs = append(specs, fetchSpec{key: fk, fi: fi, version: fi.tag.Version})
			}
		}
	}

	// Fetch all unique keys concurrently with semaphore.
	results := make(map[string]*fetchResult) // fetchKey.String() -> result
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, r.cfg.parallelism)

	for _, spec := range specs {
		wg.Add(1)
		go func(spec fetchSpec) {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			var data []byte
			var fetchErr error
			if spec.version != "" {
				vp, ok := spec.fi.provider.(VersionedProvider)
				if !ok {
					fetchErr = &ErrVersioningNotSupported{
						Field:    spec.fi.fieldName,
						Provider: spec.fi.providerName,
					}
				} else {
					data, fetchErr = vp.GetVersion(ctx, spec.fi.tag.Key, spec.version)
				}
			} else {
				data, fetchErr = spec.fi.provider.Get(ctx, spec.fi.tag.Key)
			}

			mu.Lock()
			results[spec.key.String()] = &fetchResult{data: data, err: fetchErr}
			mu.Unlock()
		}(spec)
	}
	wg.Wait()

	// Phase 3: Assign fetched values to fields.
	var assignErrs []error
	for i := range fields {
		fi := &fields[i]
		uri := fi.tag.URI()

		if fi.isVersioned {
			// Handle Versioned[T] field: set both Current and Previous.
			currentFK := fetchKey{uri: uri, version: ""}
			previousFK := fetchKey{uri: uri, version: "previous"}

			currentResult := results[currentFK.String()]
			previousResult := results[previousFK.String()]

			// Current value is required (unless optional).
			if currentResult.err != nil {
				if fi.tag.Optional && errors.Is(currentResult.err, ErrNotFound) {
					continue
				}
				assignErrs = append(assignErrs, fmt.Errorf("secrets: field %s: %w", fi.fieldName, currentResult.err))
				continue
			}

			// Extract fragment from current value.
			currentVal := currentResult.data
			if fi.tag.Fragment != "" {
				extracted, fragErr := extractFragment(currentResult.data, fi.tag.Fragment)
				if fragErr != nil {
					assignErrs = append(assignErrs, fmt.Errorf("secrets: field %s: %w", fi.fieldName, fragErr))
					continue
				}
				currentVal = extracted
			}

			// Set Current field.
			currentField := fi.fieldValue.Field(0) // Current
			if err := setField(currentField, fi.fieldName+".Current", currentVal); err != nil {
				assignErrs = append(assignErrs, err)
				continue
			}

			// Previous value: if not found, leave as zero value.
			if previousResult.err != nil {
				if !errors.Is(previousResult.err, ErrNotFound) {
					assignErrs = append(assignErrs, fmt.Errorf("secrets: field %s: %w", fi.fieldName, previousResult.err))
				}
				// Leave Previous as zero value.
				continue
			}

			previousVal := previousResult.data
			if fi.tag.Fragment != "" {
				extracted, fragErr := extractFragment(previousResult.data, fi.tag.Fragment)
				if fragErr != nil {
					assignErrs = append(assignErrs, fmt.Errorf("secrets: field %s: %w", fi.fieldName, fragErr))
					continue
				}
				previousVal = extracted
			}

			// Set Previous field.
			previousField := fi.fieldValue.Field(1) // Previous
			if err := setField(previousField, fi.fieldName+".Previous", previousVal); err != nil {
				assignErrs = append(assignErrs, err)
			}
		} else {
			// Normal (non-versioned) field.
			fk := fetchKey{uri: uri, version: fi.tag.Version}
			result := results[fk.String()]

			if result.err != nil {
				if fi.tag.Optional && errors.Is(result.err, ErrNotFound) {
					continue
				}
				assignErrs = append(assignErrs, fmt.Errorf("secrets: field %s: %w", fi.fieldName, result.err))
				continue
			}

			value := result.data
			if fi.tag.Fragment != "" {
				extracted, fragErr := extractFragment(result.data, fi.tag.Fragment)
				if fragErr != nil {
					assignErrs = append(assignErrs, fmt.Errorf("secrets: field %s: %w", fi.fieldName, fragErr))
					continue
				}
				value = extracted
			}

			if err := setField(fi.fieldValue, fi.fieldName, value); err != nil {
				assignErrs = append(assignErrs, err)
			}
		}
	}

	allErrs := append(collectErrs, assignErrs...)
	return errors.Join(allErrs...)
}

// collectFields walks a struct value recursively and collects all tagged fields.
func (r *Resolver) collectFields(sv reflect.Value, fields *[]fieldInfo, errs *[]error) {
	st := sv.Type()
	for i := range st.NumField() {
		field := st.Field(i)
		fv := sv.Field(i)

		// Handle embedded/anonymous structs: recurse into them.
		if field.Anonymous && fv.Kind() == reflect.Struct {
			r.collectFields(fv, fields, errs)
			continue
		}

		// Skip unexported fields.
		if !field.IsExported() {
			continue
		}

		tagStr, ok := field.Tag.Lookup("secret")
		if !ok {
			continue
		}

		tag, err := parseTag(tagStr)
		if err != nil {
			*errs = append(*errs, fmt.Errorf("secrets: field %s: %w", field.Name, err))
			continue
		}

		// Determine the provider.
		var provider Provider
		var providerName string
		if tag.Scheme != "" {
			p, found := r.cfg.providers[tag.Scheme]
			if !found {
				*errs = append(*errs, &ErrUnknownProvider{
					Field:  field.Name,
					Scheme: tag.Scheme,
					URI:    tag.URI(),
				})
				continue
			}
			provider = p
			providerName = tag.Scheme
		} else {
			if r.cfg.defaultProvider == nil {
				*errs = append(*errs, &ErrNoDefaultProvider{
					Field: field.Name,
					Key:   tag.Key,
				})
				continue
			}
			provider = r.cfg.defaultProvider
			providerName = "default"
		}

		// Check if this is a Versioned[T] field.
		versioned := isVersionedType(field.Type)
		if versioned {
			// Verify the provider supports versioning.
			if _, ok := provider.(VersionedProvider); !ok {
				*errs = append(*errs, &ErrVersioningNotSupported{
					Field:    field.Name,
					Provider: providerName,
				})
				continue
			}
		}

		*fields = append(*fields, fieldInfo{
			fieldName:    field.Name,
			fieldValue:   fv,
			tag:          tag,
			provider:     provider,
			providerName: providerName,
			isVersioned:  versioned,
		})
	}

	// Second pass: recurse into non-embedded struct fields that do NOT have a secret tag.
	for i := range st.NumField() {
		field := st.Field(i)
		fv := sv.Field(i)

		if field.Anonymous {
			continue // already handled above
		}
		if !field.IsExported() {
			continue
		}
		if _, ok := field.Tag.Lookup("secret"); ok {
			continue // already handled above
		}

		actualType := field.Type
		actualVal := fv
		if actualType.Kind() == reflect.Pointer {
			if actualVal.IsNil() {
				// Initialize nil pointer to struct for recursion.
				if actualType.Elem().Kind() == reflect.Struct {
					actualVal.Set(reflect.New(actualType.Elem()))
				} else {
					continue
				}
			}
			actualType = actualType.Elem()
			actualVal = actualVal.Elem()
		}

		if actualType.Kind() == reflect.Struct {
			// Check if the struct has any secret-tagged fields before recursing.
			if hasSecretTags(actualType) {
				r.collectFields(actualVal, fields, errs)
			}
		}
	}
}

// hasSecretTags returns true if the given struct type (or any nested struct) has secret-tagged fields.
func hasSecretTags(t reflect.Type) bool {
	for i := range t.NumField() {
		f := t.Field(i)
		if _, ok := f.Tag.Lookup("secret"); ok {
			return true
		}
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct && hasSecretTags(ft) {
			return true
		}
	}
	return false
}

// setField converts raw bytes to the field's type and sets the value.
func setField(fv reflect.Value, fieldName string, raw []byte) error {
	s := string(raw)
	ft := fv.Type()

	// Handle pointer types: allocate and set the underlying value.
	if ft.Kind() == reflect.Pointer {
		ptr := reflect.New(ft.Elem())
		if err := setField(ptr.Elem(), fieldName, raw); err != nil {
			return err
		}
		fv.Set(ptr)
		return nil
	}

	// Check for encoding.TextUnmarshaler first.
	if fv.CanAddr() {
		if tu, ok := fv.Addr().Interface().(encoding.TextUnmarshaler); ok {
			if err := tu.UnmarshalText(raw); err != nil {
				return &ErrConversion{Field: fieldName, TypeName: ft.String(), Raw: s, Err: err}
			}
			return nil
		}
	}

	switch ft.Kind() {
	case reflect.String:
		fv.SetString(s)
	case reflect.Slice:
		if ft.Elem().Kind() == reflect.Uint8 {
			// []byte
			fv.SetBytes(append([]byte(nil), raw...))
		} else {
			return &ErrUnsupportedType{Field: fieldName, TypeName: ft.String()}
		}
	case reflect.Bool:
		b, err := strconv.ParseBool(strings.TrimSpace(s))
		if err != nil {
			return &ErrConversion{Field: fieldName, TypeName: ft.String(), Raw: s, Err: err}
		}
		fv.SetBool(b)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// Special case for time.Duration.
		if ft == reflect.TypeFor[time.Duration]() {
			d, err := time.ParseDuration(strings.TrimSpace(s))
			if err != nil {
				return &ErrConversion{Field: fieldName, TypeName: ft.String(), Raw: s, Err: err}
			}
			fv.SetInt(int64(d))
			return nil
		}
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, ft.Bits())
		if err != nil {
			return &ErrConversion{Field: fieldName, TypeName: ft.String(), Raw: s, Err: err}
		}
		fv.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(strings.TrimSpace(s), 10, ft.Bits())
		if err != nil {
			return &ErrConversion{Field: fieldName, TypeName: ft.String(), Raw: s, Err: err}
		}
		fv.SetUint(n)
	case reflect.Float32, reflect.Float64:
		n, err := strconv.ParseFloat(strings.TrimSpace(s), ft.Bits())
		if err != nil {
			return &ErrConversion{Field: fieldName, TypeName: ft.String(), Raw: s, Err: err}
		}
		fv.SetFloat(n)
	default:
		return &ErrUnsupportedType{Field: fieldName, TypeName: ft.String()}
	}
	return nil
}
