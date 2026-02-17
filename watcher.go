package secrets

import (
	"bytes"
	"context"
	"reflect"
	"strconv"
	"sync"
	"time"
)

// WatchOption configures a Watcher.
type WatchOption func(*watcherConfig)

type watcherConfig struct {
	interval time.Duration
}

// WatchInterval sets the polling interval for the Watcher.
// Defaults to 1 minute.
func WatchInterval(d time.Duration) WatchOption {
	return func(c *watcherConfig) {
		c.interval = d
	}
}

// Watcher periodically re-resolves secrets and detects changes.
// It provides thread-safe read access via RLock/RUnlock.
type Watcher struct {
	mu      sync.RWMutex
	changes chan ChangeEvent
	stop    chan struct{}
	done    chan struct{}
}

// Changes returns a channel that receives ChangeEvents when secret values change.
// The channel is closed when the Watcher is stopped or the context is cancelled.
func (w *Watcher) Changes() <-chan ChangeEvent {
	return w.changes
}

// RLock acquires a read lock on the watched struct.
// Use this before reading the struct to ensure consistency.
func (w *Watcher) RLock() {
	w.mu.RLock()
}

// RUnlock releases the read lock.
func (w *Watcher) RUnlock() {
	w.mu.RUnlock()
}

// Stop stops the Watcher and closes the Changes channel.
func (w *Watcher) Stop() {
	select {
	case <-w.stop:
		// Already stopped.
	default:
		close(w.stop)
	}
	<-w.done // Wait for the poll loop to finish.
}

// fieldSnapshot records the raw bytes for a field after fragment extraction.
type fieldSnapshot struct {
	fieldName    string
	key          string
	providerName string
	raw          []byte // raw bytes after fragment extraction
}

// Watch starts a Watcher that periodically re-resolves secrets into dst.
// It performs an initial Resolve and then polls at the configured interval.
// The returned Watcher must be stopped via Stop() or context cancellation.
func (r *Resolver) Watch(ctx context.Context, dst any, opts ...WatchOption) (*Watcher, error) {
	cfg := watcherConfig{
		interval: 1 * time.Minute,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	// Perform the initial resolve.
	if err := r.Resolve(ctx, dst); err != nil {
		return nil, err
	}

	// Take initial snapshot.
	snapshot := r.takeSnapshot(dst)

	w := &Watcher{
		changes: make(chan ChangeEvent, 64),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}

	go w.pollLoop(ctx, r, dst, cfg.interval, snapshot)

	return w, nil
}

// takeSnapshot collects the current raw bytes for all secret-tagged fields.
func (r *Resolver) takeSnapshot(dst any) []fieldSnapshot {
	rv := reflect.ValueOf(dst)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return nil
	}
	elem := rv.Elem()
	if elem.Kind() != reflect.Struct {
		return nil
	}

	var fields []fieldInfo
	var errs []error
	r.collectFields(elem, &fields, &errs)

	var snapshots []fieldSnapshot
	for _, fi := range fields {
		raw := fieldToBytes(fi.fieldValue, fi.isVersioned)
		providerName := fi.providerName
		if providerName == "" {
			providerName = fi.tag.Scheme
		}
		snapshots = append(snapshots, fieldSnapshot{
			fieldName:    fi.fieldName,
			key:          fi.tag.Key,
			providerName: providerName,
			raw:          raw,
		})
	}
	return snapshots
}

// fieldToBytes converts a reflect.Value back to bytes for snapshot comparison.
func fieldToBytes(fv reflect.Value, isVersioned bool) []byte {
	if isVersioned {
		// For Versioned[T], snapshot the Current field.
		currentField := fv.Field(0)
		return valueToBytes(currentField)
	}
	return valueToBytes(fv)
}

// valueToBytes converts a reflect.Value to its byte representation.
func valueToBytes(v reflect.Value) []byte {
	ft := v.Type()

	// Dereference pointer.
	if ft.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
		ft = v.Type()
	}

	switch ft.Kind() {
	case reflect.String:
		return []byte(v.String())
	case reflect.Slice:
		if ft.Elem().Kind() == reflect.Uint8 {
			return v.Bytes()
		}
	case reflect.Bool:
		if v.Bool() {
			return []byte("true")
		}
		return []byte("false")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if ft == reflect.TypeFor[time.Duration]() {
			return []byte(time.Duration(v.Int()).String())
		}
		return []byte(strconv.FormatInt(v.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return []byte(strconv.FormatUint(v.Uint(), 10))
	case reflect.Float32, reflect.Float64:
		return []byte(strconv.FormatFloat(v.Float(), 'f', -1, 64))
	}
	return []byte(v.String())
}

// pollLoop runs the polling loop.
func (w *Watcher) pollLoop(ctx context.Context, r *Resolver, dst any, interval time.Duration, snapshot []fieldSnapshot) {
	defer close(w.done)
	defer close(w.changes)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-w.stop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			newSnapshot := w.poll(ctx, r, dst, snapshot)
			if newSnapshot != nil {
				snapshot = newSnapshot
			}
		}
	}
}

// poll performs one polling cycle: re-resolve into temp copy, compare, update if changed.
func (w *Watcher) poll(ctx context.Context, r *Resolver, dst any, oldSnapshot []fieldSnapshot) []fieldSnapshot {
	// Create a temporary copy and resolve into it (not dst) to avoid
	// partial updates on failure.
	dstVal := reflect.ValueOf(dst).Elem()
	tmp := reflect.New(dstVal.Type())
	if err := r.Resolve(ctx, tmp.Interface()); err != nil {
		// On error, keep the old snapshot and skip this cycle.
		return nil
	}

	// Take new snapshot from the temp copy.
	newSnapshot := r.takeSnapshot(tmp.Interface())

	// Collect change events.
	var events []ChangeEvent
	for i := range newSnapshot {
		if i >= len(oldSnapshot) {
			break
		}
		old := &oldSnapshot[i]
		new_ := &newSnapshot[i]

		if !bytes.Equal(old.raw, new_.raw) {
			events = append(events, ChangeEvent{
				Field:    new_.fieldName,
				Key:      new_.key,
				Provider: new_.providerName,
				OldValue: old.raw,
				NewValue: new_.raw,
			})
		}
	}

	// If any changes were detected, copy only secret-tagged fields from tmp
	// to dst under write lock. We must not copy the entire struct because
	// non-secret fields would be zeroed out.
	if len(events) > 0 {
		var tmpFields []fieldInfo
		var dstFields []fieldInfo
		var errs []error
		r.collectFields(tmp.Elem(), &tmpFields, &errs)
		r.collectFields(dstVal, &dstFields, &errs)

		w.mu.Lock()
		for i := range dstFields {
			if i < len(tmpFields) {
				dstFields[i].fieldValue.Set(tmpFields[i].fieldValue)
			}
		}
		w.mu.Unlock()

		// Emit change events.
		for _, event := range events {
			select {
			case w.changes <- event:
			default:
				// Channel full, skip this event to avoid blocking.
			}
		}
	}

	return newSnapshot
}
