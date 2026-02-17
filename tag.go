package secrets

import (
	"fmt"
	"strings"
)

// parsedTag holds the components extracted from a `secret` struct tag.
type parsedTag struct {
	Scheme   string // URI scheme (e.g. "awssm"), empty for bare keys
	Key      string // secret key/path
	Fragment string // JSON field to extract (from #fragment)
	Optional bool   // true if ,optional is set
	Version  string // version identifier (from ,version=X)
}

// parseTag parses a struct tag value with the format:
//
//	[scheme://]key[#fragment][,option...]
//
// Options: optional, version=X
func parseTag(raw string) (parsedTag, error) {
	if raw == "" {
		return parsedTag{}, fmt.Errorf("secrets: empty tag")
	}

	var t parsedTag

	// Split off comma-separated options.
	parts := strings.Split(raw, ",")
	uri := parts[0]
	for _, opt := range parts[1:] {
		switch {
		case opt == "optional":
			t.Optional = true
		case strings.HasPrefix(opt, "version="):
			t.Version = strings.TrimPrefix(opt, "version=")
		default:
			return parsedTag{}, fmt.Errorf("secrets: unknown tag option %q", opt)
		}
	}

	// Extract fragment (everything after the last unescaped #).
	if idx := strings.LastIndex(uri, "#"); idx >= 0 {
		t.Fragment = uri[idx+1:]
		uri = uri[:idx]
	}

	// Detect scheme by looking for "://".
	if scheme, rest, ok := strings.Cut(uri, "://"); ok {
		t.Scheme = scheme
		t.Key = rest
	} else {
		t.Key = uri
	}

	if t.Key == "" {
		return parsedTag{}, fmt.Errorf("secrets: empty key in tag %q", raw)
	}

	return t, nil
}

// URI returns the canonical URI for deduplication.
// For scheme-based tags it returns "scheme://key"; for bare keys it returns the key itself.
func (t parsedTag) URI() string {
	if t.Scheme != "" {
		return t.Scheme + "://" + t.Key
	}
	return t.Key
}
