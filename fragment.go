package secrets

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// extractFragment extracts a value from a JSON blob by dot-delimited path.
//
// Supported path components:
//   - flat keys: "password"
//   - nested keys: "db.host"
//   - array indices: "items.0.name"
//
// String values are returned as-is (without JSON quotes).
// Numbers, booleans, and null are returned as their JSON string representation.
func extractFragment(data []byte, path string) ([]byte, error) {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("secrets: invalid JSON: %w", err)
	}

	parts := strings.Split(path, ".")
	current := root

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]any:
			val, ok := v[part]
			if !ok {
				return nil, fmt.Errorf("secrets: fragment %q not found", path)
			}
			current = val
		case []any:
			idx, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("secrets: fragment %q: %q is not a valid array index", path, part)
			}
			if idx < 0 || idx >= len(v) {
				return nil, fmt.Errorf("secrets: fragment %q: index %d out of range (len %d)", path, idx, len(v))
			}
			current = v[idx]
		default:
			return nil, fmt.Errorf("secrets: fragment %q: cannot index into %T", path, current)
		}
	}

	// Convert the final value to bytes.
	switch v := current.(type) {
	case string:
		return []byte(v), nil
	case float64:
		// Use compact representation: no trailing zeros for integers.
		if v == float64(int64(v)) {
			return []byte(strconv.FormatInt(int64(v), 10)), nil
		}
		return []byte(strconv.FormatFloat(v, 'f', -1, 64)), nil
	case bool:
		return []byte(strconv.FormatBool(v)), nil
	case nil:
		return []byte("null"), nil
	default:
		// For nested objects/arrays, re-marshal as JSON.
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("secrets: fragment %q: %w", path, err)
		}
		return b, nil
	}
}
