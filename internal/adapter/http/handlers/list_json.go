package handlers

// orEmpty returns s, or an empty slice when s is nil, so a list encodes as
// JSON [] instead of null.
func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
