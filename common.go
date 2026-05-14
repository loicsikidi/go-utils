package goutils

// Copy creates a shallow copy of the value pointed to by v and returns a pointer to the copy.
// Returns nil if v is nil.
func Copy[T any](v *T) *T {
	if v == nil {
		return nil
	}
	copied := *v
	return &copied
}

// Ptr returns a pointer to the given value.
func Ptr[T any](v T) *T {
	return &v
}

// Dereference returns the value pointed to by v, or the zero value if v is nil.
func Dereference[T any](v *T) T {
	if v == nil {
		var zero T
		return zero
	}
	return *v
}
