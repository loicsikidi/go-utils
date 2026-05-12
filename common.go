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
