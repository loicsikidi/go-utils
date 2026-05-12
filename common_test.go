package goutils

import "testing"

func TestCopy(t *testing.T) {
	t.Run("nil pointer returns nil", func(t *testing.T) {
		var nilPtr *int
		result := Copy(nilPtr)
		if result != nil {
			t.Errorf("Copy(nil) = %v, want nil", result)
		}
	})

	t.Run("copies int value", func(t *testing.T) {
		original := 42
		copied := Copy(&original)

		if copied == nil {
			t.Fatal("Copy() returned nil, want non-nil")
		}
		if *copied != original {
			t.Errorf("Copy() = %d, want %d", *copied, original)
		}

		// Verify independence
		original = 99
		if *copied != 42 {
			t.Errorf("after modifying original, copy = %d, want 42", *copied)
		}
	})

	t.Run("copies string value", func(t *testing.T) {
		original := "hello"
		copied := Copy(&original)

		if copied == nil {
			t.Fatal("Copy() returned nil, want non-nil")
		}
		if *copied != original {
			t.Errorf("Copy() = %q, want %q", *copied, original)
		}

		// Verify independence
		original = "world"
		if *copied != "hello" {
			t.Errorf("after modifying original, copy = %q, want %q", *copied, "hello")
		}
	})

	t.Run("copies struct value", func(t *testing.T) {
		type person struct {
			name string
			age  int
		}

		original := person{name: "Alice", age: 30}
		copied := Copy(&original)

		if copied == nil {
			t.Fatal("Copy() returned nil, want non-nil")
		}
		if *copied != original {
			t.Errorf("Copy() = %+v, want %+v", *copied, original)
		}

		// Verify independence
		original.age = 31
		if copied.age != 30 {
			t.Errorf("after modifying original, copy.age = %d, want 30", copied.age)
		}
	})
}
