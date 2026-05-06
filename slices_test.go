// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package goutils

import (
	"reflect"
	"testing"
)

func TestFilter(t *testing.T) {
	t.Run("filter and deduplicate integers", func(t *testing.T) {
		input := []int{1, 2, 3, 2, 4, 3, 5}
		fn := func(i int) (int, bool) {
			return i, i > 2
		}

		got := Filter(input, fn)
		want := []int{3, 4, 5}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("Filter() = %v, want %v", got, want)
		}
	})

	t.Run("filter with transformation", func(t *testing.T) {
		input := []string{"apple", "banana", "apricot", "cherry", "avocado"}
		fn := func(s string) (rune, bool) {
			firstChar := rune(s[0])
			return firstChar, firstChar == 'a'
		}

		got := Filter(input, fn)
		want := []rune{'a'}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("Filter() = %v, want %v", got, want)
		}
	})

	t.Run("empty input slice", func(t *testing.T) {
		input := []int{}
		fn := func(i int) (int, bool) {
			return i, true
		}

		got := Filter(input, fn)
		want := []int{}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("Filter() = %v, want %v", got, want)
		}
	})

	t.Run("no elements match filter", func(t *testing.T) {
		input := []int{1, 2, 3, 4, 5}
		fn := func(i int) (int, bool) {
			return i, i > 10
		}

		got := Filter(input, fn)
		want := []int{}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("Filter() = %v, want %v", got, want)
		}
	})

	t.Run("all elements match and are unique", func(t *testing.T) {
		input := []int{1, 2, 3, 4, 5}
		fn := func(i int) (int, bool) {
			return i, true
		}

		got := Filter(input, fn)
		want := []int{1, 2, 3, 4, 5}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("Filter() = %v, want %v", got, want)
		}
	})

	t.Run("all elements duplicate to same value", func(t *testing.T) {
		input := []int{1, 2, 3, 4, 5}
		fn := func(i int) (int, bool) {
			return 42, true
		}

		got := Filter(input, fn)
		want := []int{42}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("Filter() = %v, want %v", got, want)
		}
	})

	t.Run("complex type transformation", func(t *testing.T) {
		type Person struct {
			Name string
			Age  int
		}

		input := []Person{
			{"Alice", 30},
			{"Bob", 25},
			{"Charlie", 30},
			{"Diana", 35},
		}

		fn := func(p Person) (int, bool) {
			return p.Age, p.Age >= 30
		}

		got := Filter(input, fn)
		want := []int{30, 35}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("Filter() = %v, want %v", got, want)
		}
	})

	t.Run("string deduplication", func(t *testing.T) {
		input := []string{"hello", "world", "hello", "go", "world", "test"}
		fn := func(s string) (string, bool) {
			return s, len(s) > 3
		}

		got := Filter(input, fn)
		want := []string{"hello", "world", "test"}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("Filter() = %v, want %v", got, want)
		}
	})
}

func TestReduce(t *testing.T) {
	t.Run("sum integers", func(t *testing.T) {
		input := []int{1, 2, 3, 4, 5}
		fn := func(acc, val int) int {
			return acc + val
		}

		got := Reduce(input, 0, fn)
		want := 15

		if got != want {
			t.Errorf("Reduce() = %v, want %v", got, want)
		}
	})

	t.Run("product of integers", func(t *testing.T) {
		input := []int{2, 3, 4}
		fn := func(acc, val int) int {
			return acc * val
		}

		got := Reduce(input, 1, fn)
		want := 24

		if got != want {
			t.Errorf("Reduce() = %v, want %v", got, want)
		}
	})

	t.Run("concatenate strings", func(t *testing.T) {
		input := []string{"hello", " ", "world"}
		fn := func(acc, val string) string {
			return acc + val
		}

		got := Reduce(input, "", fn)
		want := "hello world"

		if got != want {
			t.Errorf("Reduce() = %v, want %v", got, want)
		}
	})

	t.Run("empty slice returns initial value", func(t *testing.T) {
		input := []int{}
		fn := func(acc, val int) int {
			return acc + val
		}

		got := Reduce(input, 42, fn)
		want := 42

		if got != want {
			t.Errorf("Reduce() = %v, want %v", got, want)
		}
	})

	t.Run("build slice from integers", func(t *testing.T) {
		input := []int{1, 2, 3, 4, 5}
		fn := func(acc []int, val int) []int {
			return append(acc, val*2)
		}

		got := Reduce(input, []int{}, fn)
		want := []int{2, 4, 6, 8, 10}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("Reduce() = %v, want %v", got, want)
		}
	})

	t.Run("count elements matching condition", func(t *testing.T) {
		input := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
		fn := func(acc int, val int) int {
			if val%2 == 0 {
				return acc + 1
			}
			return acc
		}

		got := Reduce(input, 0, fn)
		want := 5

		if got != want {
			t.Errorf("Reduce() = %v, want %v", got, want)
		}
	})

	t.Run("build map from slice", func(t *testing.T) {
		type Person struct {
			ID   int
			Name string
		}

		input := []Person{
			{ID: 1, Name: "Alice"},
			{ID: 2, Name: "Bob"},
			{ID: 3, Name: "Charlie"},
		}

		fn := func(acc map[int]string, val Person) map[int]string {
			acc[val.ID] = val.Name
			return acc
		}

		got := Reduce(input, make(map[int]string), fn)
		want := map[int]string{1: "Alice", 2: "Bob", 3: "Charlie"}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("Reduce() = %v, want %v", got, want)
		}
	})

	t.Run("find maximum value", func(t *testing.T) {
		input := []int{3, 7, 2, 9, 1, 5}
		fn := func(acc, val int) int {
			if val > acc {
				return val
			}
			return acc
		}

		got := Reduce(input, input[0], fn)
		want := 9

		if got != want {
			t.Errorf("Reduce() = %v, want %v", got, want)
		}
	})
}

func TestRemoveFromSlice(t *testing.T) {
	t.Parallel()

	t.Run("remove single element", func(t *testing.T) {
		t.Parallel()
		input := []int{1, 2, 3, 4, 5}
		result := RemoveFromSlice(input, 3)
		expected := []int{1, 2, 4, 5}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
		originalInput := []int{1, 2, 3, 4, 5}
		if !reflect.DeepEqual(originalInput, input) {
			t.Errorf("input should not be modified, expected %v, got %v", originalInput, input)
		}
	})

	t.Run("remove multiple elements", func(t *testing.T) {
		t.Parallel()
		input := []string{"a", "b", "c", "d", "e"}
		result := RemoveFromSlice(input, "b", "d")
		expected := []string{"a", "c", "e"}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
		originalInput := []string{"a", "b", "c", "d", "e"}
		if !reflect.DeepEqual(originalInput, input) {
			t.Errorf("input should not be modified, expected %v, got %v", originalInput, input)
		}
	})

	t.Run("remove all occurrences", func(t *testing.T) {
		t.Parallel()
		input := []int{1, 2, 2, 3, 2, 4}
		result := RemoveFromSlice(input, 2)
		expected := []int{1, 3, 4}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})

	t.Run("remove non-existent element", func(t *testing.T) {
		t.Parallel()
		input := []int{1, 2, 3}
		result := RemoveFromSlice(input, 5)
		expected := []int{1, 2, 3}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		t.Parallel()
		input := []int{}
		result := RemoveFromSlice(input, 1)
		expected := []int{}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})

	t.Run("remove from slice with single element", func(t *testing.T) {
		t.Parallel()
		input := []int{42}
		result := RemoveFromSlice(input, 42)
		expected := []int{}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})

	t.Run("remove nothing", func(t *testing.T) {
		t.Parallel()
		input := []int{1, 2, 3}
		result := RemoveFromSlice(input)
		expected := []int{1, 2, 3}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
		originalInput := []int{1, 2, 3}
		if !reflect.DeepEqual(originalInput, input) {
			t.Errorf("input should not be modified, expected %v, got %v", originalInput, input)
		}
	})

	t.Run("remove all elements", func(t *testing.T) {
		t.Parallel()
		input := []int{1, 2, 3}
		result := RemoveFromSlice(input, 1, 2, 3)
		expected := []int{}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})

	t.Run("with custom struct", func(t *testing.T) {
		t.Parallel()
		type person struct {
			name string
			age  int
		}

		input := []person{
			{name: "Alice", age: 30},
			{name: "Bob", age: 25},
			{name: "Charlie", age: 35},
		}

		result := RemoveFromSlice(input, person{name: "Bob", age: 25})
		expected := []person{
			{name: "Alice", age: 30},
			{name: "Charlie", age: 35},
		}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})

	t.Run("preserve order", func(t *testing.T) {
		t.Parallel()
		input := []int{5, 1, 3, 8, 2, 9, 4}
		result := RemoveFromSlice(input, 3, 9)
		expected := []int{5, 1, 8, 2, 4}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})
}
