// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package goutils

// Filter applies a filter function to a slice and returns unique results.
// The filter function fn returns both the transformed value and a boolean indicating if it should be included.
func Filter[T any, S comparable](ts []T, fn func(T) (s S, include bool)) []S {
	ss := make([]S, 0, len(ts))
	seen := make(map[S]struct{}, len(ts))
	for _, t := range ts {
		if s, include := fn(t); include {
			if _, found := seen[s]; !found {
				seen[s] = struct{}{}
				ss = append(ss, s)
			}
		}
	}

	return ss
}

// Map applies a transformation function to each element of a slice and returns a new slice with the results.
func Map[T any, U any](ts []T, fn func(T) U) []U {
	us := make([]U, len(ts))
	for i, t := range ts {
		us[i] = fn(t)
	}
	return us
}

// Reduce applies a function to each element of a slice, accumulating the result.
// It takes an initial accumulator value and a function that combines the accumulator with each element.
func Reduce[T any, U any](ts []T, initial U, fn func(U, T) U) U {
	acc := initial
	for _, t := range ts {
		acc = fn(acc, t)
	}
	return acc
}

// RemoveFromSlice makes a copy of the slice and removes the passed in values from the copy.
func RemoveFromSlice[T comparable](slice []T, toRemove ...T) []T {
	if len(slice) == 0 || len(toRemove) == 0 {
		result := make([]T, len(slice))
		copy(result, slice)
		return result
	}

	removeMap := make(map[T]struct{}, len(toRemove))
	for _, item := range toRemove {
		removeMap[item] = struct{}{}
	}

	result := make([]T, 0, len(slice))
	for _, item := range slice {
		if _, shouldRemove := removeMap[item]; !shouldRemove {
			result = append(result, item)
		}
	}

	return result
}
