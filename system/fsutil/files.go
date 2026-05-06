// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fsutil

import (
	"fmt"
	"io"
	"os"

	goutils "github.com/loicsikidi/go-utils"
)

const (
	// DefaultMaxFileSize is the default maximum file size for [ReadFileSecure] (5 MiB).
	DefaultMaxFileSize int64 = 5 * 1024 * 1024
)

// FileExists checks if a file exists and is not a directory.
func FileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// DirExists checks if a directory exists.
func DirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// ReadFile reads the content of a file with a maximum size limit.
//
// If filename is "-", reads from stdin.
// Default maximum size is [DefaultMaxFileSize], but can be overridden by providing a custom maxSize in bytes.
func ReadFile(filename string, optionalMaxSize ...int64) ([]byte, error) {
	maxSize := goutils.OptionalArgWithDefault(optionalMaxSize, DefaultMaxFileSize)
	var reader io.Reader
	if filename == "-" {
		reader = os.Stdin
	} else {
		file, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		reader = file
	}

	data, err := io.ReadAll(io.LimitReader(reader, maxSize+1))
	if err != nil {
		return nil, err
	}

	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("file too large: exceeds %d bytes", maxSize)
	}

	return data, nil
}
