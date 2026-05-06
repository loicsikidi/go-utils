// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package jsonutil

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// JsonCompact compacts the provided JSON byte slice by removing insignificant
// whitespace. It returns the compacted JSON or an error if the input is invalid JSON.
func JsonCompact(b []byte) ([]byte, error) {
	var compactBuf bytes.Buffer
	if err := json.Compact(&compactBuf, b); err != nil {
		return nil, fmt.Errorf("failed to compact JSON: %w", err)
	}
	return compactBuf.Bytes(), nil
}

// MustJsonCompact is like JsonCompact but panics if an error occurs.
// It is intended for use in variable initializations where errors cannot be handled.
func MustJsonCompact(b []byte) []byte {
	compact, err := JsonCompact(b)
	if err != nil {
		panic(err)
	}
	return compact
}
