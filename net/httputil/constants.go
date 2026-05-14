// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httputil

import "time"

// HTTP security-hardened timeouts:
//   - ReadTimeout: 5s (protects against slow-reading clients)
//   - WriteTimeout: 10s (allows time for large metrics payloads)
//   - IdleTimeout: 120s (cleans up idle connections)
//
// References:
//   - https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
//   - https://adam-p.ca/blog/2022/01/golang-http-server-timeouts/
const (
	// DefaultReadTimeout is the recommended timeout for reading the entire request.
	DefaultReadTimeout = 5 * time.Second

	// DefaultWriteTimeout is the recommended timeout for writing the response.
	DefaultWriteTimeout = 10 * time.Second

	// DefaultIdleTimeout is the recommended timeout for idle connections.
	DefaultIdleTimeout = 120 * time.Second
)
