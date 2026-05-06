// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httputil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	goutils "github.com/loicsikidi/go-utils"
	"github.com/loicsikidi/go-utils/internal/backoff"
)

var (
	ErrHTTPGetTooLarge = errors.New("downloaded content exceeds maximum allowed size")
	ErrHTTPGetError    = errors.New("error during HTTP GET request")
)

const (
	maxRetries           = 3
	maxHTTPGetSize int64 = 5 * 1024 * 1024 // 5 MiB
)

// DefaultBackoffConfig holds the default exponential backoff configuration for HTTP retries.
// Can be modified for testing purposes.
var DefaultBackoffConfig = &backoff.Config{
	Strategy:     backoff.Exponential,
	InitialDelay: 100 * time.Millisecond,
	MaxDelay:     500 * time.Millisecond,
	Multiplier:   2.0,
	MaxRetries:   maxRetries,
	Jitter:       true,
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config holds the configuration for HttpGET requests.
type Config struct {
	// MaxSize is the maximum allowed size for the HTTP GET response body.
	MaxSize int64
	// Backoff is the backoff configuration for retries.
	Backoff *backoff.Config
}

// CheckAndSetDefault validates the configuration and sets default values.
func (c *Config) CheckAndSetDefaults() error {
	if c.MaxSize == 0 {
		c.MaxSize = maxHTTPGetSize
	}
	if c.Backoff == nil {
		c.Backoff = DefaultBackoffConfig
	}
	return nil
}

// HttpGET performs an HTTP GET request with automatic retries and response size validation.
//
// The function implements exponential backoff retry logic for transient failures (5xx errors)
// and validates the response size to prevent downloading excessively large content.
//
// Retry behavior:
//   - Transient errors (5xx server errors) are automatically retried with exponential backoff
//   - Permanent errors (4xx client errors, network errors) fail immediately without retry
//   - The retry configuration can be customized via [Config.Backoff]
//   - Default: 3 retries with exponential backoff (100ms initial, 500ms max, 2.0 multiplier)
//
// Size validation:
//   - Response size is checked against [Config.MaxSize] (default: 5 MiB)
//   - Validation occurs both via Content-Length header and actual content read
//   - Requests exceeding the size limit return [ErrHTTPGetTooLarge]
//
// Error handling:
//   - Returns [ErrHTTPGetError] for HTTP errors (4xx, 5xx after retries)
//   - Returns [ErrHTTPGetTooLarge] for oversized responses
//   - Returns context errors (context.Canceled, context.DeadlineExceeded) directly
//   - Returns network errors directly
//
// Example:
//
//	// Using default configuration
//	data, err := HttpGET(ctx, nil, "https://example.com/data.json")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// With custom configuration
//	cfg := Config{
//	    MaxSize: 1024 * 1024, // 1 MiB limit
//	    Backoff: &backoff.Config{
//	        Strategy:     backoff.Exponential,
//	        InitialDelay: 50 * time.Millisecond,
//	        MaxRetries:   5,
//	    },
//	}
//	data, err := HttpGET(ctx, customClient, "https://example.com/data.json", cfg)
func HttpGET(ctx context.Context, client HTTPClient, url string, optionalCfg ...Config) ([]byte, error) {
	cfg := goutils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, err
	}

	c := client
	if c == nil {
		c = http.DefaultClient
	}

	var lastStatusCode int
	operation := func() ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, backoff.Permanent(err)
		}

		res, err := c.Do(req)
		if err != nil {
			return nil, backoff.Permanent(err)
		}
		defer res.Body.Close() //nolint:errcheck

		lastStatusCode = res.StatusCode

		if is5xx(res.StatusCode) {
			return nil, fmt.Errorf("failed to download from %s: HTTP %d", url, res.StatusCode)
		}

		if res.StatusCode != http.StatusOK {
			err := fmt.Errorf("failed to download from %s: HTTP %d", url, res.StatusCode)
			return nil, backoff.Permanent(fmt.Errorf("%w: %v", ErrHTTPGetError, err))
		}

		data, err := readAndValidateResponse(res, url, cfg.MaxSize)
		if err != nil {
			return nil, backoff.Permanent(err)
		}
		return data, nil
	}

	body, err := backoff.Retry(ctx, operation, *cfg.Backoff)
	if err != nil {
		if backoff.IsPermanent(err) {
			// Unwrap permanent errors to get the original error
			err = errors.Unwrap(err)
		}

		// Return context errors directly
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}

		// Return errors already wrapped with sentinel errors
		if errors.Is(err, ErrHTTPGetError) || errors.Is(err, ErrHTTPGetTooLarge) {
			return nil, err
		}

		// Check if this is a retryable 5xx error that exhausted retries
		// These need to be wrapped with ErrHTTPGetError
		if is5xx(lastStatusCode) {
			return nil, fmt.Errorf("%w: %v", ErrHTTPGetError, err)
		}

		// All other errors (client, network, etc.) return as-is
		return nil, err
	}

	return body, nil
}

// readAndValidateResponse reads the response body and validates its size.
func readAndValidateResponse(res *http.Response, url string, maxSize int64) ([]byte, error) {
	if header := res.Header.Get("Content-Length"); header != "" {
		length, err := strconv.ParseInt(header, 10, 0)
		if err != nil {
			return nil, err
		}
		if err := validateResponseSize(url, length, maxSize); err != nil {
			return nil, err
		}
	}

	// Although the size has been checked above, use a LimitReader in case
	// the reported size is inaccurate.
	data, err := io.ReadAll(io.LimitReader(res.Body, maxSize+1))
	if err != nil {
		return nil, err
	}

	if err := validateResponseSize(url, int64(len(data)), maxSize); err != nil {
		return nil, err
	}
	return data, nil
}

// validateResponseSize checks if the content size exceeds the maximum allowed size.
// It returns an error wrapped with [ErrHTTPGetTooLarge] if the size is too large.
func validateResponseSize(url string, size, maxSize int64) error {
	if size > maxSize {
		err := fmt.Errorf("download failed for %s, length %d is larger than expected %d", url, size, maxSize)
		return fmt.Errorf("%w: %v", ErrHTTPGetTooLarge, err)
	}
	return nil
}

func is5xx(statusCode int) bool {
	return statusCode >= 500 && statusCode < 600
}
