// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package backoff

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	goutils "github.com/loicsikidi/go-utils"
)

const (
	defaultInitialDelay = 100 * time.Millisecond
	defaultMaxDelay     = 30 * time.Second
	defaultMultiplier   = 2.0
	defaultMaxRetries   = 3
	defaultIncrement    = 100 * time.Millisecond
)

// Strategy defines the backoff delay calculation method.
type Strategy int

const (
	// UnspecifiedStrategy is the zero value and defaults to [Exponential].
	UnspecifiedStrategy Strategy = iota
	// Exponential multiplies the delay by [Config.Multiplier] after each retry.
	// Delay progression: initial, initial*multiplier, initial*multiplier², ...
	Exponential
	// Linear adds [Config.Increment] to the delay after each retry.
	// Delay progression: initial, initial+increment, initial+2*increment, ...
	Linear
	// Constant uses the same delay for all retries.
	// Delay progression: initial, initial, initial, ...
	Constant
)

// String returns the string representation of the strategy.
func (s Strategy) String() string {
	switch s {
	case UnspecifiedStrategy:
		return "unspecified"
	case Exponential:
		return "exponential"
	case Linear:
		return "linear"
	case Constant:
		return "constant"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// Config holds the backoff configuration.
//
// Default values (when fields are zero/unset):
//   - Strategy: Exponential
//   - InitialDelay: 100ms
//   - MaxDelay: 30s
//   - Multiplier: 2.0 (Exponential only)
//   - Increment: 100ms (Linear only)
//   - MaxRetries: 3
//   - MaxElapsedTime: 0 (disabled, uses MaxRetries instead)
//   - Jitter: false
//
// Note: MaxElapsedTime and MaxRetries are mutually exclusive.
// If MaxElapsedTime > 0, it takes precedence over MaxRetries.
//
// Strategy-specific fields:
//   - Exponential: uses Multiplier
//   - Linear: uses Increment
//   - Constant: uses only InitialDelay
type Config struct {
	Strategy       Strategy      // Backoff strategy (default: Exponential)
	InitialDelay   time.Duration // Initial delay before the first retry
	MaxDelay       time.Duration // Maximum delay between retries
	Multiplier     float64       // Multiplication factor for Exponential (typically 2.0)
	Increment      time.Duration // Delay increment for Linear
	MaxRetries     int           // Maximum number of retries (ignored if MaxElapsedTime > 0)
	MaxElapsedTime time.Duration // Maximum total time since first attempt (takes precedence if > 0)
	Jitter         bool          // Enable randomization of delays
}

// CheckAndSetDefaults validates the configuration and sets default values.
func (c *Config) CheckAndSetDefaults() error {
	if c.InitialDelay <= 0 {
		c.InitialDelay = defaultInitialDelay
	}
	if c.MaxDelay <= 0 {
		c.MaxDelay = defaultMaxDelay
	}
	if c.MaxRetries == 0 {
		c.MaxRetries = defaultMaxRetries
	}

	if c.Strategy == UnspecifiedStrategy {
		c.Strategy = Exponential
	}

	// Strategy-specific defaults and validation
	switch c.Strategy {
	case Exponential:
		if c.Multiplier <= 1 {
			c.Multiplier = defaultMultiplier
		}
	case Linear:
		if c.Increment <= 0 {
			c.Increment = defaultIncrement
		}
	case Constant:
		// No additional fields needed, MaxDelay is not used
	default:
		return fmt.Errorf("invalid strategy: %d", c.Strategy)
	}

	// MaxDelay validation (not applicable for Constant strategy)
	if c.Strategy != Constant && c.MaxDelay < c.InitialDelay {
		return fmt.Errorf("MaxDelay (%v) must be >= InitialDelay (%v)", c.MaxDelay, c.InitialDelay)
	}
	return nil
}

// Operation represents an operation that returns a value of type T and an error.
type Operation[T any] func() (T, error)

// Retry executes the given operation with exponential backoff.
// The config parameter is optional; if omitted, default values are used.
//
// Example with custom config:
//
//	cfg := backoff.Config{
//	    InitialDelay: 100 * time.Millisecond,
//	    MaxDelay:     5 * time.Second,
//	    Multiplier:   2.0,
//	    MaxRetries:   5,
//	    Jitter:       true,
//	}
//
//	result, err := backoff.Retry(ctx, func() (*Response, error) {
//	    return makeHTTPRequest()
//	}, cfg)
//
// Example with default config:
//
//	data, err := backoff.Retry(ctx, func() ([]byte, error) {
//	    return fetchData()
//	})
//
// Example with time-based limit:
//
//	cfg := backoff.Config{
//	    InitialDelay:   100 * time.Millisecond,
//	    MaxDelay:       2 * time.Second,
//	    MaxElapsedTime: 10 * time.Second, // Stop after 10s total
//	}
//
//	result, err := backoff.Retry(ctx, func() (*Data, error) {
//	    return fetchFromAPI()
//	}, cfg)
//
// Example with permanent error:
//
//	result, err := backoff.Retry(ctx, func() (string, error) {
//	    resp, err := doSomething()
//	    if err != nil {
//	        if isAuthError(err) {
//	            return "", backoff.Permanent(err) // stop retrying
//	        }
//	        return "", err // transient, will retry
//	    }
//	    return resp, nil
//	})
func Retry[T any](ctx context.Context, op Operation[T], optionalCfg ...Config) (T, error) {
	cfg := goutils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefaults(); err != nil {
		var zero T
		return zero, fmt.Errorf("invalid config: %w", err)
	}

	var lastErr error
	currentDelay := cfg.InitialDelay
	startTime := time.Now()
	attempt := 0

	for {
		result, err := op()
		if err == nil {
			return result, nil
		}

		lastErr = err

		var permErr *permanentError
		if errors.As(err, &permErr) {
			var zero T
			return zero, err
		}

		// Check if we should retry based on time or attempt limit
		if cfg.MaxElapsedTime > 0 {
			// Time-based limit takes precedence
			if time.Since(startTime) >= cfg.MaxElapsedTime {
				break
			}
		} else {
			// Retry-based limit
			if attempt >= cfg.MaxRetries {
				break
			}
		}

		attempt++

		delay := currentDelay
		if cfg.Jitter {
			// TODO: consider using a better random source
			// Add ±25% jitter
			delay = time.Duration(float64(delay) * (0.75 + rand.Float64()*0.5))
		}

		// Wait for the delay or context cancellation
		select {
		case <-time.After(delay):
			// Continue to next attempt
		case <-ctx.Done():
			var zero T
			return zero, ctx.Err()
		}

		// Calculate next delay based on strategy
		switch cfg.Strategy {
		case Exponential:
			currentDelay = min(time.Duration(float64(currentDelay)*cfg.Multiplier), cfg.MaxDelay)
		case Linear:
			currentDelay = min(currentDelay+cfg.Increment, cfg.MaxDelay)
		case Constant:
			// Keep currentDelay unchanged
		}
	}

	var zero T
	return zero, lastErr
}

// Permanent wraps an error to signal that retries should stop immediately.
// Use this when the error is not transient and retrying won't help.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &permanentError{err: err}
}

// IsPermanent reports whether err is a permanent error created by [Permanent].
func IsPermanent(err error) bool {
	var permErr *permanentError
	return errors.As(err, &permErr)
}

type permanentError struct {
	err error
}

func (e *permanentError) Error() string {
	return e.err.Error()
}

func (e *permanentError) Unwrap() error {
	return e.err
}
