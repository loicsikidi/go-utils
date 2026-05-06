// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package backoff_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/loicsikidi/go-utils/internal/backoff"
)

func TestConfig_CheckAndSetDefaults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     backoff.Config
		want    backoff.Config
		wantErr bool
	}{
		{
			name: "all defaults",
			cfg:  backoff.Config{},
			want: backoff.Config{
				InitialDelay: 100 * time.Millisecond,
				MaxDelay:     30 * time.Second,
				Multiplier:   2.0,
				MaxRetries:   3,
				Jitter:       false,
			},
			wantErr: false,
		},
		{
			name: "custom values",
			cfg: backoff.Config{
				InitialDelay: 50 * time.Millisecond,
				MaxDelay:     10 * time.Second,
				Multiplier:   1.5,
				MaxRetries:   5,
				Jitter:       true,
			},
			want: backoff.Config{
				InitialDelay: 50 * time.Millisecond,
				MaxDelay:     10 * time.Second,
				Multiplier:   1.5,
				MaxRetries:   5,
				Jitter:       true,
			},
			wantErr: false,
		},
		{
			name: "invalid multiplier gets defaulted",
			cfg: backoff.Config{
				InitialDelay: 100 * time.Millisecond,
				MaxDelay:     5 * time.Second,
				Multiplier:   0.5, // <= 1, should default to 2.0
				MaxRetries:   3,
			},
			want: backoff.Config{
				InitialDelay: 100 * time.Millisecond,
				MaxDelay:     5 * time.Second,
				Multiplier:   2.0,
				MaxRetries:   3,
				Jitter:       false,
			},
			wantErr: false,
		},
		{
			name: "MaxDelay < InitialDelay returns error",
			cfg: backoff.Config{
				InitialDelay: 5 * time.Second,
				MaxDelay:     1 * time.Second,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.cfg.CheckAndSetDefaults()
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckAndSetDefaults() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if tt.cfg.InitialDelay != tt.want.InitialDelay {
				t.Errorf("InitialDelay = %v, want %v", tt.cfg.InitialDelay, tt.want.InitialDelay)
			}
			if tt.cfg.MaxDelay != tt.want.MaxDelay {
				t.Errorf("MaxDelay = %v, want %v", tt.cfg.MaxDelay, tt.want.MaxDelay)
			}
			if tt.cfg.Multiplier != tt.want.Multiplier {
				t.Errorf("Multiplier = %v, want %v", tt.cfg.Multiplier, tt.want.Multiplier)
			}
			if tt.cfg.MaxRetries != tt.want.MaxRetries {
				t.Errorf("MaxRetries = %v, want %v", tt.cfg.MaxRetries, tt.want.MaxRetries)
			}
			if tt.cfg.Jitter != tt.want.Jitter {
				t.Errorf("Jitter = %v, want %v", tt.cfg.Jitter, tt.want.Jitter)
			}
		})
	}
}

func TestRetry_Success(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := backoff.Config{
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
		Multiplier:   2.0,
		MaxRetries:   3,
	}

	result, err := backoff.Retry(ctx, func() (string, error) {
		return "success", nil
	}, cfg)

	if err != nil {
		t.Errorf("Retry() error = %v, want nil", err)
	}
	if result != "success" {
		t.Errorf("Retry() result = %v, want 'success'", result)
	}
}

func TestRetry_SuccessAfterRetries(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := backoff.Config{
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
		Multiplier:   2.0,
		MaxRetries:   5,
	}

	attempts := 0
	result, err := backoff.Retry(ctx, func() (int, error) {
		attempts++
		if attempts < 3 {
			return 0, errors.New("temporary error")
		}
		return 42, nil
	}, cfg)

	if err != nil {
		t.Errorf("Retry() error = %v, want nil", err)
	}
	if result != 42 {
		t.Errorf("Retry() result = %v, want 42", result)
	}
	if attempts != 3 {
		t.Errorf("attempts = %v, want 3", attempts)
	}
}

func TestRetry_MaxRetriesExceeded(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := backoff.Config{
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
		Multiplier:   2.0,
		MaxRetries:   2,
	}

	attempts := 0
	expectedErr := errors.New("persistent error")

	result, err := backoff.Retry(ctx, func() (string, error) {
		attempts++
		return "", expectedErr
	}, cfg)

	if err == nil {
		t.Error("Retry() error = nil, want error")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("Retry() error = %v, want %v", err, expectedErr)
	}
	if result != "" {
		t.Errorf("Retry() result = %v, want empty string", result)
	}
	// MaxRetries=2 means 3 total attempts (initial + 2 retries)
	if attempts != 3 {
		t.Errorf("attempts = %v, want 3", attempts)
	}
}

func TestRetry_ContextCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cfg := backoff.Config{
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   2.0,
		MaxRetries:   5,
	}

	attempts := 0
	done := make(chan struct{})

	go func() {
		_, err := backoff.Retry(ctx, func() (string, error) {
			attempts++
			return "", errors.New("error")
		}, cfg)

		if !errors.Is(err, context.Canceled) {
			t.Errorf("Retry() error = %v, want context.Canceled", err)
		}
		close(done)
	}()

	// Cancel after a short delay to allow at least one retry
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Retry() did not respect context cancellation")
	}
}

func TestRetry_DelayProgression(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := backoff.Config{
		InitialDelay: 50 * time.Millisecond,
		MaxDelay:     500 * time.Millisecond,
		Multiplier:   2.0,
		MaxRetries:   3,
		Jitter:       false, // Disable jitter for predictable delays
	}

	attempts := 0
	timestamps := []time.Time{}

	_, err := backoff.Retry(ctx, func() (string, error) {
		attempts++
		timestamps = append(timestamps, time.Now())
		return "", errors.New("error")
	}, cfg)

	if err == nil {
		t.Fatal("Retry() error = nil, want error")
	}

	// Should have MaxRetries+1 attempts
	if len(timestamps) != 4 {
		t.Fatalf("got %d attempts, want 4", len(timestamps))
	}

	// Check delays between attempts (approximately)
	// Delay 1: ~50ms, Delay 2: ~100ms, Delay 3: ~200ms
	delays := []time.Duration{
		timestamps[1].Sub(timestamps[0]),
		timestamps[2].Sub(timestamps[1]),
		timestamps[3].Sub(timestamps[2]),
	}

	// Allow 20ms tolerance
	expectedDelays := []time.Duration{50 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond}
	for i, delay := range delays {
		if delay < expectedDelays[i]-20*time.Millisecond || delay > expectedDelays[i]+20*time.Millisecond {
			t.Errorf("delay[%d] = %v, want approximately %v", i, delay, expectedDelays[i])
		}
	}
}

func TestRetry_Jitter(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := backoff.Config{
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   2.0,
		MaxRetries:   3,
		Jitter:       true,
	}

	attempts := 0
	timestamps := []time.Time{}

	_, err := backoff.Retry(ctx, func() (string, error) {
		attempts++
		timestamps = append(timestamps, time.Now())
		return "", errors.New("error")
	}, cfg)

	if err == nil {
		t.Fatal("Retry() error = nil, want error")
	}

	if len(timestamps) != 4 {
		t.Fatalf("got %d attempts, want 4", len(timestamps))
	}

	// With jitter, delays should vary but still be within expected range
	// First delay: 75ms-125ms (100ms ± 25%)
	delay1 := timestamps[1].Sub(timestamps[0])
	if delay1 < 70*time.Millisecond || delay1 > 130*time.Millisecond {
		t.Errorf("delay1 = %v, want between 75ms and 125ms (with tolerance)", delay1)
	}

	// Second delay: 150ms-250ms (200ms ± 25%)
	delay2 := timestamps[2].Sub(timestamps[1])
	if delay2 < 140*time.Millisecond || delay2 > 260*time.Millisecond {
		t.Errorf("delay2 = %v, want between 150ms and 250ms (with tolerance)", delay2)
	}
}

func TestRetry_PermanentError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := backoff.Config{
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
		Multiplier:   2.0,
		MaxRetries:   5,
	}

	attempts := 0
	permanentErr := errors.New("auth failed")

	result, err := backoff.Retry(ctx, func() (string, error) {
		attempts++
		return "", backoff.Permanent(permanentErr)
	}, cfg)

	if err == nil {
		t.Fatal("Retry() error = nil, want error")
	}
	if !errors.Is(err, permanentErr) {
		t.Errorf("Retry() error = %v, want %v", err, permanentErr)
	}
	if result != "" {
		t.Errorf("Retry() result = %v, want empty string", result)
	}
	// Should stop immediately on permanent error
	if attempts != 1 {
		t.Errorf("attempts = %v, want 1 (immediate stop on permanent error)", attempts)
	}
}

func TestRetry_WithDefaultConfig(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	result, err := backoff.Retry(ctx, func() (string, error) {
		return "default", nil
	}) // No config provided

	if err != nil {
		t.Errorf("Retry() error = %v, want nil", err)
	}
	if result != "default" {
		t.Errorf("Retry() result = %v, want 'default'", result)
	}
}

func TestRetry_DifferentTypes(t *testing.T) {
	t.Parallel()

	type customStruct struct {
		Value string
		Count int
	}

	tests := []struct {
		name string
		op   func() (any, error)
		want any
	}{
		{
			name: "string type",
			op: func() (any, error) {
				return backoff.Retry(context.Background(), func() (string, error) {
					return "test", nil
				})
			},
			want: "test",
		},
		{
			name: "int type",
			op: func() (any, error) {
				return backoff.Retry(context.Background(), func() (int, error) {
					return 123, nil
				})
			},
			want: 123,
		},
		{
			name: "struct type",
			op: func() (any, error) {
				return backoff.Retry(context.Background(), func() (customStruct, error) {
					return customStruct{Value: "hello", Count: 42}, nil
				})
			},
			want: customStruct{Value: "hello", Count: 42},
		},
		{
			name: "pointer type",
			op: func() (any, error) {
				return backoff.Retry(context.Background(), func() (*customStruct, error) {
					return &customStruct{Value: "ptr", Count: 99}, nil
				})
			},
			want: &customStruct{Value: "ptr", Count: 99},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := tt.op()
			if err != nil {
				t.Errorf("Retry() error = %v, want nil", err)
			}

			// Type-specific comparison
			switch v := result.(type) {
			case string:
				if v != tt.want.(string) {
					t.Errorf("Retry() = %v, want %v", v, tt.want)
				}
			case int:
				if v != tt.want.(int) {
					t.Errorf("Retry() = %v, want %v", v, tt.want)
				}
			case customStruct:
				want := tt.want.(customStruct)
				if v.Value != want.Value || v.Count != want.Count {
					t.Errorf("Retry() = %+v, want %+v", v, want)
				}
			case *customStruct:
				want := tt.want.(*customStruct)
				if v.Value != want.Value || v.Count != want.Count {
					t.Errorf("Retry() = %+v, want %+v", v, want)
				}
			}
		})
	}
}

func TestIsPermanent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "permanent error",
			err:  backoff.Permanent(errors.New("test error")),
			want: true,
		},
		{
			name: "regular error",
			err:  errors.New("test error"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "wrapped permanent error",
			err:  fmt.Errorf("wrapped: %w", backoff.Permanent(errors.New("test"))),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := backoff.IsPermanent(tt.err)
			if got != tt.want {
				t.Errorf("IsPermanent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRetry_MaxElapsedTime(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := backoff.Config{
		InitialDelay:   50 * time.Millisecond,
		MaxDelay:       200 * time.Millisecond,
		Multiplier:     2.0,
		MaxElapsedTime: 300 * time.Millisecond,
		Jitter:         false,
	}

	attempts := 0
	startTime := time.Now()

	_, err := backoff.Retry(ctx, func() (string, error) {
		attempts++
		return "", errors.New("error")
	}, cfg)

	elapsed := time.Since(startTime)

	if err == nil {
		t.Fatal("Retry() error = nil, want error")
	}

	// Should respect MaxElapsedTime (300ms) with some tolerance
	if elapsed < 250*time.Millisecond || elapsed > 400*time.Millisecond {
		t.Errorf("elapsed time = %v, want approximately 300ms", elapsed)
	}

	// Should have made multiple attempts but stopped due to time limit
	if attempts < 2 {
		t.Errorf("attempts = %v, want at least 2", attempts)
	}
}

func TestRetry_MaxElapsedTimeTakesPrecedence(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := backoff.Config{
		InitialDelay:   50 * time.Millisecond,
		MaxDelay:       100 * time.Millisecond,
		Multiplier:     2.0,
		MaxRetries:     10,                     // High retry count
		MaxElapsedTime: 200 * time.Millisecond, // But low time limit
		Jitter:         false,
	}

	attempts := 0
	startTime := time.Now()

	_, err := backoff.Retry(ctx, func() (string, error) {
		attempts++
		return "", errors.New("error")
	}, cfg)

	elapsed := time.Since(startTime)

	if err == nil {
		t.Fatal("Retry() error = nil, want error")
	}

	// Should respect MaxElapsedTime, not MaxRetries
	if elapsed < 150*time.Millisecond || elapsed > 300*time.Millisecond {
		t.Errorf("elapsed time = %v, want approximately 200ms", elapsed)
	}

	// Should not reach MaxRetries (10), stopped by time
	if attempts >= 10 {
		t.Errorf("attempts = %v, want < 10 (stopped by time, not retries)", attempts)
	}
}

func TestRetry_LinearStrategy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := backoff.Config{
		Strategy:     backoff.Linear,
		InitialDelay: 50 * time.Millisecond,
		Increment:    50 * time.Millisecond,
		MaxDelay:     500 * time.Millisecond,
		MaxRetries:   3,
		Jitter:       false,
	}

	attempts := 0
	timestamps := []time.Time{}

	_, err := backoff.Retry(ctx, func() (string, error) {
		attempts++
		timestamps = append(timestamps, time.Now())
		return "", errors.New("error")
	}, cfg)

	if err == nil {
		t.Fatal("Retry() error = nil, want error")
	}

	if len(timestamps) != 4 {
		t.Fatalf("got %d attempts, want 4", len(timestamps))
	}

	// Check linear delay progression: 50ms, 100ms, 150ms
	delays := []time.Duration{
		timestamps[1].Sub(timestamps[0]),
		timestamps[2].Sub(timestamps[1]),
		timestamps[3].Sub(timestamps[2]),
	}

	expectedDelays := []time.Duration{50 * time.Millisecond, 100 * time.Millisecond, 150 * time.Millisecond}
	for i, delay := range delays {
		if delay < expectedDelays[i]-20*time.Millisecond || delay > expectedDelays[i]+20*time.Millisecond {
			t.Errorf("delay[%d] = %v, want approximately %v", i, delay, expectedDelays[i])
		}
	}
}

func TestRetry_LinearStrategy_WithMaxDelay(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := backoff.Config{
		Strategy:     backoff.Linear,
		InitialDelay: 50 * time.Millisecond,
		Increment:    100 * time.Millisecond,
		MaxDelay:     120 * time.Millisecond,
		MaxRetries:   4,
		Jitter:       false,
	}

	attempts := 0
	timestamps := []time.Time{}

	_, err := backoff.Retry(ctx, func() (string, error) {
		attempts++
		timestamps = append(timestamps, time.Now())
		return "", errors.New("error")
	}, cfg)

	if err == nil {
		t.Fatal("Retry() error = nil, want error")
	}

	// Check that delays are capped at MaxDelay
	// Expected: 50ms, 120ms (capped), 120ms (capped), 120ms (capped)
	delays := []time.Duration{
		timestamps[1].Sub(timestamps[0]),
		timestamps[2].Sub(timestamps[1]),
		timestamps[3].Sub(timestamps[2]),
		timestamps[4].Sub(timestamps[3]),
	}

	expectedDelays := []time.Duration{
		50 * time.Millisecond,
		120 * time.Millisecond,
		120 * time.Millisecond,
		120 * time.Millisecond,
	}

	for i, delay := range delays {
		if delay < expectedDelays[i]-20*time.Millisecond || delay > expectedDelays[i]+20*time.Millisecond {
			t.Errorf("delay[%d] = %v, want approximately %v", i, delay, expectedDelays[i])
		}
	}
}

func TestRetry_ConstantStrategy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := backoff.Config{
		Strategy:     backoff.Constant,
		InitialDelay: 100 * time.Millisecond,
		MaxRetries:   3,
		Jitter:       false,
	}

	attempts := 0
	timestamps := []time.Time{}

	_, err := backoff.Retry(ctx, func() (string, error) {
		attempts++
		timestamps = append(timestamps, time.Now())
		return "", errors.New("error")
	}, cfg)

	if err == nil {
		t.Fatal("Retry() error = nil, want error")
	}

	if len(timestamps) != 4 {
		t.Fatalf("got %d attempts, want 4", len(timestamps))
	}

	// Check constant delay: 100ms, 100ms, 100ms
	delays := []time.Duration{
		timestamps[1].Sub(timestamps[0]),
		timestamps[2].Sub(timestamps[1]),
		timestamps[3].Sub(timestamps[2]),
	}

	expectedDelay := 100 * time.Millisecond
	for i, delay := range delays {
		if delay < expectedDelay-20*time.Millisecond || delay > expectedDelay+20*time.Millisecond {
			t.Errorf("delay[%d] = %v, want approximately %v", i, delay, expectedDelay)
		}
	}
}

func TestRetry_ConstantStrategy_IgnoresMaxDelay(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := backoff.Config{
		Strategy:     backoff.Constant,
		InitialDelay: 150 * time.Millisecond,
		MaxDelay:     50 * time.Millisecond, // Should be ignored for Constant
		MaxRetries:   2,
		Jitter:       false,
	}

	attempts := 0
	timestamps := []time.Time{}

	_, err := backoff.Retry(ctx, func() (string, error) {
		attempts++
		timestamps = append(timestamps, time.Now())
		return "", errors.New("error")
	}, cfg)

	if err == nil {
		t.Fatal("Retry() error = nil, want error")
	}

	// All delays should be InitialDelay, MaxDelay is ignored
	delays := []time.Duration{
		timestamps[1].Sub(timestamps[0]),
		timestamps[2].Sub(timestamps[1]),
	}

	expectedDelay := 150 * time.Millisecond
	for i, delay := range delays {
		if delay < expectedDelay-20*time.Millisecond || delay > expectedDelay+20*time.Millisecond {
			t.Errorf("delay[%d] = %v, want approximately %v (MaxDelay should be ignored)", i, delay, expectedDelay)
		}
	}
}

func TestConfig_CheckAndSetDefaults_Strategies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     backoff.Config
		want    backoff.Config
		wantErr bool
	}{
		{
			name: "exponential with defaults",
			cfg: backoff.Config{
				Strategy: backoff.Exponential,
			},
			want: backoff.Config{
				Strategy:     backoff.Exponential,
				InitialDelay: 100 * time.Millisecond,
				MaxDelay:     30 * time.Second,
				Multiplier:   2.0,
				MaxRetries:   3,
			},
		},
		{
			name: "linear with defaults",
			cfg: backoff.Config{
				Strategy: backoff.Linear,
			},
			want: backoff.Config{
				Strategy:     backoff.Linear,
				InitialDelay: 100 * time.Millisecond,
				MaxDelay:     30 * time.Second,
				Increment:    100 * time.Millisecond,
				MaxRetries:   3,
			},
		},
		{
			name: "constant with defaults",
			cfg: backoff.Config{
				Strategy: backoff.Constant,
			},
			want: backoff.Config{
				Strategy:     backoff.Constant,
				InitialDelay: 100 * time.Millisecond,
				MaxDelay:     30 * time.Second,
				MaxRetries:   3,
			},
		},
		{
			name: "linear with custom increment",
			cfg: backoff.Config{
				Strategy:  backoff.Linear,
				Increment: 50 * time.Millisecond,
			},
			want: backoff.Config{
				Strategy:     backoff.Linear,
				InitialDelay: 100 * time.Millisecond,
				MaxDelay:     30 * time.Second,
				Increment:    50 * time.Millisecond,
				MaxRetries:   3,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.cfg.CheckAndSetDefaults()
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckAndSetDefaults() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			if tt.cfg.Strategy != tt.want.Strategy {
				t.Errorf("Strategy = %v, want %v", tt.cfg.Strategy, tt.want.Strategy)
			}
			if tt.cfg.InitialDelay != tt.want.InitialDelay {
				t.Errorf("InitialDelay = %v, want %v", tt.cfg.InitialDelay, tt.want.InitialDelay)
			}
			if tt.cfg.MaxDelay != tt.want.MaxDelay {
				t.Errorf("MaxDelay = %v, want %v", tt.cfg.MaxDelay, tt.want.MaxDelay)
			}
			if tt.cfg.MaxRetries != tt.want.MaxRetries {
				t.Errorf("MaxRetries = %v, want %v", tt.cfg.MaxRetries, tt.want.MaxRetries)
			}

			// Strategy-specific checks
			switch tt.cfg.Strategy {
			case backoff.Exponential:
				if tt.cfg.Multiplier != tt.want.Multiplier {
					t.Errorf("Multiplier = %v, want %v", tt.cfg.Multiplier, tt.want.Multiplier)
				}
			case backoff.Linear:
				if tt.cfg.Increment != tt.want.Increment {
					t.Errorf("Increment = %v, want %v", tt.cfg.Increment, tt.want.Increment)
				}
			}
		})
	}
}
