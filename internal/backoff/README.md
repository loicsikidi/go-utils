# Backoff

A flexible, type-safe retry mechanism with support for multiple backoff strategies.

## Features

- **Multiple Strategies**: Exponential, Linear, and Constant backoff
- **Type-Safe**: Generic implementation works with any return type
- **Context-Aware**: Respects context cancellation
- **Flexible Limits**: Stop retries based on attempt count or elapsed time
- **Jitter Support**: Add randomization to prevent thundering herd
- **Permanent Errors**: Stop retrying immediately for non-transient errors

## Backoff Strategies

### Exponential (Default)

Multiplies the delay by a constant factor after each retry. Best for most use cases.

**Delay progression**: `initial`, `initial×multiplier`, `initial×multiplier²`, ...

**Use when**:
- Making API calls that may be rate-limited
- Retrying operations where load increases failure probability
- You want aggressive backoff to give systems time to recover

**Example**: With `InitialDelay=100ms` and `Multiplier=2.0`:
```
Attempt 1: 100ms
Attempt 2: 200ms
Attempt 3: 400ms
Attempt 4: 800ms
```

### Linear

Adds a constant increment to the delay after each retry. Predictable and gradual.

**Delay progression**: `initial`, `initial+increment`, `initial+2×increment`, ...

**Use when**:
- You need predictable, evenly-spaced retries
- Working with systems that have known, fixed recovery times
- Testing or debugging retry logic

**Example**: With `InitialDelay=100ms` and `Increment=50ms`:
```
Attempt 1: 100ms
Attempt 2: 150ms
Attempt 3: 200ms
Attempt 4: 250ms
```

### Constant

Uses the same delay for all retries. Simple and predictable.

**Delay progression**: `initial`, `initial`, `initial`, ...

**Use when**:
- Polling for a resource that may become available at any time
- Retrying operations with unpredictable failure durations
- You want maximum simplicity

**Example**: With `InitialDelay=200ms`:
```
Attempt 1: 200ms
Attempt 2: 200ms
Attempt 3: 200ms
Attempt 4: 200ms
```

## Usage

### Basic Usage

```go
import "github.com/loicsikidi/go-utils/pkg/backoff"

// With default exponential backoff
result, err := backoff.Retry(ctx, func() (string, error) {
    return makeAPICall()
})
```

### Exponential Backoff

```go
cfg := backoff.Config{
    Strategy:     backoff.Exponential, // Can be omitted (default)
    InitialDelay: 100 * time.Millisecond,
    MaxDelay:     5 * time.Second,
    Multiplier:   2.0,
    MaxRetries:   5,
    Jitter:       true,
}

result, err := backoff.Retry(ctx, func() (*Response, error) {
    return makeHTTPRequest()
}, cfg)
```

### Linear Backoff

```go
cfg := backoff.Config{
    Strategy:     backoff.Linear,
    InitialDelay: 100 * time.Millisecond,
    Increment:    50 * time.Millisecond,
    MaxDelay:     500 * time.Millisecond,
    MaxRetries:   10,
}

data, err := backoff.Retry(ctx, func() ([]byte, error) {
    return fetchData()
}, cfg)
```

### Constant Backoff

```go
cfg := backoff.Config{
    Strategy:     backoff.Constant,
    InitialDelay: 200 * time.Millisecond,
    MaxRetries:   20,
}

status, err := backoff.Retry(ctx, func() (Status, error) {
    return pollStatus()
}, cfg)
```

### Time-Based Limits

```go
cfg := backoff.Config{
    InitialDelay:   100 * time.Millisecond,
    MaxDelay:       2 * time.Second,
    MaxElapsedTime: 30 * time.Second, // Stop after 30s total
}

result, err := backoff.Retry(ctx, func() (*Data, error) {
    return fetchFromAPI()
}, cfg)
```

### Permanent Errors

```go
result, err := backoff.Retry(ctx, func() (User, error) {
    user, err := authenticate()
    if err != nil {
        if isAuthError(err) {
            return User{}, backoff.Permanent(err) // Stop immediately
        }
        return User{}, err // Transient, will retry
    }
    return user, nil
})

// Check if an error is permanent
if backoff.IsPermanent(err) {
    log.Fatal("permanent error, cannot retry")
}
```

## Configuration Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Strategy` | `Strategy` | `Exponential` | Backoff calculation method |
| `InitialDelay` | `time.Duration` | `100ms` | Delay before first retry |
| `MaxDelay` | `time.Duration` | `30s` | Maximum delay between retries |
| `Multiplier` | `float64` | `2.0` | Exponential growth factor |
| `Increment` | `time.Duration` | `100ms` | Linear delay increment |
| `MaxRetries` | `int` | `3` | Maximum retry attempts |
| `MaxElapsedTime` | `time.Duration` | `0` | Total time limit (overrides MaxRetries) |
| `Jitter` | `bool` | `false` | Add ±25% randomization |

## Strategy Comparison

| Scenario | Recommended Strategy | Reason |
|----------|---------------------|--------|
| API rate limits | Exponential | Aggressive backoff reduces load |
| Database reconnection | Exponential | Give DB time to recover |
| Polling for completion | Constant | Resource availability is unpredictable |
| Testing/debugging | Linear | Predictable timing |
| Known recovery time | Linear | Match expected recovery duration |
| Network timeouts | Exponential with jitter | Prevent synchronized retries |

## Design Notes

- **Default behavior**: Exponential backoff with sensible defaults for backward compatibility
- **MaxDelay applies** to Exponential and Linear strategies; ignored for Constant
- **Jitter** adds ±25% randomization to prevent thundering herd
- **Context cancellation** is checked between retries
- **Permanent errors** bypass retry logic immediately
