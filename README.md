# go-utils

![go version](https://img.shields.io/github/go-mod/go-version/loicsikidi/go-utils)
[![godoc](https://pkg.go.dev/badge/github.com/loicsikidi/go-utils/v1.svg)](https://pkg.go.dev/github.com/loicsikidi/go-utils)
[![license](https://img.shields.io/badge/license-BSD--3--Clause-blue?style=flat-square)](https://raw.githubusercontent.com/loicsikidi/go-utils/main/LICENSE)

> [!IMPORTANT]
> I plan to use this library strictly for my own projects, so contributions are **closed**.

A collection of utility packages for Go, providing helpers for common tasks across various domains (crypto, network, file system, JSON encoding, etc.).

## Philosophy

This repository follows two core principles:

1. **Minimal dependencies**: The project aims to have the strict minimum of external dependencies, ideally none. This ensures lightweight imports and reduces potential security vulnerabilities.

2. **Consistent naming**: To avoid conflicts with other libraries and ensure consistency, all subpackages must end with the `util` suffix (e.g., `jsonutil`, `httputil`, `fsutil`).

## License

BSD-style license. See the [LICENSE](LICENSE) file for details.
