// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	goutils "github.com/loicsikidi/go-utils"
)

var (
	// ErrCrlIsExpired is returned when the current time is after the CRL's NextUpdate field.
	ErrCrlIsExpired = errors.New("crl is expired")
	// ErrCrlNotYetValid is returned when the current time is before the CRL's ThisUpdate field.
	ErrCrlNotYetValid = errors.New("crl is not yet valid")
	// ErrUnknownAuthorityError is returned when the CRL signature cannot be verified by any of the provided issuers.
	ErrUnknownAuthorityError = errors.New("crl signed by unknown authority")
	// ErrCrlCannotBeNil is returned when a nil [x509.RevocationList] is provided to [NewCRL].
	ErrCrlCannotBeNil = errors.New("crl cannot be nil")
)

// CRL provides methods for working with X.509 Certificate Revocation Lists.
// It validates CRL time validity, signature verification, and revocation status checks.
type CRL interface {
	// IsValid checks if the CRL is currently valid based on its ThisUpdate and NextUpdate fields.
	IsValid() error
	// Verify checks if the CRL is signed by one of the provided issuer certificates.
	Verify(issuers ...*x509.Certificate) error
	// IsRevoked checks if the given certificate is listed as revoked in the CRL.
	IsRevoked(cert *x509.Certificate) bool
}

type crl struct {
	*x509.RevocationList
}

// NewCRL creates a [CRL] from an [x509.RevocationList] and validates it.
// Returns an error if the revocation list is nil or not currently valid.
func NewCRL(rl *x509.RevocationList) (CRL, error) {
	if rl == nil {
		return nil, ErrCrlCannotBeNil
	}

	c := &crl{RevocationList: rl}

	if err := c.IsValid(); err != nil {
		return nil, err
	}

	return c, nil
}

// MustCRL is like [NewCRL] but panics if the revocation list cannot be created or is invalid.
// It simplifies initialization where errors should not occur.
func MustCRL(rl *x509.RevocationList) CRL {
	c, err := NewCRL(rl)
	if err != nil {
		panic(err)
	}
	return c
}

func (c *crl) IsValid() error {
	now := time.Now()

	if now.After(c.NextUpdate) {
		return ErrCrlIsExpired
	}
	if now.Before(c.ThisUpdate) {
		return ErrCrlNotYetValid
	}
	return nil
}

func (c *crl) Verify(issuers ...*x509.Certificate) error {
	for _, cert := range issuers {
		if err := c.CheckSignatureFrom(cert); err == nil {
			return nil
		}
	}
	return ErrUnknownAuthorityError
}

func (c *crl) IsRevoked(cert *x509.Certificate) bool {
	for _, entry := range c.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true
		}
	}
	return false
}

type CreateCRLConfig struct {
	// NextUpdate specifies the time at which the CRL will no longer be considered valid.
	NextUpdate time.Time
	// Number is the unique identifier for the CRL.
	Number *big.Int
	// PreviousCRL is the previous CRL in the sequence, if any.
	//
	// It is used to automatically increment the CRL number if not explicitly set.
	// In other words, it's an alternative to cfg.Number.
	PreviousCRL *x509.RevocationList
	// RevokedCertificates is the list of certificates that have been revoked.
	RevokedCertificates []x509.RevocationListEntry
}

func (c *CreateCRLConfig) CheckAndSetDefaults() error {
	if c.NextUpdate.IsZero() {
		return fmt.Errorf("nextupdate is required")
	}
	if c.Number == nil {
		if c.PreviousCRL != nil {
			c.Number = new(big.Int).Add(c.PreviousCRL.Number, big.NewInt(1))
		} else {
			return fmt.Errorf("number is required")
		}
	}
	return nil
}

// NewRevocationList creates a new X.509 revocation list based on the provided configuration.
func NewRevocationList(optionalCfg ...CreateCRLConfig) (*x509.RevocationList, error) {
	cfg := goutils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, err
	}

	return &x509.RevocationList{
		Number:                    cfg.Number,
		ThisUpdate:                time.Now(),
		NextUpdate:                cfg.NextUpdate.Add(-1 * time.Minute),
		RevokedCertificateEntries: cfg.RevokedCertificates,
	}, nil
}

// MustRevocationList is like [NewRevocationList] but panics if the revocation list cannot be created or is invalid.
func MustRevocationList(optionalCfg ...CreateCRLConfig) *x509.RevocationList {
	rl, err := NewRevocationList(optionalCfg...)
	if err != nil {
		panic(err)
	}
	return rl
}

// MarshalCRL creates and signs a DER-encoded X.509 certificate revocation list.
// It delegates to [x509.CreateRevocationList] using [crypto/rand.Reader] for entropy.
func MarshalCRL(template *x509.RevocationList, issuer *x509.Certificate, signer crypto.Signer) ([]byte, error) {
	return x509.CreateRevocationList(rand.Reader, template, issuer, signer)
}
