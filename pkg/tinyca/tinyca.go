// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tinyca provides a minimal PKI (Public Key Infrastructure) for testing.
//
// It creates a Root CA and an Intermediate CA with an HTTP server to expose
// their Certificate Revocation Lists (CRLs). This package is designed for testing
// purposes and supports running multiple instances in parallel without conflicts.
package tinyca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"

	goutils "github.com/loicsikidi/go-utils"
)

const (
	DefaultValidity     = time.Hour
	DefaultOrganization = "tinyca ACME CA"
)

// CA represents a minimal PKI with a Root CA and an Intermediate CA.
type CA struct {
	Root            *x509.Certificate
	RootKey         crypto.Signer
	Intermediate    *x509.Certificate
	IntermediateKey crypto.Signer
}

// Config configures the CA creation.
type Config struct {
	// Validity is the validity period for the certificates.
	// If not set, defaults to 1 hour.
	Validity time.Duration
	// Organization is the organization name for the certificates.
	// If not set, defaults to "tinyca ACME".
	Organization string
}

// CheckAndSetDefaults validates and sets default values for the config.
func (c *Config) CheckAndSetDefaults() error {
	if c.Validity == 0 {
		c.Validity = DefaultValidity
	}
	if c.Organization == "" {
		c.Organization = DefaultOrganization
	}
	return nil
}

// New creates a new CA with a Root CA and an Intermediate CA.
func New(optionalCfg ...Config) (*CA, error) {
	cfg := goutils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	now := time.Now()
	notBefore := now.Add(-time.Minute) // Start 1 minute in the past to avoid clock skew issues
	notAfter := now.Add(cfg.Validity)

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Root CA",
			Organization: []string{cfg.Organization},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("create root certificate: %w", err)
	}

	rootCert, err := x509.ParseCertificate(rootCertDER)
	if err != nil {
		return nil, fmt.Errorf("parse root certificate: %w", err)
	}

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate intermediate key: %w", err)
	}

	intTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Intermediate CA",
			Organization: []string{cfg.Organization},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	intCertDER, err := x509.CreateCertificate(rand.Reader, intTemplate, rootCert, &intKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("create intermediate certificate: %w", err)
	}

	intCert, err := x509.ParseCertificate(intCertDER)
	if err != nil {
		return nil, fmt.Errorf("parse intermediate certificate: %w", err)
	}

	return &CA{
		Root:            rootCert,
		RootKey:         rootKey,
		Intermediate:    intCert,
		IntermediateKey: intKey,
	}, nil
}

func Must(optionalCfg ...Config) *CA {
	ca, err := New(optionalCfg...)
	if err != nil {
		panic(err)
	}
	return ca
}

// Generate issues a new leaf certificate signed by the Intermediate CA.
func (c *CA) Generate(req CertificateRequest) (*x509.Certificate, crypto.Signer, error) {
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, nil, fmt.Errorf("invalid request: %w", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now()
	notBefore := now.Add(-time.Minute)
	notAfter := req.NotAfter
	if notAfter.IsZero() {
		notAfter = c.Intermediate.NotAfter
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      req.Subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     req.KeyUsage,
		ExtKeyUsage:  req.ExtKeyUsage,
		DNSNames:     req.DNSNames,
		IPAddresses:  req.IPAddresses,
	}

	// Add CRL Distribution Points if provided
	if len(req.CRLDistributionPoints) > 0 {
		template.CRLDistributionPoints = req.CRLDistributionPoints
	}

	// Add Issuing Certificate URL if provided
	if len(req.IssuingCertificateURL) > 0 {
		template.IssuingCertificateURL = req.IssuingCertificateURL
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, template, c.Intermediate, &leafKey.PublicKey, c.IntermediateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create leaf certificate: %w", err)
	}

	leafCert, err := x509.ParseCertificate(leafCertDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse leaf certificate: %w", err)
	}

	return leafCert, leafKey, nil
}

// GetPool returns a certificate pool containing the root and intermediate certificates.
func (c *CA) GetPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.Root)
	pool.AddCert(c.Intermediate)
	return pool
}

// CertificateRequest represents a request to issue a leaf certificate.
type CertificateRequest struct {
	Subject               pkix.Name
	NotAfter              time.Time
	DNSNames              []string
	IPAddresses           []net.IP
	KeyUsage              x509.KeyUsage
	ExtKeyUsage           []x509.ExtKeyUsage
	CRLDistributionPoints []string
	IssuingCertificateURL []string
}

// CheckAndSetDefaults validates and sets default values for the request.
func (r *CertificateRequest) CheckAndSetDefaults() error {
	if r.Subject.CommonName == "" {
		return fmt.Errorf("subject.commonname is required")
	}
	if r.KeyUsage == 0 {
		r.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
	return nil
}
