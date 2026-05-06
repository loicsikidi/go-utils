// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	goutils "github.com/loicsikidi/go-utils"
)

const (
	// maxURLsToTry limits the number of URLs to attempt when downloading certificates or CRLs.
	maxURLsToTry = 5
)

var (
	ErrMaxDepthReached    = errors.New("maximum download depth reached")
	ErrChainIncomplete    = errors.New("certificate chain cannot be completed")
	ErrIssuerNotFound     = errors.New("issuer certificate not found")
	ErrCertificateRevoked = errors.New("certificate is revoked")
	ErrCRLNotFound        = errors.New("crl not found")
)

// RevocationConfig configures certificate revocation checking behavior.
type RevocationConfig struct {
	Chain     []*x509.Certificate
	FullChain bool
}

// cache defines the interface for a certificate cache.
//
// Note: it's a read-only cache.
type cache interface {
	FindFunc(fn func(c *x509.Certificate) bool) *x509.Certificate
}

// Config configures a trust checker instance.
type Config struct {
	MaxDepth          int
	HttpClient        httpClient
	Timeout           time.Duration
	Cache             cache
	AfterDownloadHook func(url *url.URL, kind string)
}

// certVerifier is responsible for verifying if a certificate has been revoked.
//
// Note: currently, it only supports checking revocation via CRLs.
type certVerifier struct {
	// downloader is responsible for downloading certificates and CRLs.
	downloader *trustDownloader
	// maxDepth is the maximum depth for certificate chain building.
	maxDepth int
	// cache is used to look up certificates.
	cache cache
	// afterDownloadHook is called after a certificate or CRL is downloaded.
	afterDownloadHook func(url *url.URL, kind string)
	// downloadedCerts keeps track of certificates that have been downloaded to avoid redundant downloads.
	downloadedCerts map[string]*x509.Certificate
}

// CheckAndSetDefaults validates the configuration and sets default values.
func (c *Config) CheckAndSetDefaults() error {
	if c.MaxDepth == 0 {
		c.MaxDepth = 10
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultDownloadTimeout
	}
	if c.HttpClient == nil {
		c.HttpClient = http.DefaultClient
	}
	return nil
}

// NewCertVerifier creates a new certificate verifier with the provided configuration.
func NewCertVerifier(cfg Config) (*certVerifier, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, err
	}

	return &certVerifier{
		downloader: &trustDownloader{
			client:  cfg.HttpClient,
			timeout: cfg.Timeout,
		},
		maxDepth:          cfg.MaxDepth,
		cache:             cfg.Cache,
		afterDownloadHook: cfg.AfterDownloadHook,
		downloadedCerts:   make(map[string]*x509.Certificate),
	}, nil
}

// getChain builds the certificate chain from the leaf certificate up to (but excluding) the root.
// It returns only intermediate certificates, using optionalChain, cache, and AIA downloads as needed.
// Returns [ErrChainIncomplete] if the chain cannot be completed or [ErrMaxDepthReached] if too many downloads are required.
func (t *certVerifier) getChain(ctx context.Context, cert *x509.Certificate, optionalChain ...[]*x509.Certificate) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	current := cert

	outerChain := goutils.OptionalArg(optionalChain)

	for range t.maxDepth {
		if IsRoot(current) {
			return chain, nil
		}

		issuer, err := t.findIssuer(ctx, current, outerChain)
		if err != nil {
			return nil, err
		}
		if issuer == nil {
			return nil, ErrChainIncomplete
		}

		if !IsRoot(issuer) {
			chain = append(chain, issuer)
		}

		current = issuer
	}

	return nil, ErrMaxDepthReached
}

// CheckRevocation verifies that the certificate and optionally its chain are not revoked.
// If cfg.FullChain is true, checks all certificates in the chain. Otherwise, checks only the leaf certificate.
// Returns [ErrCertificateRevoked] if any certificate is revoked, or nil if all certificates are valid.
// Special case: if FullChain is false and the certificate has no CRL distribution points, returns nil.
func (t *certVerifier) CheckRevocation(ctx context.Context, cert *x509.Certificate, cfg RevocationConfig) error {
	chain, err := t.getChain(ctx, cert, cfg.Chain)
	if err != nil {
		return err
	}

	certsToCheck := []*x509.Certificate{cert}
	if cfg.FullChain {
		certsToCheck = chain
	}

	for i, certToCheck := range certsToCheck {
		var issuer *x509.Certificate
		if i+1 < len(chain) {
			issuer = chain[i+1]
		} else {
			var err error
			issuer, err = t.findIssuer(ctx, certToCheck, cfg.Chain)
			if err != nil {
				return err
			}
		}

		if issuer == nil {
			if !cfg.FullChain && len(certToCheck.CRLDistributionPoints) == 0 {
				return nil
			}
			return ErrIssuerNotFound
		}

		if err := t.checkCertRevocation(ctx, certToCheck, issuer); err != nil {
			return err
		}
	}

	return nil
}

func (t *certVerifier) checkCertRevocation(ctx context.Context, cert *x509.Certificate, issuer *x509.Certificate) error {
	if len(cert.CRLDistributionPoints) == 0 {
		return nil
	}

	crlURLs := parseURLs(cert.CRLDistributionPoints, maxURLsToTry)
	for _, crlURL := range crlURLs {
		crl, err := t.downloader.DownloadCRL(ctx, crlURL)
		if err != nil {
			continue
		}

		if t.afterDownloadHook != nil {
			t.afterDownloadHook(crlURL, "crl")
		}

		if err := crl.Verify(issuer); err != nil {
			return fmt.Errorf("CRL signature verification failed: %w", err)
		}

		if crl.IsRevoked(cert) {
			return ErrCertificateRevoked
		}

		return nil
	}

	return ErrCRLNotFound
}

func makeKey(cert *x509.Certificate) string {
	return cert.Subject.String() + cert.SerialNumber.String()
}

// parseURLs parses and validates a list of URL strings, returning only HTTP(S) URLs.
// It limits the number of URLs processed to maxURLs.
func parseURLs(urls []string, maxURLs int) []*url.URL {
	var result []*url.URL
	for i, u := range urls {
		if i >= maxURLs {
			break
		}

		if u == "" {
			continue
		}

		parsedURL, err := url.Parse(u)
		if err != nil {
			continue
		}

		if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
			continue
		}
		result = append(result, parsedURL)
	}
	return result
}

func (t *certVerifier) findIssuer(ctx context.Context, cert *x509.Certificate, optionalChain []*x509.Certificate) (*x509.Certificate, error) {
	// 1. Check optionalChain first
	for _, candidate := range optionalChain {
		if cert.CheckSignatureFrom(candidate) == nil {
			return candidate, nil
		}
	}

	// 2. Check cache if provided
	if t.cache != nil {
		candidate := t.cache.FindFunc(func(c *x509.Certificate) bool {
			return c.Subject.String() == cert.Issuer.String()
		})
		if candidate != nil && cert.CheckSignatureFrom(candidate) == nil {
			return candidate, nil
		}
	}

	// 3. Check internal downloaded certs
	for _, issuer := range t.downloadedCerts {
		if issuer.Subject.String() == cert.Issuer.String() {
			if cert.CheckSignatureFrom(issuer) == nil {
				return issuer, nil
			}
		}
	}

	// 4. Download from AIA
	aiaURLs := parseURLs(cert.IssuingCertificateURL, maxURLsToTry)
	for _, aiaURL := range aiaURLs {
		issuer, err := t.downloader.DownloadCertificate(ctx, aiaURL)
		if err != nil {
			continue
		}

		t.downloadedCerts[makeKey(issuer)] = issuer

		if t.afterDownloadHook != nil {
			t.afterDownloadHook(aiaURL, "certificate")
		}

		// should always works but let's be defensive
		if cert.CheckSignatureFrom(issuer) == nil {
			return issuer, nil
		}
	}

	return nil, nil
}
