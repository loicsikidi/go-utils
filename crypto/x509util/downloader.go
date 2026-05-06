// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"time"

	goutils "github.com/loicsikidi/go-utils"
	"github.com/loicsikidi/go-utils/net/httputil"
)

const (
	DefaultDownloadTimeout = 2 * time.Second
)

// httpClient interface is used essentially to mock [http.Client] in tests
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type trustDownloader struct {
	client  httpClient
	timeout time.Duration
}

// DownloadCRL downloads a Certificate Revocation List (CRL) from the specified URL.
func (d *trustDownloader) DownloadCRL(ctx context.Context, url *url.URL) (CRL, error) {
	ctx, cancel := goutils.WithTimeout(ctx, d.timeout)
	defer cancel()

	crlBytes, err := httputil.HttpGET(ctx, d.client, url.String())
	if err != nil {
		return nil, fmt.Errorf("failed retrieving CRL from %q: %w", url, err)
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, fmt.Errorf("failed parsing CRL from %q: %w", url, err)
	}

	return NewCRL(crl)
}

// DownloadCertificate downloads a certificate from the specified URL.
func (d *trustDownloader) DownloadCertificate(ctx context.Context, url *url.URL) (*x509.Certificate, error) {
	ctx, cancel := goutils.WithTimeout(ctx, d.timeout)
	defer cancel()

	certBytes, err := httputil.HttpGET(ctx, d.client, url.String())
	if err != nil {
		return nil, fmt.Errorf("failed retrieving certificate from %q: %w", url, err)
	}

	// RFC 5280 section 4.2.2.1 states that the certificate
	// is expected to be in DER format in HTTP/FTP.
	crl, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed parsing certificate from %q: %w", url, err)
	}

	return crl, nil
}

func (d *trustDownloader) SetTimeout(timeout time.Duration) {
	d.timeout = timeout
}
