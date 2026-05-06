// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util

import (
	"context"
	"crypto/x509"
	"io"
	"net/url"
	"testing"
)

func TestDownloadCRL(t *testing.T) {
	root, rootKey := createRootCA(t, certOptions{
		keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	})
	crlBytes := createCRL(t, root, rootKey)

	tests := []struct {
		name        string
		url         string
		client      httpClient
		expectError bool
	}{
		{
			name: "success",
			url:  "http://example.com/crl",
			client: &mockHTTPClient{
				responses: map[string][]byte{
					"http://example.com/crl": crlBytes,
				},
			},
			expectError: false,
		},
		{
			name: "http error",
			url:  "http://example.com/crl",
			client: &mockHTTPClient{
				errors: map[string]error{
					"http://example.com/crl": io.EOF,
				},
			},
			expectError: true,
		},
		{
			name: "invalid CRL",
			url:  "http://example.com/crl",
			client: &mockHTTPClient{
				responses: map[string][]byte{
					"http://example.com/crl": []byte("invalid"),
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &trustDownloader{
				client:  tt.client,
				timeout: DefaultDownloadTimeout,
			}

			u, _ := url.Parse(tt.url)
			_, err := d.DownloadCRL(context.Background(), u)

			if (err != nil) != tt.expectError {
				t.Errorf("DownloadCRL() error = %v, expectError %v", err, tt.expectError)
			}
		})
	}
}

func TestDownloadCertificate(t *testing.T) {
	root, _ := createRootCA(t, certOptions{})
	certBytes := root.Raw

	tests := []struct {
		name        string
		url         string
		client      httpClient
		expectError bool
	}{
		{
			name: "success",
			url:  "http://example.com/cert",
			client: &mockHTTPClient{
				responses: map[string][]byte{
					"http://example.com/cert": certBytes,
				},
			},
			expectError: false,
		},
		{
			name: "http error",
			url:  "http://example.com/cert",
			client: &mockHTTPClient{
				errors: map[string]error{
					"http://example.com/cert": io.EOF,
				},
			},
			expectError: true,
		},
		{
			name: "invalid certificate",
			url:  "http://example.com/cert",
			client: &mockHTTPClient{
				responses: map[string][]byte{
					"http://example.com/cert": []byte("invalid"),
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &trustDownloader{
				client:  tt.client,
				timeout: DefaultDownloadTimeout,
			}

			u, _ := url.Parse(tt.url)
			_, err := d.DownloadCertificate(context.Background(), u)

			if (err != nil) != tt.expectError {
				t.Errorf("DownloadCertificate() error = %v, expectError %v", err, tt.expectError)
			}
		})
	}
}
