// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util

import (
	"crypto/x509"
	"testing"
)

func TestCertificatesAbove(t *testing.T) {
	// Create a certificate chain: leaf -> int1 -> int2 -> root
	root, rootKey := createRootCA(t, certOptions{commonName: "Root CA"})
	int2, int2Key := createIntermediateCA(t, root, rootKey, certOptions{commonName: "Intermediate 2"})
	int1, int1Key := createIntermediateCA(t, int2, int2Key, certOptions{commonName: "Intermediate 1"})
	leaf := createLeafCert(t, int1, int1Key, certOptions{commonName: "Leaf"})

	tests := []struct {
		name     string
		cert     *x509.Certificate
		chain    []*x509.Certificate
		expected int
	}{
		{
			name:     "leaf cert with full chain",
			cert:     leaf,
			chain:    []*x509.Certificate{leaf, int1, int2, root},
			expected: 3, // int1, int2, root
		},
		{
			name:     "intermediate cert",
			cert:     int1,
			chain:    []*x509.Certificate{leaf, int1, int2, root},
			expected: 2, // int2, root
		},
		{
			name:     "last intermediate before root",
			cert:     int2,
			chain:    []*x509.Certificate{leaf, int1, int2, root},
			expected: 1, // root
		},
		{
			name:     "root cert",
			cert:     root,
			chain:    []*x509.Certificate{leaf, int1, int2, root},
			expected: 0, // nothing above
		},
		{
			name:     "cert not in chain",
			cert:     leaf,
			chain:    []*x509.Certificate{int1, int2, root},
			expected: 3, // returns original chain
		},
		{
			name:     "chain without root",
			cert:     leaf,
			chain:    []*x509.Certificate{leaf, int1, int2},
			expected: 2, // int1, int2
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CertificatesAbove(tt.cert, tt.chain)
			if len(result) != tt.expected {
				t.Errorf("expected %d certificates, got %d", tt.expected, len(result))
			}
		})
	}
}
