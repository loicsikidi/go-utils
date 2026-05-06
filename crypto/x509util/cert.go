// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util

import "crypto/x509"

// IsRoot checks if a certificate is a root certificate.
func IsRoot(cert *x509.Certificate) bool {
	if !cert.IsCA {
		return false
	}
	if cert.Issuer.String() != cert.Subject.String() {
		return false
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return false
	}
	return true
}

// CertificatesAbove returns all certificates in the chain above the given certificate.
// If cert is not found in chain, it returns the original chain.
// If there are no certificates above cert, it returns an empty slice.
func CertificatesAbove(cert *x509.Certificate, chain []*x509.Certificate) []*x509.Certificate {
	// Find the certificate in the chain
	index := -1
	for i, c := range chain {
		if cert.Equal(c) {
			index = i
			break
		}
	}

	// Certificate not found, return original chain
	if index == -1 {
		return chain
	}

	// Return all certificates above (including root if present)
	return chain[index+1:]
}
