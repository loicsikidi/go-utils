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
