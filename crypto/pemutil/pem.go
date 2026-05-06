// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pemutil

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParseCertificate extracts the first certificate from the given pem.
func ParseCertificate(pemData []byte) (*x509.Certificate, error) {
	var block *pem.Block
	for len(pemData) > 0 {
		block, pemData = pem.Decode(pemData)
		if block == nil {
			return nil, fmt.Errorf("error decoding pem block")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert, nil
	}

	return nil, fmt.Errorf("error parsing certificate: no certificate found")
}
