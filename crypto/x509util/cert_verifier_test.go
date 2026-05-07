// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"
)

type mockCache struct {
	certs []*x509.Certificate
}

func (m *mockCache) FindFunc(fn func(c *x509.Certificate) bool) *x509.Certificate {
	for _, cert := range m.certs {
		if fn(cert) {
			return cert
		}
	}
	return nil
}

type mockHTTPClient struct {
	responses     map[string][]byte
	errors        map[string]error
	requestedURLs []string
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.requestedURLs = append(m.requestedURLs, req.URL.String())
	if err, ok := m.errors[req.URL.String()]; ok {
		return nil, err
	}
	if data, ok := m.responses[req.URL.String()]; ok {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(data)),
		}, nil
	}
	return &http.Response{
		StatusCode: 404,
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}, nil
}

func generateCert(t *testing.T, template *x509.Certificate, parent *x509.Certificate, pubKey crypto.PublicKey, privKey crypto.PrivateKey) *x509.Certificate {
	t.Helper()

	if parent == nil {
		parent = template
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func generateKey(t *testing.T) (*ecdsa.PrivateKey, crypto.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return key, key.Public()
}

type certOptions struct {
	serialNumber          int64
	commonName            string
	keyUsage              x509.KeyUsage
	crlDistributionPoints []string
	issuingCertificateURL []string
	authorityKeyID        []byte
	subjectKeyID          []byte
}

func createRootCA(t *testing.T, opts certOptions) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, pub := generateKey(t)

	if opts.serialNumber == 0 {
		opts.serialNumber = 1
	}
	if opts.commonName == "" {
		opts.commonName = "Root CA"
	}
	if opts.keyUsage == 0 {
		opts.keyUsage = x509.KeyUsageCertSign
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(opts.serialNumber),
		Subject:               pkix.Name{CommonName: opts.commonName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              opts.keyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          opts.subjectKeyID,
	}

	cert := generateCert(t, template, nil, pub, key)
	return cert, key
}

func createIntermediateCA(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, opts certOptions) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, pub := generateKey(t)

	if opts.serialNumber == 0 {
		opts.serialNumber = 2
	}
	if opts.commonName == "" {
		opts.commonName = "Intermediate CA"
	}
	if opts.keyUsage == 0 {
		opts.keyUsage = x509.KeyUsageCertSign
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(opts.serialNumber),
		Subject:               pkix.Name{CommonName: opts.commonName},
		Issuer:                parent.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              opts.keyUsage,
		CRLDistributionPoints: opts.crlDistributionPoints,
		BasicConstraintsValid: true,
		IsCA:                  true,
		AuthorityKeyId:        opts.authorityKeyID,
		SubjectKeyId:          opts.subjectKeyID,
	}

	cert := generateCert(t, template, parent, pub, parentKey)
	return cert, key
}

func createLeafCert(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, opts certOptions) *x509.Certificate {
	t.Helper()
	_, pub := generateKey(t)

	if opts.serialNumber == 0 {
		opts.serialNumber = 3
	}
	if opts.commonName == "" {
		opts.commonName = "Leaf"
	}
	if opts.keyUsage == 0 {
		opts.keyUsage = x509.KeyUsageDigitalSignature
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(opts.serialNumber),
		Subject:               pkix.Name{CommonName: opts.commonName},
		Issuer:                parent.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              opts.keyUsage,
		CRLDistributionPoints: opts.crlDistributionPoints,
		IssuingCertificateURL: opts.issuingCertificateURL,
		BasicConstraintsValid: true,
		IsCA:                  false,
		AuthorityKeyId:        opts.authorityKeyID,
	}

	return generateCert(t, template, parent, pub, parentKey)
}

func createCRL(t *testing.T, issuer *x509.Certificate, issuerKey crypto.Signer, revokedSerials ...*big.Int) []byte {
	t.Helper()

	var entries []x509.RevocationListEntry
	for _, serial := range revokedSerials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now(),
		})
	}

	template := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: entries,
	}

	crlBytes, err := MarshalCRL(template, issuer, issuerKey)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}
	return crlBytes
}

func TestNewTrustChecker(t *testing.T) {
	cfg := VerifierConfig{}
	tc, err := NewCertVerifier(cfg)
	if err != nil {
		t.Fatalf("NewTrustChecker failed: %v", err)
	}

	if tc.maxDepth != 10 {
		t.Errorf("expected maxDepth=10, got %d", tc.maxDepth)
	}
	if tc.downloader.timeout != DefaultDownloadTimeout {
		t.Errorf("expected timeout=%v, got %v", DefaultDownloadTimeout, tc.downloader.timeout)
	}
}

func TestGetChain_ThreeLevel(t *testing.T) {
	root, rootKey := createRootCA(t, certOptions{})
	intermediate, intKey := createIntermediateCA(t, root, rootKey, certOptions{})
	leaf := createLeafCert(t, intermediate, intKey, certOptions{})

	cfg := VerifierConfig{}
	tc, err := NewCertVerifier(cfg)
	if err != nil {
		t.Fatalf("NewTrustChecker failed: %v", err)
	}

	chain, err := tc.GetFullChain(context.Background(), leaf, []*x509.Certificate{intermediate, root})
	if err != nil {
		t.Fatalf("GetChain failed: %v", err)
	}

	if len(chain) != 2 {
		t.Fatalf("expected chain length 2, got %d", len(chain))
	}

	if chain[0].Subject.CommonName != "Intermediate CA" {
		t.Errorf("expected intermediate in chain[0], got %s", chain[0].Subject.CommonName)
	}

	if chain[1].Subject.CommonName != "Root CA" {
		t.Errorf("expected root in chain[1], got %s", chain[1].Subject.CommonName)
	}
}

func TestGetChain_RootOnly(t *testing.T) {
	root, _ := createRootCA(t, certOptions{})

	cfg := VerifierConfig{}
	tc, err := NewCertVerifier(cfg)
	if err != nil {
		t.Fatalf("NewTrustChecker failed: %v", err)
	}

	chain, err := tc.GetFullChain(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("GetChain failed: %v", err)
	}

	if len(chain) != 0 {
		t.Errorf("expected empty chain for root cert, got %d certs", len(chain))
	}
}

func TestGetChain_MissingIntermediate(t *testing.T) {
	root, rootKey := createRootCA(t, certOptions{})
	_, leafPub := generateKey(t)

	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "Leaf"},
		Issuer:                pkix.Name{CommonName: "Missing Intermediate"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	leaf := generateCert(t, leafTemplate, root, leafPub, rootKey)

	cfg := VerifierConfig{}
	tc, err := NewCertVerifier(cfg)
	if err != nil {
		t.Fatalf("NewTrustChecker failed: %v", err)
	}

	_, err = tc.GetFullChain(context.Background(), leaf, nil)
	if !errors.Is(err, ErrChainIncomplete) {
		t.Errorf("expected ErrChainIncomplete, got %v", err)
	}
}

func TestCheckRevocation_NotRevoked(t *testing.T) {
	root, rootKey := createRootCA(t, certOptions{
		keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	})
	leaf := createLeafCert(t, root, rootKey, certOptions{
		crlDistributionPoints: []string{"http://example.com/crl"},
	})

	crlBytes := createCRL(t, root, rootKey)

	mockClient := &mockHTTPClient{
		responses: map[string][]byte{
			"http://example.com/crl": crlBytes,
		},
	}

	cfg := VerifierConfig{HttpClient: mockClient}
	tc, err := NewCertVerifier(cfg)
	if err != nil {
		t.Fatalf("NewTrustChecker failed: %v", err)
	}

	revCfg := RevocationConfig{
		Chain: []*x509.Certificate{leaf, root},
	}

	err = tc.Verify(context.Background(), leaf, revCfg)
	if err != nil {
		t.Errorf("CheckRevocation failed: %v", err)
	}
}

func TestCheckRevocation_Revoked(t *testing.T) {
	root, rootKey := createRootCA(t, certOptions{
		keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	})
	leaf := createLeafCert(t, root, rootKey, certOptions{
		serialNumber:          2,
		crlDistributionPoints: []string{"http://example.com/crl"},
	})

	crlBytes := createCRL(t, root, rootKey, big.NewInt(2))

	mockClient := &mockHTTPClient{
		responses: map[string][]byte{
			"http://example.com/crl": crlBytes,
		},
	}

	cfg := VerifierConfig{HttpClient: mockClient}
	tc, err := NewCertVerifier(cfg)
	if err != nil {
		t.Fatalf("NewTrustChecker failed: %v", err)
	}

	revCfg := RevocationConfig{
		Chain: []*x509.Certificate{leaf, root},
	}

	err = tc.Verify(context.Background(), leaf, revCfg)
	if !errors.Is(err, ErrCertificateRevoked) {
		t.Errorf("expected ErrCertificateRevoked, got %v", err)
	}
}

func TestCheckRevocation_NoCRLDP_FullChainFalse(t *testing.T) {
	root, rootKey := createRootCA(t, certOptions{})
	leaf := createLeafCert(t, root, rootKey, certOptions{})

	cfg := VerifierConfig{}
	tc, err := NewCertVerifier(cfg)
	if err != nil {
		t.Fatalf("NewTrustChecker failed: %v", err)
	}

	revCfg := RevocationConfig{
		Chain:     []*x509.Certificate{leaf, root},
		FullChain: false,
	}

	err = tc.Verify(context.Background(), leaf, revCfg)
	if err != nil {
		t.Errorf("expected nil error for no CRLDP with FullChain=false, got %v", err)
	}
}

func TestAfterDownloadHook(t *testing.T) {
	root, rootKey := createRootCA(t, certOptions{})
	intermediate, intKey := createIntermediateCA(t, root, rootKey, certOptions{})
	leaf := createLeafCert(t, intermediate, intKey, certOptions{
		issuingCertificateURL: []string{"http://example.com/intermediate"},
	})

	mockClient := &mockHTTPClient{
		responses: map[string][]byte{
			"http://example.com/intermediate": intermediate.Raw,
		},
	}

	var hookCalls []struct {
		url  string
		kind string
	}

	cfg := VerifierConfig{
		HttpClient: mockClient,
		AfterDownloadHook: func(u *url.URL, kind string) {
			hookCalls = append(hookCalls, struct {
				url  string
				kind string
			}{u.String(), kind})
		},
	}
	tc, err := NewCertVerifier(cfg)
	if err != nil {
		t.Fatalf("NewTrustChecker failed: %v", err)
	}

	_, err = tc.GetFullChain(context.Background(), leaf, []*x509.Certificate{root})
	if err != nil {
		t.Fatalf("GetChain failed: %v", err)
	}

	if len(hookCalls) != 1 {
		t.Errorf("expected 1 hook call, got %d", len(hookCalls))
	}
	if len(hookCalls) > 0 {
		if hookCalls[0].url != "http://example.com/intermediate" {
			t.Errorf("expected hook URL http://example.com/intermediate, got %s", hookCalls[0].url)
		}
		if hookCalls[0].kind != "certificate" {
			t.Errorf("expected hook kind certificate, got %s", hookCalls[0].kind)
		}
	}
}

func TestMaxURLsToTry_CRL(t *testing.T) {
	root, rootKey := createRootCA(t, certOptions{
		keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	})
	leaf := createLeafCert(t, root, rootKey, certOptions{
		crlDistributionPoints: []string{
			"http://example.com/crl1",
			"http://example.com/crl2",
			"http://example.com/crl3",
			"http://example.com/crl4",
			"http://example.com/crl5",
			"http://example.com/crl6",
			"http://example.com/crl7",
		},
	})

	crlBytes := createCRL(t, root, rootKey)

	mockClient := &mockHTTPClient{
		responses: map[string][]byte{
			"http://example.com/crl5": crlBytes,
		},
	}

	cfg := VerifierConfig{HttpClient: mockClient}
	tc, err := NewCertVerifier(cfg)
	if err != nil {
		t.Fatalf("NewTrustChecker failed: %v", err)
	}

	revCfg := RevocationConfig{
		Chain: []*x509.Certificate{leaf, root},
	}

	err = tc.Verify(context.Background(), leaf, revCfg)
	if err != nil {
		t.Errorf("CheckRevocation failed: %v", err)
	}

	if len(mockClient.requestedURLs) > maxURLsToTry {
		t.Errorf("expected at most %d URLs to be tried, got %d: %v", maxURLsToTry, len(mockClient.requestedURLs), mockClient.requestedURLs)
	}
}

func TestMaxURLsToTry_AIA(t *testing.T) {
	root, rootKey := createRootCA(t, certOptions{})
	intermediate, intKey := createIntermediateCA(t, root, rootKey, certOptions{})
	// Create a leaf with more than maxURLsToTry issuing certificate URLs
	leaf := createLeafCert(t, intermediate, intKey, certOptions{
		issuingCertificateURL: []string{
			"http://example.com/int1",
			"http://example.com/int2",
			"http://example.com/int3",
			"http://example.com/int4",
			"http://example.com/int5",
			"http://example.com/int6",
			"http://example.com/int7",
		},
	})

	mockClient := &mockHTTPClient{
		responses: map[string][]byte{
			"http://example.com/int5": intermediate.Raw,
		},
	}

	cfg := VerifierConfig{HttpClient: mockClient}
	tc, err := NewCertVerifier(cfg)
	if err != nil {
		t.Fatalf("NewTrustChecker failed: %v", err)
	}

	_, err = tc.GetFullChain(context.Background(), leaf, []*x509.Certificate{root})
	if err != nil {
		t.Fatalf("GetChain failed: %v", err)
	}

	if len(mockClient.requestedURLs) > maxURLsToTry {
		t.Errorf("expected at most %d URLs to be tried, got %d: %v", maxURLsToTry, len(mockClient.requestedURLs), mockClient.requestedURLs)
	}
}

func TestCheckRevocation_FullChain(t *testing.T) {
	tests := []struct {
		name              string
		revokedLeafSerial *big.Int
		revokedIntSerial  *big.Int
		expectError       error
		expectedCRLCount  int
	}{
		{
			name:             "no revocation",
			expectedCRLCount: 2,
		},
		{
			name:              "leaf revoked",
			revokedLeafSerial: big.NewInt(100),
			expectError:       ErrCertificateRevoked,
			expectedCRLCount:  1,
		},
		{
			name:             "intermediate revoked",
			revokedIntSerial: big.NewInt(2),
			expectError:      ErrCertificateRevoked,
			expectedCRLCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, rootKey := createRootCA(t, certOptions{
				keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			})
			intermediate, intKey := createIntermediateCA(t, root, rootKey, certOptions{
				keyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
				crlDistributionPoints: []string{"http://example.com/crl-int"},
			})
			leaf := createLeafCert(t, intermediate, intKey, certOptions{
				serialNumber:          100,
				crlDistributionPoints: []string{"http://example.com/crl-leaf"},
			})

			var rootCRLBytes []byte
			if tt.revokedIntSerial != nil {
				rootCRLBytes = createCRL(t, root, rootKey, tt.revokedIntSerial)
			} else {
				rootCRLBytes = createCRL(t, root, rootKey)
			}

			var intCRLBytes []byte
			if tt.revokedLeafSerial != nil {
				intCRLBytes = createCRL(t, intermediate, intKey, tt.revokedLeafSerial)
			} else {
				intCRLBytes = createCRL(t, intermediate, intKey)
			}

			mockClient := &mockHTTPClient{
				responses: map[string][]byte{
					"http://example.com/crl-int":  rootCRLBytes,
					"http://example.com/crl-leaf": intCRLBytes,
				},
			}

			cfg := VerifierConfig{HttpClient: mockClient}
			tc, err := NewCertVerifier(cfg)
			if err != nil {
				t.Fatalf("NewTrustChecker failed: %v", err)
			}

			revCfg := RevocationConfig{
				Chain:     []*x509.Certificate{leaf, intermediate, root},
				FullChain: true,
			}

			err = tc.Verify(context.Background(), leaf, revCfg)
			if !errors.Is(err, tt.expectError) {
				t.Errorf("expected error %v, got %v", tt.expectError, err)
			}

			if len(mockClient.requestedURLs) != tt.expectedCRLCount {
				t.Errorf("expected %d CRL requests, got %d", tt.expectedCRLCount, len(mockClient.requestedURLs))
			}
		})
	}
}

func TestGetChain_MaxDepthReached(t *testing.T) {
	// Create a chain deeper than maxDepth
	keys := make([]*ecdsa.PrivateKey, 12)
	pubs := make([]crypto.PublicKey, 12)
	for i := range keys {
		keys[i], pubs[i] = generateKey(t)
	}

	// Create root
	certs := make([]*x509.Certificate, 12)
	certs[0] = generateCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, pubs[0], keys[0])

	// Create 10 intermediates
	for i := 1; i < 11; i++ {
		certs[i] = generateCert(t, &x509.Certificate{
			SerialNumber:          big.NewInt(int64(i + 1)),
			Subject:               pkix.Name{CommonName: fmt.Sprintf("Intermediate CA %d", i)},
			Issuer:                certs[i-1].Subject,
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}, certs[i-1], pubs[i], keys[i-1])
	}

	// Create leaf
	certs[11] = generateCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(12),
		Subject:               pkix.Name{CommonName: "Leaf"},
		Issuer:                certs[10].Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}, certs[10], pubs[11], keys[10])

	cfg := VerifierConfig{MaxDepth: 5}
	tc, err := NewCertVerifier(cfg)
	if err != nil {
		t.Fatalf("NewTrustChecker failed: %v", err)
	}

	_, err = tc.GetFullChain(context.Background(), certs[11], certs)
	if !errors.Is(err, ErrMaxDepthReached) {
		t.Errorf("expected ErrMaxDepthReached, got %v", err)
	}
}

func TestGetChain_WithCache(t *testing.T) {
	root, rootKey := createRootCA(t, certOptions{
		subjectKeyID: []byte{1, 2, 3, 4},
	})
	intermediate, intKey := createIntermediateCA(t, root, rootKey, certOptions{
		authorityKeyID: []byte{1, 2, 3, 4},
		subjectKeyID:   []byte{5, 6, 7, 8},
	})
	leaf := createLeafCert(t, intermediate, intKey, certOptions{
		authorityKeyID: []byte{5, 6, 7, 8},
	})

	cache := &mockCache{
		certs: []*x509.Certificate{root, intermediate},
	}

	cfg := VerifierConfig{Cache: cache}
	tc, err := NewCertVerifier(cfg)
	if err != nil {
		t.Fatalf("NewTrustChecker failed: %v", err)
	}

	chain, err := tc.GetFullChain(context.Background(), leaf, nil)
	if err != nil {
		t.Fatalf("GetChain failed: %v", err)
	}

	if len(chain) != 2 {
		t.Fatalf("expected chain length 2, got %d", len(chain))
	}

	if chain[0].Subject.CommonName != "Intermediate CA" {
		t.Errorf("expected intermediate in chain[0], got %s", chain[0].Subject.CommonName)
	}

	if chain[1].Subject.CommonName != "Root CA" {
		t.Errorf("expected root in chain[1], got %s", chain[1].Subject.CommonName)
	}
}

func TestCheckRevocation_CRLNotFound(t *testing.T) {
	root, rootKey := createRootCA(t, certOptions{
		keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	})
	leaf := createLeafCert(t, root, rootKey, certOptions{
		crlDistributionPoints: []string{"http://example.com/crl"},
	})

	mockClient := &mockHTTPClient{
		responses: map[string][]byte{},
	}

	cfg := VerifierConfig{HttpClient: mockClient}
	tc, err := NewCertVerifier(cfg)
	if err != nil {
		t.Fatalf("NewTrustChecker failed: %v", err)
	}

	revCfg := RevocationConfig{
		Chain: []*x509.Certificate{leaf, root},
	}

	err = tc.Verify(context.Background(), leaf, revCfg)
	if !errors.Is(err, ErrCRLNotFound) {
		t.Errorf("expected ErrCRLNotFound, got %v", err)
	}
}
