// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tinyca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	cfg := Config{
		Validity:     time.Hour,
		Organization: "Test Org",
	}

	ca, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if ca.Root == nil {
		t.Fatal("Root CA is nil")
	}
	if ca.Intermediate == nil {
		t.Fatal("Intermediate CA is nil")
	}

	if ca.Root.Subject.CommonName != "Root CA" {
		t.Errorf("Root CA CommonName = %q, want %q", ca.Root.Subject.CommonName, "Root CA")
	}
	if ca.Intermediate.Subject.CommonName != "Intermediate CA" {
		t.Errorf("Intermediate CA CommonName = %q, want %q", ca.Intermediate.Subject.CommonName, "Intermediate CA")
	}

	if !ca.Root.IsCA {
		t.Error("Root CA is not marked as CA")
	}
	if !ca.Intermediate.IsCA {
		t.Error("Intermediate CA is not marked as CA")
	}
}

func TestIssueCertificate(t *testing.T) {
	ca, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req := CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		DNSNames: []string{"test.example.com"},
	}

	cert, key, err := ca.Generate(req)
	if err != nil {
		t.Fatalf("IssueCertificate() failed: %v", err)
	}

	if cert == nil {
		t.Fatal("Certificate is nil")
	}
	if key == nil {
		t.Fatal("Key is nil")
	}

	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("Certificate CommonName = %q, want %q", cert.Subject.CommonName, "test.example.com")
	}

	// Verify certificate chain
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(ca.Intermediate)

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}

	if _, err := cert.Verify(opts); err != nil {
		t.Errorf("Certificate verification failed: %v", err)
	}
}

func TestServer(t *testing.T) {
	ca, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	srv := NewServer(t, ca)

	t.Run("root issuer", func(t *testing.T) {
		resp, err := http.Get(srv.IssuerURL(CATypeRoot))
		if err != nil {
			t.Fatalf("GET /issuer/root failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Read response body failed: %v", err)
		}

		cert, err := x509.ParseCertificate(body)
		if err != nil {
			t.Fatalf("Parse certificate failed: %v", err)
		}

		if cert.Subject.CommonName != "Root CA" {
			t.Errorf("Certificate CommonName = %q, want %q", cert.Subject.CommonName, "Root CA")
		}
	})

	t.Run("intermediate issuer", func(t *testing.T) {
		resp, err := http.Get(srv.IssuerURL(CATypeIntermediate))
		if err != nil {
			t.Fatalf("GET /issuer/intermediate failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Read response body failed: %v", err)
		}

		cert, err := x509.ParseCertificate(body)
		if err != nil {
			t.Fatalf("Parse certificate failed: %v", err)
		}

		if cert.Subject.CommonName != "Intermediate CA" {
			t.Errorf("Certificate CommonName = %q, want %q", cert.Subject.CommonName, "Intermediate CA")
		}
	})

	t.Run("root CRL", func(t *testing.T) {
		resp, err := http.Get(srv.CRLURL(CATypeRoot))
		if err != nil {
			t.Fatalf("GET /crl/root failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Read response body failed: %v", err)
		}

		crl, err := x509.ParseRevocationList(body)
		if err != nil {
			t.Fatalf("Parse CRL failed: %v", err)
		}

		if len(crl.RevokedCertificateEntries) != 0 {
			t.Errorf("CRL has %d revoked certificates, want 0", len(crl.RevokedCertificateEntries))
		}
	})

	t.Run("intermediate CRL", func(t *testing.T) {
		resp, err := http.Get(srv.CRLURL(CATypeIntermediate))
		if err != nil {
			t.Fatalf("GET /crl/intermediate failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Read response body failed: %v", err)
		}

		crl, err := x509.ParseRevocationList(body)
		if err != nil {
			t.Fatalf("Parse CRL failed: %v", err)
		}

		if len(crl.RevokedCertificateEntries) != 0 {
			t.Errorf("CRL has %d revoked certificates, want 0", len(crl.RevokedCertificateEntries))
		}
	})
}

func TestRevokeCertificate(t *testing.T) {
	ca, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	srv := NewServer(t, ca)

	// Issue a certificate
	req := CertificateRequest{
		Subject: pkix.Name{
			CommonName: "revoked.example.com",
		},
	}

	cert, _, err := ca.Generate(req)
	if err != nil {
		t.Fatalf("IssueCertificate() failed: %v", err)
	}

	if err := srv.RevokeCertificate(CATypeIntermediate, cert); err != nil {
		t.Fatalf("RevokeCertificate() failed: %v", err)
	}

	// Fetch the CRL and verify the certificate is revoked
	resp, err := http.Get(srv.CRLURL(CATypeIntermediate))
	if err != nil {
		t.Fatalf("GET /crl/intermediate failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Read response body failed: %v", err)
	}

	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		t.Fatalf("Parse CRL failed: %v", err)
	}

	if len(crl.RevokedCertificateEntries) != 1 {
		t.Errorf("CRL has %d revoked certificates, want 1", len(crl.RevokedCertificateEntries))
	}

	if len(crl.RevokedCertificateEntries) > 0 && crl.RevokedCertificateEntries[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("Revoked certificate serial = %v, want %v", crl.RevokedCertificateEntries[0].SerialNumber, cert.SerialNumber)
	}
}

func TestParallelServers(t *testing.T) {
	// Test that multiple servers can run in parallel without conflicts
	const numServers = 5

	var wg sync.WaitGroup
	wg.Add(numServers)

	for range numServers {
		go func() {
			defer wg.Done()

			ca, err := New()
			if err != nil {
				t.Errorf("New() failed: %v", err)
				return
			}

			srv := NewServer(t, ca)
			if srv == nil {
				t.Errorf("NewServer() failed")
				return
			}

			resp, err := http.Get(srv.IssuerURL(CATypeRoot))
			if err != nil {
				t.Errorf("GET /issuer/root failed: %v", err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Status = %d, want %d", resp.StatusCode, http.StatusOK)
			}
		}()
	}

	wg.Wait()
}

func TestHTTPSServer(t *testing.T) {
	ca, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	srv := NewServer(t, ca)
	client := srv.Client()

	t.Run("https root issuer", func(t *testing.T) {
		resp, err := client.Get(srv.IssuerURL(
			CATypeRoot,
			/* optionalUseTLS= */ true),
		)
		if err != nil {
			t.Fatalf("GET /issuer/root failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Read response body failed: %v", err)
		}

		cert, err := x509.ParseCertificate(body)
		if err != nil {
			t.Fatalf("Parse certificate failed: %v", err)
		}

		if cert.Subject.CommonName != "Root CA" {
			t.Errorf("Certificate CommonName = %q, want %q", cert.Subject.CommonName, "Root CA")
		}
	})

	t.Run("https intermediate CRL", func(t *testing.T) {
		resp, err := client.Get(srv.CRLURL(
			CATypeIntermediate,
			/* optionalUseTLS= */ true),
		)
		if err != nil {
			t.Fatalf("GET /crl/intermediate failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Read response body failed: %v", err)
		}

		crl, err := x509.ParseRevocationList(body)
		if err != nil {
			t.Fatalf("Parse CRL failed: %v", err)
		}

		if len(crl.RevokedCertificateEntries) != 0 {
			t.Errorf("CRL has %d revoked certificates, want 0", len(crl.RevokedCertificateEntries))
		}
	})
}

func TestBaseTLSURL(t *testing.T) {
	ca, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	srv := NewServer(t, ca)

	if srv.BaseURL() == "" {
		t.Error("BaseURL() returned empty string")
	}

	if srv.BaseTLSURL() == "" {
		t.Error("BaseTLSURL() returned empty string")
	}

	if srv.BaseURL() == srv.BaseTLSURL() {
		t.Error("BaseURL() and BaseTLSURL() should return different URLs")
	}
}

func TestGetPool(t *testing.T) {
	ca, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	srv := NewServer(t, ca)
	pool := srv.GetPool()

	if pool == nil {
		t.Fatal("GetPool() returned nil")
	}

	// Verify that the pool contains the CA certificates by using it to verify a cert
	req := CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		DNSNames: []string{"test.example.com"},
	}

	cert, _, err := ca.Generate(req)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	intermediates := x509.NewCertPool()
	intermediates.AddCert(ca.Intermediate)

	opts := x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
	}

	if _, err := cert.Verify(opts); err != nil {
		t.Errorf("Certificate verification failed: %v", err)
	}
}

func TestClient(t *testing.T) {
	ca, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	srv := NewServer(t, ca)
	client := srv.Client()

	if client == nil {
		t.Fatal("Client() returned nil")
	}

	resp, err := client.Get(srv.BaseTLSURL())
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()

	resp, err = client.Get(srv.BaseURL())
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()
}

func TestSetServerCertificate(t *testing.T) {
	ca, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	srv := NewServer(t, ca)
	client := srv.Client()

	// Initial HTTPS request should work
	resp, err := client.Get(srv.IssuerURL(
		CATypeRoot,
		/* optionalUseTLS= */ true),
	)
	if err != nil {
		t.Fatalf("Initial HTTPS request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Initial status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Generate a new server certificate
	newCert, _, err := generateServerCertificate(ca)
	if err != nil {
		t.Fatalf("Generate new certificate failed: %v", err)
	}

	// Update the server certificate
	srv.SetServerCertificate(newCert)

	// Subsequent HTTPS request should still work with the new certificate
	resp, err = client.Get(srv.IssuerURL(
		CATypeIntermediate,
		/* optionalUseTLS= */ true),
	)
	if err != nil {
		t.Fatalf("HTTPS request after certificate update failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status after certificate update = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}
