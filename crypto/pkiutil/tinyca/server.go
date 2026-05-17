// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tinyca

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	goutils "github.com/loicsikidi/go-utils"
	"github.com/loicsikidi/go-utils/crypto/x509util"
	"github.com/loicsikidi/go-utils/net/httputil"
)

// CAType represents the type of Certificate Authority (Root or Intermediate).
type CAType string

const (
	// CATypeRoot represents a Root Certificate Authority.
	CATypeRoot CAType = "root"
	// CATypeIntermediate represents an Intermediate Certificate Authority.
	CATypeIntermediate CAType = "intermediate"
)

// String returns the string representation of [CAType].
func (c CAType) String() string {
	return string(c)
}

// IsValid returns true if the [CAType] is valid.
func (c CAType) IsValid() bool {
	return c == CATypeRoot || c == CATypeIntermediate
}

// Server provides HTTP and HTTPS endpoints for serving CA certificates and CRLs.
//
// The server uses an HTTP/HTTPS multiplexer to serve both protocols on the same port,
// allowing tests to run in parallel without port conflicts. Each server instance gets
// a unique OS-assigned port.
type Server struct {
	listener      net.Listener
	handler       *serverHandler
	ca            *CA
	baseURL       string
	baseTLSURL    string
	tlsConfig     *tls.Config
	certMu        sync.RWMutex
	serverCert    *tls.Certificate
	serverCertKey crypto.Signer
}

// serverHandler is the internal HTTP handler with thread-safe mutable state.
type serverHandler struct {
	mu              sync.RWMutex
	ca              *CA
	rootCRL         *x509.RevocationList
	intermediateCRL *x509.RevocationList
	revokedCerts    map[CAType][]x509.RevocationListEntry
}

// generateServerCertificate generates a TLS server certificate signed by the Intermediate CA.
// The certificate includes localhost and 127.0.0.1 in the SANs.
func generateServerCertificate(ca *CA) (*tls.Certificate, crypto.Signer, error) {
	req := CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: ca.Intermediate.Subject.Organization,
		},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	cert, key, err := ca.Generate(req)
	if err != nil {
		return nil, nil, fmt.Errorf("generate server certificate: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{cert.Raw, ca.Intermediate.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}

	return tlsCert, key, nil
}

// NewServer creates and starts a new HTTP/HTTPS server for the given CA.
//
// The server exposes endpoints for:
//   - CA certificates (DER format)
//   - Certificate Revocation Lists (CRLs)
//
// The server multiplexes HTTP and HTTPS on the same port, with both protocols
// serving the same content. Use [Server.BaseURL] for HTTP and [Server.BaseTLSURL]
// for HTTPS.
//
// The server should be closed when no longer needed using [Server.Close].
func NewServer(t *testing.T, optionalCA ...*CA) *Server {
	ca := goutils.OptionalArgWithDefault(optionalCA, Must())
	if ca == nil {
		t.Fatalf("ca is required")
	}

	h := &serverHandler{
		ca:           ca,
		revokedCerts: make(map[CAType][]x509.RevocationListEntry),
	}

	// Generate initial empty CRLs
	if err := h.regenerateCRLs(); err != nil {
		t.Fatalf("generate initial CRLs: %v", err)
	}

	serverCert, serverKey, err := generateServerCertificate(ca)
	if err != nil {
		t.Fatalf("generate server certificate: %v", err)
	}

	srv := &Server{
		handler:       h,
		ca:            ca,
		serverCert:    serverCert,
		serverCertKey: serverKey,
	}

	// Create TLS config with GetCertificate callback for dynamic certificate updates
	tlsConfig := &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			srv.certMu.RLock()
			defer srv.certMu.RUnlock()
			return srv.serverCert, nil
		},
		MinVersion: tls.VersionTLS13,
	}
	srv.tlsConfig = tlsConfig

	// Create listener on random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}
	srv.listener = listener

	addr := listener.Addr().String()
	srv.baseURL = "http://" + addr
	srv.baseTLSURL = "https://" + addr

	mux, err := httputil.NewHTTPSMux(httputil.MuxConfig{
		HTTPHandler:  h,
		HTTPSHandler: h,
		TLSConfig:    tlsConfig,
	})
	if err != nil {
		listener.Close()
		t.Fatalf("create multiplexer: %v", err)
	}

	// Start serving in background
	go func() {
		if err := mux.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("unexpected server error: %v", err)
		}
	}()

	t.Cleanup(func() {
		srv.Close()
	})

	return srv
}

// regenerateCRLs regenerates the CRLs based on the current revoked certificates.
// Must be called with the lock held or during initialization.
func (h *serverHandler) regenerateCRLs() error {
	validity := h.ca.Intermediate.NotAfter
	rootCRL, err := generateCRL(validity, h.revokedCerts[CATypeRoot], h.ca.Root, h.ca.RootKey, h.rootCRL)
	if err != nil {
		return fmt.Errorf("generate root CRL: %w", err)
	}

	intCRL, err := generateCRL(validity, h.revokedCerts[CATypeIntermediate], h.ca.Intermediate, h.ca.IntermediateKey, h.intermediateCRL)
	if err != nil {
		return fmt.Errorf("generate intermediate CRL: %w", err)
	}

	h.rootCRL = rootCRL
	h.intermediateCRL = intCRL
	return nil
}

// ServeHTTP handles HTTP requests for CA certificates and CRLs.
//
// Supported endpoints:
//   - GET /issuer/root - Returns Root CA certificate (DER format)
//   - GET /issuer/intermediate - Returns Intermediate CA certificate (DER format)
//   - GET /crl/root - Returns Root CA CRL
//   - GET /crl/intermediate - Returns Intermediate CA CRL
func (h *serverHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.Split(path, "/")

	if len(parts) != 2 {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	resourceType := parts[0]
	caType := CAType(parts[1])

	if !caType.IsValid() {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	switch resourceType {
	case "issuer":
		h.serveIssuer(w, caType)
	case "crl":
		h.serveCRL(w, caType)
	default:
		http.Error(w, "Not found", http.StatusNotFound)
	}
}

func (h *serverHandler) serveIssuer(w http.ResponseWriter, caType CAType) {
	var cert []byte
	switch caType {
	case CATypeRoot:
		cert = h.ca.Root.Raw
	case CATypeIntermediate:
		cert = h.ca.Intermediate.Raw
	default:
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.WriteHeader(http.StatusOK)
	w.Write(cert) //nolint:errcheck
}

func (h *serverHandler) serveCRL(w http.ResponseWriter, caType CAType) {
	var crl []byte
	switch caType {
	case CATypeRoot:
		crl = h.rootCRL.Raw
	case CATypeIntermediate:
		crl = h.intermediateCRL.Raw
	default:
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/pkix-crl")
	w.WriteHeader(http.StatusOK)
	w.Write(crl) //nolint:errcheck
}

// BaseURL returns the HTTP base URL of the server.
func (s *Server) BaseURL() string {
	return s.baseURL
}

// BaseTLSURL returns the HTTPS base URL of the server.
func (s *Server) BaseTLSURL() string {
	return s.baseTLSURL
}

// IssuerURL returns the full URL for the issuer certificate endpoint.
// Uses HTTP by default. Pass true to use HTTPS.
//
// Example:
//
//	IssuerURL(CATypeRoot)       // returns "http://127.0.0.1:12345/issuer/root"
//	IssuerURL(CATypeRoot, true) // returns "https://127.0.0.1:12345/issuer/root"
func (s *Server) IssuerURL(caType CAType, optionalUseTLS ...bool) string {
	useTLS := goutils.OptionalArg(optionalUseTLS)
	base := s.baseURL
	if useTLS {
		base = s.baseTLSURL
	}
	return fmt.Sprintf("%s/issuer/%s", base, caType)
}

// CRLURL returns the full URL for the CRL endpoint.
// Uses HTTP by default. Pass true to use HTTPS.
//
// Example:
//
//	CRLURL(CATypeIntermediate)       // returns "http://127.0.0.1:12345/crl/intermediate"
//	CRLURL(CATypeIntermediate, true) // returns "https://127.0.0.1:12345/crl/intermediate"
func (s *Server) CRLURL(caType CAType, optionalUseTLS ...bool) string {
	useTLS := goutils.OptionalArg(optionalUseTLS)
	base := s.baseURL
	if useTLS {
		base = s.baseTLSURL
	}
	return fmt.Sprintf("%s/crl/%s", base, caType)
}

// GetPool returns a certificate pool containing the CA certificates.
// Use this pool to configure HTTP clients for trusting the server's TLS certificate.
//
// Example:
//
//	srv := tinyca.NewServer(t)
//	client := &http.Client{
//	    Transport: &http.Transport{
//	        TLSClientConfig: &tls.Config{
//	            RootCAs: srv.GetPool(),
//	        },
//	    },
//	}
func (s *Server) GetPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(s.ca.Root)
	return pool
}

// Client returns an HTTP client configured to trust the server's TLS certificate.
// The client can be used to make HTTPS requests to the server.
//
// Example:
//
//	srv := tinyca.NewServer(t)
//	client := srv.Client()
//	resp, err := client.Get(srv.IssuerURL(tinyca.CATypeRoot, /* optionalUseTLS= */ true))
func (s *Server) Client() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: s.GetPool(),
			},
		},
	}
}

// SetServerCertificate updates the server's TLS certificate.
// This method is thread-safe and the new certificate will be used for subsequent TLS connections.
//
// Example:
//
//	srv := tinyca.NewServer(t)
//	newCert := &tls.Certificate{...}
//	srv.SetServerCertificate(newCert)
func (s *Server) SetServerCertificate(cert *tls.Certificate) {
	s.certMu.Lock()
	defer s.certMu.Unlock()
	s.serverCert = cert
}

// RevokeCertificate revokes a certificate and updates the CRL.
func (s *Server) RevokeCertificate(caType CAType, cert *x509.Certificate, optionalReason ...int) error {
	if !caType.IsValid() {
		return fmt.Errorf("invalid CA type: %s", caType)
	}

	s.handler.mu.Lock()
	defer s.handler.mu.Unlock()

	revoked := x509.RevocationListEntry{
		SerialNumber:   cert.SerialNumber,
		RevocationTime: time.Now(),
		ReasonCode:     goutils.OptionalArg(optionalReason),
	}

	s.handler.revokedCerts[caType] = append(s.handler.revokedCerts[caType], revoked)
	return s.handler.regenerateCRLs()
}

// Close stops the server and releases resources.
func (s *Server) Close() {
	s.listener.Close()
}

// ToTLSCertificate converts an [x509.Certificate] and a [crypto.Signer] into a [tls.Certificate].
func (s *Server) ToTLSCertificate(cert *x509.Certificate, key crypto.Signer) *tls.Certificate {
	return &tls.Certificate{
		Certificate: [][]byte{cert.Raw, s.ca.Intermediate.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}
}

func generateCRL(validaty time.Time, revokedCerts []x509.RevocationListEntry, issuer *x509.Certificate, signer crypto.Signer, previousCRL *x509.RevocationList) (*x509.RevocationList, error) {
	cfg := x509util.CreateCRLConfig{
		NextUpdate:          validaty,
		RevokedCertificates: revokedCerts,
		PreviousCRL:         previousCRL,
	}

	if previousCRL == nil {
		cfg.Number = big.NewInt(1)
	}

	template := x509util.MustRevocationList(cfg)
	b, err := x509util.MarshalCRL(template, issuer, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseRevocationList(b)
}
