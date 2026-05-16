// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httputil_test

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/loicsikidi/go-utils/crypto/pkiutil/tinyca"
	"github.com/loicsikidi/go-utils/net/httputil"
)

func generateTestCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	ca := tinyca.Must()
	cert, key, err := ca.Generate(tinyca.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		DNSNames: []string{"localhost"},
	})
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	}, ca.GetPool()
}

func TestMuxConfigCheckAndSetDefaults(t *testing.T) {
	t.Parallel()

	t.Run("valid config", func(t *testing.T) {
		t.Parallel()
		tlsCert, _ := generateTestCert(t)
		cfg := httputil.MuxConfig{
			HTTPHandler:  http.NotFoundHandler(),
			HTTPSHandler: http.NotFoundHandler(),
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
			},
		}

		if err := cfg.CheckAndSetDefaults(); err != nil {
			t.Errorf("CheckAndSetDefaults() error = %v, want nil", err)
		}
	})

	t.Run("nil HTTPHandler", func(t *testing.T) {
		t.Parallel()
		cfg := httputil.MuxConfig{
			HTTPSHandler: http.NotFoundHandler(),
			TLSConfig:    &tls.Config{},
		}

		err := cfg.CheckAndSetDefaults()
		if err == nil {
			t.Fatal("CheckAndSetDefaults() error = nil, want error")
		}
	})

	t.Run("nil HTTPSHandler", func(t *testing.T) {
		t.Parallel()
		cfg := httputil.MuxConfig{
			HTTPHandler: http.NotFoundHandler(),
			TLSConfig:   &tls.Config{},
		}

		err := cfg.CheckAndSetDefaults()
		if err == nil {
			t.Fatal("CheckAndSetDefaults() error = nil, want error")
		}
	})

	t.Run("nil TLSConfig", func(t *testing.T) {
		t.Parallel()
		cfg := httputil.MuxConfig{
			HTTPHandler:  http.NotFoundHandler(),
			HTTPSHandler: http.NotFoundHandler(),
		}

		err := cfg.CheckAndSetDefaults()
		if err == nil {
			t.Fatal("CheckAndSetDefaults() error = nil, want error")
		}
	})
}

func TestNewHTTPSMux(t *testing.T) {
	t.Parallel()

	t.Run("valid config", func(t *testing.T) {
		t.Parallel()
		tlsCert, _ := generateTestCert(t)
		cfg := httputil.MuxConfig{
			HTTPHandler:  http.NotFoundHandler(),
			HTTPSHandler: http.NotFoundHandler(),
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
			},
		}

		mux, err := httputil.NewHTTPSMux(cfg)
		if err != nil {
			t.Fatalf("NewHTTPSMux() error = %v, want nil", err)
		}

		if mux == nil {
			t.Fatal("NewHTTPSMux() returned nil")
		}
	})

	t.Run("invalid config", func(t *testing.T) {
		t.Parallel()
		cfg := httputil.MuxConfig{}

		_, err := httputil.NewHTTPSMux(cfg)
		if err == nil {
			t.Fatal("NewHTTPSMux() error = nil, want error")
		}
	})
}

func TestHTTPSMux_ServeHTTP(t *testing.T) {
	t.Parallel()

	httpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("http response"))
	})

	httpsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("https response"))
	})

	tlsCert, pool := generateTestCert(t)

	cfg := httputil.MuxConfig{
		HTTPHandler:  httpHandler,
		HTTPSHandler: httpsHandler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		},
	}

	mux, err := httputil.NewHTTPSMux(cfg)
	if err != nil {
		t.Fatalf("NewHTTPSMux() error = %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	go mux.Serve(listener)

	t.Run("http request", func(t *testing.T) {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer conn.Close()

		req := "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatalf("failed to write request: %v", err)
		}

		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("failed to read response: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}

		if string(body) != "http response" {
			t.Errorf("body = %q, want %q", body, "http response")
		}
	})

	t.Run("https request", func(t *testing.T) {
		tlsConfig := &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: false,
			ServerName:         "localhost",
		}

		conn, err := tls.Dial("tcp", listener.Addr().String(), tlsConfig)
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer conn.Close()

		req := "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatalf("failed to write request: %v", err)
		}

		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("failed to read response: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}

		if string(body) != "https response" {
			t.Errorf("body = %q, want %q", body, "https response")
		}
	})

	t.Run("http client request", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				DisableKeepAlives: true,
			},
		}

		resp, err := client.Get("http://" + listener.Addr().String() + "/")
		if err != nil {
			t.Fatalf("failed to get: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}

		if string(body) != "http response" {
			t.Errorf("body = %q, want %q", body, "http response")
		}
	})

	t.Run("https client request", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    pool,
					ServerName: "localhost",
				},
				DisableKeepAlives: true,
			},
		}

		resp, err := client.Get("https://" + listener.Addr().String() + "/")
		if err != nil {
			t.Fatalf("failed to get: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}

		if string(body) != "https response" {
			t.Errorf("body = %q, want %q", body, "https response")
		}
	})
}
