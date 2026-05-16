// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package httputil provides HTTP utilities.
//
// The HTTP/HTTPS multiplexer in this package is a naive implementation
// intended for testing purposes only. It should not be used in production
// environments as it lacks proper error handling, timeouts, and other features
// required for production-grade traffic handling.
package httputil

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
)

// MuxConfig configures an HTTP/HTTPS multiplexer.
type MuxConfig struct {
	// HTTPHandler handles plain HTTP connections
	HTTPHandler http.Handler
	// HTTPSHandler handles TLS connections
	HTTPSHandler http.Handler
	// TLSConfig is the TLS configuration for HTTPS connections
	TLSConfig *tls.Config
}

// CheckAndSetDefaults validates the configuration.
func (c *MuxConfig) CheckAndSetDefaults() error {
	if c.HTTPHandler == nil {
		return errors.New("httphandler cannot be nil")
	}
	if c.HTTPSHandler == nil {
		return errors.New("httpshandler cannot be nil")
	}
	if c.TLSConfig == nil {
		return errors.New("tlsconfig cannot be nil")
	}
	if len(c.TLSConfig.Certificates) == 0 &&
		c.TLSConfig.GetCertificate == nil &&
		c.TLSConfig.GetConfigForClient == nil {
		return errors.New("tlsconfig must provide server certificate material")
	}
	return nil
}

// httpsMux multiplexes HTTP and HTTPS connections on the same port.
// It detects the protocol by inspecting the first byte of the connection:
// - TLS handshake starts with 0x16
// - HTTP starts with ASCII characters (GET, POST, etc.)
type httpsMux struct {
	httpHandler  http.Handler
	httpsHandler http.Handler
	tlsConfig    *tls.Config
}

// NewHTTPSMux creates a new HTTP/HTTPS multiplexer.
func NewHTTPSMux(cfg MuxConfig) (*httpsMux, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, err
	}
	return &httpsMux{
		httpHandler:  cfg.HTTPHandler,
		httpsHandler: cfg.HTTPSHandler,
		tlsConfig:    cfg.TLSConfig,
	}, nil
}

func (m *httpsMux) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go m.handleConn(conn)
	}
}

func (m *httpsMux) handleConn(conn net.Conn) {
	reader := bufio.NewReader(conn)
	firstByte, err := reader.Peek(1)
	if err != nil {
		conn.Close()
		return
	}

	if firstByte[0] == 0x16 {
		m.serveTLS(conn, reader)
	} else {
		m.serveHTTP(conn, reader)
	}
}

func (m *httpsMux) serveTLS(rawConn net.Conn, reader *bufio.Reader) {
	defer rawConn.Close()

	conn := &readerConn{
		Reader: reader,
		Conn:   rawConn,
	}

	tlsConn := tls.Server(conn, m.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	req, err := http.ReadRequest(bufio.NewReader(tlsConn))
	if err != nil {
		return
	}
	req.RemoteAddr = rawConn.RemoteAddr().String()
	state := tlsConn.ConnectionState()
	req.TLS = &state

	w := newResponseWriter(tlsConn)
	m.httpsHandler.ServeHTTP(w, req)
	w.finishRequest()
}

func (m *httpsMux) serveHTTP(rawConn net.Conn, reader *bufio.Reader) {
	defer rawConn.Close()

	conn := &readerConn{
		Reader: reader,
		Conn:   rawConn,
	}

	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	req.RemoteAddr = rawConn.RemoteAddr().String()

	w := newResponseWriter(conn)
	m.httpHandler.ServeHTTP(w, req)
	w.finishRequest()
}

type readerConn struct {
	io.Reader
	net.Conn
}

func (c *readerConn) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}

type responseWriter struct {
	conn        net.Conn
	header      http.Header
	statusCode  int
	wroteHeader bool
	body        []byte
}

func newResponseWriter(conn net.Conn) *responseWriter {
	return &responseWriter{
		conn:       conn,
		header:     make(http.Header),
		statusCode: http.StatusOK,
	}
}

func (w *responseWriter) Header() http.Header {
	return w.header
}

func (w *responseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.statusCode = statusCode
	w.wroteHeader = true
}

func (w *responseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	w.body = append(w.body, data...)
	return len(data), nil
}

func (w *responseWriter) finishRequest() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	// Write HTTP response
	fmt.Fprintf(w.conn, "HTTP/1.1 %d %s\r\n", w.statusCode, http.StatusText(w.statusCode)) //nolint:errcheck

	// Set Content-Length if not already set
	if w.header.Get("Content-Length") == "" && len(w.body) > 0 {
		w.header.Set("Content-Length", fmt.Sprintf("%d", len(w.body)))
	}

	w.header.Write(w.conn)      //nolint:errcheck
	fmt.Fprintf(w.conn, "\r\n") //nolint:errcheck

	if len(w.body) > 0 {
		w.conn.Write(w.body) //nolint:errcheck
	}
}
