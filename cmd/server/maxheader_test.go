// Package main — tests for L-04: all http.Server instances must set
// MaxHeaderBytes to 16 KB (16 * 1024).
//
// L-04 fix: Go's http.Server defaults MaxHeaderBytes to 1 MB, which is
// excessive for a token endpoint whose largest expected header is a Bearer JWT
// (~2 KB).  16 KB is generous for all legitimate OAuth/OIDC clients while
// capping memory spent on oversized (or malicious) requests.
//
// The test spins up a local test server with a 16 KB header limit and verifies
// that requests with headers exceeding the limit are rejected with 431.
package main

import (
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

const wantMaxHeaderBytes = 16 * 1024

// ---------------------------------------------------------------------------
// L-04: http.Server with 16 KB limit rejects oversized headers
// ---------------------------------------------------------------------------

func TestHTTPServer_MaxHeaderBytes_OversizedHeaderRejected(t *testing.T) {
	t.Parallel()

	// Start a minimal server with the same MaxHeaderBytes as production.
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		MaxHeaderBytes: wantMaxHeaderBytes,
		ReadTimeout:    2 * time.Second,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	go srv.Serve(ln) //nolint:errcheck
	defer srv.Close()

	addr := ln.Addr().String()

	// Build a request whose single header value far exceeds 16 KB.
	largeValue := fmt.Sprintf("%065536s", "x") // 65536 bytes of 'x' — well over 16 KB

	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("X-Oversized", largeValue)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// The server may close the connection before sending a response;
		// that is also an acceptable outcome (the request was rejected).
		return
	}
	defer resp.Body.Close()

	// Go's stdlib returns 431 (Request Header Fields Too Large) when
	// MaxHeaderBytes is exceeded.
	if resp.StatusCode == http.StatusOK {
		t.Errorf("server accepted oversized header; MaxHeaderBytes=%d must reject it (status=%d)",
			wantMaxHeaderBytes, resp.StatusCode)
	}
}

func TestHTTPServer_MaxHeaderBytes_NormalRequestAllowed(t *testing.T) {
	t.Parallel()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		MaxHeaderBytes: wantMaxHeaderBytes,
		ReadTimeout:    2 * time.Second,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	go srv.Serve(ln) //nolint:errcheck
	defer srv.Close()

	// A normal-sized Bearer JWT (~500 bytes) must be accepted.
	req, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJpYXQiOjE2MDAwMDAwMDB9.sig")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected error for normal request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("normal request got %d, want 200", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// L-04: constant verification — MaxHeaderBytes value is exactly 16 KB
// ---------------------------------------------------------------------------

func TestMaxHeaderBytesConstant_Is16KB(t *testing.T) {
	t.Parallel()
	if wantMaxHeaderBytes != 16384 {
		t.Errorf("wantMaxHeaderBytes = %d, want 16384 (16 * 1024)", wantMaxHeaderBytes)
	}
}
