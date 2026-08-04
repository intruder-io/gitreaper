package fetch

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// ErrNotFound is returned when the server responds with 404.
var ErrNotFound = errors.New("not found")

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// Client is an HTTP client for fetching git object files.
type Client struct {
	http *http.Client
}

// NewClient creates a Client with layered timeouts:
//
//   - Dialer timeout         → bounds TCP connect time
//   - TLS timeout            → bounds TLS handshake time
//   - ResponseHeaderTimeout  → bounds time until first response byte is received
//   - http.Client.Timeout    → safety net covering the entire request including body
//
// The safety timeout is set to 10× the connect timeout (minimum 5 minutes).
// This catches servers that accept a connection and send headers promptly but
// then stall sending the response body — which would otherwise block blob worker
// goroutines indefinitely and prevent the scan from ever completing.
// 10× is large enough for pack file downloads to complete on slow servers.
//
// TLS certificate verification is intentionally skipped: targets commonly have
// expired, self-signed, or hostname-mismatched certificates.
func NewClient(connectTimeout time.Duration) *Client {
	safetyTimeout := connectTimeout * 10
	if safetyTimeout < 5*time.Minute {
		safetyTimeout = 5 * time.Minute
	}
	return &Client{
		http: &http.Client{
			Timeout: safetyTimeout,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   connectTimeout,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   connectTimeout,
				ResponseHeaderTimeout: connectTimeout,
				TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   20,
				IdleConnTimeout:       90 * time.Second,
				DisableCompression:    true, // git objects are already zlib-compressed
			},
		},
	}
}

// Get fetches the full content of a URL.
func (c *Client) Get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}
	// Some servers send Content-Encoding: gzip even when not asked (DisableCompression
	// suppresses Accept-Encoding: gzip but not the server's response encoding).
	// Go does not auto-decompress when DisableCompression is set, so we do it manually.
	body := resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gr, err := gzip.NewReader(body)
		if err != nil {
			return nil, fmt.Errorf("gzip decode: %w", err)
		}
		defer gr.Close()
		body = gr
	}
	return io.ReadAll(body)
}

// ContentLength performs a HEAD request and returns the Content-Length, or -1 if unknown.
func (c *Client) ContentLength(ctx context.Context, url string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return 0, fmt.Errorf("HEAD HTTP %d for %s", resp.StatusCode, url)
	}
	return resp.ContentLength, nil
}

