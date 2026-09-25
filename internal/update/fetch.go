package update

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Size caps on what a release server may send; anything longer is refused.
const (
	maxLatestBytes = 64
	maxSumsBytes   = 8 << 10
	maxSigBytes    = 256
	// A build is about 8 MiB; the cap leaves room to grow and none to fill a disk.
	maxBinaryBytes = 64 << 20

	textTimeout     = 30 * time.Second
	downloadTimeout = 10 * time.Minute
	maxRedirects    = 5
)

// fetcher reads a release server over HTTPS, or plain HTTP to loopback for
// tests and local trials (the rule install.sh keeps). It trusts the system
// store: the relay's `--relay-ca` is for the relay, not for claircode.app.
type fetcher struct {
	base *url.URL
	http *http.Client
	ua   string
}

// newFetcher checks base and builds a client for it; client nil means one
// with the proxy from the environment (RELAY.md §12).
func newFetcher(base, ua string, client *http.Client) (*fetcher, error) {
	u, err := url.Parse(strings.TrimSuffix(base, "/"))
	if err != nil {
		return nil, fmt.Errorf("update: releases url %q: %w", base, err)
	}
	if !allowedURL(u) {
		return nil, fmt.Errorf("update: releases url %q: want https://, or http:// to this machine", base)
	}
	u.RawQuery, u.Fragment = "", ""
	if client == nil {
		client = &http.Client{
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
				ForceAttemptHTTP2:     true,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
				TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
				// Every cap below counts bytes on the wire; a transparently
				// inflated body would count something else.
				DisableCompression: true,
			},
		}
	}
	// A redirect may not leave HTTPS (or loopback).
	redirects := *client
	redirects.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return errors.New("too many redirects")
		}
		if !allowedURL(req.URL) {
			return fmt.Errorf("redirected to %s", req.URL.Redacted())
		}
		return nil
	}
	return &fetcher{base: u, http: &redirects, ua: ua}, nil
}

// allowedURL is https://, or http:// to a loopback host.
func allowedURL(u *url.URL) bool {
	switch {
	case u.Host == "":
		return false
	case u.Scheme == "https":
		return true
	case u.Scheme == "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		return host == "localhost" || (ip != nil && ip.IsLoopback())
	default:
		return false
	}
}

// text fetches a small file under the base.
func (f *fetcher) text(ctx context.Context, path string, maxBytes int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, textTimeout)
	defer cancel()
	var buf strings.Builder
	if _, err := f.copy(ctx, path, maxBytes, &buf); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

// download copies a file under the base into w.
func (f *fetcher) download(ctx context.Context, path string, w io.Writer) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	return f.copy(ctx, path, maxBinaryBytes, w)
}

func (f *fetcher) copy(ctx context.Context, path string, maxBytes int64, w io.Writer) (int64, error) {
	target := f.base.JoinPath(path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), http.NoBody)
	if err != nil {
		return 0, fmt.Errorf("update: %s: %w", path, err)
	}
	req.Header.Set("User-Agent", f.ua)
	resp, err := f.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("update: get %s: %w", target.Redacted(), err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("update: get %s: %s", target.Redacted(), resp.Status)
	}
	if resp.ContentLength > maxBytes {
		return 0, fmt.Errorf("update: %s is %d bytes, over the %d-byte cap", path, resp.ContentLength, maxBytes)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return n, fmt.Errorf("update: read %s: %w", target.Redacted(), err)
	}
	if n > maxBytes {
		return n, fmt.Errorf("update: %s is over the %d-byte cap", path, maxBytes)
	}
	return n, nil
}
