// Package ruleset implements the application-owned rule-set cache.
//
// The package deliberately stores response bytes verbatim. It does not parse,
// transcode, or manufacture SRS/JSON data; sing-box receives exactly the bytes
// that were downloaded (or imported offline).
package ruleset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func defaultHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// The standard transport validates certificates and host names by default.
	// Do not install an insecure TLS config here: callers may replace the HTTP
	// client explicitly when they own that policy (for example, a test client).
	return &http.Client{Transport: transport}
}

const (
    DefaultMaxBytes = int64(64 << 20)
    DefaultTimeout = 30 * time.Second
    cacheDirectory = "rule_sets"
    metaSuffix = ".meta.json"
)

var (
    ErrInvalidID = errors.New("ruleset: invalid cache id")
    ErrEmptyBody = errors.New("ruleset: empty response body")
    ErrTooLarge = errors.New("ruleset: response exceeds size limit")
    ErrNotModifiedWithoutCache = errors.New("ruleset: server returned 304 without a cached file")
)

type Outcome string

const (
    Downloaded Outcome = "downloaded"
    NotModified Outcome = "not_modified"
    Failed Outcome = "failed"
)

type Meta struct {
    LastUpdated *time.Time `json:"lastUpdated,omitempty"`
    LastAttempt *time.Time `json:"lastAttempt,omitempty"`
    ETag        string     `json:"etag,omitempty"`
    LastError   string     `json:"lastError,omitempty"`
}

func (m Meta) Failing() bool { return m.LastError != "" }

type Result struct {
    Outcome Outcome `json:"outcome"`
    Path    string  `json:"path,omitempty"`
    Meta    Meta    `json:"meta"`
    Err     error   `json:"-"`
}

func (r Result) OK() bool      { return r.Outcome != Failed }
func (r Result) Changed() bool { return r.Outcome == Downloaded }

type HTTPDoer interface {
    Do(*http.Request) (*http.Response, error)
}

type Option func(*Client)

func WithHTTPClient(client HTTPDoer) Option {
    return func(c *Client) {
        if client != nil {
            c.http = client
        }
    }
}

func WithMaxBytes(n int64) Option {
    return func(c *Client) {
        if n > 0 {
            c.maxBytes = n
        }
    }
}

func WithTimeout(d time.Duration) Option {
    return func(c *Client) {
        if d > 0 {
            c.timeout = d
        }
    }
}

// Client owns only the cache directory supplied to New. It has no runtime or
// platform dependency, so a caller can use it from a UI, service, or headless
// process. The mutex serializes replacement of the same cache id.
type Client struct {
    root     string
    http     HTTPDoer
    maxBytes int64
    timeout  time.Duration
    mu       sync.Mutex
    changes  chan string
}

func New(root string, options ...Option) (*Client, error) {
    if strings.TrimSpace(root) == "" {
        return nil, errors.New("ruleset: cache root is empty")
    }
    c := &Client{
		root: filepath.Clean(root), http: defaultHTTPClient(),
		maxBytes: DefaultMaxBytes, timeout: DefaultTimeout,
        changes: make(chan string, 16),
    }
    for _, option := range options {
        if option != nil {
            option(c)
        }
    }
    return c, nil
}

func (c *Client) Changes() <-chan string { return c.changes }

func (c *Client) dir() string { return filepath.Join(c.root, cacheDirectory) }

func validateID(id string) error {
    if id == "" || id == "." || id == ".." || strings.ContainsAny(id, `/\\`) || strings.Contains(id, "..") {
        return ErrInvalidID
    }
    return nil
}

func (c *Client) file(id string) (string, error) {
    if err := validateID(id); err != nil {
        return "", err
    }
    return filepath.Join(c.dir(), id+".srs"), nil
}

func (c *Client) metaFile(id string) (string, error) {
    if err := validateID(id); err != nil {
        return "", err
    }
    return filepath.Join(c.dir(), id+metaSuffix), nil
}

func (c *Client) CachedPath(id string) (string, bool, error) {
	return c.CachedPathFormat(id, "srs")
}

func (c *Client) CachedPathFormat(id, format string) (string, bool, error) {
	path, err := c.formatFile(id, format)
	if err != nil { return "", false, err }
	_, err = os.Stat(path)
	if errors.Is(err, os.ErrNotExist) { return "", false, nil }
	if err != nil { return "", false, err }
	return path, true, nil
}

func (c *Client) ReadOffline(ctx context.Context, id string) ([]byte, Meta, error) {
	return c.ReadFormat(ctx, id, "srs")
}

// ReadFormat reads an offline artifact without interpreting or converting it.
// Supported formats mirror existing cache naming: srs and json.
func (c *Client) ReadFormat(ctx context.Context, id, format string) ([]byte, Meta, error) {
	if ctx == nil { ctx = context.Background() }
	if err := contextErr(ctx); err != nil { return nil, Meta{}, err }
	path, err := c.formatFile(id, format)
	if err != nil { return nil, Meta{}, err }
	data, err := os.ReadFile(path)
	if err != nil { return nil, Meta{}, err }
	meta, metaErr := c.ReadMeta(id)
	if metaErr != nil { return data, Meta{}, nil }
	return data, meta, nil
}

// StoreOffline atomically stores already-encoded SRS or JSON bytes verbatim.
// It is useful for SAF/file import and never claims one format is another.
func (c *Client) StoreOffline(id, format string, data []byte) (string, error) {
	path, err := c.formatFile(id, format)
	if err != nil { return "", err }
	if len(data) == 0 { return "", ErrEmptyBody }
	if int64(len(data)) > c.maxBytes { return "", ErrTooLarge }
	if err := atomicWrite(path, data, 0600); err != nil { return "", err }
	return path, nil
}

func (c *Client) formatFile(id, format string) (string, error) {
	if err := validateID(id); err != nil { return "", err }
	switch format { case "srs", "json": default: return "", fmt.Errorf("ruleset: unsupported format %q", format) }
	return filepath.Join(c.dir(), id+"."+format), nil
}

func (c *Client) ReadMeta(id string) (Meta, error) {
    path, err := c.metaFile(id)
    if err != nil { return Meta{}, err }
    data, err := os.ReadFile(path)
    if errors.Is(err, os.ErrNotExist) { return Meta{}, nil }
    if err != nil { return Meta{}, err }
    var meta Meta
    if err := json.Unmarshal(data, &meta); err != nil { return Meta{}, nil }
    return meta, nil
}

func (c *Client) Download(ctx context.Context, id, rawURL string, conditional bool) Result {
    return c.DownloadWith(ctx, id, rawURL, DownloadOptions{Conditional: conditional})
}

type DownloadOptions struct {
	Conditional bool
	Format      string
	MaxBytes    int64
    Backoff     []time.Duration
    Attempts    int
}

func (c *Client) DownloadWith(ctx context.Context, id, rawURL string, options DownloadOptions) Result {
	if ctx == nil { ctx = context.Background() }
	path, err := c.file(id)
	if err != nil { return Result{Outcome: Failed, Err: err} }
	format := options.Format
	if format == "" {
		format = formatFromURL(rawURL)
	}
	path, err = c.formatFile(id, format)
	if err != nil { return Result{Outcome: Failed, Err: err} }
	if strings.TrimSpace(rawURL) == "" {
		return c.finish(id, path, Failed, "invalid URL", "")
	}
	if err := contextErr(ctx); err != nil {
		return c.finish(id, path, Failed, shortError(err), "")
	}

	requestCtx := ctx
	cancel := func() {}
	if ctx == nil {
		requestCtx = context.Background()
	}
	if c.timeout > 0 {
		requestCtx, cancel = context.WithTimeout(requestCtx, c.timeout)
	}
	defer cancel()

	maxBytes := options.MaxBytes
    if maxBytes <= 0 { maxBytes = c.maxBytes }
    attempts := options.Attempts
    if attempts <= 0 { attempts = 3 }
    backoffs := options.Backoff
    if backoffs == nil { backoffs = []time.Duration{time.Second, 3 * time.Second} }

    c.mu.Lock()
    defer c.mu.Unlock()
    previous, _ := c.ReadMeta(id)
    hasCache := false
    if _, statErr := os.Stat(path); statErr == nil { hasCache = true }
	for attempt := 0; attempt < attempts; attempt++ {
		if err := contextErr(requestCtx); err != nil {
			return c.finishWithMeta(id, path, Failed, previous, shortError(err), "")
		}
		req, reqErr := http.NewRequestWithContext(requestCtx, http.MethodGet, rawURL, nil)
		if reqErr != nil { return c.finishWithMeta(id, path, Failed, previous, shortError(reqErr), "") }
		if parsedURL, parseErr := url.Parse(rawURL); parseErr != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
			return c.finishWithMeta(id, path, Failed, previous, "invalid URL", "")
		}
		req.Header.Set("User-Agent", "LxBox/Go")
        if options.Conditional && hasCache && previous.ETag != "" {
            req.Header.Set("If-None-Match", previous.ETag)
        }
		response, doErr := c.http.Do(req)
		if doErr != nil {
			if requestCtx.Err() != nil { return c.finishWithMeta(id, path, Failed, previous, shortError(requestCtx.Err()), "") }
			if attempt+1 < attempts { if err := wait(requestCtx, backoffAt(backoffs, attempt)); err != nil { return c.finishWithMeta(id, path, Failed, previous, shortError(err), "") }; continue }
			return c.finishWithMeta(id, path, Failed, previous, shortError(doErr), "")
		}
        body, readErr := readResponse(response, maxBytes)
        response.Body.Close()
		if response.StatusCode == http.StatusNotModified {
			if !hasCache { return c.finishWithMeta(id, path, Failed, previous, ErrNotModifiedWithoutCache.Error(), "") }
			result := c.finishWithMeta(id, path, NotModified, previous, "", response.Header.Get("ETag"))
			result.Path = path
			return result
		}
        if response.StatusCode >= 400 && response.StatusCode < 500 {
            return c.finishWithMeta(id, path, Failed, previous, fmt.Sprintf("HTTP %d", response.StatusCode), "")
        }
        if readErr != nil {
            if errors.Is(readErr, ErrTooLarge) { return c.finishWithMeta(id, path, Failed, previous, readErr.Error(), "") }
			if attempt+1 < attempts { if err := wait(requestCtx, backoffAt(backoffs, attempt)); err != nil { return c.finishWithMeta(id, path, Failed, previous, shortError(err), "") }; continue }
            return c.finishWithMeta(id, path, Failed, previous, shortError(readErr), "")
        }
        if response.StatusCode != http.StatusOK || len(body) == 0 {
            if response.StatusCode == http.StatusOK && len(body) == 0 && attempt+1 == attempts {
                return c.finishWithMeta(id, path, Failed, previous, ErrEmptyBody.Error(), "")
            }
			if attempt+1 < attempts { if err := wait(requestCtx, backoffAt(backoffs, attempt)); err != nil { return c.finishWithMeta(id, path, Failed, previous, shortError(err), "") }; continue }
            return c.finishWithMeta(id, path, Failed, previous, fmt.Sprintf("HTTP %d", response.StatusCode), "")
        }
        if err := atomicWrite(path, body, 0600); err != nil {
            return c.finishWithMeta(id, path, Failed, previous, shortError(err), "")
        }
		result := c.finishWithMeta(id, path, Downloaded, previous, "", response.Header.Get("ETag"))
		result.Path = path
	select {
	case c.changes <- id:
	default:
	}
	return result
    }
    return c.finishWithMeta(id, path, Failed, previous, "retries exhausted", "")
}

func readResponse(response *http.Response, maxBytes int64) ([]byte, error) {
    if response.ContentLength > maxBytes { return nil, ErrTooLarge }
    reader := io.LimitReader(response.Body, maxBytes+1)
    data, err := io.ReadAll(reader)
    if err != nil { return nil, err }
    if int64(len(data)) > maxBytes { return nil, ErrTooLarge }
    return data, nil
}

func (c *Client) finish(id, path string, outcome Outcome, errorText, etag string) Result {
    previous, _ := c.ReadMeta(id)
    return c.finishWithMeta(id, path, outcome, previous, errorText, etag)
}

func (c *Client) finishWithMeta(id, path string, outcome Outcome, previous Meta, errorText, etag string) Result {
    now := time.Now().UTC()
    meta := previous
    meta.LastAttempt = &now
    if errorText == "" && (outcome == Downloaded || outcome == NotModified) { meta.LastUpdated = &now; meta.LastError = "" } else { meta.LastError = errorText }
		if etag != "" { meta.ETag = etag }
		_ = c.writeMeta(id, meta)
		result := Result{Outcome: outcome, Meta: meta}
		if outcome != Failed && path != "" {
			if _, err := os.Stat(path); err == nil { result.Path = path }
		}
		if result.Path == "" {
			if cached, ok, _ := c.CachedPathFormat(id, extensionForPath(path)); ok { result.Path = cached }
		}
		if errorText != "" { result.Err = errors.New(errorText) }
    return result
}

func extensionForPath(path string) string {
	if strings.HasSuffix(path, ".json") { return "json" }
	return "srs"
}

func formatFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err == nil && strings.EqualFold(filepath.Ext(parsed.Path), ".json") { return "json" }
	return "srs"
}

func (c *Client) writeMeta(id string, meta Meta) error {
    path, err := c.metaFile(id); if err != nil { return err }
    data, err := json.Marshal(meta); if err != nil { return err }
    return atomicWrite(path, data, 0600)
}

func (c *Client) Delete(id string) error {
	path, err := c.file(id)
	if err != nil { return err }
	jsonPath, err := c.formatFile(id, "json")
	if err != nil { return err }
	meta, err := c.metaFile(id)
	if err != nil { return err }
	if err := removeIfExists(path); err != nil { return err }
	if err := removeIfExists(jsonPath); err != nil { return err }
	return removeIfExists(meta)
}

func (c *Client) PruneOrphans(active map[string]struct{}) (int, error) {
    entries, err := os.ReadDir(c.dir())
    if errors.Is(err, os.ErrNotExist) { return 0, nil }
    if err != nil { return 0, err }
    removed := 0
    for _, entry := range entries {
        name := entry.Name()
        id := ""
		switch {
		case strings.HasSuffix(name, metaSuffix):
			id = strings.TrimSuffix(name, metaSuffix)
		case strings.HasSuffix(name, ".srs"):
			id = strings.TrimSuffix(name, ".srs")
		case strings.HasSuffix(name, ".json"):
			id = strings.TrimSuffix(name, ".json")
        default:
            continue
        }
		if _, keep := active[id]; keep { continue }
		for _, ext := range []string{".srs", ".json", metaSuffix} {
			if name != id+ext { continue }
			if err := os.Remove(filepath.Join(c.dir(), name)); err == nil { removed++ } else if !errors.Is(err, os.ErrNotExist) { return removed, err }
			break
		}
    }
    return removed, nil
}

func PresetCacheID(presetID, tag string) string { return "preset__" + presetID + "__" + tag }
func (c *Client) FetchPreset(ctx context.Context, presetID, tag, rawURL string, conditional bool) Result {
    return c.Download(ctx, PresetCacheID(presetID, tag), rawURL, conditional)
}
func (c *Client) ReadPreset(ctx context.Context, presetID, tag string) ([]byte, Meta, error) {
    return c.ReadOffline(ctx, PresetCacheID(presetID, tag))
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
    if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil { return err }
    tmp, err := os.CreateTemp(filepath.Dir(path), ".ruleset-*")
    if err != nil { return err }
    tmpName := tmp.Name()
    defer os.Remove(tmpName)
    if err = tmp.Chmod(mode); err == nil { _, err = tmp.Write(data) }
    if err == nil { err = tmp.Sync() }
    closeErr := tmp.Close(); if err == nil { err = closeErr }
    if err != nil { return err }
    if err = os.Rename(tmpName, path); err == nil { return nil }
    // os.Rename cannot replace an existing file on Windows. Move the old
    // generation aside, install the complete new generation, and restore it
    // if installation fails; no reader can observe a partial file.
    old := path + ".old"
    _ = os.Remove(old)
    if moveErr := os.Rename(path, old); moveErr != nil && !errors.Is(moveErr, os.ErrNotExist) { return err }
    if installErr := os.Rename(tmpName, path); installErr != nil {
        _ = os.Rename(old, path)
        return installErr
    }
    _ = os.Remove(old)
    return nil
}

func removeIfExists(path string) error {
    err := os.Remove(path)
    if errors.Is(err, os.ErrNotExist) { return nil }
    return err
}

func wait(ctx context.Context, d time.Duration) error {
    if d <= 0 { return contextErr(ctx) }
    timer := time.NewTimer(d); defer timer.Stop()
    select { case <-ctx.Done(): return ctx.Err(); case <-timer.C: return nil }
}
func backoffAt(backoffs []time.Duration, attempt int) time.Duration { if attempt < len(backoffs) { return backoffs[attempt] }; return 0 }
func contextErr(ctx context.Context) error { if ctx == nil { return nil }; return ctx.Err() }
func shortError(err error) string {
    if err == nil { return "" }
    if errors.Is(err, context.Canceled) { return "canceled" }
    if errors.Is(err, context.DeadlineExceeded) { return "timeout" }
    return err.Error()
}

// Dispatch is an optional small transport-neutral facade. The root is passed
// in args so a runtime bridge can keep package state out of its own registry.
// Unsupported or malformed calls return errors rather than a fake success.
func Dispatch(ctx context.Context, method string, args map[string]any) (any, error) {
    root, _ := args["root"].(string)
    client, err := New(root)
    if err != nil { return nil, err }
    return client.Dispatch(ctx, method, args)
}

func (c *Client) Dispatch(ctx context.Context, method string, args map[string]any) (any, error) {
    id, _ := args["id"].(string)
    switch method {
	case "read", "rulesets.read":
		format := "srs"
		if rawFormat, ok := args["format"].(string); ok && rawFormat != "" { format = rawFormat }
		data, meta, err := c.ReadFormat(ctx, id, format)
		return map[string]any{"bytes": data, "meta": meta, "format": format}, err
	case "meta", "metadata", "rulesets.metadata":
		return c.ReadMeta(id)
	case "delete":
		return nil, c.Delete(id)
	case "download", "rulesets.download":
		rawURL, _ := args["url"].(string)
		conditional, _ := args["conditional"].(bool)
		format, _ := args["format"].(string)
		return c.DownloadWith(ctx, id, rawURL, DownloadOptions{Conditional: conditional, Format: format}), nil
    default:
        return nil, fmt.Errorf("ruleset: unsupported dispatch method %q", method)
    }
}

// Candidate is an updater input, intentionally independent from Flutter model
// types. CacheID is either a rule id or PresetCacheID(...).
type Candidate struct { CacheID, URL, Label string; Interval time.Duration }
type UpdateSummary struct { Considered, Updated, NotModified, Failed int }

type AutoUpdater struct { cache *Client; sessionDone bool; perItemDelay time.Duration; changed func(context.Context, string) error; mu sync.Mutex }

type UpdaterOption func(*AutoUpdater)
func WithPerItemDelay(d time.Duration) UpdaterOption { return func(u *AutoUpdater) { if d >= 0 { u.perItemDelay = d } } }
func OnChanged(fn func(context.Context, string) error) UpdaterOption { return func(u *AutoUpdater) { u.changed = fn } }
func NewAutoUpdater(cache *Client, options ...UpdaterOption) (*AutoUpdater, error) {
    if cache == nil { return nil, errors.New("ruleset: nil cache") }
    u := &AutoUpdater{cache: cache, perItemDelay: 2 * time.Second}
    for _, option := range options { if option != nil { option(u) } }
    return u, nil
}
func (u *AutoUpdater) SessionDone() bool { u.mu.Lock(); defer u.mu.Unlock(); return u.sessionDone }
func (u *AutoUpdater) ResetSession() { u.mu.Lock(); u.sessionDone = false; u.mu.Unlock() }
func ShouldUpdate(meta Meta, interval time.Duration, now time.Time) bool {
    if interval <= 0 || meta.LastUpdated == nil { return interval > 0 }
    return !now.Before(meta.LastUpdated.Add(interval))
}
func (u *AutoUpdater) Run(ctx context.Context, candidates []Candidate) (UpdateSummary, error) {
	if ctx == nil { ctx = context.Background() }
	u.mu.Lock()
	if u.sessionDone {
		u.mu.Unlock()
		return UpdateSummary{}, nil
	}
	u.mu.Unlock()
    summary := UpdateSummary{}
    failed := false
    for i, candidate := range candidates {
        if err := contextErr(ctx); err != nil { return summary, err }
        meta, err := u.cache.ReadMeta(candidate.CacheID); if err != nil { failed = true; summary.Failed++; continue }
        if !ShouldUpdate(meta, candidate.Interval, time.Now()) { continue }
        summary.Considered++
        result := u.cache.DownloadWith(ctx, candidate.CacheID, candidate.URL, DownloadOptions{Conditional: true})
        switch result.Outcome {
        case Downloaded:
            summary.Updated++; if u.changed != nil { if err := u.changed(ctx, candidate.CacheID); err != nil { failed = true } }
        case NotModified: summary.NotModified++
        default: summary.Failed++; failed = true
        }
        if i+1 < len(candidates) { if err := wait(ctx, u.perItemDelay); err != nil { return summary, err } }
    }
    if !failed { u.mu.Lock(); u.sessionDone = true; u.mu.Unlock() }
    return summary, nil
}
