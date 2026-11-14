package ruleset

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func newTestClient(t *testing.T, options ...Option) *Client {
	t.Helper()
	client, err := New(t.TempDir(), options...)
	if err != nil { t.Fatal(err) }
	return client
}

func TestDownloadPreservesBytesAndConditional304LeavesFileUntouched(t *testing.T) {
	payload := []byte{0, 0xff, 0x53, 0x52, 0x53, 0x00}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			if got := r.Header.Get("If-None-Match"); got != "" { t.Errorf("unexpected initial ETag %q", got) }
			w.Header().Set("ETag", `"v1"`)
			_, _ = w.Write(payload)
			return
		}
		if got := r.Header.Get("If-None-Match"); got != `"v1"` { t.Errorf("If-None-Match = %q", got) }
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	client := newTestClient(t, WithTimeout(2*time.Second))
	first := client.DownloadWith(context.Background(), "stable-id", server.URL, DownloadOptions{Backoff: []time.Duration{0}})
	if first.Outcome != Downloaded || !first.Changed() { t.Fatalf("first outcome = %#v", first) }
	path := first.Path
	before, err := os.Stat(path); if err != nil { t.Fatal(err) }
	got, meta, err := client.ReadOffline(context.Background(), "stable-id")
	if err != nil { t.Fatal(err) }
	if string(got) != string(payload) { t.Fatalf("cached bytes changed: %v", got) }
	if meta.ETag != `"v1"` { t.Fatalf("etag = %q", meta.ETag) }

	second := client.DownloadWith(context.Background(), "stable-id", server.URL, DownloadOptions{Conditional:true})
	if second.Outcome != NotModified || second.Changed() { t.Fatalf("second outcome = %#v", second) }
	after, err := os.Stat(path); if err != nil { t.Fatal(err) }
	if !before.ModTime().Equal(after.ModTime()) { t.Fatal("304 rewrote cached bytes") }
	if requests != 2 { t.Fatalf("requests = %d", requests) }
}

func TestDownloadFailureKeepsOldFileAndWritesFailureMetadata(t *testing.T) {
	responses := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		responses++
		if responses == 1 { _, _ = w.Write([]byte("first")); return }
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer server.Close()
	client := newTestClient(t, WithTimeout(2*time.Second))
	first := client.DownloadWith(context.Background(), "id", server.URL, DownloadOptions{Attempts:1})
	if first.Outcome != Downloaded { t.Fatalf("download failed: %#v", first) }
	second := client.Download(context.Background(), "id", server.URL, false)
	if second.Outcome != Failed || second.Path == "" { t.Fatalf("404 result = %#v", second) }
	bytes, err := os.ReadFile(first.Path); if err != nil { t.Fatal(err) }
	if string(bytes) != "first" { t.Fatalf("old cache lost: %q", bytes) }
	meta, err := client.ReadMeta("id"); if err != nil { t.Fatal(err) }
	if meta.LastError != "HTTP 404" || meta.LastUpdated == nil { t.Fatalf("meta = %#v", meta) }
}

type roundTripFunc func(*http.Request) (*http.Response, error)
func (f roundTripFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestDownloadSizeLimitCancellationAndOfflineRead(t *testing.T) {
	client := newTestClient(t, WithMaxBytes(4), WithHTTPClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode:200, Header:make(http.Header), Body:http.NoBody, ContentLength:5, Request:r}
	})))
	result := client.DownloadWith(context.Background(), "limited", "http://example.invalid/rs", DownloadOptions{Attempts:1})
	if result.Outcome != Failed || !errors.Is(result.Err, ErrTooLarge) { t.Fatalf("oversize result = %#v", result) }
	if _, _, err := client.ReadOffline(context.Background(), "limited"); !errors.Is(err, os.ErrNotExist) { t.Fatalf("oversized response created cache: %v", err) }

	cancelled, cancel := context.WithCancel(context.Background()); cancel()
	if _, _, err := client.ReadOffline(cancelled, "missing"); !errors.Is(err, context.Canceled) { t.Fatalf("offline cancel error = %v", err) }
}

func TestDispatchUsesActualDownloadAndRejectsTraversal(t *testing.T) {
	client := newTestClient(t, WithHTTPClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode:200, Header:make(http.Header), Body:io.NopCloser(strings.NewReader("json bytes remain exact")), ContentLength:-1, Request:r}, nil
	})))
	value, err := client.Dispatch(context.Background(), "rulesets.download", map[string]any{"id":"json", "url":"http://example.invalid/rules.json"})
	if err != nil { t.Fatal(err) }
	result := value.(Result)
	if result.Outcome != Downloaded || !strings.HasSuffix(result.Path, ".json") { t.Fatalf("dispatch result = %#v", result) }
	got, _, err := client.ReadFormat(context.Background(), "json", "json")
	if err != nil { t.Fatal(err) }
	if string(got) != "json bytes remain exact" { t.Fatalf("stored JSON transformed: %q", got) }
	if _, err := client.ReadMeta("../outside"); !errors.Is(err, ErrInvalidID) { t.Fatalf("traversal error = %v", err) }
}

func TestShouldUpdateBoundaries(t *testing.T) {
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	fresh := now.Add(-time.Hour)
	if !ShouldUpdate(Meta{}, time.Hour, now) { t.Fatal("missing successful timestamp must be stale") }
	if !ShouldUpdate(Meta{LastUpdated:&fresh}, time.Hour, now) { t.Fatal("timestamp exactly at TTL boundary must be stale") }
	notYet := now.Add(-30 * time.Minute)
	if ShouldUpdate(Meta{LastUpdated:&notYet}, time.Hour, now) { t.Fatal("unexpired TTL was stale") }
	if ShouldUpdate(Meta{}, 0, now) { t.Fatal("disabled interval must not update") }
}
