package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/Leadaxe/lxbox/app/internal/automation"
	"github.com/Leadaxe/lxbox/app/internal/core"
	"github.com/Leadaxe/lxbox/app/internal/storage"
)

func newDebugHTTPTestApp(t *testing.T) *Application {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &Application{store: store, supportDir: filepath.Join(dir, "files"), dataDir: filepath.Join(dir, "files"), ctx: ctx, events: eventLog{}}
}

func TestParseDebugMethod(t *testing.T) {
	for _, test := range []struct {
		input, verb, path string
		ok                bool
	}{
		{"http.GET /settings", "GET", "/settings", true},
		{"http.PUT /config", "PUT", "/config", true},
		{"http.GET /state/subs", "GET", "/state/subs", true},
		{"http.DELETE /settings/vars/key", "DELETE", "/settings/vars/key", true},
		{"http.GET /settings?x=y", "", "", false},
		{"GET /settings", "", "", false},
		{"http.TRACE /state", "", "", false},
	} {
		verb, path, ok := parseDebugMethod(test.input)
		if ok != test.ok || verb != test.verb || path != test.path {
			t.Fatalf("parseDebugMethod(%q)=(%q,%q,%v)", test.input, verb, path, ok)
		}
	}
}

func TestDebugHTTPRejectsUnportedRoutesAndWrongMethod(t *testing.T) {
	a := newDebugHTTPTestApp(t)
	_, err := a.debugHTTP(context.Background(), "http.GET /profiler/live", json.RawMessage(`{}`))
	var apiErr *automation.Error
	if !errors.As(err, &apiErr) || apiErr.Code != "not_found" {
		t.Fatalf("expected 404, got %v", err)
	}
	_, err = a.debugHTTP(context.Background(), "http.PATCH /config", json.RawMessage(`{}`))
	if !errors.As(err, &apiErr) || apiErr.Code != "not_found" {
		t.Fatalf("expected explicit 404 for unimplemented method, got %v", err)
	}
}

func TestDebugHTTPConfigReadWriteAndSettingsBlocklist(t *testing.T) {
	a := newDebugHTTPTestApp(t)
	if err := os.MkdirAll(a.supportDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.configPath(), []byte(`{"outbounds":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	value, err := a.debugHTTP(context.Background(), "http.GET /config", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(value.(json.RawMessage)) != `{"outbounds":[]}` {
		t.Fatalf("raw config changed: %#v", value)
	}
	_, err = a.debugHTTP(context.Background(), "http.GET /settings/debug_token", json.RawMessage(`{}`))
	var apiErr *automation.Error
	if !errors.As(err, &apiErr) || apiErr.Code != "not_found" {
		t.Fatalf("arbitrary setting access accepted: %v", err)
	}
	_, err = a.debugHTTP(context.Background(), "http.GET /files/local", json.RawMessage(`{"name":"../../singbox_config.json"}`))
	if !errors.As(err, &apiErr) || apiErr.Code != "not_found" {
		t.Fatalf("arbitrary file path accepted: %v", err)
	}
}

func TestScrubDebugStorageMasksSecrets(t *testing.T) {
	doc := map[string]any{
		"vars": map[string]any{"debug_token": "bearer-secret", "automation_receive_enabled": "false"},
		"sources": []any{
			map[string]any{"id": "sub", "kind": "subscription", "url": "https://example.com/sub/token"},
			map[string]any{"id": "server", "kind": "server", "origin": map[string]any{"kind": "uri", "raw": "vless://id:secret@example.com:443"}},
			map[string]any{"id": "folder", "kind": "folder", "nodes": []any{map[string]any{"raw": "vless://secret"}}},
		},
	}
	got := scrubDebugStorage(doc)
	vars := got["vars"].(map[string]any)
	if vars["debug_token"] != "***" {
		t.Fatalf("token not masked: %#v", vars)
	}
	sources := got["sources"].([]any)
	if sources[0].(map[string]any)["url"] != "https://example.com/***" {
		t.Fatalf("URL not masked: %#v", sources[0])
	}
	origin := sources[1].(map[string]any)["origin"].(map[string]any)
	if origin["raw_bytes"] == nil || origin["raw"] != nil {
		t.Fatalf("raw credentials leaked: %#v", origin)
	}
	folder := sources[2].(map[string]any)
	if folder["nodes_count"] != 1 || folder["nodes"] != nil {
		t.Fatalf("folder nodes leaked: %#v", folder)
	}
}

func TestRuntimeCoreStatusHasExpectedShape(t *testing.T) {
	status := core.Status{State: "stopped"}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err = json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	if debugBool(value["running"]) {
		t.Fatal("stopped runtime status is running")
	}
}

func TestDebugURLMask(t *testing.T) {
	masked := maskDebugURL("https://user:pass@example.com/path/token?key=value")
	parsed, err := url.Parse(masked)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.User != nil || parsed.Path != "/***" || parsed.RawQuery != "" {
		t.Fatalf("sensitive URL remained: %s", masked)
	}
}
