package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportsDispatchRejectsArbitraryPaths(t *testing.T) {
	dir := t.TempDir()
	a := &Application{supportDir: dir, dataDir: dir, ctx: context.Background()}
	_, err := a.reportsDispatch(context.Background(), "reports.read", json.RawMessage(`{"id":"crash:current","file":"..\\outside"}`))
	if err == nil {
		t.Fatal("expected arbitrary path to be rejected")
	}
}

func TestReportsDispatchListsCrashAndOOMWithUIShape(t *testing.T) {
	dir := t.TempDir()
	crashDir := filepath.Join(dir, reportCrashArchive, "2026-11-14T00-00-00")
	oomDir := filepath.Join(dir, reportOOMArchive, "2026-11-14T00-01-00")
	for _, path := range []string{crashDir, oomDir} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(crashDir, reportTraceName), []byte("token=secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crashDir, reportMetadataName), []byte(`{"coreVersion":"1.14.4"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oomDir, reportMetadataName), []byte(`{"memoryUsage":"1 MB","token":"secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	a := &Application{supportDir: dir, dataDir: dir, ctx: context.Background()}
	value, err := a.reportsDispatch(context.Background(), "reports.list", nil)
	if err != nil {
		t.Fatal(err)
	}
	items, ok := value.([]map[string]any)
	if !ok || len(items) != 2 {
		t.Fatalf("unexpected report list: %#v", value)
	}
	for _, item := range items {
		if item["kind"] != "crash" && item["kind"] != "oom" {
			t.Fatalf("missing UI kind: %#v", item)
		}
		if item["id"] == "" || item["name"] == "" {
			t.Fatalf("missing UI id/name: %#v", item)
		}
	}
}

func TestReportsShareReturnsRedactedUIPayload(t *testing.T) {
	dir := t.TempDir()
	reportDir := filepath.Join(dir, reportCrashArchive, "2026-11-14T00-00-00")
	if err := os.MkdirAll(reportDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reportDir, reportTraceName), []byte("Authorization: Bearer super-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a := &Application{supportDir: dir, dataDir: dir, ctx: context.Background()}
	value, err := a.reportsDispatch(context.Background(), "reports.share", json.RawMessage(`{"kind":"crash","id":"2026-11-14T00-00-00"}`))
	if err != nil {
		t.Fatal(err)
	}
	payload, ok := value.(map[string]any)
	if !ok || payload["name"] != "2026-11-14T00-00-00-go.log" || payload["mime"] != "text/plain" {
		t.Fatalf("unexpected share payload: %#v", value)
	}
	if strings.Contains(payload["data"].(string), "super-secret") {
		t.Fatal("share payload leaked bearer token")
	}
}

func TestReportsDispatchPprofKindAlias(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := &Application{}
	_, err := a.reportsDispatch(ctx, "pprof.capture", json.RawMessage(`{"kind":"heap"}`))
	if err == nil || err != context.Canceled {
		t.Fatalf("expected canceled pprof request, got %v", err)
	}
}

func TestFormatRuntimeConfigUsesSingParserAndKeepsUnknownFields(t *testing.T) {
	ctx := context.Background()
	value, err := formatRuntimeConfig(ctx, json.RawMessage(`{"inbounds":[],"future_field":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains([]byte(value.(string)), []byte(`"future_field": true`)) {
		t.Fatalf("unknown field was not preserved: %s", value)
	}
}
