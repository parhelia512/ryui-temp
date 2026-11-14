package storage

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateIsAtomicAndSnapshotIsDeepCopy(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(doc map[string]any) error {
		doc["future"] = map[string]any{"nested": []any{"kept"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	snapshot["future"].(map[string]any)["nested"].([]any)[0] = "changed outside store"
	again, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if got := again["future"].(map[string]any)["nested"].([]any)[0]; got != "kept" {
		t.Fatalf("snapshot mutation changed store: %v", got)
	}
	before, err := os.ReadFile(filepath.Join(dir, SettingsFileName))
	if err != nil {
		t.Fatal(err)
	}
	expected := errors.New("abort")
	if err := store.Update(func(doc map[string]any) error {
		doc["future"] = "must not commit"
		return expected
	}); !errors.Is(err, expected) {
		t.Fatalf("Update error = %v, want %v", err, expected)
	}
	after, err := os.ReadFile(filepath.Join(dir, SettingsFileName))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("failed transaction changed settings file")
	}
}

func TestSourcesRemainRawAndUnknownFieldsSurvive(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(doc map[string]any) error {
		doc["sources"] = []any{map[string]any{
			"kind":                "server",
			"id":                  "one",
			"future_record_field": map[string]any{"value": true},
		}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	records, err := store.Sources()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || !strings.Contains(string(records[0]), "future_record_field") {
		t.Fatalf("raw source lost unknown field: %s", records)
	}
}

func TestCacheUsesStableHashAndSeparateDirectory(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(t.TempDir(), "files", "sub_cache")
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetCacheDir(cache); err != nil {
		t.Fatal(err)
	}
	url := "https://example.invalid/subscription"
	body := []byte("raw subscription body\x00")
	headers := map[string]string{"etag": "abc", "content-type": "text/plain"}
	if err := store.WriteCache(url, body, headers); err != nil {
		t.Fatal(err)
	}
	gotBody, gotHeaders, err := store.ReadCache(url)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotBody) != string(body) || gotHeaders["etag"] != "abc" {
		t.Fatalf("cache round trip mismatch: %q %#v", gotBody, gotHeaders)
	}
	entries, err := os.ReadDir(cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("unexpected cache layout: %#v", entries)
	}
	for _, entry := range entries {
		if len(entry.Name()) >= 64 {
			return
		}
	}
	t.Fatalf("cache body key is not SHA-256 named: %#v", entries)
}

func TestLegacyMigrationRetainsUnknownFieldsWhenComplete(t *testing.T) {
	input := map[string]any{
		"server_lists": []any{map[string]any{
			"type": "user", "id": "server-1", "raw_body": "vless://example",
			"future": "must remain",
		}},
		"custom_rules":     []any{map[string]any{"kind": "json", "json": `{"outbound":"direct"}`}},
		"dns_options":      map[string]any{"servers": []any{}, "rules": []any{}},
		"future_top_level": map[string]any{"x": 1},
	}
	got, report, err := MigrateDocumentWithOptions(input, MigrationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Migrated || report.ReadOnly {
		t.Fatalf("migration report = %#v", report)
	}
	for _, key := range []string{"future_top_level", "sources", "rules", "dns", "storage_version"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("migration failed to produce %q", key)
		}
	}
	for _, key := range []string{"server_lists", "custom_rules", "dns_options"} {
		if _, ok := got[key]; ok {
			t.Fatalf("legacy key %q was not normalized away", key)
		}
	}
	server := got["sources"].([]any)[0].(map[string]any)
	if server["future"] != "must remain" {
		t.Fatal("unknown legacy record field was dropped")
	}
}

func TestLegacyMigrationWithoutNodeLinkIsReadOnlyAndUnchanged(t *testing.T) {
	input := map[string]any{"chains": []any{map[string]any{"tag": "chain", "order": 0, "enabled": true, "hops": []any{"node-a"}}}}
	got, report, err := MigrateDocumentWithOptions(input, MigrationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !report.ReadOnly || report.Migrated {
		t.Fatalf("report = %#v", report)
	}
	if _, exists := got["storage_version"]; exists {
		t.Fatal("read-only migration wrote storage_version")
	}
	if _, exists := got["chains"]; !exists {
		t.Fatal("read-only migration changed the original document")
	}
}

func TestVersionedDocumentWithLegacyKeysIsReadOnly(t *testing.T) {
	input := map[string]any{"storage_version": 1, "sources": []any{map[string]any{"kind": "server"}}, "server_lists": []any{}}
	got, report, err := MigrateDocumentWithOptions(input, MigrationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !report.ReadOnly || got["sources"].([]any)[0].(map[string]any)["kind"] != "server" {
		t.Fatalf("unexpected conflict handling: %#v %#v", got, report)
	}
}

func TestOpenLegacyDocumentDoesNotRewriteAndBlocksUpdates(t *testing.T) {
	dir := t.TempDir()
	original := []byte(`{"server_lists":[],"future":{"x":1}}`)
	path := filepath.Join(dir, SettingsFileName)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !store.MigrationStatus().ReadOnly {
		t.Fatal("legacy document should be read-only until migration completes")
	}
	if err := store.Update(func(doc map[string]any) error { doc["x"] = true; return nil }); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Update error = %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatal("Open rewrote legacy settings")
	}
}

func TestWorkspaceManifestPreservesUnknownFields(t *testing.T) {
	manifestJSON := []byte(`{"version":1,"current":"Default","slots":[{"name":"Work","saved_at":"2026-01-01T00:00:00Z","future_slot":42}],"pending":null,"future_manifest":{"v":true}}`)
	var manifest WorkspaceManifest
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"future_slot", "future_manifest"} {
		if !strings.Contains(string(encoded), field) {
			t.Fatalf("manifest field %q was not preserved: %s", field, encoded)
		}
	}
}

func TestWorkspaceLoadChangesGeneration(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(doc map[string]any) error { doc["active"] = "default"; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveWorkspace("Default"); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(doc map[string]any) error { doc["active"] = "work"; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveWorkspace("Work"); err != nil {
		t.Fatal(err)
	}
	before := store.Generation()
	changed, err := store.LoadWorkspace("Default")
	if err != nil || !changed {
		t.Fatalf("LoadWorkspace = %v, %v", changed, err)
	}
	if store.Generation() != before+1 {
		t.Fatalf("generation = %d, want %d", store.Generation(), before+1)
	}
	doc, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if doc["active"] != "default" {
		t.Fatalf("workspace did not replace scene: %#v", doc["active"])
	}
	if err := store.UpdateIfGeneration(before, func(doc map[string]any) error { doc["stale"] = true; return nil }); err == nil {
		t.Fatal("stale generation update unexpectedly committed")
	}
}
