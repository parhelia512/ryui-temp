package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Leadaxe/lxbox/app/internal/storage"
)

func backupTestApp(t *testing.T) *Application {
	t.Helper()
	store, err := storage.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &Application{store: store, ctx: context.Background(), platform: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{}`), nil
	}}
}

func TestBackupDispatchPreviewAndList(t *testing.T) {
	a := backupTestApp(t)
	if err := a.store.Update(func(doc map[string]any) error { doc["vars"] = map[string]any{"log_level": "warn"}; return nil }); err != nil {
		t.Fatal(err)
	}
	before, err := a.store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.backupDispatch(context.Background(), "backup.preview", mustJSON(map[string]any{"data": `{"lx_backup":2,"vars":{"log_level":"debug","tun_mtu":"1400"}}`}))
	if err != nil {
		t.Fatal(err)
	}
	response := result.(map[string]any)
	if response["format"] != "lx_backup" || response["counts"] == nil || response["categories"] == nil || response["warnings"] == nil {
		t.Fatalf("preview interface: %#v", response)
	}
	after, err := a.store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if string(mustJSON(before)) != string(mustJSON(after)) || a.revision != 0 || a.generation != 0 {
		t.Fatal("preview mutated state")
	}
	listed, err := a.backupDispatch(context.Background(), "backup.list", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if listed.(map[string]any)["categories"] == nil || listed.(map[string]any)["counts"] == nil {
		t.Fatalf("category list: %#v", listed)
	}
}

func TestBackupDispatchExportModesAndCancellation(t *testing.T) {
	a := backupTestApp(t)
	for _, format := range []string{"snapshot", "portable"} {
		result, err := a.backupDispatch(context.Background(), "backup.export", mustJSON(map[string]any{"format": format}))
		if err != nil {
			t.Fatal(err)
		}
		body, ok := result.(map[string]any)["data"].(string)
		if !ok || !json.Valid([]byte(body)) {
			t.Fatalf("export %s: %#v", format, result)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.backupDispatch(ctx, "backup.list", json.RawMessage(`{}`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestBackupExportCategorySelection(t *testing.T) {
	a := backupTestApp(t)
	if err := a.store.Update(func(doc map[string]any) error {
		doc["vars"] = map[string]any{"log_level": "warn"}
		doc["sources"] = []any{map[string]any{"kind": "subscription", "id": "s", "url": "https://example.test"}}
		doc["native_prefs"] = map[string]any{"auto_start": true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	result, err := a.backupDispatch(context.Background(), "backup.export", mustJSON(map[string]any{"categories": []string{"vars"}}))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Storage map[string]any `json:"storage"`
	}
	if err := json.Unmarshal([]byte(result.(map[string]any)["data"].(string)), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Storage["storage_version"] == nil || envelope.Storage["vars"] == nil {
		t.Fatalf("selected data/version missing: %#v", envelope.Storage)
	}
	if _, exists := envelope.Storage["sources"]; exists {
		t.Fatal("unselected sources exported")
	}
	if _, exists := envelope.Storage["native_prefs"]; exists {
		t.Fatal("unselected native settings exported")
	}
}

func TestBackupImportMigrationResultIsUsed(t *testing.T) {
	a := backupTestApp(t)
	result, err := a.backupDispatch(context.Background(), "backup.import", mustJSON(map[string]any{"data": `{"app":"lxbox","kind":"backup","storage":{"storage_version":1,"vars":{"log_level":"debug"}}}`, "categories": []string{"vars"}}))
	if err != nil {
		t.Fatal(err)
	}
	if result.(map[string]any)["applied"] != true || a.revision != 1 || a.generation != 1 {
		t.Fatalf("commit counters: %#v", result)
	}
	doc, err := a.store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if doc["vars"].(map[string]any)["log_level"] != "debug" {
		t.Fatalf("import did not use migrated input: %#v", doc)
	}
}
