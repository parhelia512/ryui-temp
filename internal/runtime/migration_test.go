package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/Leadaxe/lxbox/app/internal/core"
	"github.com/Leadaxe/lxbox/app/internal/storage"
)

func migrationTestApplication(t *testing.T, doc map[string]any, platform core.CallFunc) *Application {
	t.Helper()
	store, err := storage.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if doc != nil {
		if err := store.Update(func(current map[string]any) error {
			for key := range current {
				delete(current, key)
			}
			for key, value := range doc {
				current[key] = value
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	return &Application{store: store, platform: platform, ctx: context.Background()}
}

func TestMigrationOptionsUseEmbeddedTemplateAndParsedLegacyNodeFacts(t *testing.T) {
	a := migrationTestApplication(t, nil, nil)
	doc := map[string]any{
		"server_lists": []any{
			map[string]any{
				"type": "user", "id": "local", "enabled": true,
				"tag_prefix": "Home",
				"raw_body": `{"outbounds":[{"type":"socks","tag":"proxy-a","server":"127.0.0.1","server_port":1080}]}`,
			},
			map[string]any{"type": "subscription", "id": "sub-1", "url": "https://offline.invalid/sub"},
		},
	}
	if err := a.store.Update(func(current map[string]any) error {
		current["server_lists"] = doc["server_lists"]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.store.WriteCache("https://offline.invalid/sub", []byte("vless://11111111-1111-1111-1111-111111111111@example.invalid:443#remote-a"), nil); err != nil {
		t.Fatal(err)
	}
	options := a.migrationOptions(context.Background())
	if got := options.NodeLinks["Home proxy-a"]; !reflect.DeepEqual(got, map[string]any{"tag": "Home proxy-a"}) {
		t.Fatalf("user node link = %#v", got)
	}
	if got := options.NodeLinks["remote-a"]; !reflect.DeepEqual(got, map[string]any{"folder_id": "sub-1", "tag": "remote-a"}) {
		t.Fatalf("cached subscription node link = %#v", got)
	}
	if options.SubscriptionBodies["https://offline.invalid/sub"] == nil {
		t.Fatal("offline cache body was not supplied to migration")
	}
	if options.PresetIDsByDNSTag["ru-direct:yandex_udp"] != "ru-direct" {
		t.Fatalf("DNS preset mapping missing: %#v", options.PresetIDsByDNSTag)
	}
	if options.RuleVarDefaults["ru-direct"]["outbound"] != "direct-out" {
		t.Fatalf("rule preset variable defaults missing: %#v", options.RuleVarDefaults["ru-direct"])
	}
	if options.PresetVarDefaults["google_udp"]["dns_ip"] != "8.8.8.8" {
		t.Fatalf("DNS variable defaults missing: %#v", options.PresetVarDefaults["google_udp"])
	}
}

func TestMigrationDispatchRunsMutationAndSurfacesReadOnlyGuard(t *testing.T) {
	a := migrationTestApplication(t, map[string]any{
		"server_lists": []any{map[string]any{
				"type": "user", "id": "manual", "name": "manual", "enabled": true,
				"raw_body": `{"outbounds":[{"type":"socks","tag":"local","server":"127.0.0.1","server_port":1080}]}`,
			}},
	}, nil)
	beforeGeneration, beforeRevision := a.generation, a.revision
	value, err := a.migrationDispatch(context.Background(), "storage.migrate", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	report, ok := value.(storage.MigrationReport)
	if !ok || !report.Migrated || report.ReadOnly {
		t.Fatalf("unexpected migration report: %#v", value)
	}
	if a.generation != beforeGeneration+1 || a.revision != beforeRevision+1 {
		t.Fatalf("mutation counters = generation %d, revision %d", a.generation, a.revision)
	}
	status, err := a.migrationDispatch(context.Background(), "storage.status", nil)
	if err != nil {
		t.Fatal(err)
	}
	statusObject, ok := status.(map[string]any)
	if !ok || statusObject["read_only"] != false {
		t.Fatalf("status did not expose writable state: %#v", status)
	}

	blocked := migrationTestApplication(t, map[string]any{
		"chains": []any{map[string]any{"tag": "chain-a", "enabled": true, "hops": []any{"unresolved"}}},
	}, nil)
	value, err = blocked.migrationDispatch(context.Background(), "storage.migrate", json.RawMessage(`{}`))
	if !errors.Is(err, storage.ErrReadOnly) {
		t.Fatalf("unresolved NodeLink error = %v, want ErrReadOnly", err)
	}
	blockedReport, ok := value.(storage.MigrationReport)
	if !ok || !blockedReport.ReadOnly || len(blockedReport.Warnings) == 0 {
		t.Fatalf("read-only guard report was not returned: %#v", value)
	}
	blockedStatus, err := blocked.migrationDispatch(context.Background(), "storage.status", nil)
	if err != nil {
		t.Fatal(err)
	}
	blockedState, _ := blockedStatus.(map[string]any)
	if blockedState["read_only"] != true {
		t.Fatalf("status hid read-only guard: %#v", blockedStatus)
	}
}

func TestApplyNativeSettingsUsesHostShapeAndOmitsDefaults(t *testing.T) {
	var gotMethod string
	var gotArgs map[string]any
	platform := func(_ context.Context, method string, args json.RawMessage) (json.RawMessage, error) {
		gotMethod = method
		if err := json.Unmarshal(args, &gotArgs); err != nil {
			return nil, err
		}
		return json.RawMessage(`{"applied":2}`), nil
	}
	a := migrationTestApplication(t, nil, platform)
	doc := map[string]any{
		"native_prefs": map[string]any{
			"auto_start": true, "background_mode": "lazy", "app_theme_mode": "dark",
			"not_a_native_pref": "drop",
		},
		"vars": map[string]any{
			"appfunctions_enabled": true, "automation_receive_enabled": false,
			"wizard_battery_v1": "asked", "app_language": "en",
		},
	}
	if err := a.applyNativeSettings(context.Background(), doc); err != nil {
		t.Fatal(err)
	}
	if gotMethod != "nativeprefs.apply" {
		t.Fatalf("platform method = %q", gotMethod)
	}
	want := map[string]any{
		"native_prefs": map[string]any{"auto_start": true, "background_mode": "lazy", "app_theme_mode": "dark"},
		"vars": map[string]any{"appfunctions_enabled": true, "automation_receive_enabled": false, "wizard_battery_v1": "asked"},
	}
	if !reflect.DeepEqual(gotArgs, want) {
		t.Fatalf("nativeprefs.apply payload = %#v, want %#v", gotArgs, want)
	}
}

func TestMigrationDispatchRejectsUnsupportedRecoveryAndUnknownMethod(t *testing.T) {
	a := migrationTestApplication(t, nil, nil)
	if _, err := a.migrationDispatch(context.Background(), "storage.recover", json.RawMessage(`{}`)); err == nil {
		t.Fatal("recover without explicit corrupt_settings guard unexpectedly succeeded")
	}
	if _, err := a.migrationDispatch(context.Background(), "storage.unknown", nil); err == nil {
		t.Fatal("unknown migration method unexpectedly succeeded")
	}
}
