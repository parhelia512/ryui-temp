package backup

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDecodeMarkersAndExactRaw(t *testing.T) {
	ctx := context.Background()
	raw := []byte(" {\n\"lx_backup\":2,\"sources\":[{\"kind\":\"server\",\"tag\":\"node\",\"origin\":{\"kind\":\"uri\",\"raw\":\"ss://exact%20raw#name\"}}]}")
	doc, err := Decode(ctx, raw)
	if err != nil { t.Fatal(err) }
	if !doc.Portable || doc.Version != 2 || string(doc.Raw) != string(raw) || doc.Context != ctx { t.Fatalf("document metadata lost: %#v", doc) }
	record := doc.Data["sources"].([]any)[0].(map[string]any)
	if record["origin"].(map[string]any)["raw"] != "ss://exact%20raw#name" { t.Fatal("origin raw changed") }
	for _, input := range []string{`{"lx_backup":2} []`, `{"lx_backup":2} garbage`, `null`, `[]`} {
		if _, err := Decode(ctx, []byte(input)); err == nil { t.Fatalf("accepted invalid document %q", input) }
	}
	if _, err := Decode(ctx, []byte(`{"lx_backup":3}`)); !errors.Is(err, ErrUnsupportedVersion) { t.Fatalf("version guard: %v", err) }
	cancelled, cancel := context.WithCancel(ctx); cancel()
	if _, err := Decode(cancelled, raw); !errors.Is(err, context.Canceled) { t.Fatalf("cancellation ignored: %v", err) }
}

func TestDecodeSnapshotAndPortableFamilies(t *testing.T) {
	snapshot, err := Decode(context.Background(), []byte(`{"app":"lxbox","kind":"backup","storage":{"storage_version":1,"future":{"safe":true}}}`))
	if err != nil || !snapshot.Snapshot { t.Fatalf("snapshot: %#v %v", snapshot, err) }
	if snapshot.Data["future"].(map[string]any)["safe"] != true { t.Fatal("snapshot field lost") }
	legacy, err := Decode(context.Background(), []byte(`{"lx_backup":1,"subscriptions":[{"url":"https://example.test/sub","enabled":true}],"servers":[{"uri":"ss://secret","node_tag":"node"}]}`))
	if err != nil { t.Fatal(err) }
	if len(legacy.Data["sources"].([]any)) != 2 { t.Fatalf("legacy sources: %#v", legacy.Data) }
	modern, err := Decode(context.Background(), []byte(`{"lx_backup":2,"sources":[{"kind":"server","tag":"node","origin":{"kind":"uri","raw":"ss://raw","unrecognized":1},"unknown":2}],"native_prefs":{"auto_start":"yes","keep_on_exit":false},"vars":{"log_level":"debug","bind_interface":"eth0"}}`))
	if err != nil { t.Fatal(err) }
	source := modern.Data["sources"].([]any)[0].(map[string]any)
	if _, exists := source["unknown"]; exists { t.Fatal("unknown field stored") }
	if _, exists := source["origin"].(map[string]any)["unrecognized"]; exists { t.Fatal("unknown nested field stored") }
	if modern.Data["native_prefs"].(map[string]any)["keep_on_exit"] != false { t.Fatal("false preference lost") }
	if _, exists := modern.Data["native_prefs"].(map[string]any)["auto_start"]; exists { t.Fatal("wrong preference type accepted") }
	if _, exists := modern.Data["vars"].(map[string]any)["bind_interface"]; exists { t.Fatal("local var imported") }
	for _, expected := range []string{WarnUnknownField, WarnTypeMismatch, WarnVarSkipped} { if !containsWarning(modern.Warnings, expected) { t.Fatalf("missing %s: %#v", expected, modern.Warnings) } }
}

func TestMergePreservesEditedSettingsAndSelection(t *testing.T) {
	current := map[string]any{"storage_version":1,"vars":map[string]any{"log_level":"warn"},"sources":[]any{map[string]any{"id":"mine","kind":"server","tag":"first"}},"rules":[]any{map[string]any{"id":"old","num":1005,"body":map[string]any{"domain":[]any{"old.test"}}}}}
	incoming := map[string]any{"vars":map[string]any{"log_level":"debug","tun_mtu":"1400"},"sources":[]any{map[string]any{"id":"mine","kind":"server","tag":"changed"},map[string]any{"id":"new","kind":"server","tag":"second"}}}
	merged, err := Merge(current, incoming, []string{"sources","vars"}, false, nil)
	if err != nil { t.Fatal(err) }
	vars := merged.Data["vars"].(map[string]any)
	if vars["log_level"] != "warn" || vars["tun_mtu"] != "1400" { t.Fatalf("vars: %#v", vars) }
	if len(merged.Data["sources"].([]any)) != 2 || merged.Data["sources"].([]any)[0].(map[string]any)["tag"] != "first" { t.Fatal("source identity did not preserve receiver") }
	replaced, err := Merge(current, incoming, []string{"sources"}, true, nil)
	if err != nil { t.Fatal(err) }
	if len(replaced.Data["rules"].([]any)) != 1 { t.Fatal("unselected rules were replaced") }
	if current["vars"].(map[string]any)["tun_mtu"] != nil { t.Fatal("receiver mutated") }
	if _, err := Merge(current, incoming, []string{"typo"}, false, nil); err == nil { t.Fatal("invalid category accepted") }
}

func TestRulesAbsentVersusDeclaredEmptyAndSnapshotAxis(t *testing.T) {
	current := map[string]any{"rules":[]any{map[string]any{"id":"a","kind":"inline","num":1008,"body":map[string]any{"domain":[]any{"a"}}}}}
	merged, err := Merge(current, map[string]any{}, []string{"rules"}, false, map[string]bool{})
	if err != nil || len(merged.Data["rules"].([]any)) != 1 { t.Fatalf("absent rules: %#v %v", merged, err) }
	merged, err = Merge(current, map[string]any{"rules":[]any{}}, []string{"rules"}, false, map[string]bool{"rules":true})
	if err != nil || len(merged.Data["rules"].([]any)) != 0 || !containsWarning(merged.Warnings, WarnRulesReplaced) { t.Fatalf("declared empty rules: %#v %v", merged, err) }
	merged, err = Merge(current, map[string]any{"rules":[]any{map[string]any{"id":"b","kind":"inline","num":9,"body":map[string]any{"domain":[]any{"b"}}}}}, []string{"rules"}, false, nil)
	if err != nil { t.Fatal(err) }
	num, _ := integer(merged.Data["rules"].([]any)[1].(map[string]any)["num"])
	if num != 1009 { t.Fatalf("append rule num = %d", num) }
}

func TestExportPortableDoesNotCarryRuntimeFields(t *testing.T) {
	snapshot := map[string]any{"sources":[]any{map[string]any{"kind":"subscription","id":"sub","url":"https://example.test","last_updated":"runtime","identity":map[string]any{"user_agent":"custom"}}},"vars":map[string]any{"log_level":"debug","bind_interface":"eth0"}}
	raw, warnings, err := ExportPortable(snapshot, "test")
	if err != nil { t.Fatal(err) }
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil { t.Fatal(err) }
	if root["lx_backup"] != float64(2) { t.Fatal("wrong export marker") }
	if _, exists := root["rules"]; !exists { t.Fatal("export must declare rules") }
	if strings.Contains(string(raw), "last_updated") || strings.Contains(string(raw), "bind_interface") { t.Fatalf("runtime data exported: %s", raw) }
	if len(warnings) == 0 { t.Fatal("losses need warnings") }
}

func containsWarning(warnings []Warning, code string) bool {
	for _, warning := range warnings { if warning.Code == code { return true } }
	return false
}
