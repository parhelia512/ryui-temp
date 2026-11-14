package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Leadaxe/lxbox/app/internal/builder"
	"github.com/Leadaxe/lxbox/app/internal/core"
	"github.com/Leadaxe/lxbox/app/internal/parser"
	"github.com/Leadaxe/lxbox/app/internal/storage"
)

func configTestApplication(t *testing.T, sources []any) *Application {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(doc map[string]any) error {
		doc["sources"] = sources
		doc["future_settings"] = map[string]any{"preserve": true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return &Application{store: store, dataDir: dir, supportDir: dir, ctx: context.Background()}
}

func configTestServer(raw string) map[string]any {
	return map[string]any{
		"kind": "server", "id": "manual", "enabled": true,
		"origin":        map[string]any{"kind": "singbox", "raw": raw, "future_origin": "keep"},
		"body":          map[string]any{"type": "socks", "tag": "stale", "server": "stale.example", "server_port": 1},
		"future_record": map[string]any{"keep": true},
	}
}

func TestConfigPreparationReparsesOriginAndPreservesRecords(t *testing.T) {
	raw := `{"type":"socks","tag":"fresh","server":"fresh.example","server_port":1080,"future_core":{"limit":9007199254740993}}`
	record := configTestServer(raw)
	folder := map[string]any{
		"kind": "folder", "id": "folder", "nodes": []any{record},
		"future_folder": "keep",
	}
	a := configTestApplication(t, []any{record, folder})
	snapshot, err := a.snapshotConfigBuild(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(snapshot.settings)
	input, diagnostics, err := prepareConfigBuild(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("prepare: %v; diagnostics=%+v", err, diagnostics)
	}
	if input.Template["config"] == nil || input.Settings["future_settings"] == nil {
		t.Fatal("template or unknown settings were omitted")
	}
	if len(input.Sources) != 2 || len(input.Sources[0].Nodes) != 1 || len(input.Sources[1].Members) != 1 {
		t.Fatalf("unexpected prepared sources: %#v", input.Sources)
	}
	for _, node := range []map[string]any{input.Sources[0].Nodes[0], input.Sources[1].Members[0].Node} {
		if node["server"] != "fresh.example" || node["tag"] != "fresh" || node["type"] != "socks" {
			t.Fatalf("stale projection used instead of origin.raw: %#v", node)
		}
		unknown, err := json.Marshal(node["future_core"])
		if err != nil || !bytes.Contains(unknown, []byte("9007199254740993")) {
			t.Fatalf("unknown core value changed during parsing: %s, %v", unknown, err)
		}
	}
	if input.Sources[0].Raw["future_record"] == nil || input.Sources[1].Raw["future_folder"] != "keep" {
		t.Fatal("unknown source fields were dropped")
	}
	memberRaw, ok := input.Sources[1].Members[0].Raw.(map[string]any)
	if !ok || memberRaw["future_record"] == nil {
		t.Fatal("complete folder member record was not retained")
	}
	after, _ := json.Marshal(snapshot.settings)
	if !bytes.Equal(before, after) {
		t.Fatal("preparation changed the captured settings")
	}
}

func TestConfigPreparationParsesNativeBodyAndSkipsDisabledMaterial(t *testing.T) {
	native := map[string]any{
		"kind": "server", "id": "native", "future_record": true,
		"body": map[string]any{"type": "socks", "tag": "native", "server": "native.example", "server_port": 1080},
	}
	a := configTestApplication(t, []any{native,
		map[string]any{"kind": "subscription", "enabled": false, "url": "https://must-not-fetch.invalid/list"},
		map[string]any{"kind": "folder", "id": "disabled-members", "nodes": []any{
			map[string]any{"kind": "server", "enabled": false, "origin": map[string]any{"raw": "broken"}},
		}},
	})
	snapshot, err := a.snapshotConfigBuild(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	input, diagnostics, err := prepareConfigBuild(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("native body or disabled source was handled incorrectly: %v; %+v", err, diagnostics)
	}
	if len(input.Sources[0].Nodes) != 1 || input.Sources[0].Nodes[0]["server"] != "native.example" {
		t.Fatalf("native body did not use the unified parser: %#v", input.Sources[0])
	}
	if len(snapshot.cache) != 0 || len(snapshot.cacheError) != 0 || len(input.Sources[1].Nodes) != 0 {
		t.Fatal("disabled subscription read cache or supplied nodes")
	}
	if len(input.Sources[2].Members) != 1 || input.Sources[2].Members[0].Node != nil {
		t.Fatal("disabled member was parsed")
	}
}

func TestConfigBuildWithBundledWizardTemplate(t *testing.T) {
	a := configTestApplication(t, []any{configTestServer(`{"type":"socks","tag":"online","server":"proxy.example","server_port":1080}`)})
	snapshot, err := a.snapshotConfigBuild(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	input, diagnostics, err := prepareConfigBuild(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("prepare: %v; %+v", err, diagnostics)
	}
	result, err := builder.Build(context.Background(), input)
	if err != nil {
		t.Fatalf("bundled wizard template could not build a supported node: %v; %+v", err, result.Diagnostics)
	}
	if !json.Valid(result.Config) || !configHasNodes(result.Config) {
		t.Fatalf("builder returned no usable configuration: %s", result.Config)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.commitConfigBuild(ctx, snapshot, json.RawMessage(result.Config)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled commit did not retain cancellation: %v", err)
	}
	if _, err := os.Stat(a.configPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled commit wrote configuration: %v", err)
	}
}

func TestConfigPreparationUsesOnlyOriginalOfflineCache(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "build must not fetch", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	url := server.URL + "/subscription"
	source := map[string]any{
		"kind": "subscription", "id": "sub", "url": url,
		"nodes": []any{map[string]any{"type": "socks", "tag": "stale"}},
	}
	a := configTestApplication(t, []any{source})
	original := []byte("ss://YWVzLTI1Ni1nY206cGFzcw==@cached.example:443#cached")
	if err := a.store.WriteCache(url, original, map[string]string{"etag": "original"}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := a.snapshotConfigBuild(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	input, diagnostics, err := prepareConfigBuild(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("prepare: %v; diagnostics=%+v", err, diagnostics)
	}
	if len(input.Sources[0].Nodes) != 1 || input.Sources[0].Nodes[0]["server"] != "cached.example" {
		t.Fatalf("original cache did not produce emitted node: %#v", input.Sources[0].Nodes)
	}
	if _, exists := input.Sources[0].Nodes[0]["uri"]; exists {
		t.Fatal("foreign raw URI map was passed to builder instead of SingBox output")
	}
	body, headers, err := a.store.ReadCache(url)
	if err != nil || !bytes.Equal(body, original) || headers["etag"] != "original" {
		t.Fatalf("build preparation changed cache: %s, %v, %v", body, headers, err)
	}
	if err := a.store.RemoveCache(url); err != nil {
		t.Fatal(err)
	}
	value, err := a.buildConfig(context.Background())
	if err == nil || !strings.Contains(err.Error(), "cache") {
		t.Fatalf("missing cache was silently accepted: value=%#v error=%v", value, err)
	}
	response, ok := value.(map[string]any)
	if !ok || response["saved"] != false || len(response["diagnostics"].([]any)) == 0 {
		t.Fatalf("missing cache did not return failure diagnostics: %#v", value)
	}
	if requests.Load() != 0 {
		t.Fatal("configuration build performed a network request")
	}
}

func TestConfigSubscriptionUsesSharedDisabledNodeOverlay(t *testing.T) {
	url := "https://cached.invalid/disabled"
	record := map[string]any{
		"kind": "subscription", "id": "disabled-overlay", "url": url,
		"disabled": map[string]any{"cached": json.Number("0")},
	}
	a := configTestApplication(t, []any{record})
	if err := a.store.WriteCache(url, []byte("ss://YWVzLTI1Ni1nY206cGFzcw==@cached.example:443#cached"), nil); err != nil {
		t.Fatal(err)
	}
	snapshot, err := a.snapshotConfigBuild(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	input, diagnostics, err := prepareConfigBuild(context.Background(), snapshot)
	if err != nil || len(input.Sources[0].Nodes) != 0 {
		t.Fatalf("disabled-only source should prepare as empty: %#v %v %+v", input.Sources, err, diagnostics)
	}
	if _, err := os.Stat(a.configPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("offline preparation wrote config: %v", err)
	}
}

func TestConfigPreparationLeavesChainAndAutoForBuilder(t *testing.T) {
	chain := map[string]any{
		"kind": "chain", "tag": "chain", "hops": []any{map[string]any{"tag": "hop"}},
		"body": map[string]any{"type": "chain", "idle_timeout": "0s"}, "future_chain": true,
	}
	auto := map[string]any{
		"kind": "auto", "tag": "pool", "future_group": true,
		"origin": map[string]any{"raw": "intentionally not a parseable server"},
		"body":   map[string]any{"type": "urltest", "outbounds": []any{"hop"}, "interval": "5m"},
	}
	a := configTestApplication(t, []any{chain, map[string]any{
		"kind": "folder", "id": "folder", "nodes": []any{auto, chain},
	}})
	snapshot, err := a.snapshotConfigBuild(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	input, diagnostics, err := prepareConfigBuild(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("groups were parsed as server documents: %v; %+v", err, diagnostics)
	}
	if input.Sources[0].Raw["future_chain"] != true || len(input.Sources[0].Nodes) != 0 {
		t.Fatalf("chain record lost: %#v", input.Sources[0])
	}
	members := input.Sources[1].Members
	if len(members) != 2 || members[0].Node != nil || members[1].Node != nil {
		t.Fatalf("group records were prematurely emitted: %#v", members)
	}
	if members[0].Raw.(map[string]any)["future_group"] != true {
		t.Fatal("auto record was not retained")
	}
}

func TestConfigPreparationRejectsUnknownUnsupportedAndBrokenOrigin(t *testing.T) {
	for _, test := range []struct {
		name   string
		source map[string]any
	}{
		{"future source", map[string]any{"kind": "future-source"}},
		{"unsupported member", map[string]any{"kind": "folder", "nodes": []any{map[string]any{"kind": "unsupported", "reason": "unparsed"}}}},
		{"invalid origin", configTestServer("this is not a supported node")},
		{"empty origin", configTestServer("")},
		{"mixed supported and unsupported", configTestServer("ss://YWVzLTI1Ni1nY206cGFzcw==@valid.example:443#valid\nnot-supported://host:1")},
		{"mixed subscription", map[string]any{"kind": "subscription", "id": "mixed", "url": "https://cached.invalid/list"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := configTestApplication(t, []any{test.source})
			if test.name == "mixed subscription" {
				if err := a.store.WriteCache("https://cached.invalid/list", []byte("ss://YWVzLTI1Ni1nY206cGFzcw==@valid.example:443#valid\nnot-supported://host:1"), nil); err != nil {
					t.Fatal(err)
				}
			}
			value, err := a.buildConfig(context.Background())
			if err == nil {
				t.Fatalf("invalid input reported success: %#v", value)
			}
			response, ok := value.(map[string]any)
			if !ok || response["saved"] != false || len(response["diagnostics"].([]any)) == 0 {
				t.Fatalf("missing diagnostic failure envelope: %#v", value)
			}
			if _, err := os.Stat(a.configPath()); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid build wrote configuration: %v", err)
			}
		})
	}
}

func TestConfigBuildPropagatesCancellationAndDeadline(t *testing.T) {
	a := configTestApplication(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.buildConfig(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was lost: %v", err)
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := a.buildConfig(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline was lost: %v", err)
	}
	if _, _, err := parseConfigNodes(ctx, []byte("ignored"), parser.Source{}, "test"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("parse deadline was lost: %v", err)
	}
}

func TestConfigBuildCancelsWhileWaitingForMutation(t *testing.T) {
	for _, commit := range []bool{false, true} {
		a := configTestApplication(t, nil)
		a.mutation.Lock()
		ctx, cancel := context.WithCancel(context.Background())
		started := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			close(started)
			if commit {
				done <- a.commitConfigBuild(ctx, configBuildSnapshot{}, json.RawMessage(`{}`))
			} else {
				_, err := a.snapshotConfigBuild(ctx)
				done <- err
			}
		}()
		<-started
		cancel()
		select {
		case err := <-done:
			a.mutation.Unlock()
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("lock wait swallowed cancellation: %v", err)
			}
		case <-time.After(2 * time.Second):
			a.mutation.Unlock()
			<-done
			t.Fatal("canceled build stayed blocked on mutation lock")
		}
	}
}

func TestConfigCommitRejectsChangedRevisionAndWorkspace(t *testing.T) {
	for _, ownershipChange := range []bool{false, true} {
		a := configTestApplication(t, nil)
		snapshot, err := a.snapshotConfigBuild(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		a.mutation.Lock()
		if ownershipChange {
			a.generation++
		} else {
			a.revision++
		}
		a.mutation.Unlock()
		if err := a.commitConfigBuild(context.Background(), snapshot, json.RawMessage(`{}`)); !errors.Is(err, errConfigBuildStale) {
			t.Fatalf("stale commit reached core/save: %v", err)
		}
		if _, err := os.Stat(a.configPath()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale build wrote configuration: %v", err)
		}
	}
}

func TestConfigCommitUsesRealCoreValidationBeforeReplacingFile(t *testing.T) {
	a := configTestApplication(t, nil)
	// validate does not need an initialized controller or Android callbacks.
	a.core = &core.Controller{}
	previous := []byte(`{"outbounds":[{"type":"direct","tag":"previous"}]}`)
	if err := os.WriteFile(a.configPath(), previous, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := a.snapshotConfigBuild(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	invalid := json.RawMessage(`{"outbounds":[{"type":"this-protocol-does-not-exist","tag":"broken"}]}`)
	if err := a.commitConfigBuild(context.Background(), snapshot, invalid); err == nil {
		t.Fatal("invalid configuration bypassed real core validation")
	}
	actual, err := os.ReadFile(a.configPath())
	if err != nil || !bytes.Equal(previous, actual) {
		t.Fatalf("failed validation replaced saved config: %s, %v", actual, err)
	}
	current, err := a.store.Snapshot()
	if err != nil || !reflect.DeepEqual(current, snapshot.settings) {
		t.Fatalf("failed validation mutated settings: %v", err)
	}
}

func TestConfigHasNodesRejectsControlOnlyAndEmptyConfigurations(t *testing.T) {
	for _, raw := range []string{
		`{}`, `{"outbounds":[]}`, `{"outbounds":[{"type":"direct"},{"type":"block"},{"type":"selector"},{"type":"urltest"},{"type":"chain"}]}`,
	} {
		if configHasNodes([]byte(raw)) {
			t.Fatalf("control-only config reported usable nodes: %s", raw)
		}
	}
	for _, raw := range []string{
		`{"outbounds":[{"type":"socks","tag":"node"}]}`,
		`{"endpoints":[{"type":"wireguard","tag":"endpoint"}]}`,
	} {
		if !configHasNodes([]byte(raw)) {
			t.Fatalf("proxy or endpoint was not recognized: %s", raw)
		}
	}
}
