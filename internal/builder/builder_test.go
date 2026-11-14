package builder

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/Leadaxe/lxbox/app/assets"
)

func TestEmbeddedWizardFreshBuildWithCachedShadowsocks(t *testing.T) {
	templateBytes, err := assets.Read("wizard_template.json")
	if err != nil {
		t.Fatal(err)
	}
	var template map[string]any
	if err := json.Unmarshal(templateBytes, &template); err != nil {
		t.Fatal(err)
	}
	input := Input{
		Template: template,
		Sources: []SourceInput{{
			ID: "server-1", Kind: "server", Raw: map[string]any{"kind": "server", "id": "server-1"},
			Nodes: []map[string]any{{"type": "shadowsocks", "tag": "ss-home", "server": "192.0.2.10", "server_port": 8388, "method": "aes-128-gcm", "password": "secret"}},
		}},
	}
	result, err := Build(context.Background(), input)
	if err != nil {
		t.Fatalf("fresh build failed: %v; diagnostics: %#v", err, result.Diagnostics)
	}
	if !result.Complete {
		t.Fatalf("builder returned incomplete result: %#v", result.Diagnostics)
	}
	var config map[string]any
	if err := json.Unmarshal(result.Config, &config); err != nil {
		t.Fatal(err)
	}
	outbounds := mapList(config["outbounds"])
	if findTag(outbounds, "ss-home") == nil {
		t.Fatalf("cached node missing: %#v", outbounds)
	}
	for _, tag := range []string{"vpn-1", "vpn-1-auto"} {
		if findTag(outbounds, tag) == nil {
			t.Fatalf("default direction member %q missing: %#v", tag, outbounds)
		}
	}
	dns, _ := config["dns"].(map[string]any)
	servers := mapList(dns["servers"])
	for _, tag := range []string{"local_dns_resolver", "google_udp", "google_dot", "google_doh", "cloudflare_udp", "cloudflare_dot", "dns_shield"} {
		if findTag(servers, tag) == nil {
			t.Fatalf("wizard DNS server %q missing: %#v", tag, servers)
		}
	}
	inbounds := mapList(config["inbounds"])
	if len(inbounds) != 1 || inbounds[0]["type"] != "tun" {
		t.Fatalf("default TUN inbound missing: %#v", inbounds)
	}
	address, _ := inbounds[0]["address"].([]any)
	if len(address) != 1 || address[0] != "172.16.0.1/30" {
		t.Fatalf("unexpected default TUN address: %#v", address)
	}
	route, _ := config["route"].(map[string]any)
	if route["final"] != "vpn-1" {
		t.Fatalf("vpn-1 must remain the default route final, got %#v", route["final"])
	}
}

func TestBuildJSONPreservesLargeInteger(t *testing.T) {
	raw := []byte(`{"settings":{"config_overrides":{"dns":{"cache_capacity":9007199254740993}}},"template":{"sections":[],"default_directions":[{"tag":"vpn-1","default_enabled":true}],"config":{"dns":{"servers":[{"type":"local","tag":"local"}],"final":"local"},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct-out"},{"type":"block","tag":"block"}],"endpoints":[],"route":{"rules":[],"final":"vpn-1"}}}}`)
	result, err := BuildJSON(context.Background(), raw)
	if err != nil {
		t.Fatalf("BuildJSON error: %v", err)
	}
	var decoded map[string]any
	decoder := json.NewDecoder(bytes.NewReader(result.Config))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	dns, _ := decoded["dns"].(map[string]any)
	number, ok := dns["cache_capacity"].(json.Number)
	if !ok || number.String() != "9007199254740993" {
		t.Fatalf("large integer was changed: %#v", dns["cache_capacity"])
	}
}

func TestFreshDirectionsPreserveRequiredVPNOne(t *testing.T) {
	input := Input{Template: testTemplate()}
	result, err := Build(context.Background(), input)
	if err != nil {
		t.Fatalf("build failed: %v %#v", err, result.Diagnostics)
	}
	var config map[string]any
	if err := json.Unmarshal(result.Config, &config); err != nil {
		t.Fatal(err)
	}
	if findTag(mapList(config["outbounds"]), "vpn-1") == nil {
		t.Fatal("required vpn-1 direction was not emitted")
	}
}

func TestBuildJSONReportsOfflineRuleSetWithoutNetwork(t *testing.T) {
	input := map[string]any{"template": testTemplate(), "settings": map[string]any{"custom_rules": []any{map[string]any{"kind": "preset", "preset_id": "remote-rule"}}}}
	raw, _ := json.Marshal(input)
	result, err := BuildJSON(context.Background(), raw)
	if err == nil || !hasDiagnostic(result.Diagnostics, "offline_ruleset_missing") {
		t.Fatalf("expected explicit offline ruleset failure, got err=%v diagnostics=%#v", err, result.Diagnostics)
	}
	if result.Complete {
		t.Fatal("fatal diagnostic must make result incomplete")
	}
}

func TestBuildReportsUnsupportedChainField(t *testing.T) {
	input := Input{Template: testTemplate(), Sources: []SourceInput{{ID: "chain-1", Kind: "chain", Raw: map[string]any{"kind": "chain", "tag": "path", "enabled": true, "hops": []any{"a", "b"}, "body": map[string]any{"type": "chain", "future_option": true}}}}}
	result, err := Build(context.Background(), input)
	if err == nil || !hasDiagnostic(result.Diagnostics, "chain_body_field_unsupported") {
		t.Fatalf("expected explicit unknown chain field failure, got %v %#v", err, result.Diagnostics)
	}
}

func TestBuildReportsUnparsedFolderMember(t *testing.T) {
	input := Input{Template: testTemplate(), Sources: []SourceInput{{ID: "folder", Kind: "folder", Members: []MemberInput{{Raw: map[string]any{"kind": "server", "tag": "bad", "enabled": true}}}}}}
	result, err := Build(context.Background(), input)
	if err == nil || !hasDiagnostic(result.Diagnostics, "folder_member_node_missing") {
		t.Fatalf("expected explicit missing node failure, got %v %#v", err, result.Diagnostics)
	}
}

func testTemplate() map[string]any {
	return map[string]any{
		"sections":           []any{map[string]any{"vars": []any{map[string]any{"name": "dns_final", "type": "text", "default_value": "local"}, map[string]any{"name": "dns_default_domain_resolver", "type": "text", "default_value": "local"}}}},
		"default_directions": []any{map[string]any{"tag": "vpn-1", "default_enabled": true}},
		"group_templates":    map[string]any{"magic_nodes": map[string]any{"direct": map[string]any{"source": "preset", "tag": "direct-out"}, "block": map[string]any{"source": "preset", "tag": "block"}, "auto": map[string]any{"source": "generate", "tpl": "{parent_tag}-auto"}}, "direction": map[string]any{"include": []any{"direct", "auto"}, "options": map[string]any{"interrupt_exist_connections": true}}, "auto": map[string]any{"options": map[string]any{"url": "https://example.invalid/204", "interval": "15m", "tolerance": 30}}},
		"config":             map[string]any{"dns": map[string]any{"servers": []any{}, "rules": []any{}, "final": "@dns_final"}, "inbounds": []any{}, "endpoints": []any{}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct-out"}, map[string]any{"type": "block", "tag": "block"}}, "route": map[string]any{"rules": []any{}, "final": "vpn-1", "default_domain_resolver": map[string]any{"server": "@dns_default_domain_resolver"}}},
		"dns_options":        map[string]any{"servers": []any{map[string]any{"enabled": true, "server": map[string]any{"type": "local", "tag": "local"}}}},
		"selectable_rules":   []any{map[string]any{"preset_id": "remote-rule", "rule_set": []any{map[string]any{"tag": "cached", "type": "remote", "format": "binary", "url": "https://not-fetched.invalid/rules.srs"}}}},
	}
}
func hasDiagnostic(diagnostics []Diagnostic, code string) bool {
	for _, d := range diagnostics {
		if d.Code == code && d.Fatal {
			return true
		}
	}
	return false
}
func mapList(value any) []map[string]any {
	raw, _ := value.([]any)
	result := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if entry, ok := item.(map[string]any); ok {
			result = append(result, entry)
		}
	}
	return result
}
func findTag(entries []map[string]any, tag string) map[string]any {
	for _, entry := range entries {
		if entry["tag"] == tag {
			return entry
		}
	}
	return nil
}
