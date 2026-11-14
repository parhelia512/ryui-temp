package builder

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Leadaxe/lxbox/app/assets"
)

func TestApplyRuleRecordsSeedsTemplateDefaultsAndRespectsExplicitEmpty(t *testing.T) {
	raw, err := assets.Read("wizard_template.json")
	if err != nil {
		t.Fatal(err)
	}
	var template map[string]any
	if err := json.Unmarshal(raw, &template); err != nil {
		t.Fatal(err)
	}
	config := cloneMap(template["config"].(map[string]any))
	state := &buildState{vars: map[string]any{
		"vpn_mode": "vpn", "sniff_timeout": "300ms", "sniff_enabled": true,
		"hijack_dns_enabled": true, "resolve_enabled": true, "resolve_strategy": "prefer_ipv4",
	}, root: map[string]string{}}
	if err := applyRuleRecords(config, template, map[string]any{}, CacheInput{}, state); err != nil {
		t.Fatal(err)
	}
	var seeded bool
	for _, rawRule := range recordMapList(config["route"].(map[string]any)["rules"]) {
		if rawRule["action"] == "sniff" {
			seeded = true
			break
		}
	}
	if !seeded {
		t.Fatal("missing rules did not seed traffic-processing default")
	}

	emptyConfig := cloneMap(template["config"].(map[string]any))
	if err := applyRuleRecords(emptyConfig, template, map[string]any{"rules": []any{}}, CacheInput{}, state); err != nil {
		t.Fatal(err)
	}
	if got := emptyConfig["route"].(map[string]any)["rules"].([]any); len(got) != 0 {
		t.Fatalf("explicit empty rules unexpectedly seeded defaults: %#v", got)
	}
}

func TestApplyDNSRecordsRealWizardTemplateUsesLocalDefaults(t *testing.T) {
	raw, err := assets.Read("wizard_template.json")
	if err != nil {
		t.Fatal(err)
	}
	var template map[string]any
	if err := json.Unmarshal(raw, &template); err != nil {
		t.Fatal(err)
	}
	config, _ := template["config"].(map[string]any)
	config = cloneMap(config)
	state := &buildState{vars: map[string]any{
		"vpn_mode": "vpn", "dns_final": "cloudflare_udp", "dns_default_domain_resolver": "local_dns_resolver",
		"proxy_type": "", "proxy_listen": "", "proxy_port": 0,
	}, root: map[string]string{}}
	settings := map[string]any{"dns": map[string]any{"servers": []any{
		map[string]any{"kind": "template", "tag": "google_udp", "enabled": true, "vars": map[string]any{"dns_ip": "8.8.4.4"}},
	}}}
	if err := applyDNSRecords(config, template, settings, state); err != nil {
		t.Fatal(err)
	}
	dns := config["dns"].(map[string]any)
	servers := recordMapList(dns["servers"])
	if got := recordFindTag(servers, "google_udp"); got == nil || got["server"] != "8.8.4.4" {
		t.Fatalf("template local variable was not applied: %#v", got)
	}
}

func TestApplyDNSRecordsContractNestedFixture(t *testing.T) {
	input := readContractObject(t, filepath.Join("dns", "nested_vars_substituted.dns.json"))
	want := readContractObject(t, filepath.Join("dns", "nested_vars_substituted.expected.json"))
	template := map[string]any{"dns_options": map[string]any{"servers": input["servers"]}}
	config := map[string]any{"dns": map[string]any{}}
	state := &buildState{vars: map[string]any{}, root: map[string]string{}}
	settings := map[string]any{"dns": map[string]any{"servers": []any{
		map[string]any{"kind": "template", "tag": "google_dot", "enabled": true, "vars": map[string]any{"dns_ip": "8.8.4.4"}},
	}}}
	if err := applyDNSRecords(config, template, settings, state); err != nil {
		t.Fatal(err)
	}
	got := map[string]any{"servers": config["dns"].(map[string]any)["servers"]}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fixture mismatch: got %#v want %#v", got, want)
	}
}

func TestApplyRuleRecordsPreservesUnknownInlineBodyAndResolvePair(t *testing.T) {
	config := map[string]any{"route": map[string]any{}}
	template := map[string]any{"selectable_rules": []any{}}
	settings := map[string]any{"rules": []any{map[string]any{
		"kind": "inline", "enabled": true,
		"body": map[string]any{"domain": []any{"example.com"}, "outbound": "direct-out", "future_field": map[string]any{"keep": true}},
		"resolve": map[string]any{"only": false, "strategy": "prefer_ipv4", "serverTag": "local_dns_resolver"},
	}}}
	state := &buildState{vars: map[string]any{}, root: map[string]string{}}
	if err := applyRuleRecords(config, template, settings, CacheInput{}, state); err != nil {
		t.Fatal(err)
	}
	rules := config["route"].(map[string]any)["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("expected resolve + route rules, got %#v", rules)
	}
	first := rules[0].(map[string]any)
	if first["action"] != "resolve" || first["server"] != "local_dns_resolver" || first["future_field"] == nil {
		t.Fatalf("unknown body or resolve action lost: %#v", first)
	}
	second := rules[1].(map[string]any)
	if second["outbound"] != "direct-out" || second["future_field"] == nil {
		t.Fatalf("terminal route body changed: %#v", second)
	}
}

func TestApplyRuleRecordsContractFixedDNSFixture(t *testing.T) {
	input := readContractObject(t, filepath.Join("rule_dns", "inline_fixed_v4.rule.json"))
	want := readContractObject(t, filepath.Join("rule_dns", "inline_fixed_v4.expected.json"))
	config := map[string]any{"route": map[string]any{}, "dns": map[string]any{}}
	template := map[string]any{"selectable_rules": []any{}}
	settings := map[string]any{"rules": []any{input["rule"]}}
	state := &buildState{vars: map[string]any{}, root: map[string]string{}}
	if err := applyRuleRecords(config, template, settings, CacheInput{}, state); err != nil {
		t.Fatal(err)
	}
	// applyRuleRecords emits route rules; DNS mirrors are emitted by the DNS
	// record pass, which consumes the same record list and preserves order.
	if err := applyDNSRecords(config, template, settings, state); err != nil {
		t.Fatal(err)
	}
	got := map[string]any{"dns_rules": config["dns"].(map[string]any)["rules"]}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fixture mismatch: got %#v want %#v", got, want)
	}
}

func readContractObject(t *testing.T, relative string) map[string]any {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "contract", relative)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func recordMapList(value any) []map[string]any {
	raw, _ := value.([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if object, ok := item.(map[string]any); ok {
			out = append(out, object)
		}
	}
	return out
}

func recordFindTag(items []map[string]any, tag string) map[string]any {
	for _, item := range items {
		if item["tag"] == tag {
			return item
		}
	}
	return nil
}
