package builder

import (
	"encoding/json"
	"fmt"
)

func applyRules(config,template,settings map[string]any,cache CacheInput,state *buildState){
	custom,_:=settings["custom_rules"].([]any);if len(custom)==0{return};route,_:=config["route"].(map[string]any);if route==nil{route=map[string]any{};config["route"]=route};routing,_:=route["rules"].([]any);presets,_:=template["selectable_rules"].([]any)
	for index, raw := range custom {
		record, ok := raw.(map[string]any)
		if !ok { state.fatal("custom_rule_invalid", fmt.Sprintf("custom_rules[%d]", index), "custom rule must be an object"); continue }
		if record["enabled"] == false { continue }
		kind := stringValue(record, "kind")
		if kind == "inline" || kind == "json" {
			routing = append(routing, buildInlineRule(record, index, kind, state)...)
			continue
		}
		if kind == "srs" { state.fatal("srs_rule_unsupported", fmt.Sprintf("custom_rules[%d]", index), "SRS matching requires a cached path and typed match expansion"); continue }
		if kind != "preset" { state.fatal("custom_rule_kind_unsupported", fmt.Sprintf("custom_rules[%d].kind", index), "unsupported custom rule kind "+kind); continue }
		id := stringValue(record, "preset_id")
		preset := lookupPreset(presets, id)
		if preset == nil { state.fatal("preset_missing", fmt.Sprintf("custom_rules[%d].preset_id", index), "enabled preset is absent from supplied template: "+id); continue }
		vars := cloneMap(state.vars)
		values := recordMap(record, "vars_values")
		for key, value := range values { vars[key] = value }
		if rawRule, exists := preset["rule"]; exists { appendExpandedRule(rawRule, vars, "rule", id, route, cache, state, &routing) }
		if rawRules, exists := preset["rules"]; exists { appendExpandedRule(rawRules, vars, "rules", id, route, cache, state, &routing) }
		if rawSets, exists := preset["rule_set"]; exists { appendExpandedRule(rawSets, vars, "rule_set", id, route, cache, state, &routing) }
		if preset["dns_rules"] != nil || preset["dns_servers"] != nil { state.fatal("preset_dns_unsupported", "selectable_rules."+id, "preset contains DNS aspects which cannot be omitted") }
	}
	route["rules"] = routing
}

func buildInlineRule(record map[string]any, index int, kind string, state *buildState) []any {
	if rawJSON := stringValue(record, "json"); rawJSON != "" {
		var parsed any
		if err := json.Unmarshal([]byte(rawJSON), &parsed); err != nil { state.fatal("inline_rule_json_invalid", fmt.Sprintf("custom_rules[%d].json", index), err.Error()); return nil }
		if object, ok := parsed.(map[string]any); ok { return []any{object} }
		if list, ok := parsed.([]any); ok { result := []any{}; for i, item := range list { if _, ok := item.(map[string]any); ok { result = append(result, item) } else { state.fatal("inline_rule_array_item_invalid", fmt.Sprintf("custom_rules[%d].json[%d]", index, i), "rule array elements must be objects") } }; return result }
		state.fatal("inline_rule_json_type_invalid", fmt.Sprintf("custom_rules[%d].json", index), "rule JSON must be an object or array")
		return nil
	}
	body, _ := record["body"].(map[string]any)
	rule := cloneMap(body)
	if rule == nil { rule = map[string]any{} }
	for _, key := range []string{"domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr", "ip_is_private", "port", "port_range", "protocol", "package_name", "package_name_regex", "inbound", "network", "wifi_ssid", "wifi_bssid", "network_type", "network_is_expensive", "source_ip_cidr", "source_ip_is_private", "outbound", "action", "rule_set"} {
		if value, exists := record[key]; exists { rule[key] = clone(value) }
	}
	if len(rule) == 0 { state.warn("inline_rule_empty", fmt.Sprintf("custom_rules[%d]", index), "rule has no recognizable matcher", nil); return nil }
	return []any{rule}
}

func appendExpandedRule(raw any, vars map[string]any, section, id string, route map[string]any, cache CacheInput, state *buildState, routing *[]any) {
	expanded, err := expand(raw, vars, nil, state)
	if err == errDrop { return }
	if err != nil { state.fatal("preset_expand_failed", "selectable_rules."+id+"."+section, err.Error()); return }
	if section == "rule_set" {
		items, ok := expanded.([]any); if !ok { items = []any{expanded} }
		if len(cache.RuleSets) == 0 && anyRemoteRuleset(items) { state.fatal("offline_ruleset_missing", "selectable_rules."+id+".rule_set", "remote ruleset cannot be fetched offline"); return }
		addRuleSets(route, items, CacheInput{RuleSets: cache.RuleSets}, state)
		return
	}
	if list, ok := expanded.([]any); ok { *routing = append(*routing, list...); return }
	if object, ok := expanded.(map[string]any); ok { *routing = append(*routing, object); return }
	state.fatal("preset_rule_invalid", "selectable_rules."+id+"."+section, "expanded rule is not an object or object list")
}
func anyRemoteRuleset(items []any) bool {
	for _, raw := range items { if object, ok := raw.(map[string]any); ok && stringValue(object,"type")=="remote" { return true } }
	return false
}
func lookupPreset(presets []any,id string)map[string]any{for _,raw:=range presets{object,ok:=raw.(map[string]any);if ok&&stringValue(object,"preset_id")==id{return object}};return nil}
func recordMap(record map[string]any,key string)map[string]any{result,_:=record[key].(map[string]any);return result}
