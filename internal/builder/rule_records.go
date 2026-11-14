package builder

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// applyRuleRecords builds route.rules and route.rule_set from contract-1.0
// records in settings.rules (and the earlier custom_rules spelling).
func applyRuleRecords(config, template, settings map[string]any, cache CacheInput, state *buildState) error {
	if config == nil || template == nil || state == nil {
		return fmt.Errorf("route record application received nil input")
	}
	route, _ := config["route"].(map[string]any)
	if route == nil {
		route = map[string]any{}
		config["route"] = route
	}
	records, hasRecords := dnsRecordEffectiveRuleRecords(template, settings)
	if !hasRecords {
		state.add(LevelInfo, "default_rule_records_seeded", "settings.rules", "template default and required rule presets were seeded", nil, false)
	}
	ordered := append([]any(nil), records...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, _ := ordered[i].(map[string]any)
		b, _ := ordered[j].(map[string]any)
		an, aok := dnsRecordNumber(a["num"])
		bn, bok := dnsRecordNumber(b["num"])
		if !aok {
			an = 1<<62 + int64(i)
		}
		if !bok {
			bn = 1<<62 + int64(j)
		}
		return an < bn
	})

	rules := append([]any(nil), recordSettingList(route, "rules")...)
	knownRuleSets := map[string]bool{}
	for _, raw := range recordSettingList(route, "rule_set") {
		if item, ok := raw.(map[string]any); ok {
			knownRuleSets[stringValue(item, "tag")] = true
		}
	}
	for _, raw := range ordered {
		record, ok := raw.(map[string]any)
		if !ok {
			state.warn("route_record_dropped", "settings.rules", "route rule record is not an object and was dropped", raw)
			continue
		}
		if record["enabled"] == false {
			continue
		}
		kind := stringValue(record, "kind")
		switch kind {
		case "preset":
			id := stringValue(record, "ref")
			if id == "" {
				id = stringValue(record, "preset_id")
			}
			preset := dnsRecordFindPreset(template, id)
			if preset == nil {
				state.fatal("route_preset_missing", "settings.rules.ref", "enabled preset is absent from supplied template: "+id)
				continue
			}
			parts := dnsRecordExpandPreset(config, preset, record, cache, state)
			for _, set := range parts.ruleSets {
				ruleRecordRegisterRuleSet(route, set, knownRuleSets, cache, state)

			}
			for _, rule := range parts.route {
				rules = append(rules, rule)
			}
		case "inline", "user", "json":
			rules = append(rules, ruleRecordBuildInline(record, state)...)
		case "srs":
			rules = append(rules, ruleRecordBuildSRS(record, cache, route, knownRuleSets, state)...)
		default:
			state.warn("route_record_kind_unsupported", "settings.rules.kind", "unknown route rule record kind was dropped", kind)
		}
	}
	route["rules"] = rules
	return nil
}

func dnsRecordEffectiveRuleRecords(template, settings map[string]any) ([]any, bool) {
	if settings != nil {
		if value, exists := settings["rules"]; exists {
			if records, ok := value.([]any); ok {
				return records, true
			}
			return nil, true
		}
		if value, exists := settings["custom_rules"]; exists {
			if records, ok := value.([]any); ok {
				return records, true
			}
			return nil, true
		}
	}
	var seeded []any
	for _, raw := range recordSettingList(template, "selectable_rules") {
		preset, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		ui, _ := preset["ui"].(map[string]any)
		if !boolValue(ui, "default", false) && !boolValue(ui, "locked", false) && !boolValue(preset, "required", false) {
			continue
		}
		id := stringValue(preset, "preset_id")
		if id == "" {
			continue
		}
		record := map[string]any{"kind": "preset", "ref": id, "enabled": true}
		if num, ok := dnsRecordNumber(ui["num"]); ok {
			record["num"] = num
		}
		seeded = append(seeded, record)
	}
	return seeded, false
}

func ruleRecordBuildInline(record map[string]any, state *buildState) []any {
	body, _ := record["body"].(map[string]any)
	if body == nil {
		if raw := stringValue(record, "json"); raw != "" {
			var value any
			if err := json.Unmarshal([]byte(raw), &value); err != nil {
				state.warn("route_inline_json_invalid", "settings.rules.json", err.Error(), nil)
				return nil
			}
			switch parsed := value.(type) {
			case map[string]any:
				return []any{parsed}
			case []any:
				out := []any{}
				for i, item := range parsed {
					if object, ok := item.(map[string]any); ok {
						out = append(out, object)
					} else {
						state.warn("route_inline_array_item_invalid", fmt.Sprintf("settings.rules.json[%d]", i), "non-object route rule was dropped", item)
					}
				}
				return out
			default:
				state.warn("route_inline_json_type_invalid", "settings.rules.json", "inline JSON must be an object or array", nil)
				return nil
			}
		}
		state.warn("route_inline_body_missing", "settings.rules.body", "inline route rule body is missing and was dropped", nil)
		return nil
	}
	base := cloneMap(body) // Preserve unknown sing-box fields verbatim.
	resolve, _ := record["resolve"].(map[string]any)
	if resolve == nil {
		return []any{base}
	}
	if resolve["only"] != true {
		terminal := cloneMap(base)
		intermediate := cloneMap(base)
		ruleRecordApplyResolve(intermediate, resolve)
		return []any{intermediate, terminal}
	}
	ruleRecordApplyResolve(base, resolve)
	return []any{base}
}

func ruleRecordApplyResolve(rule, resolve map[string]any) {
	delete(rule, "outbound")
	delete(rule, "action")
	rule["action"] = "resolve"
	for source, target := range map[string]string{
		"strategy": "strategy", "serverTag": "server", "timeout": "timeout", "clientSubnet": "client_subnet",
		"rewriteTtl": "rewrite_ttl", "disableCache": "disable_cache", "disableOptimisticCache": "disable_optimistic_cache",
	} {
		value, exists := resolve[source]
		if !exists || value == nil || value == "" || value == false || value == 0 {
			continue
		}
		rule[target] = clone(value)
	}
}

func ruleRecordBuildSRS(record map[string]any, cache CacheInput, route map[string]any, known map[string]bool, state *buildState) []any {
	name := stringValue(record, "name")
	if strings.TrimSpace(name) == "" {
		name = "unnamed"
	}
	refs := recordStringList(record["refs"])
	if len(refs) == 0 {
		if ref := stringValue(record, "ref"); ref != "" {
			refs = []string{ref}
		}
	}
	id := stringValue(record, "id")
	if len(refs) == 0 || id == "" {
		state.warn("route_srs_record_invalid", "settings.rules", "SRS rule requires id and refs/ref", record)
		return nil
	}
	tags := []any{}
	for i := range refs {
		cacheID := id
		if i > 0 {
			cacheID = fmt.Sprintf("%s~%d", id, i)
		}
		cached := ruleRecordCachedRuleSet(cacheID, cache)
		if cached == nil {
			state.warn("route_srs_cache_missing", "settings.rules.refs", "SRS rule has no usable offline cache and was dropped", cacheID)
			return nil
		}
		requested := name
		if i > 0 {
			requested = fmt.Sprintf("%s-%d", name, i+1)
		}
		cached["tag"] = requested
		if cached["type"] == nil {
			cached["type"] = "local"
		}
		if cached["format"] == nil {
			cached["format"] = "binary"
		}
		tag := ruleRecordAllocateSetTag(route, requested)
		cached["tag"] = tag
		ruleRecordRegisterRuleSet(route, cached, known, cache, state)
		tags = append(tags, tag)
	}
	match := cloneMap(recordMapValue(record, "body"))
	if match == nil {
		match = map[string]any{}
	}
	if len(tags) == 1 {
		match["rule_set"] = tags[0]
	} else {
		match["rule_set"] = tags
	}
	if outbound := stringValue(match, "outbound"); outbound == "reject" {
		delete(match, "outbound")
		match["action"] = "reject"
	}
	resolve, _ := record["resolve"].(map[string]any)
	if resolve != nil {
		if resolve["only"] != true {
			terminal := cloneMap(match)
			intermediate := cloneMap(match)
			ruleRecordApplyResolve(intermediate, resolve)
			return []any{intermediate, terminal}
		}
		ruleRecordApplyResolve(match, resolve)
	}
	return []any{match}
}

func ruleRecordCachedRuleSet(id string, cache CacheInput) map[string]any {
	if raw, ok := cache.RuleSets[id]; ok {
		var object map[string]any
		if json.Unmarshal(raw, &object) == nil && object != nil {
			return object
		}
	}
	if raw, ok := cache.Files[id]; ok {
		// Files carries payload bytes but no filesystem path. A JSON cache
		// projection may provide a local rule_set body/path without I/O.
		var object map[string]any
		if json.Unmarshal(raw, &object) == nil && object != nil {
			return object
		}
	}
	return nil
}

func ruleRecordRegisterRuleSet(route map[string]any, set map[string]any, known map[string]bool, cache CacheInput, state *buildState) {
	tag := stringValue(set, "tag")
	if tag == "" {
		state.fatal("route_ruleset_tag_missing", "route.rule_set", "expanded rule_set has no tag")
		return
	}
	if set["type"] == "remote" {
		cached := ruleRecordCachedRuleSet(tag, cache)
		if cached == nil {
			state.warn("preset_ruleset_cache_missing", "route.rule_set."+tag, "remote preset rule_set has no offline cache and its declaration is retained", tag)
		} else {
			cached["tag"] = tag
			cached["type"] = "local"
			set = cached
		}
	}
	if known[tag] {
		return
	}
	route["rule_set"] = appendAny(route["rule_set"], cloneMap(set))
	known[tag] = true
}

func ruleRecordAllocateSetTag(route map[string]any, requested string) string {
	used := map[string]bool{}
	for _, raw := range recordSettingList(route, "rule_set") {
		if item, ok := raw.(map[string]any); ok {
			used[stringValue(item, "tag")] = true
		}
	}
	if !used[requested] {
		return requested
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s (%d)", requested, i)
		if !used[candidate] {
			return candidate
		}
	}
}

func dnsRecordNumber(value any) (int64, bool) {
	switch n := value.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), true
	case json.Number:
		v, err := n.Int64()
		return v, err == nil
	}
	return 0, false
}
