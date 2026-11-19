package builder

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// applyDNSRecords materializes the contract-1.0 dns records. It is deliberately
// independent from settings.go: the caller can place it after source emission
// (and after route records when DNS mirrors need the final rule_set names).
func applyDNSRecords(config, template, settings map[string]any, state *buildState) error {
	if config == nil || template == nil || state == nil {
		return fmt.Errorf("DNS record application received nil input")
	}
	dns, _ := config["dns"].(map[string]any)
	if dns == nil {
		dns = map[string]any{}
		config["dns"] = dns
	}
	dnsRecordApplyRouteMirrors(dns, settings, state)
	options, _ := template["dns_options"].(map[string]any)
	if options == nil {
		return nil
	}

	presetServers, presetRules := dnsRecordPresetDNS(config, template, settings, state)
	stored, _ := settings["dns"].(map[string]any)
	serverRecords, hasServers := stored["servers"]
	serverList := []any{}
	if hasServers {
		if raw, ok := serverRecords.([]any); ok {
			serverList = dnsRecordMaterializeServers(raw, options, presetServers, state)
		} else {
			state.fatal("dns_records_servers_invalid", "settings.dns.servers", "DNS server records must be an array")
		}
	} else {
		// A missing key is the first-launch state. Seed enabled template servers,
		// then append active preset servers. An explicitly empty list stays empty.
		serverList = dnsRecordMaterializeTemplateServers(options, state)
		serverList = append(serverList, dnsRecordMapList(presetServers)...)
	}
	if len(serverList) > 0 || hasServers {
		dns["servers"] = serverList
	}

	storedRules, hasRules := stored["rules"]
	ruleRecords := []any{}
	if hasRules {
		if raw, ok := storedRules.([]any); ok {
			ruleRecords = raw
		} else {
			state.fatal("dns_records_rules_invalid", "settings.dns.rules", "DNS rule records must be an array")
		}
	}
	dnsRules := dnsRecordMaterializeRules(ruleRecords, options, presetRules, config, settings, state, hasRules)
	if len(dnsRules) > 0 || hasRules {
		dns["rules"] = dnsRules
	}
	return nil
}

type dnsRecordPresetParts struct {
	servers  []map[string]any
	rules    []map[string]any
	route    []map[string]any
	ruleSets []map[string]any
}

// dnsRecordPresetDNS expands active preset records once for both record APIs.
func dnsRecordPresetDNS(config, template, settings map[string]any, state *buildState) ([]map[string]any, []map[string]any) {
	outServers, outRules := []map[string]any{}, []map[string]any{}
	records, _ := dnsRecordEffectiveRuleRecords(template, settings)
	for _, raw := range records {
		record, ok := raw.(map[string]any)
		if !ok || record["enabled"] == false || stringValue(record, "kind") != "preset" {
			continue
		}
		id := stringValue(record, "ref")
		if id == "" {
			id = stringValue(record, "preset_id")
		}
		preset := dnsRecordFindPreset(template, id)
		if preset == nil {
			state.fatal("record_preset_missing", "settings.rules.ref", "enabled preset is absent from supplied template: "+id)
			continue
		}
		parts := dnsRecordExpandPreset(config, preset, record, CacheInput{}, state)
		outServers = append(outServers, parts.servers...)
		outRules = append(outRules, parts.rules...)
	}
	return outServers, outRules
}

func dnsRecordMaterializeTemplateServers(options map[string]any, state *buildState) []any {
	var out []any
	for i, raw := range recordSettingList(options, "servers") {
		decl, ok := raw.(map[string]any)
		if !ok {
			state.fatal("dns_records_template_server_invalid", fmt.Sprintf("template.dns_options.servers[%d]", i), "DNS server declaration must be an object")
			continue
		}
		if decl["enabled"] == false {
			continue
		}
		body := dnsRecordTemplateServerBody(decl, nil, state)
		if body != nil {
			out = append(out, body)
		}
	}
	return out
}

func dnsRecordMaterializeServers(records []any, options map[string]any, presets []map[string]any, state *buildState) []any {
	templateByTag := map[string]map[string]any{}
	for _, raw := range recordSettingList(options, "servers") {
		if decl, ok := raw.(map[string]any); ok {
			if body, ok := decl["server"].(map[string]any); ok && stringValue(body, "tag") != "" {
				templateByTag[stringValue(body, "tag")] = decl
			}
		}
	}
	presetByTag := map[string]map[string]any{}
	for _, body := range presets {
		if tag := stringValue(body, "tag"); tag != "" {
			presetByTag[tag] = body
		}
	}
	out := []any{}
	seen := map[string]bool{}
	for i, raw := range records {
		record, ok := raw.(map[string]any)
		if !ok {
			state.warn("dns_record_dropped", fmt.Sprintf("settings.dns.servers[%d]", i), "DNS server record is not an object and was dropped", raw)
			continue
		}
		if record["enabled"] == false {
			continue
		}
		kind, tag := stringValue(record, "kind"), stringValue(record, "tag")
		var body map[string]any
		switch kind {
		case "user", "inline":
			body, _ = record["body"].(map[string]any)
			body = cloneMap(body)
			if body == nil {
				state.fatal("dns_record_body_missing", fmt.Sprintf("settings.dns.servers[%d].body", i), "user DNS server body is missing")
				continue
			}
		case "template":
			decl := templateByTag[tag]
			if decl == nil {
				state.warn("dns_record_orphan", fmt.Sprintf("settings.dns.servers[%d]", i), "template DNS server is absent from supplied template", tag)
				continue
			}
			body = dnsRecordTemplateServerBody(decl, record, state)
		case "preset":
			ref := stringValue(record, "ref")
			if ref == "" {
				ref = tag
			}
			body = cloneMap(presetByTag[dnsRecordPresetRefTag(ref)])
			if body == nil {
				state.warn("dns_record_orphan", fmt.Sprintf("settings.dns.servers[%d]", i), "preset DNS server is absent from active presets", ref)
				continue
			}
		default:
			state.warn("dns_record_kind_unsupported", fmt.Sprintf("settings.dns.servers[%d].kind", i), "unknown DNS server record kind was dropped", kind)
			continue
		}
		if body == nil {
			continue
		}
		if tag == "" {
			tag = stringValue(body, "tag")
		}
		if tag == "" {
			state.warn("dns_record_tag_missing", fmt.Sprintf("settings.dns.servers[%d]", i), "DNS server record has no tag and was dropped", nil)
			continue
		}
		body["tag"] = tag
		delete(body, "enabled")
		delete(body, "description")
		if body["detour"] == "direct-out" {
			delete(body, "detour")
		}
		if !seen[tag] {
			out = append(out, body)
			seen[tag] = true
		}
	}
	// Preset servers are auto-discovered after user records, preserving record
	// order while still making preset DNS rules referencable.
	for _, body := range presets {
		tag := stringValue(body, "tag")
		if tag == "" || seen[tag] {
			continue
		}
		copy := cloneMap(body)
		copy["tag"] = tag
		out = append(out, copy)
		seen[tag] = true
	}
	return out
}

func dnsRecordTemplateServerBody(decl, record map[string]any, state *buildState) map[string]any {
	server, ok := decl["server"].(map[string]any)
	if !ok {
		state.fatal("dns_record_template_body_missing", "template.dns_options.servers.server", "template DNS server body is missing")
		return nil
	}
	vars := dnsRecordLocalVars(state.vars, decl["vars"])
	if record != nil {
		for k, v := range recordMapValue(record, "vars") {
			if fallback, exists := vars[k]; exists {
				vars[k] = coerce(v, fallback)
			} else {
				vars[k] = v
			}
		}
	}
	expanded, err := expand(server, vars, nil, state)
	if err != nil && err != errDrop {
		state.warn("dns_record_template_expand_failed", "template.dns_options.servers", err.Error(), nil)
		return nil
	}
	if err == errDrop || expanded == nil {
		return nil
	}
	body, _ := expanded.(map[string]any)
	return body
}

func dnsRecordMaterializeRules(records []any, options map[string]any, presetRules []map[string]any, config, settings map[string]any, state *buildState, hasRecords bool) []any {
	templateByName := map[string]map[string]any{}
	for _, raw := range recordSettingList(options, "rules") {
		if item, ok := raw.(map[string]any); ok {
			if name := stringValue(item, "name"); name != "" {
				templateByName[name] = item
			}
		}
	}
	out := []any{}
	if !hasRecords {
		for _, body := range presetRules {
			copy := cloneMap(body)
			delete(copy, "_preset_id")
			out = append(out, copy)
		}
	}
	if !hasRecords {
		for _, item := range templateByName {
			if item["enabled_default"] == false {
				continue
			}
			body := cloneMap(item)
			delete(body, "name")
			delete(body, "enabled_default")
			out = append(out, body)
		}
	}
	for i, raw := range records {
		record, ok := raw.(map[string]any)
		if !ok {
			state.warn("dns_rule_record_dropped", fmt.Sprintf("settings.dns.rules[%d]", i), "DNS rule record is not an object and was dropped", raw)
			continue
		}
		if record["enabled"] == false && stringValue(record, "kind") != "preset" {
			continue
		}
		kind := stringValue(record, "kind")
		switch kind {
		case "user", "inline":
			body, _ := record["body"].(map[string]any)
			if body == nil {
				state.warn("dns_rule_body_missing", fmt.Sprintf("settings.dns.rules[%d].body", i), "user DNS rule body is missing and was dropped", nil)
				continue
			}
			out = append(out, cloneMap(body))
		case "template":
			name := stringValue(record, "name")
			body := cloneMap(templateByName[name])
			if body == nil {
				state.warn("dns_rule_record_orphan", fmt.Sprintf("settings.dns.rules[%d]", i), "template DNS rule is absent from supplied template", name)
				continue
			}
			delete(body, "name")
			delete(body, "enabled_default")
			out = append(out, body)
		case "preset":
			ref := stringValue(record, "ref")
			for _, body := range presetRules {
				if stringValue(body, "_preset_id") == ref || ref == "" {
					copy := cloneMap(body)
					delete(copy, "_preset_id")
					out = append(out, copy)
				}
			}
		case "srs":
			body := dnsRecordSRSRule(record, CacheInput{}, state, fmt.Sprintf("settings.dns.rules[%d]", i))
			if body != nil {
				out = append(out, body)
			}
		default:
			state.warn("dns_rule_kind_unsupported", fmt.Sprintf("settings.dns.rules[%d].kind", i), "unknown DNS rule record kind was dropped", kind)
		}
	}
	return out
}

func dnsRecordSRSRule(record map[string]any, cache CacheInput, state *buildState, path string) map[string]any {
	id := stringValue(record, "id")
	name := stringValue(record, "name")
	if name == "" {
		name = "dns_srs_" + id
	}
	cacheKey := id
	if cacheKey == "" {
		state.warn("dns_srs_cache_missing", path, "DNS SRS rule has no cache id and was dropped", nil)
		return nil
	}
	if _, ok := cache.Files[cacheKey]; !ok {
		if _, ok := cache.RuleSets[cacheKey]; !ok {
			state.warn("dns_srs_cache_missing", path, "DNS SRS rule has no offline cached file and was dropped", cacheKey)
			return nil
		}
	}
	body, _ := record["body"].(map[string]any)
	if body == nil {
		body, _ = record["rule"].(map[string]any)
	}
	result := cloneMap(body)
	if result == nil {
		result = map[string]any{}
	}
	result["rule_set"] = name
	if server := stringValue(record, "server"); server != "" {
		result["server"] = server
	}
	return result
}

func dnsRecordApplyRouteMirrors(dns map[string]any, settings map[string]any, state *buildState) {
	out := append([]any(nil), recordSettingList(dns, "rules")...)
	for _, raw := range recordSettingList(settings, "rules") {
		record, ok := raw.(map[string]any)
		if !ok || record["enabled"] == false {
			continue
		}
		meta, _ := record["dns"].(map[string]any)
		if meta == nil {
			if ref, ok := record["dns_ref"].(string); ok && ref != "" {
				meta = map[string]any{"enabled": true, "serverTag": ref}
			}
		}
		if meta == nil {
			continue
		}
		body, _ := record["body"].(map[string]any)
		if body == nil {
			continue
		}
		match := cloneMap(body)
		delete(match, "outbound")
		delete(match, "action")
		delete(match, "server")
		delete(match, "rule_set")
		fixed := recordStringList(meta["fixedIps"])
		v4, v6 := []string{}, []string{}
		for _, ip := range fixed {
			parsed := net.ParseIP(strings.TrimSpace(ip))
			if parsed == nil {
				state.warn("dns_mirror_ip_invalid", "settings.rules.dns.fixedIps", "invalid fixed DNS answer was ignored", ip)
				continue
			}
			if parsed.To4() != nil {
				v4 = append(v4, strings.TrimSpace(ip))
			} else {
				v6 = append(v6, strings.TrimSpace(ip))
			}
		}
		if len(v4) > 0 || len(v6) > 0 {
			if len(v4) > 0 {
				answers := []any{}
				for _, ip := range v4 {
					answers = append(answers, "*. 300 IN A "+ip)
				}
				ruleA := cloneMap(match)
				ruleA["query_type"] = []any{"A"}
				ruleA["action"] = "predefined"
				ruleA["rcode"] = "NOERROR"
				ruleA["answer"] = answers
				out = append(out, ruleA)
			}
			if len(v6) > 0 {
				answers := []any{}
				for _, ip := range v6 {
					answers = append(answers, "*. 300 IN AAAA "+ip)
				}
				ruleAAAA := cloneMap(match)
				ruleAAAA["query_type"] = []any{"AAAA"}
				ruleAAAA["action"] = "predefined"
				ruleAAAA["rcode"] = "NOERROR"
				ruleAAAA["answer"] = answers
				out = append(out, ruleAAAA)
			}
			if len(v4) == 0 {
				ruleA := cloneMap(match)
				ruleA["query_type"] = []any{"A"}
				ruleA["action"] = "predefined"
				ruleA["rcode"] = "NOERROR"
				out = append(out, ruleA)
			}
			if len(v6) == 0 {
				ruleAAAA := cloneMap(match)
				ruleAAAA["query_type"] = []any{"AAAA"}
				ruleAAAA["action"] = "predefined"
				ruleAAAA["rcode"] = "NOERROR"
				out = append(out, ruleAAAA)
			}
			continue
		}
		if meta["enabled"] != true {
			continue
		}
		if meta["forceIpv4"] == true {
			rule := cloneMap(match)
			rule["ip_version"] = 6
			rule["action"] = "predefined"
			rule["rcode"] = "NOERROR"
			out = append(out, rule)
		}
		if tag := stringValue(meta, "serverTag"); tag != "" {
			match["server"] = tag
			out = append(out, match)
		}
	}
	if len(out) > 0 {
		dns["rules"] = out
	}
}

// dnsRecordExpandPreset expands #if and node-loop fragments using the existing
// expansion engine. The wrapper supplies the node variables that old expand
// does not itself synthesize (node.body.*, node flags, and @node).
func dnsRecordExpandPreset(config map[string]any, preset, record map[string]any, cache CacheInput, state *buildState) dnsRecordPresetParts {
	parts := dnsRecordPresetParts{}
	vars := dnsRecordPresetVars(preset, record, state)
	seededDefault := boolValue(record, "_seeded_default", false)
	loop, _ := preset["for_each_node"].(map[string]any)
	loopDo, _ := preset["for_each_node_do"].(map[string]any)
	if loop != nil {
		for _, node := range dnsRecordConfigNodes(config) {
			if filter, exists := loop["#filter"]; exists && !dnsRecordNodeCondition(filter, vars, node, state) {
				continue
			}
			local := dnsRecordVarsForNode(vars, node)
			parts = dnsRecordMergePresetParts(parts, dnsRecordExpandPresetBody(preset, local, node, cache, state, false, seededDefault))
		}
		return parts
	}
	if loopDo != nil {
		vars = dnsRecordCollectNodeVars(vars, loopDo, config, state)
	}
	return dnsRecordMergePresetParts(parts, dnsRecordExpandPresetBody(preset, vars, nil, cache, state, true, seededDefault))
}

func dnsRecordExpandPresetBody(preset map[string]any, vars map[string]any, node map[string]any, cache CacheInput, state *buildState, namespace bool, seededDefault bool) dnsRecordPresetParts {
	parts := dnsRecordPresetParts{}
	for _, item := range dnsRecordExpandedList(preset["dns_servers"], vars, node, state) {
		if item["tag"] == nil {
			state.warn("preset_dns_server_dropped", "selectable_rules.dns_servers", "preset DNS server has no tag and was dropped", item)
			continue
		}
		parts.servers = append(parts.servers, item)
	}
	for _, item := range dnsRecordExpandedList(preset["dns_rules"], vars, node, state) {
		if item["server"] == nil && item["action"] != "predefined" && item["action"] != "reject" && item["action"] != "route-options" {
			state.warn("preset_dns_rule_dropped", "selectable_rules.dns_rules", "preset DNS rule has no server or serverless action and was dropped", item)
			continue
		}
		item["_preset_id"] = stringValue(preset, "preset_id")
		parts.rules = append(parts.rules, item)
	}
	for _, item := range dnsRecordExpandedList(preset["rule_set"], vars, node, state) {
		if item["type"] == "remote" {
			id := stringValue(preset, "preset_id")
			tag := stringValue(item, "tag")
			cacheID := "preset__" + id + "__" + tag
			if payload, ok := cache.RuleSets[cacheID]; ok {
				var local map[string]any
				if err := json.Unmarshal(payload, &local); err == nil && local != nil {
					local["type"], local["tag"] = "local", tag
					local["format"] = "binary"
					if cache.Files[cacheID] != nil {
						local["path"] = string(cache.Files[cacheID])
					}
					item = local
				} else {
					state.fatal("preset_ruleset_cache_invalid", "cache.rule_sets."+cacheID, err.Error())
					continue
				}
			} else if payload, ok := cache.RuleSets[tag]; ok {
				var local map[string]any
				if err := json.Unmarshal(payload, &local); err == nil && local != nil {
					local["type"], local["tag"] = "local", tag
					if local["format"] == nil {
						local["format"] = "binary"
					}
					item = local
				} else {
					state.fatal("preset_ruleset_cache_invalid", "cache.rule_sets."+tag, err.Error())
					continue
				}
			} else {
				if seededDefault {
					state.warn("preset_ruleset_cache_missing", "selectable_rules."+id+".rule_set."+tag, "default remote preset rule_set has no offline cache payload and was skipped", tag)
					continue
				}
				state.fatal("offline_ruleset_missing", "selectable_rules."+id+".rule_set."+tag, "remote preset rule_set has no offline cache payload", tag)
				continue
			}

		}
		parts.ruleSets = append(parts.ruleSets, item)
	}
	for _, item := range dnsRecordExpandedList(preset["rules"], vars, node, state) {
		if item["outbound"] == nil && item["action"] == nil {
			state.warn("preset_route_rule_dropped", "selectable_rules.rules", "preset route rule has no outbound or action and was dropped", item)
			continue
		}
		parts.route = append(parts.route, item)
	}
	if raw, exists := preset["rule"]; exists {
		for _, item := range dnsRecordExpandedList(raw, vars, node, state) {
			if item["outbound"] == nil && item["action"] == nil {
				state.warn("preset_route_rule_dropped", "selectable_rules.rule", "preset route rule has no outbound or action and was dropped", item)
				continue
			}
			parts.route = append(parts.route, item)
		}
	}
	if namespace && stringValue(preset, "preset_id") != "" {
		parts = dnsRecordNamespacePreset(parts, stringValue(preset, "preset_id"))
	}
	return parts
}

func dnsRecordExpandedList(raw any, vars map[string]any, node map[string]any, state *buildState) []map[string]any {
	if raw == nil {
		return nil
	}
	prepared, err := dnsRecordPrepareTpl(raw, vars, node, state)
	if err != nil {
		state.warn("preset_template_expand_failed", "selectable_rules", err.Error(), nil)
		return nil
	}
	expanded, err := expand(prepared, vars, node, state)
	if err != nil && err != errDrop {
		state.warn("preset_template_expand_failed", "selectable_rules", err.Error(), nil)
		return nil
	}
	if err == errDrop || expanded == nil {
		return nil
	}
	result := []map[string]any{}
	switch value := expanded.(type) {
	case map[string]any:
		result = append(result, value)
	case []any:
		for _, item := range value {
			if object, ok := item.(map[string]any); ok {
				result = append(result, object)
			}
		}
	}
	return result
}

func dnsRecordPrepareTpl(value any, vars map[string]any, node map[string]any, state *buildState) (any, error) {
	switch raw := value.(type) {
	case []any:
		out := make([]any, 0, len(raw))
		for _, item := range raw {
			v, err := dnsRecordPrepareTpl(item, vars, node, state)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case map[string]any:
		if tpl, ok := raw["#tpl"]; ok {
			text, ok := tpl.(string)
			if !ok {
				return nil, fmt.Errorf("#tpl must be a string")
			}
			return dnsRecordTplString(text, vars, node, state), nil
		}
		out := map[string]any{}
		for k, item := range raw {
			v, err := dnsRecordPrepareTpl(item, vars, node, state)
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	default:
		return value, nil
	}
}

var dnsRecordTplSlot = regexp.MustCompile(`@\{([^{}]+)\}`)

func dnsRecordTplString(text string, vars map[string]any, node map[string]any, state *buildState) string {
	return dnsRecordTplSlot.ReplaceAllStringFunc(text, func(slot string) string {
		name := strings.TrimSuffix(strings.TrimPrefix(slot, "@{"), "}")
		if node != nil {
			if name == "node" {
				return stringValue(node, "tag")
			}
			if strings.HasPrefix(name, "node.") {
				if value, ok := lookup(node, strings.TrimPrefix(name, "node.")); ok {
					return fmt.Sprint(value)
				}
			}
		}
		if value, ok := lookup(vars, name); ok {
			return fmt.Sprint(value)
		}
		state.warn("unresolved_template_tpl", "template", "unknown #tpl value "+name, nil)
		return ""
	})
}

func dnsRecordNodeCondition(raw any, vars map[string]any, node map[string]any, state *buildState) bool {
	local := dnsRecordVarsForNode(vars, node)
	prepared, err := dnsRecordPrepareTpl(raw, local, node, state)
	if err != nil {
		return false
	}
	ok, _ := evaluate(prepared, local, node)
	return ok
}

func dnsRecordConfigNodes(config map[string]any) []map[string]any {
	out := []map[string]any{}
	for _, key := range []string{"outbounds", "endpoints"} {
		for _, raw := range recordSettingList(config, key) {
			if item, ok := raw.(map[string]any); ok && stringValue(item, "tag") != "" {
				out = append(out, cloneMap(item))
			}
		}
	}
	return out
}

func dnsRecordVarsForNode(vars map[string]any, node map[string]any) map[string]any {
	out := cloneMap(vars)
	tag := stringValue(node, "tag")
	out["node"] = tag
	for key, value := range node {
		out["node."+key] = clone(value)
	}
	out["node.body"] = cloneMap(node)
	for key, value := range node {
		out["node.body."+key] = clone(value)
	}
	return out
}

func dnsRecordCollectNodeVars(vars map[string]any, loop map[string]any, config map[string]any, state *buildState) map[string]any {
	out := cloneMap(vars)
	do, _ := loop["#do"].(map[string]any)
	for name, operation := range do {
		values := []any{}
		for _, node := range dnsRecordConfigNodes(config) {
			local := dnsRecordVarsForNode(out, node)
			if filter, exists := loop["#filter"]; exists && !dnsRecordNodeCondition(filter, local, node, state) {
				continue
			}
			rhs := operation
			if object, ok := operation.(map[string]any); ok {
				if cond, exists := object["#if"]; exists {
					parts, _ := cond.([]any)
					if len(parts) != 2 || !dnsRecordNodeCondition(parts[0], local, node, state) {
						continue
					}
					rhs = parts[1]
				}
				if objectRHS, ok := rhs.(map[string]any); ok {
					rhs = objectRHS["#append"]
				}
			}
			if text, ok := rhs.(string); ok {
				values = append(values, dnsRecordTplString(dnsRecordNormalizeTplText(text), local, node, state))
			}
		}
		out[name] = values
	}
	return out
}

func dnsRecordNormalizeTplText(text string) string {
	if strings.HasPrefix(text, "@") && !strings.HasPrefix(text, "@{") {
		return "@{" + strings.TrimPrefix(text, "@") + "}"
	}
	return text
}

func dnsRecordPresetVars(preset, record map[string]any, state *buildState) map[string]any {
	vars := cloneMap(state.vars)
	for _, raw := range recordSettingList(preset, "vars") {
		decl, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name := stringValue(decl, "name")
		ref := stringValue(decl, "ref")
		if ref != "" {
			if value, exists := state.vars[ref]; exists {
				vars[name] = clone(value)
			}
			continue
		}
		vars[name] = typedDefault(decl["default_value"], stringValue(decl, "type"))
	}
	for key, value := range recordMapValue(record, "vars") {
		if fallback, exists := vars[key]; exists {
			vars[key] = coerce(value, fallback)
		} else {
			vars[key] = value
		}
	}
	return vars
}

func dnsRecordLocalVars(global map[string]any, declarations any) map[string]any {
	vars := cloneMap(global)
	for _, raw := range recordSettingList(map[string]any{"vars": declarations}, "vars") {
		decl, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name := stringValue(decl, "name")
		if name != "" {
			vars[name] = typedDefault(decl["default_value"], stringValue(decl, "type"))
		}
	}
	return vars
}

func dnsRecordFindPreset(template map[string]any, id string) map[string]any {
	for _, raw := range recordSettingList(template, "selectable_rules") {
		if item, ok := raw.(map[string]any); ok && stringValue(item, "preset_id") == id {
			return item
		}
	}
	return nil
}

func dnsRecordPresetRefTag(ref string) string {
	if at := strings.IndexByte(ref, ':'); at >= 0 {
		return ref
	}
	return ref
}

func dnsRecordMapList(items []map[string]any) []any {
	out := make([]any, 0, len(items))
	for _, item := range items {
		out = append(out, cloneMap(item))
	}
	return out
}

func dnsRecordMergePresetParts(a, b dnsRecordPresetParts) dnsRecordPresetParts {
	a.servers = append(a.servers, b.servers...)
	a.rules = append(a.rules, b.rules...)
	a.route = append(a.route, b.route...)
	a.ruleSets = append(a.ruleSets, b.ruleSets...)
	return a
}

func dnsRecordNamespacePreset(parts dnsRecordPresetParts, presetID string) dnsRecordPresetParts {
	// Namespace tags declared by a preset and every reference to those tags.
	// This mirrors the record contract: references to global tags remain intact.
	localDNS, localSets := map[string]bool{}, map[string]bool{}
	for _, item := range parts.servers {
		if tag := stringValue(item, "tag"); tag != "" {
			localDNS[tag] = true
		}
	}
	for _, item := range parts.ruleSets {
		if tag := stringValue(item, "tag"); tag != "" {
			localSets[tag] = true
		}
	}
	qualify := func(tag string, local map[string]bool) string {
		if tag == "" || !local[tag] || presetID == "" {
			return tag
		}
		return presetID + ":" + tag
	}
	for _, item := range parts.servers {
		item["tag"] = qualify(stringValue(item, "tag"), localDNS)
		if members, ok := item["servers"].([]any); ok {
			for i, raw := range members {
				if tag, ok := raw.(string); ok {
					members[i] = qualify(tag, localDNS)
				}
			}
		}
	}
	for _, item := range parts.ruleSets {
		item["tag"] = qualify(stringValue(item, "tag"), localSets)
	}
	for _, item := range parts.rules {
		dnsRecordMapRuleRefs(item, localDNS, localSets, qualify)
	}
	for _, item := range parts.route {
		dnsRecordMapRuleRefs(item, localDNS, localSets, qualify)
	}
	return parts
}

func dnsRecordMapRuleRefs(rule map[string]any, localDNS, localSets map[string]bool, qualify func(string, map[string]bool) string) {
	if tag, ok := rule["server"].(string); ok {
		rule["server"] = qualify(tag, localDNS)
	}
	if ref, ok := rule["rule_set"].(string); ok {
		rule["rule_set"] = qualify(ref, localSets)
	} else if refs, ok := rule["rule_set"].([]any); ok {
		for i, raw := range refs {
			if ref, ok := raw.(string); ok {
				refs[i] = qualify(ref, localSets)
			}
		}
	}
	if subs, ok := rule["rules"].([]any); ok {
		for _, raw := range subs {
			if sub, ok := raw.(map[string]any); ok {
				dnsRecordMapRuleRefs(sub, localDNS, localSets, qualify)
			}
		}
	}
}

func recordSettingList(m map[string]any, key string) []any {
	if m == nil {
		return nil
	}
	if list, ok := m[key].([]any); ok {
		return list
	}
	return nil
}

func recordMapValue(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	result, _ := m[key].(map[string]any)
	return result
}

func recordStringList(value any) []string {
	result := []string{}
	switch raw := value.(type) {
	case []any:
		for _, item := range raw {
			if text, ok := item.(string); ok {
				result = append(result, text)
			}
		}
	case []string:
		result = append(result, raw...)
	case string:
		if raw != "" {
			result = append(result, raw)
		}
	}
	return result
}
