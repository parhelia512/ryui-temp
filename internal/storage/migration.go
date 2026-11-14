package storage

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// MigrationOptions supplies application facts needed to resolve legacy
// references. NodeLinks maps the final tag emitted by the old builder to its
// contract NodeLink record. PresetIDsByDNSTag maps a legacy config tag to the
// owning template preset id. PresetVarDefaults can be supplied by the template
// loader to remove values equal to declared defaults.
type MigrationOptions struct {
	NodeLinks          map[string]map[string]any
	PresetIDsByDNSTag  map[string]string
	PresetVarDefaults  map[string]map[string]string
	RuleVarDefaults    map[string]map[string]string
	SubscriptionBodies map[string][]byte
}

func migrateDocument(input map[string]any) (map[string]any, MigrationReport, error) {
	return MigrateDocumentWithOptions(input, MigrationOptions{})
}

// MigrateDocumentWithOptions converts recognized 2.23.2 records. It returns an
// unchanged clone and ReadOnly=true whenever required semantics are unavailable.
func MigrateDocumentWithOptions(input map[string]any, options MigrationOptions) (map[string]any, MigrationReport, error) {
	original, err := cloneDocument(input)
	if err != nil {
		return nil, MigrationReport{}, err
	}
	doc, err := cloneDocument(input)
	if err != nil {
		return nil, MigrationReport{}, err
	}
	report := MigrationReport{}
	version, hasVersion := integerValue(doc["storage_version"])
	if hasVersion {
		report.FoundVersion = &version
	}
	if raw, exists := doc["storage_version"]; exists && !hasVersion {
		return guardMigration(original, report, fmt.Sprintf("unrecognized storage_version %v; writes are disabled", raw))
	}
	if hasVersion && version > SettingsVersion {
		return guardMigration(original, report, fmt.Sprintf("storage_version %d is newer than supported version %d; writes are disabled", version, SettingsVersion))
	}
	legacyKeys := []string{}
	for _, key := range []string{"server_lists", "chains", "custom_rules", "dns_options"} {
		if _, exists := doc[key]; exists {
			legacyKeys = append(legacyKeys, key)
		}
	}
	if hasVersion && len(legacyKeys) > 0 {
		return guardMigration(original, report, "storage_version is present together with legacy collections; refusing mixed-form rewrite")
	}
	if hasVersion {
		if hasLegacyAutoGroup(doc["sources"]) {
			return guardMigration(original, report, "versioned document contains autogroup:// members which require node-identity parsing")
		}
		return doc, report, nil
	}
	if len(legacyKeys) == 0 {
		return guardMigration(original, report, "unversioned storage has no recognizable legacy collections; writes are disabled")
	}
	for _, pair := range [][2]string{{"server_lists", "sources"}, {"chains", "sources"}, {"custom_rules", "rules"}, {"dns_options", "dns"}} {
		if _, old := doc[pair[0]]; old {
			if _, current := doc[pair[1]]; current {
				return guardMigration(original, report, fmt.Sprintf("both %s and %s are present; refusing ambiguous merge", pair[0], pair[1]))
			}
		}
	}

	if raw, exists := doc["server_lists"]; exists {
		lists, ok := raw.([]any)
		if !ok {
			return guardMigration(original, report, "server_lists is not an array")
		}
		converted := make([]any, 0, len(lists))
		for i, item := range lists {
			record, ok := item.(map[string]any)
			if !ok {
				return guardMigration(original, report, fmt.Sprintf("server_lists[%d] is not an object", i))
			}
			out, reason := migrateLegacySource(record, options)
			if reason != "" {
				return guardMigration(original, report, fmt.Sprintf("server_lists[%d]: %s", i, reason))
			}
			converted = append(converted, out)
		}
		doc["sources"] = converted
	}
	if raw, exists := doc["chains"]; exists {
		chains, ok := raw.([]any)
		if !ok {
			return guardMigration(original, report, "chains is not an array")
		}
		type orderedChain struct {
			order  int
			index  int
			record map[string]any
		}
		ordered := make([]orderedChain, 0, len(chains))
		for i, item := range chains {
			record, ok := item.(map[string]any)
			if !ok {
				return guardMigration(original, report, fmt.Sprintf("chains[%d] is not an object", i))
			}
			converted, reason := migrateLegacyChain(record, options.NodeLinks)
			if reason != "" {
				return guardMigration(original, report, fmt.Sprintf("chains[%d]: %s", i, reason))
			}
			order, ok := integerValue(record["order"])
			if !ok || order < 0 {
				order = int(^uint(0) >> 2)
			}
			ordered = append(ordered, orderedChain{order: order, index: i, record: converted})
		}
		sort.SliceStable(ordered, func(i, j int) bool {
			if ordered[i].order == ordered[j].order {
				return ordered[i].index < ordered[j].index
			}
			return ordered[i].order < ordered[j].order
		})
		sources, _ := doc["sources"].([]any)
		for _, chain := range ordered {
			sources = append(sources, chain.record)
		}
		doc["sources"] = sources
	}
	if raw, exists := doc["custom_rules"]; exists {
		rules, ok := raw.([]any)
		if !ok {
			return guardMigration(original, report, "custom_rules is not an array")
		}
		converted := make([]any, 0, len(rules))
		for i, item := range rules {
			record, ok := item.(map[string]any)
			if !ok {
				return guardMigration(original, report, fmt.Sprintf("custom_rules[%d] is not an object", i))
			}
			out, reason := migrateLegacyRule(record, options)
			if reason != "" {
				return guardMigration(original, report, fmt.Sprintf("custom_rules[%d]: %s", i, reason))
			}
			converted = append(converted, out...)
		}
		doc["rules"] = converted
	}
	if raw, exists := doc["dns_options"]; exists {
		optionsMap, ok := raw.(map[string]any)
		if !ok {
			return guardMigration(original, report, "dns_options is not an object")
		}
		dns, reason := migrateLegacyDNS(optionsMap, options)
		if reason != "" {
			return guardMigration(original, report, reason)
		}
		doc["dns"] = dns
	}
	if value, exists := doc["channels"]; exists {
		if _, has := doc["directions"]; !has {
			doc["directions"] = value
		}
	}
	if value, exists := doc["channels_migrated"]; exists {
		if _, has := doc["directions_migrated"]; !has {
			doc["directions_migrated"] = value
		}
	} else if _, has := doc["channels"]; has {
		if _, migrated := doc["directions_migrated"]; !migrated {
			doc["directions_migrated"] = true
		}
	}
	if err := migrateURLTestMode(doc); err != nil {
		return guardMigration(original, report, err.Error())
	}
	if vars, ok := doc["vars"].(map[string]any); ok {
		delete(vars, "auto_rebuild")
	}
	for _, key := range []string{"excluded_nodes", "preset_ids_remapped", "proxy_sources", "app_rules", "enabled_rules", "rule_outbounds", "node_overrides", "show_detour_servers"} {
		delete(doc, key)
	}
	for _, key := range append(append([]string{}, legacyKeys...), "channels", "channels_migrated") {
		delete(doc, key)
	}
	doc["storage_version"] = SettingsVersion
	report.Migrated = true
	report.Info = append(report.Info, "2.23.2 storage collections migrated to storage_version 1")
	return doc, report, nil
}

func guardMigration(original map[string]any, report MigrationReport, reason string) (map[string]any, MigrationReport, error) {
	report.ReadOnly = true
	report.Migrated = false
	report.Warnings = append(report.Warnings, reason)
	return original, report, nil
}

func migrateLegacySource(record map[string]any, options MigrationOptions) (map[string]any, string) {
	out, err := cloneDocument(record)
	if err != nil {
		return nil, err.Error()
	}
	typeName, _ := record["type"].(string)
	switch typeName {
	case "subscription":
		if _, exists := record["identity"]; exists {
			return nil, "subscription identity requires the frozen identity model"
		}
		if _, exists := record["import_rules"]; exists {
			return nil, "subscription import_rules require the frozen ImportRule codec"
		}
		if _, exists := record["disabled_hashes"]; exists {
			return nil, "disabled_hashes timestamps require node identity and unix-time normalization"
		}
		out["kind"] = "subscription"
		interval, exists := record["update_interval_hours"]
		if !exists {
			interval = json.Number("24")
		}
		out["update"] = map[string]any{"interval_hours": interval}
		for _, key := range []string{"type", "tag_prefix", "update_interval_hours"} {
			delete(out, key)
		}
		if value, ok := record["on_update_action"]; ok {
			out["on_update_action"] = value
		}
	case "user":
		out["kind"] = "server"
		raw, ok := record["raw_body"].(string)
		if !ok || raw == "" {
			return nil, "user server has no raw_body"
		}
		out["origin"] = map[string]any{"kind": legacyOriginKind(raw), "raw": raw}
		delete(out, "type")
		delete(out, "raw_body")
		if reason := migrateLegacyDetour(out, record["detour_policy"], options.NodeLinks); reason != "" {
			return nil, reason
		}
	case "folder":
		out["kind"] = "folder"
		members, ok := record["members"].([]any)
		if !ok {
			return nil, "members is not an array"
		}
		nodes := make([]any, 0, len(members))
		for i, item := range members {
			member, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Sprintf("member %d is not an object", i)
			}
			raw, _ := member["raw"].(string)
			if strings.HasPrefix(raw, "autogroup://") {
				return nil, "autogroup member needs parsed sibling node identities"
			}
			node, err := cloneDocument(member)
			if err != nil {
				return nil, err.Error()
			}
			if raw != "" {
				node["kind"] = "server"
				node["origin"] = map[string]any{"kind": legacyOriginKind(raw), "raw": raw}
			}
			delete(node, "raw")
			if detour, ok := member["detour"].(string); ok && detour != "" {
				link, found := MigrationLinkForTag(detour, options.NodeLinks)
				if !found {
					return nil, fmt.Sprintf("member detour %q has no resolved NodeLink", detour)
				}
				node["detour"] = link
			}
			nodes = append(nodes, node)
		}
		out["nodes"] = nodes
		delete(out, "type")
		delete(out, "members")
		if reason := migrateLegacyDetour(out, record["detour_policy"], options.NodeLinks); reason != "" {
			return nil, reason
		}
	default:
		return nil, fmt.Sprintf("unknown legacy source type %q", typeName)
	}
	if prefix, ok := record["tag_prefix"].(string); ok && prefix != "" {
		out["tag_policy"] = map[string]any{"prefix": strings.TrimRight(prefix, " ") + " "}
	}
	delete(out, "tag_prefix")
	return out, ""
}

func migrateLegacyDetour(out map[string]any, rawPolicy any, links map[string]map[string]any) string {
	policy, ok := rawPolicy.(map[string]any)
	if !ok {
		return ""
	}
	copyPolicy, err := cloneDocument(policy)
	if err != nil {
		return err.Error()
	}
	tag, _ := policy["override_detour"].(string)
	if tag != "" {
		link, found := MigrationLinkForTag(tag, links)
		if !found {
			return fmt.Sprintf("detour %q has no resolved NodeLink", tag)
		}
		out["detour"] = link
		delete(copyPolicy, "override_detour")
	}
	out["detour_policy"] = copyPolicy
	return ""
}

func migrateLegacyChain(record map[string]any, links map[string]map[string]any) (map[string]any, string) {
	out, err := cloneDocument(record)
	if err != nil {
		return nil, err.Error()
	}
	tag, _ := record["tag"].(string)
	if strings.TrimSpace(tag) == "" {
		return nil, "chain without tag"
	}
	hops, ok := record["hops"].([]any)
	if !ok {
		return nil, "hops is not an array"
	}
	convertedHops := make([]any, 0, len(hops))
	for _, item := range hops {
		hop, ok := item.(string)
		if !ok {
			return nil, "hop is not a string tag"
		}
		link, found := MigrationLinkForTag(hop, links)
		if !found {
			return nil, fmt.Sprintf("hop %q has no resolved NodeLink", hop)
		}
		convertedHops = append(convertedHops, link)
	}
	body := map[string]any{"type": "chain"}
	for _, key := range []string{"idle_timeout", "strip_evasion", "strip", "rewrite"} {
		if value, ok := record[key]; ok {
			body[key] = value
			delete(out, key)
		}
	}
	out["kind"] = "chain"
	out["body"] = body
	out["hops"] = convertedHops
	delete(out, "order")
	return out, ""
}

func MigrationLinkForTag(tag string, links map[string]map[string]any) (map[string]any, bool) {
	link, ok := links[tag]
	return link, ok
}

func migrateLegacyRule(record map[string]any, options MigrationOptions) ([]any, string) {
	out, err := cloneDocument(record)
	if err != nil {
		return nil, err.Error()
	}
	kind, _ := record["kind"].(string)
	switch kind {
	case "", "inline":
		body := map[string]any{}
		mapping := map[string]string{"domains": "domain", "domainSuffixes": "domain_suffix", "domainKeywords": "domain_keyword", "ipCidrs": "ip_cidr", "portRanges": "port_range", "packages": "package_name", "protocols": "protocol", "network": "network", "ipIsPrivate": "ip_is_private", "sourceIpCidrs": "source_ip_cidr", "sourceIpIsPrivate": "source_ip_is_private", "inbounds": "inbound", "wifiSsids": "wifi_ssid", "wifiBssids": "wifi_bssid", "outbound": "outbound", "target": "outbound"}
		for old, current := range mapping {
			if value, ok := record[old]; ok {
				body[current] = value
				delete(out, old)
			}
		}
		if ports, ok := record["ports"].([]any); ok {
			converted := make([]any, 0, len(ports))
			for i, p := range ports {
				text := fmt.Sprint(p)
				number, err := json.Number(text).Int64()
				if err != nil || number < 0 || number > 65535 {
					return nil, fmt.Sprintf("port %d is not a numeric port", i)
				}
				converted = append(converted, number)
			}
			body["port"] = converted
			delete(out, "ports")
		}
		out["kind"] = "inline"
		if len(body) > 0 {
			out["body"] = body
		}
	case "srs":
		out["kind"] = "srs"
		if refs, ok := record["srsUrls"].([]any); ok {
			out["refs"] = refs
		} else if ref, ok := record["srsUrl"].(string); ok && ref != "" {
			out["refs"] = []any{ref}
		}
		delete(out, "srsUrl")
		delete(out, "srsUrls")
		delete(out, "ports")
		delete(out, "portRanges")
		delete(out, "packages")
		delete(out, "protocols")
		delete(out, "network")
		delete(out, "outbound")
		delete(out, "target")
	case "preset":
		preset, ok := record["presetId"].(string)
		if !ok || preset == "" {
			return nil, "preset rule has no presetId"
		}
		values, _ := record["varsValues"].(map[string]any)
		if len(values) > 0 {
			defaults, ok := options.RuleVarDefaults[preset]
			if !ok {
				return nil, fmt.Sprintf("preset rule %q vars need template defaults", preset)
			}
			normalized := map[string]any{}
			for key, value := range values {
				if def, known := defaults[key]; !known || fmt.Sprint(value) != def {
					normalized[key] = value
				}
			}
			out["vars"] = normalized
		}
		out["kind"] = "preset"
		out["ref"] = preset
		delete(out, "presetId")
		delete(out, "varsValues")
	case "json":
		raw, ok := record["json"].(string)
		if !ok {
			return nil, "json rule text is missing"
		}
		var decoded any
		if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
			out["kind"] = "inline"
			out["verbatim"] = true
			delete(out, "json")
			return []any{out}, ""
		}
		if object, ok := decoded.(map[string]any); ok {
			out["kind"] = "inline"
			out["verbatim"] = true
			out["body"] = object
			delete(out, "json")
			return []any{out}, ""
		}
		if array, ok := decoded.([]any); ok {
			objects := []map[string]any{}
			for _, element := range array {
				if object, ok := element.(map[string]any); ok {
					objects = append(objects, object)
				}
			}
			if len(objects) <= 1 {
				out["kind"] = "inline"
				out["verbatim"] = true
				if len(objects) == 1 {
					out["body"] = objects[0]
				}
				delete(out, "json")
				return []any{out}, ""
			}
			return nil, "JSON array has multiple records and requires stable ID generation"
		}
		out["kind"] = "inline"
		out["verbatim"] = true
		delete(out, "json")
		return []any{out}, ""
	default:
		return nil, fmt.Sprintf("unknown rule kind %q", kind)
	}
	return []any{out}, ""
}

func migrateLegacyDNS(input map[string]any, options MigrationOptions) (map[string]any, string) {
	if _, exists := input["rules_json"]; exists {
		return nil, "dns_options.rules_json requires the frozen pre-§061 parser"
	}
	out := map[string]any{}
	for _, collection := range []string{"servers", "rules"} {
		items, exists := input[collection]
		if !exists {
			out[collection] = []any{}
			continue
		}
		list, ok := items.([]any)
		if !ok {
			return nil, "dns_options." + collection + " is not an array"
		}
		converted := make([]any, 0, len(list))
		for i, item := range list {
			record, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Sprintf("dns_options.%s[%d] is not an object", collection, i)
			}
			copy, err := cloneDocument(record)
			if err != nil {
				return nil, err.Error()
			}
			kind, _ := record["kind"].(string)
			if collection == "servers" {
				switch kind {
				case "inline":
					copy["kind"] = "user"
					if body, ok := record["body"].(map[string]any); ok {
						delete(body, "tag")
						copy["body"] = body
					}
				case "preset":
					tag, _ := record["tag"].(string)
					preset, ok := options.PresetIDsByDNSTag[tag]
					if !ok || preset == "" {
						return nil, fmt.Sprintf("preset DNS server %q needs template preset mapping", tag)
					}
					copy["kind"] = "preset"
					copy["ref"] = preset + ":" + tag
					delete(copy, "tag")
				case "template":
					values, hasValues := record["varValues"].(map[string]any)
					if hasValues && len(values) > 0 {
						defaults, known := options.PresetVarDefaults[tagOf(record)]
						if !known {
							return nil, fmt.Sprintf("template DNS server %q vars need template defaults", tagOf(record))
						}
						filtered := map[string]any{}
						for key, value := range values {
							if def, exists := defaults[key]; !exists || fmt.Sprint(value) != def {
								filtered[key] = value
							}
						}
						copy["vars"] = filtered
					}
					copy["kind"] = "template"
					delete(copy, "varValues")
				default:
					return nil, fmt.Sprintf("unknown DNS server kind %q", kind)
				}
			} else {
				switch kind {
				case "inline":
					copy["kind"] = "user"
					if body, ok := record["rule"].(map[string]any); ok {
						copy["body"] = body
					}
					delete(copy, "rule")
				case "srs":
					copy["kind"] = "srs"
				case "preset":
					copy["kind"] = "preset"
					if ref, ok := record["presetId"]; ok {
						copy["ref"] = ref
					}
					delete(copy, "presetId")
				case "template":
					copy["kind"] = "template"
				default:
					return nil, fmt.Sprintf("unknown DNS rule kind %q", kind)
				}
			}
			converted = append(converted, copy)
		}
		out[collection] = converted
	}
	return out, ""
}

func tagOf(record map[string]any) string { tag, _ := record["tag"].(string); return tag }

func migrateURLTestMode(doc map[string]any) error {
	if doc["urltest_mode_migrated"] == true {
		return nil
	}
	vars, _ := doc["vars"].(map[string]any)
	passive, exists := vars["urltest_passive_check"]
	toFailover := !exists
	if exists {
		flag, ok := passive.(bool)
		if !ok {
			return fmt.Errorf("urltest_passive_check has unsupported type")
		}
		toFailover = flag
	}
	fix := func(value any) {
		auto, ok := value.(map[string]any)
		if !ok {
			return
		}
		mode, exists := auto["mode"]
		if exists && mode != "least_test" {
			return
		}
		auto["mode"] = "failover"
	}
	if toFailover {
		if directions, ok := doc["directions"].([]any); ok {
			for _, v := range directions {
				if d, ok := v.(map[string]any); ok {
					fix(d["auto"])
				}
			}
		}
		if sources, ok := doc["sources"].([]any); ok {
			for _, v := range sources {
				src, ok := v.(map[string]any)
				if !ok {
					continue
				}
				if replace, ok := src["replace"].(map[string]any); ok {
					fix(replace["auto"])
				}
				if nodes, ok := src["nodes"].([]any); ok {
					for _, v := range nodes {
						node, ok := v.(map[string]any)
						if !ok || node["kind"] != "auto" {
							continue
						}
						group, ok := node["group"].(map[string]any)
						if !ok || group["group_type"] == "selector" {
							continue
						}
						if strategy, ok := group["strategy"].(map[string]any); ok {
							fix(strategy)
						} else {
							group["strategy"] = map[string]any{"mode": "failover"}
						}
					}
				}
			}
		}
	}
	if vars != nil {
		delete(vars, "urltest_passive_check")
	}
	doc["urltest_mode_migrated"] = true
	return nil
}

func hasLegacyAutoGroup(value any) bool {
	sources, ok := value.([]any)
	if !ok {
		return false
	}
	for _, sourceValue := range sources {
		source, ok := sourceValue.(map[string]any)
		if !ok || source["kind"] != "folder" {
			continue
		}
		nodes, ok := source["nodes"].([]any)
		if !ok {
			continue
		}
		for _, nodeValue := range nodes {
			node, ok := nodeValue.(map[string]any)
			if !ok {
				continue
			}
			origin, ok := node["origin"].(map[string]any)
			if !ok {
				continue
			}
			raw, _ := origin["raw"].(string)
			if strings.HasPrefix(raw, "autogroup://") {
				return true
			}
		}
	}
	return false
}

func legacyOriginKind(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return "json"
	}
	return "uri"
}
func integerValue(value any) (int, bool) {
	switch number := value.(type) {
	case int:
		return number, true
	case int32:
		return int(number), true
	case int64:
		return int(number), true
	case float64:
		if number == float64(int(number)) {
			return int(number), true
		}
	case json.Number:
		n, err := number.Int64()
		return int(n), err == nil
	}
	return 0, false
}
