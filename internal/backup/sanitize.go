package backup

import "fmt"

// sanitizePortable drops fields outside the portable contract before they can
// become storage. Native protocol bodies and mixin values remain opaque JSON.
func sanitizePortable(root map[string]any, warnings *[]Warning) map[string]any {
	out := filterPortable(cloneMap(root), warnings)
	for _, section := range []string{"sources", "directions", "rules", "warp", "mixins"} {
		items, ok := out[section].([]any)
		if !ok {
			if _, exists := out[section]; exists {
				*warnings = append(*warnings, Warning{Code: WarnTypeMismatch, Detail: section})
				delete(out, section)
			}
			continue
		}
		for i, value := range items {
			record, ok := value.(map[string]any)
			if !ok {
				*warnings = append(*warnings, Warning{Code: WarnTypeMismatch, Detail: fmt.Sprintf("%s[%d]", section, i)})
				continue
			}
			path := fmt.Sprintf("%s[%d]", section, i)
			if section == "sources" {
				sanitizeSource(record, path, warnings)
			}
			if section == "directions" {
				filterNested(record, "auto", autoKeys(), path, warnings)
			}
		}
	}
	filterNested(out, "exported_by", set("app", "version", "platform"), "", warnings)
	filterNested(out, "route", set("final"), "", warnings)
	if raw, exists := out["dns"]; exists {
		dns, ok := raw.(map[string]any)
		if !ok {
			*warnings = append(*warnings, Warning{Code: WarnTypeMismatch, Detail: "dns"})
			delete(out, "dns")
		} else {
			dns = filterObject(dns, set("servers", "rules", "final", "strategy", "default_domain_resolver", "template_catalog"), "dns", warnings)
			for _, section := range []string{"servers", "rules"} {
				if items, ok := dns[section].([]any); ok {
					for i, value := range items {
						if record, ok := value.(map[string]any); ok {
							keys := set("kind", "tag", "ref", "id", "name", "enabled", "body", "description")
							if section == "servers" && record["kind"] == "template" {
								keys["vars"] = true
							}
							items[i] = filterObject(record, keys, fmt.Sprintf("dns.%s[%d]", section, i), warnings)
						}
					}
				}
			}
			out["dns"] = dns
		}
	}
	return out
}

func sanitizeSource(record map[string]any, path string, warnings *[]Warning) {
	filterNested(record, "origin", set("kind", "raw", "sub_url"), path, warnings)
	filterNested(record, "detour", set("folder_id", "tag"), path, warnings)
	filterNested(record, "tag_policy", set("prefix", "postfix"), path, warnings)
	filterNested(record, "update", set("interval_hours", "auto_refresh"), path, warnings)
	if sections, exists := record["sections"]; exists {
		if !empty(sections) {
			*warnings = append(*warnings, Warning{Code: "backup_section_record_dropped", Detail: path + ".sections", Kind: text(record["kind"]), Reason: "not_allowed"})
		}
		delete(record, "sections")
	}
	if nodes, ok := record["nodes"].([]any); ok {
		for i, value := range nodes {
			if node, ok := value.(map[string]any); ok {
				nodePath := fmt.Sprintf("%s.nodes[%d]", path, i)
				keys := add(sourceKeys("server"), "group", "reason")
				delete(keys, "id")
				node = filterObject(node, keys, nodePath, warnings)
				sanitizeSource(node, nodePath, warnings)
				nodes[i] = node
			}
		}
	}
	if group, ok := record["group"].(map[string]any); ok {
		group = filterObject(group, set("group_type", "default", "members", "strategy", "members_rule", "pool_badge"), path+".group", warnings)
		filterNested(group, "strategy", autoKeys(), path+".group", warnings)
		filterNested(group, "members_rule", set("include", "exclude"), path+".group", warnings)
		record["group"] = group
	}
}

func autoKeys() map[string]bool {
	return set("mode", "url", "interval", "tolerance", "idle_timeout", "interrupt_exist_connections", "pool", "pool_tolerance", "sticky_hash")
}

func filterNested(parent map[string]any, key string, keys map[string]bool, path string, warnings *[]Warning) {
	value, exists := parent[key]
	if !exists {
		return
	}
	if path != "" {
		path += "."
	}
	path += key
	record, ok := value.(map[string]any)
	if !ok {
		*warnings = append(*warnings, Warning{Code: WarnTypeMismatch, Detail: path})
		delete(parent, key)
		return
	}
	parent[key] = filterObject(record, keys, path, warnings)
}

func emptyCategory(category string) any {
	switch category {
	case "route":
		return ""
	case "vars", "native_prefs", "dns", "tun_apps":
		return map[string]any{}
	default:
		return []any{}
	}
}

func clearOther(doc map[string]any) {
	known := set("storage_version")
	for _, category := range Categories {
		known[storageKey(category)] = true
	}
	for key := range doc {
		if !known[key] {
			delete(doc, key)
		}
	}
}
