package builder

import (
	"fmt"
	"strings"
)

func applyDNSDefaults(config, template map[string]any, vars, settings map[string]any, state *buildState) error {
	options, ok := template["dns_options"].(map[string]any)
	if !ok {
		state.warn("dns_template_missing", "template.dns_options", "template has no DNS catalog", nil)
		return nil
	}
	declarations, _ := options["servers"].([]any)
	dns, _ := config["dns"].(map[string]any)
	if dns == nil {
		return fmt.Errorf("config.dns is not an object")
	}
	stored, _ := settings["dns"].(map[string]any)
	storedServers, _ := stored["servers"].([]any)
	result := []any{}
	seen := map[string]bool{}
	for index, raw := range declarations {
		decl, ok := raw.(map[string]any)
		if !ok {
			state.fatal("dns_declaration_invalid", fmt.Sprintf("template.dns_options.servers[%d]", index), "DNS declaration must be an object")
			continue
		}
		body, ok := decl["server"].(map[string]any)
		if !ok {
			state.fatal("dns_body_missing", fmt.Sprintf("template.dns_options.servers[%d].server", index), "DNS server declaration is missing its server body")
			continue
		}
		tag := stringValue(body, "tag")
		entryVars := cloneMap(vars)
		for _, rawVar := range asList(decl["vars"]) {
			variable, ok := rawVar.(map[string]any)
			if !ok {
				state.fatal("dns_var_invalid", fmt.Sprintf("template.dns_options.servers[%d].vars", index), "DNS variable declaration must be an object")
				continue
			}
			name := stringValue(variable, "name")
			if name != "" {
				entryVars[name] = typedDefault(variable["default_value"], stringValue(variable, "type"))
			}
		}
		enabled := decl["enabled"] != false
		for _, optionRaw := range storedServers {
			option, ok := optionRaw.(map[string]any)
			if !ok || stringValue(option, "tag") != tag {
				continue
			}
			enabled = boolValue(option, "enabled", true)
			if values, ok := option["vars"].(map[string]any); ok {
				for key, value := range values {
					if fallback, declared := entryVars[key]; declared {
						entryVars[key] = coerce(value, fallback)
					}
				}
			}
		}
		if !enabled {
			continue
		}
		expanded, err := expand(body, entryVars, nil, state)
		if err == errDrop {
			continue
		}
		if err != nil {
			return err
		}
		entry, ok := expanded.(map[string]any)
		if !ok {
			return fmt.Errorf("DNS server %q did not expand to an object", tag)
		}
		if tag == "" {
			tag = stringValue(entry, "tag")
		}
		entry["tag"] = tag
		if entry["detour"] == "direct-out" {
			delete(entry, "detour")
		}
		if !seen[tag] {
			seen[tag] = true
			result = append(result, entry)
		}
	}
	for _, raw := range storedServers {
		option, ok := raw.(map[string]any)
		if !ok {
			state.fatal("dns_override_invalid", "settings.dns.servers", "DNS server override must be an object")
			continue
		}
		kind, tag := stringValue(option, "kind"), stringValue(option, "tag")
		switch kind {
		case "user", "inline":
			body, _ := option["body"].(map[string]any)
			if body == nil {
				state.fatal("dns_inline_body_missing", "settings.dns.servers."+tag, "inline server body is missing")
				continue
			}
			entry := cloneMap(body)
			entry["tag"] = tag
			if seen[tag] {
				replaceByTag(result, tag, entry)
			} else {
				seen[tag] = true
				result = append(result, entry)
			}
		case "template", "preset":
		default:
			state.fatal("dns_kind_unsupported", "settings.dns.servers."+tag, "DNS server kind is unsupported: "+kind)
		}
	}
	dns["servers"] = result
	if rules, ok := stored["rules"].([]any); ok && len(rules) > 0 {
		state.fatal("dns_rules_unsupported", "settings.dns.rules", "stored DNS rule references are not implemented")
	}
	if rules, ok := options["rules"].([]any); ok && len(rules) > 0 {
		state.fatal("dns_template_rules_unsupported", "template.dns_options.rules", "template DNS rule catalog is not resolved")
	}
	return nil
}

func replaceByTag(list []any, tag string, value map[string]any) {
	for index, raw := range list {
		entry, ok := raw.(map[string]any)
		if ok && stringValue(entry, "tag") == tag {
			list[index] = value
			return
		}
	}
}
func applyStoredDNS(config, settings map[string]any, state *buildState) {
	stored, ok := settings["dns"].(map[string]any)
	if !ok {
		return
	}
	dns, _ := config["dns"].(map[string]any)
	if dns == nil {
		dns = map[string]any{}
		config["dns"] = dns
	}
	for key, value := range stored {
		if key != "servers" && key != "rules" {
			dns[key] = clone(value)
		}
	}
	if rules, ok := stored["rules"].([]any); ok && len(rules) > 0 {
		state.fatal("dns_rules_unsupported", "settings.dns.rules", "stored DNS rule references are not implemented")
	}
}
func applyConfigOverrides(config, settings map[string]any, state *buildState) {
	for _, key := range []string{"config", "config_overrides"} {
		if override, ok := settings[key].(map[string]any); ok {
			deepMerge(config, override)
		}
	}
	for key, value := range settings {
		if !knownSettingSection(key) {
			state.warn("unknown_setting_section", "settings."+key, "unknown setting section is not interpreted", value)
		}
	}
}
func deepMerge(dst, src map[string]any) {
	for key, value := range src {
		if nested, ok := value.(map[string]any); ok {
			current, ok := dst[key].(map[string]any)
			if !ok {
				current = map[string]any{}
				dst[key] = current
			}
			deepMerge(current, nested)
		} else {
			dst[key] = clone(value)
		}
	}
}
func knownSettingSection(key string) bool {
	switch key {
	case "vars", "directions", "enabled_groups", "custom_rules", "route_final", "vpn_mode", "tun", "dns", "route", "config", "config_overrides", "sources", "chains", "mixins", "tun_apps", "rule_sets":
		return true
	}
	return false
}
func asList(value any) []any {
	if list, ok := value.([]any); ok {
		return list
	}
	return nil
}
func routeRules(config map[string]any) []any {
	route, _ := config["route"].(map[string]any)
	if route == nil {
		route = map[string]any{}
		config["route"] = route
	}
	rules, _ := route["rules"].([]any)
	return rules
}
func diagnosticPath(parts ...string) string { return strings.Join(parts, ".") }
