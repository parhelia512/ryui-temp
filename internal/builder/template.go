package builder

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var errDrop = fmt.Errorf("template value is disabled")

func resolveVars(template, settings map[string]any, state *buildState) map[string]any {
	vars := map[string]any{}
	sections, _ := template["sections"].([]any)
	for _, raw := range sections {
		section, _ := raw.(map[string]any)
		declarations, _ := section["vars"].([]any)
		for _, item := range declarations {
			declaration, _ := item.(map[string]any)
			name := stringValue(declaration, "name")
			if name != "" {
				vars[name] = typedDefault(declaration["default_value"], stringValue(declaration, "type"))
			}
		}
	}
	user, _ := settings["vars"].(map[string]any)
	for key, value := range user {
		if _, declared := vars[key]; declared {
			vars[key] = coerce(value, vars[key])
		}
	}
	if vpn, ok := settings["vpn_mode"].(map[string]any); ok {
		for from, to := range map[string]string{"mode": "vpn_mode", "proxy_protocol": "proxy_type", "proxy_type": "proxy_type", "proxy_listen": "proxy_listen", "proxy_port": "proxy_port", "proxy_username": "proxy_user", "proxy_password": "proxy_pass", "proxy_auth": "proxy_auth", "system_proxy_enabled": "sys_proxy", "system_proxy_port": "sys_proxy_port"} {
			if value, exists := vpn[from]; exists {
				vars[to] = coerce(value, vars[to])
			}
		}
	}
	if tun, ok := settings["tun"].(map[string]any); ok {
		for from, to := range map[string]string{"address": "tun_address", "address6": "tun_address6", "ipv6_enabled": "ipv6_enabled", "route_address_enable": "route_address_enable", "route_exclude": "tun_route_exclude", "route_exclude_address": "tun_route_exclude", "name": "tun_name", "mtu": "tun_mtu", "auto_route": "tun_auto_route", "strict_route": "tun_strict_route", "stack": "tun_stack"} {
			if value, exists := tun[from]; exists {
				vars[to] = coerce(value, vars[to])
			}
		}
	}
	state.vars = vars
	return vars
}

func coerce(value, fallback any) any {
	if value == nil {
		return fallback
	}
	switch fallback.(type) {
	case bool:
		if v, ok := value.(bool); ok { return v }
		if v, ok := value.(string); ok { parsed, err := strconv.ParseBool(v); if err == nil { return parsed } }
	case int:
		switch v := value.(type) { case int: return v; case float64: return int(v); case string: parsed, err := strconv.Atoi(strings.TrimSpace(v)); if err == nil { return parsed } }
	case []any:
		return stringsToAny(stringsOf(value))
	}
	return value
}
func stringsToAny(values []string) []any { result := make([]any, len(values)); for i, value := range values { result[i] = value }; return result }

func expandConfig(template map[string]any, vars map[string]any, state *buildState) (map[string]any, error) {
	root, ok := template["config"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("template.config must be an object")
	}
	value, err := expand(root, vars, nil, state)
	if err != nil { return nil, err }
	result, _ := value.(map[string]any)
	if result == nil { return nil, fmt.Errorf("expanded config is not an object") }
	return result, nil
}

func expand(value any, vars map[string]any, node map[string]any, state *buildState) (any, error) {
	switch raw := value.(type) {
	case string:
		if strings.HasPrefix(raw, "@{") && strings.HasSuffix(raw, "}") {
			return expandTemplate(raw, vars, node, state), nil
		}
		if strings.HasPrefix(raw, "@") && !strings.Contains(raw, " ") {
			name := strings.TrimPrefix(raw, "@")
			if resolved, ok := lookup(vars, name); ok {
				return clone(resolved), nil
			}
			if node != nil {
				if resolved, ok := lookup(node, name); ok {
					return clone(resolved), nil
				}
			}
			if _, known := state.vars[name]; known {
				state.fatal("template_var_default_missing", "template.vars."+name, "template variable has no usable value")
			} else {
				state.fatal("unresolved_template_var", "template", "unknown variable "+raw)
			}
			return nil, errDrop
		}
		return raw, nil
	case []any:
		result := make([]any, 0, len(raw))
		for _, item := range raw {
			resolved, err := expand(item, vars, node, state)
			if err == errDrop || resolved == nil {
				continue
			}
			if err != nil {
				return nil, err
			}
			result = append(result, resolved)
		}
		return result, nil
	case map[string]any:
		if condition, exists := raw["#enable"]; exists { enabled, err := evaluate(condition, vars, node); if err != nil { return nil, err }; if !enabled { return nil, errDrop } }
		result := map[string]any{}
		for key, item := range raw {
			if key == "#enable" { continue }
			if key == "#if" {
				resolved, err := expandIf(item, vars, node, state)
				if err == errDrop {
					if len(raw) == 1 {
						return nil, errDrop
					}
					continue
				}
				if err != nil {
					return nil, err
				}
				if object, ok := resolved.(map[string]any); ok {
					merge(result, object)
				} else if resolved != nil {
					if len(raw) == 1 {
						return resolved, nil
					}
					return nil, fmt.Errorf("scalar #if result cannot be merged into object")
				} else if len(raw) == 1 {
					return nil, errDrop
				}
				continue
			}
			if strings.HasPrefix(key, "#if ") {
				resolved, err := expandIf(item, vars, node, state)
				if err != nil && err != errDrop { return nil, err }
				if object, ok := resolved.(map[string]any); ok {
					merge(result, object)
				} else if resolved != nil {
					return nil, fmt.Errorf("%s directive must produce an object", key)
				}
				continue
			}
			if strings.HasPrefix(key, "#") { return nil, fmt.Errorf("unsupported template directive %q", key) }
			resolved, err := expand(item, vars, node, state); if err == errDrop { continue }; if err != nil { return nil, err }; result[key] = resolved
		}
		return result, nil
	default:
		return value, nil
	}
}

func expandIf(raw any, vars map[string]any, node map[string]any, state *buildState) (any, error) {
	if list, ok := raw.([]any); ok {
		if len(list) != 2 {
			return nil, fmt.Errorf("unsupported #if list shape")
		}
		enabled, err := evaluate(list[0], vars, node)
		if err != nil {
			return nil, err
		}
		if !enabled {
			return nil, errDrop
		}
		return expand(list[1], vars, node, state)
	}
	object, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unsupported #if value %T", raw)
	}
	if value, exists := object["#value"]; exists {
		condition := cloneMap(object)
		delete(condition, "#value")
		delete(condition, "#else")
		enabled, err := evaluate(condition, vars, node)
		if err != nil {
			return nil, err
		}
		if !enabled {
			value = object["#else"]
		}
		if value == nil {
			return nil, errDrop
		}
		return expand(value, vars, node, state)
	}
	enabled, err := evaluate(object, vars, node)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, errDrop
	}
	return nil, nil
}

func expandTemplate(raw string, vars map[string]any, node map[string]any, state *buildState) string {
	name := strings.TrimSuffix(strings.TrimPrefix(raw, "@{"), "}")
	if node != nil {
		if name == "node" { return fmt.Sprint(node["tag"]) }
		if strings.HasPrefix(name, "node.") { if value, ok := lookup(node, strings.TrimPrefix(name, "node.")); ok { return fmt.Sprint(value) } }
	}
	if value, ok := lookup(vars, name); ok { return fmt.Sprint(value) }
	state.fatal("unresolved_template_var", "template", "unknown #tpl value "+name)
	return raw
}

func evaluate(raw any, vars map[string]any, node map[string]any) (bool, error) {
	switch value := raw.(type) {
	case bool: return value, nil
	case string:
		if strings.HasPrefix(value, "@") { resolved, ok := lookup(vars, strings.TrimPrefix(value, "@")); if !ok && node != nil { resolved, ok = lookup(node, strings.TrimPrefix(value, "@")) }; return ok && truthy(resolved), nil }
		return value != "" && value != "false" && value != "0" && value != "off", nil
	case []any: return len(value) > 0, nil
	case map[string]any:
		if expressions, ok := value["#and"].([]any); ok {
			for _, item := range expressions { enabled, err := evaluate(item, vars, node); if err != nil || !enabled { return false, err } }
			return true, nil
		}
		if expressions, ok := value["#or"].([]any); ok {
			for _, item := range expressions { enabled, err := evaluate(item, vars, node); if err != nil { return false, err }; if enabled { return true, nil } }
			return false, nil
		}
		if item, ok := value["#not"]; ok { enabled, err := evaluate(item, vars, node); return !enabled, err }
		for key, expected := range value {
			var actual any
			var ok bool
			if strings.HasPrefix(key, "@") {
				actual, ok = lookup(vars, strings.TrimPrefix(key, "@"))
			} else if node != nil {
				actual, ok = lookup(node, key)
			} else {
				actual, ok = lookup(vars, key)
			}
			if !ok { return false, nil }
			if condition, ok := expected.(map[string]any); ok {
				if list, exists := condition["#in"].([]any); exists {
					matched := false
					for _, candidate := range list { if fmt.Sprint(actual) == fmt.Sprint(candidate) { matched = true } }
					if !matched { return false, nil }
					continue
				}
				if condition["#notEmpty"] == true { if !truthy(actual) { return false, nil }; continue }
				if forbidden, exists := condition["#not"]; exists { if fmt.Sprint(actual) == fmt.Sprint(forbidden) { return false, nil }; continue }
			}
			if fmt.Sprint(actual) != fmt.Sprint(expected) { return false, nil }
		}

		return true, nil
	default: return truthy(raw), nil
	}
}
func truthy(value any) bool { switch v := value.(type) { case nil: return false; case bool: return v; case string: return v != "" && v != "false" && v != "off"; case []any: return len(v) > 0; default: return true } }
func lookup(root map[string]any, path string) (any, bool) { var current any = root; for _, part := range strings.Split(path, ".") { object, ok := current.(map[string]any); if !ok { return nil, false }; current, ok = object[part]; if !ok { return nil, false } }; return current, true }
func hasTemplateVar(name string, state *buildState) bool {
	_, ok := state.vars[name]
	return ok
}

func merge(dst map[string]any, value any) { if value == nil { return }; if source, ok := value.(map[string]any); ok { for key, item := range source { dst[key] = item } } }
func regexpFilter(pattern string, values []string) ([]string, error) { re, err := regexp.Compile("(?i)" + pattern); if err != nil { return values, err }; result := []string{}; for _, value := range values { if re.MatchString(value) { result = append(result, value) } }; return result, nil }
