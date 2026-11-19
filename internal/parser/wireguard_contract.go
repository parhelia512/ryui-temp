package parser

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Execute the conf records independently for each [Peer] and validate the
// assembled endpoint once. This keeps defaults, diagnostics and MTU decisions
// shared between pasted .conf files, base64 links and Amnezia containers.
func mapWireGuardINI(text string, source Source, reg *registry, fragment, hint string, raw map[string]any, origin string) (*Node, []Diagnostic) {
	p := registryProtocolFor(reg, "wireguard")
	var conf map[string]any
	if p != nil {
		conf = fieldMap(fieldMap(p.raw, "mappers"), "conf")
	}
	if conf == nil {
		// Minimal/legacy contract files do not declare a conf mapper.
		node, ok := parseLegacyINI(text, source, origin)
		if !ok {
			return nil, []Diagnostic{diag("form_unrecognized", "error", "WireGuard INI has no usable peer", source)}
		}
		name := node.Name
		if fragment != "" {
			name = fragmentName(fragment)
		} else if hint != "" {
			name = hint
		}
		return ptrNode(makeNode(name, node.Protocol, raw, node.Canonical, source, origin)), nil
	}
	label := fieldMap(conf, "label")
	iface, sections, comment := mapperINIValues(text, fieldMap(label, "comment"))
	peerRule := fieldMap(fieldMap(fieldMap(conf, "ini_dialect"), "sections"), "Peer")
	peerPath := strings.TrimSuffix(stringValue(peerRule["into"]), "[]")
	var result *mapperState
	var peers []any
	var diagnostics []Diagnostic
	kinds := map[string]bool{}
	for index, peer := range sections {
		if index > 0 && peerRule["repeat"] != "each" {
			break
		}
		root := map[string]any{"Interface": iface, "Peer": peer, "$comment": map[string]any{"Peer": comment}}
		s := &mapperState{entry: map[string]any{"type": p.singboxType}, input: mapperInput{root: root, form: "conf"}, reg: reg}
		if err := executeMapper(s, p, "conf", conf); err != nil {
			return nil, []Diagnostic{diag("mapper_error", "error", err.Error(), source)}
		}
		if s.dropNode || len(stringSliceAny(s.entry[peerPath])) == 0 {
			diagnostics = append(diagnostics, Diagnostic{Code: stringValue(fieldMap(peerRule, "on_drop")["code"]), Severity: "warning", Message: "incomplete WireGuard peer", Path: fmt.Sprintf("%s[%d]", peerPath, index), Source: source})
			continue
		}
		for kind, rule := range fieldMap(conf, "kind_when") {
			if conditionMatches(rule, s) {
				kinds[kind] = true
			}
		}
		peers = append(peers, stringSliceAny(s.entry[peerPath])...)
		if result == nil {
			result = s
		}
	}
	if result == nil {
		return nil, append(diagnostics, diag("field_missing", "error", "WireGuard INI has no usable peer", source))
	}
	result.input.root["$kinds"] = kinds
	result.entry[peerPath] = peers
	sanitizeMapperBody(result, p.raw)
	for i := range result.diags {
		result.diags[i].Source = source
	}
	diagnostics = append(diagnostics, result.diags...)
	if result.dropNode {
		return nil, append(diagnostics, diag(result.dropReason, "error", "WireGuard configuration violates the registry contract", source))
	}
	name := normalizeLabel(fragment, label["normalize"])
	if name == "" {
		for _, path := range sourceList(label["source"]) {
			var value any
			switch {
			case path == "hint":
				value = hint
			case strings.HasPrefix(path, "ini."):
				value, _ = getSourcePath(path, *result)
			default:
				value, _ = getPath(result.entry, strings.ReplaceAll(path, "[]", ".0"))
			}
			if name = normalizeLabel(stringValue(value), label["normalize"]); name != "" {
				break
			}
		}
	}
	if name == "" {
		name = mapperLabel(conf, result, p.singboxType)
	}
	return ptrNode(makeNode(name, p.singboxType, raw, result.entry, source, origin)), diagnostics
}

func mapperAnyPathSet(state *mapperState, raw any) bool {
	for _, path := range sourceList(raw) {
		if _, ok := getSourcePath(path, *state); ok {
			return true
		}
	}
	return false
}

func mapperSourceKindMatches(state *mapperState, raw any) bool {
	kinds := sourceList(raw)
	if len(kinds) == 0 {
		return false
	}
	p := registryProtocolFor(state.reg, stringValue(state.entry["type"]))
	if p == nil {
		return false
	}
	dialect := "uri"
	switch state.input.form {
	case "conf", "xray", "singbox":
		dialect = state.input.form
	}
	mapper := fieldMap(fieldMap(p.raw, "mappers"), dialect)
	for _, kind := range kinds {
		rule := fieldMap(fieldMap(mapper, "kind_when"), kind)
		if len(rule) != 0 && conditionMatches(rule, state) {
			return true
		}
		// The INI mapper visits one peer at a time. Another peer may be
		// the one whose keepalive range declared the kind of the endpoint.
		if matched, _ := state.input.root["$kinds"].(map[string]bool); matched[kind] {
			return true
		}
	}
	return false
}

// awg_range is either an unsigned 32-bit number or a pair of such bounds.
// Reversed magic headers can be normalized; reversed timers cannot.
type wgRange struct {
	lo, hi uint64
	pair   bool
}

func parseWGRange(v any, reorder bool) (wgRange, bool) {
	a, b, pair := strings.Cut(strings.TrimSpace(fmt.Sprint(v)), "-")
	lo, err := strconv.ParseUint(a, 10, 32)
	if err != nil {
		return wgRange{}, false
	}
	hi := lo
	if pair {
		hi, err = strconv.ParseUint(b, 10, 32)
		if err != nil || (hi < lo && !reorder) {
			return wgRange{}, false
		}
		if hi < lo {
			lo, hi = hi, lo
		}
	}
	return wgRange{lo, hi, pair}, true
}

// Apply the WireGuard-specific field types before generic required, default,
// and cross-field checks see the body. Peer diagnostics retain their index.
func prepareWireGuardFields(state *mapperState, target, schema map[string]any, prefix string) {
	fields := fieldMap(schema, "fields")
	for _, name := range orderedKeys(fields, stringSlice(schema["order"])) {
		value, exists := target[name]
		if !exists {
			continue
		}
		field := fieldMap(fields, name)
		path := prefix + name
		valid := true
		switch stringValue(field["type"]) {
		case "awg_range":
			r, ok := parseWGRange(value, field["normalize"] == "range_order")
			valid = ok
			if valid {
				if r.pair {
					target[name] = fmt.Sprintf("%d-%d", r.lo, r.hi)
				} else {
					target[name] = int64(r.lo)
				}
			}
		case "string_array":
			if field["format"] != "cidr" {
				continue
			}
			items := mapperAnyList(value)
			valid = len(items) > 0
			for i, item := range items {
				text := strings.TrimSpace(stringValue(item))
				if field["normalize"] == "cidr_prefix" {
					text = normalizeCIDR(text)
				}
				if _, err := netip.ParsePrefix(text); err != nil {
					valid = false
					break
				}
				items[i] = text
			}
			if valid {
				target[name] = items
			}
		case "int_array":
			items, ok := value.([]any)
			valid = ok && (field["len"] == nil || scalarEqual(field["len"], len(items)))
			min, max := numberValue(field["min"]), numberValue(field["max"])
			for _, item := range items {
				n, err := strconv.ParseInt(fmt.Sprint(item), 10, 64)
				if err != nil || min != nil && float64(n) < *min || max != nil && float64(n) > *max {
					valid = false
					break
				}
			}
		case "bool":
			if _, ok := value.(bool); !ok {
				switch strings.ToLower(stringValue(value)) {
				case "true":
					target[name] = true
				case "off", "false", "0":
					target[name] = false
				default:
					valid = false
				}
			}
		case "array":
			items, _ := value.([]any)
			for i, item := range items {
				if obj, ok := item.(map[string]any); ok {
					prepareWireGuardFields(state, obj, fieldMap(field, "items"), fmt.Sprintf("%s[%d].", path, i))
				}
			}
		}
		if !valid {
			rule := fieldMap(field, "on_invalid")
			if rule == nil {
				rule = map[string]any{"action": "drop"}
			}
			handleMapperInvalid(state, target, name, path, field, rule, value)
			// An invalid explicit route list must not become the absent-field
			// default routing all traffic. Required checks see an empty list.
			if field["format"] == "cidr" && field["required"] == true && field["default_when"] != nil {
				target[name] = []any{}
			}
		}
	}
}

func checkWireGuardRelations(state *mapperState, body map[string]any) {
	for _, raw := range stringSliceAny(body["relations"]) {
		rule, _ := raw.(map[string]any)
		paths := sourceList(rule["paths"])
		if len(paths) == 0 {
			continue
		}
		violates := false
		switch rule["kind"] {
		case "ranges_disjoint":
			defaults := stringSliceAny(rule["defaults"])
			var ranges []wgRange
			for i, path := range paths {
				value, ok := getPath(state.entry, path)
				if !ok && i < len(defaults) {
					value = defaults[i]
				}
				r, ok := parseWGRange(value, false)
				if !ok {
					continue
				}
				for _, other := range ranges {
					if r.lo <= other.hi && other.lo <= r.hi {
						violates = true
					}
				}
				ranges = append(ranges, r)
			}
		case "ordered":
			if len(paths) == 2 {
				lo, hi := numberValue(state.entry[paths[0]]), numberValue(state.entry[paths[1]])
				violates = lo != nil && hi != nil && *lo > *hi
			}
		case "cooccurrence":
			when := fieldMap(rule, "when")
			for key, cond := range when {
				if key == "$range_width" {
					width, _ := cond.(map[string]any)
					limit := numberValue(width["gt"])
					violates = false
					for _, path := range sourceList(width["paths"]) {
						r, ok := parseWGRange(state.entry[path], false)
						if ok && r.pair && limit != nil && float64(r.hi-r.lo) > *limit {
							violates = true
							break
						}
					}
				} else {
					value, exists := getPath(state.entry, key)
					violates = conditionValueMatches(cond, value, exists)
				}
				if !violates {
					break
				}
			}
		}
		if !violates {
			continue
		}
		d := Diagnostic{Code: stringValue(rule["code"]), Severity: "warning", Path: paths[0], Message: "WireGuard fields violate a registry relation"}
		switch rule["action"] {
		case "drop_node":
			state.dropNode, state.dropReason = true, d.Code
			d.Severity = "error"
		case "drop":
			for _, path := range paths {
				deletePath(state.entry, path)
			}
		case "warn":
			d.Severity = "info"
		}
		state.diags = append(state.diags, d)
	}
}
