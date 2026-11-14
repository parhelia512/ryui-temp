package builder

import (
	"fmt"
	"regexp"
)

func applyDirections(config, template, settings map[string]any, state *buildState) {
	directions, _ := settings["directions"].([]any)
	if len(directions) == 0 {
		defaults, _ := template["default_directions"].([]any)
		groupTemplates, _ := template["group_templates"].(map[string]any)
		directionTemplate, _ := groupTemplates["direction"].(map[string]any)
		includeRoles := stringsOf(directionTemplate["include"])
		magicNodes, _ := groupTemplates["magic_nodes"].(map[string]any)
		for _, raw := range defaults {
			record, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			direction := map[string]any{"tag": record["tag"], "label": record["label"], "enabled": boolValue(record, "default_enabled", true)}
			for _, role := range includeRoles {
				node, ok := magicNodes[role].(map[string]any)
				if !ok {
					state.fatal("direction_magic_node_missing", "template.group_templates.magic_nodes."+role, "default direction role is absent from template")
					continue
				}
				switch stringValue(node, "source") {
				case "preset":
					switch role {
					case "direct":
						direction["include_direct"] = true
					case "block":
						direction["include_block"] = true
					default:
						state.fatal("direction_magic_preset_unsupported", "template.group_templates.magic_nodes."+role, "unknown preset role cannot be represented")
					}
				case "generate":
					if role != "auto" {
						state.fatal("direction_magic_generated_unsupported", "template.group_templates.magic_nodes."+role, "generated direction role is unsupported")
						continue
					}
					autoTemplate, _ := groupTemplates["auto"].(map[string]any)
					auto := map[string]any{}
					for key, value := range autoTemplate["options"].(map[string]any) {
						if key == "url" || key == "interval" || key == "tolerance" || key == "interrupt_exist_connections" {
							expanded, err := expand(value, state.vars, nil, state)
							if err == nil && expanded != nil {
								auto[key] = expanded
							}
						}
					}
					direction["auto"] = auto
				default:
					state.fatal("direction_magic_source_unsupported", "template.group_templates.magic_nodes."+role, "magic-node source is unsupported")
				}
			}
			options, _ := directionTemplate["options"].(map[string]any)
			if value, ok := options["interrupt_exist_connections"].(bool); ok {
				direction["interrupt_exist_connections"] = value
			}
			directions = append(directions, direction)
		}
	}

	if len(directions) == 0 {
		state.fatal("directions_missing", "directions", "settings and template contain no directions")
		return
	}

	outbounds, _ := config["outbounds"].([]any)
	pool := append([]string(nil), state.tags...)
	for _, raw := range outbounds {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		tag := stringValue(entry, "tag")
		if tag != "" && tag != "direct-out" && tag != "block" && !contains(pool, tag) {
			pool = append(pool, tag)
		}
	}

	active := map[string]bool{}
	for index, raw := range directions {
		direction, ok := raw.(map[string]any)
		if !ok {
			state.fatal("direction_invalid", fmt.Sprintf("directions[%d]", index), "direction record must be an object")
			continue
		}
		tag := stringValue(direction, "tag")
		if tag == "" {
			state.fatal("direction_tag_missing", fmt.Sprintf("directions[%d].tag", index), "direction tag is required")
			continue
		}
		if !boolValue(direction, "enabled", true) && tag != "vpn-1" {
			state.root[tag] = tag
			continue
		}
		active[tag] = true

		members := append([]string(nil), pool...)
		if pattern := stringValue(direction, "node_filter"); pattern != "" {
			filtered, err := filterDirectionNodes(pattern, boolValue(direction, "node_filter_invert", false), members)
			if err != nil {
				state.warn("direction_filter_invalid", "directions."+tag+".node_filter", "invalid regex; all nodes retained", pattern)
			} else {
				members = filtered
			}
		}

		included := []string{}
		for _, candidate := range stringsOf(direction["include"]) {
			if active[candidate] && !contains(included, candidate) {
				included = append(included, candidate)
			} else {
				if !active[candidate] && knownDirection(candidate, directions) {
					state.fatal("direction_include_disabled", "directions."+tag+".include", "include references a disabled direction: "+candidate)
					continue
				}
				state.warn("direction_include_dropped", "directions."+tag+".include", "include must reference an enabled direction above", candidate)
			}
		}

		selector := []string{}
		auto, hasAuto := direction["auto"].(map[string]any)
		autoTag := tag + "-auto"
		if hasAuto {
			candidates := []string{}
			for _, member := range members {
				if !isGroupTag(member, outbounds) {
					candidates = append(candidates, member)
				}
			}
			if len(candidates) > 0 {
				group := map[string]any{"type": "urltest", "tag": autoTag, "outbounds": candidates}
				for _, key := range []string{"url", "interval", "tolerance", "idle_timeout", "interrupt_exist_connections", "mode", "balancer"} {
					if value, exists := auto[key]; exists {
						group[key] = clone(value)
					}
				}
				outbounds = append(outbounds, group)
				selector = append(selector, autoTag)
			}
		}
		if boolValue(direction, "include_direct", false) {
			selector = append(selector, "direct-out")
		}
		if boolValue(direction, "include_block", false) {
			selector = append(selector, "block")
		}
		selector = append(selector, included...)
		for _, member := range members {
			if !contains(selector, member) {
				selector = append(selector, member)
			}
		}
		fallback := len(selector) == 0
		if fallback {
			selector = []string{"block", "direct-out"}
			state.warn("direction_empty_fallback", "directions."+tag, "empty direction falls back to block; direct remains explicit", nil)
		}
		group := map[string]any{
			"type": "selector", "tag": tag, "outbounds": selector,
			"interrupt_exist_connections": boolValue(direction, "interrupt_exist_connections", true),
		}
		if fallback {
			group["default"] = "block"
		}
		if hasAuto && contains(selector, autoTag) {
			group["default"] = autoTag
		}
		if pattern := stringValue(direction, "default_filter"); pattern != "" {
			re, err := regexp.Compile("(?i)" + pattern)
			if err != nil {
				state.warn("direction_default_filter_invalid", "directions."+tag+".default_filter", "invalid default regex ignored", pattern)
			} else {
				for _, member := range members {
					if re.MatchString(member) && contains(selector, member) {
						group["default"] = member
						break
					}
				}
			}
		}
		outbounds = append(outbounds, group)
		state.root[tag] = tag
	}
	config["outbounds"] = outbounds
	route, _ := config["route"].(map[string]any)
	if route == nil {
		route = map[string]any{}
		config["route"] = route
	}
	final := settingString(settings, "route_final")
	if final == "" {
		final = "vpn-1"
	}
	if !active[final] && final != "direct-out" && final != "block" {
		if knownDirection(final, directions) {
			state.fatal("route_final_disabled_direction", "route.final", "route final references a disabled direction: "+final)
		} else {
			state.warn("route_final_fallback", "route.final", "route final is not active; using vpn-1", final)
			final = "vpn-1"
		}
	}
	route["final"] = final
}

func filterDirectionNodes(pattern string, invert bool, nodes []string) ([]string, error) {
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return nil, err
	}
	result := []string{}
	for _, tag := range nodes {
		if re.MatchString(tag) != invert {
			result = append(result, tag)
		}
	}
	return result, nil
}

func isGroupTag(tag string, outbounds []any) bool {
	for _, raw := range outbounds {
		entry, ok := raw.(map[string]any)
		if ok && stringValue(entry, "tag") == tag {
			kind := stringValue(entry, "type")
			return kind == "selector" || kind == "urltest"
		}
	}
	return false
}

func knownDirection(tag string, directions []any) bool {
	for _, raw := range directions {
		direction, ok := raw.(map[string]any)
		if ok && stringValue(direction, "tag") == tag {
			return true
		}
	}
	return false
}
