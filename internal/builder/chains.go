package builder

import "fmt"

func emitChain(source SourceInput, state *buildState) (map[string]any, bool) {
	raw := source.Raw
	if raw == nil {
		state.fatal("chain_record_missing", "sources."+source.ID, "chain record is missing")
		return nil, false
	}
	tag := stringValue(raw, "tag")
	if tag == "" { tag = source.Name }
	if tag == "" {
		state.fatal("chain_tag_missing", "sources."+source.ID, "chain tag is missing")
		return nil, false
	}
	if (source.Enabled != nil && !*source.Enabled) || raw["enabled"] == false {
		return nil, false
	}
	settings, _ := raw["body"].(map[string]any)
	invalid := false
	for key, value := range settings {
		switch key {
		case "type":
			if value != "chain" {
				state.fatal("chain_body_type_invalid", "sources."+source.ID+".body.type", "chain body type must be chain")
				invalid = true
			}
		case "idle_timeout", "strip_evasion", "strip", "rewrite":
		default:
			state.fatal("chain_body_field_unsupported", "sources."+source.ID+".body."+key, "chain body field cannot be dropped")
			invalid = true
		}
	}
	for key := range raw {
		switch key {
		case "kind", "tag", "enabled", "label", "body", "hops":
		default:
			state.fatal("chain_record_field_unsupported", "sources."+source.ID+"."+key, "chain record field is unsupported")
			invalid = true
		}
	}
	if invalid { return nil, false }
	hops, _ := raw["hops"].([]any)
	if len(hops) < 2 {
		state.fatal("chain_positions_invalid", "sources."+source.ID+".hops", "chain requires at least two positions")
		return nil, false
	}
	resolved := []string{}
	seen := map[string]bool{}
	for index, rawHop := range hops {
		ref := reference(rawHop)
		target, ok := resolveReference(ref, source.ID, state)
		if !ok {
			state.fatal("chain_hop_missing", fmt.Sprintf("sources.%s.hops[%d]", source.ID, index), "chain hop does not resolve: "+ref)
			return nil, false
		}
		if seen[target] {
			state.fatal("chain_hop_duplicate", fmt.Sprintf("sources.%s.hops[%d]", source.ID, index), "chain repeats hop "+target)
			return nil, false
		}
		seen[target] = true
		resolved = append(resolved, target)
	}
	body := map[string]any{"type": "chain", "tag": allocate(tag, state), "outbounds": resolved}
	for key, value := range settings {
		if key != "type" { body[key] = clone(value) }
	}
	state.root[tag] = body["tag"].(string)
	return body, true
}
