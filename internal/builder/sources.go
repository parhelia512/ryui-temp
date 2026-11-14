package builder

import (
	"fmt"
	"strings"
)

type emittedNode struct {
	body map[string]any
	source SourceInput
	rawTag string
	endpoint bool
}

func emitSources(sources []SourceInput, state *buildState) []emittedNode {
	state.root["direct-out"] = "direct-out"
	state.root["block"] = "block"
	state.seen["direct-out"] = 1
	state.seen["block"] = 1
	var out []emittedNode
	for sourceIndex, source := range sources {
		kind := strings.ToLower(source.Kind)
		if kind == "chain" { state.chains = append(state.chains, source); continue }
		if source.Enabled != nil && !*source.Enabled { continue }
		if kind == "" { kind = "server" }
		if kind != "server" && kind != "subscription" && kind != "folder" { state.fatal("unsupported_source_kind", fmt.Sprintf("sources[%d].kind", sourceIndex), "source kind is unsupported: "+kind); continue }
		prefix := source.TagPrefix
		if prefix == "" { if policy, ok := source.Raw["tag_policy"].(map[string]any); ok { prefix = strings.TrimSpace(stringValue(policy, "prefix")) } }
		nodes := append([]map[string]any(nil), source.Nodes...)
		if kind == "folder" {
			for memberIndex, member := range source.Members {
				path := fmt.Sprintf("sources[%s].members[%d]", source.ID, memberIndex)
				if member.Enabled != nil && !*member.Enabled { continue }
				raw, _ := member.Raw.(map[string]any)
				memberKind := stringValue(raw, "kind")
				switch memberKind {
				case "chain": state.chains = append(state.chains, SourceInput{ID: source.ID, Kind: "chain", Raw: raw}); continue
				case "auto": group := normalizeAutoGroup(raw, path, state); if group != nil { nodes = append(nodes, group) }; continue
				case "unsupported": state.fatal("folder_member_unsupported", path, "folder member has unsupported parser data"); continue
				}
				if member.Node == nil { if member.Raw != nil { state.fatal("folder_member_node_missing", path, "folder member has no parsed node and is not an auto group or chain") }; continue }
				node := cloneMap(member.Node)
				if member.Detour != nil { if _, exists := node["detour"]; !exists { node["detour"] = clone(member.Detour) } else { state.warn("member_detour_conflict", path+".detour", "node body detour takes precedence over record detour", member.Detour) } }
				for key, value := range member.Flags { if value == true { state.fatal("unsupported_member_flag", path+".flags."+key, "member flag affects presets and is not yet supported") } }
				for key, value := range raw { switch key { case "kind", "tag", "enabled", "origin", "body", "detour", "warnings", "reason": case "allow_local", "allow_lan", "allow_gateway", "own_routes", "skip_tailscale_presets": if value == true { state.fatal("unsupported_member_flag", path+"."+key, "member flag affects presets and is not yet supported") }; default: state.fatal("unsupported_member_metadata", path+"."+key, "member metadata is not supported and cannot be dropped") } }
				nodes = append(nodes, node)
			}
		}
		for nodeIndex, rawNode := range nodes {
			path := fmt.Sprintf("sources[%s].nodes[%d]", source.ID, nodeIndex)
			node := normalizeNode(rawNode, source, path, state)
			if node == nil { continue }
			tag := stringValue(node, "tag")
			if tag == "" { state.fatal("node_missing_tag", path+".tag", "cached parsed node has no tag and source record has no applicable tag hint"); continue }
			finalTag := allocate(prefixTag(prefix, tag), state)
			node["tag"] = finalTag
			out = append(out, emittedNode{body: node, source: source, rawTag: tag, endpoint: endpointType(stringValue(node,"type"))})
			state.root[tag] = finalTag
			if source.ID != "" { state.root[source.ID+"/"+tag] = finalTag }
		}
	}
	for i := range out {
		entry := &out[i]
		if raw := reference(entry.body["detour"]); raw != "" { if resolved, ok := resolveReference(raw, entry.source.ID, state); ok { entry.body["detour"] = resolved } else { state.fatal("unresolved_node_detour", "outbounds."+stringValue(entry.body,"tag")+".detour", "node detour target does not resolve: "+raw) } }
		if raw := reference(entry.source.Detour); raw != "" { if resolved, ok := resolveReference(raw, entry.source.ID, state); ok { if entry.body["detour"] == nil || entry.source.DetourPolicy["replace_detour_chain"] == true { entry.body["detour"] = resolved } else { state.fatal("detour_append_unsupported", "sources."+entry.source.ID+".detour", "appending source detour while preserving native detours is not supported") } } else { state.fatal("unresolved_source_detour", "sources."+entry.source.ID+".detour", "source detour target does not resolve: "+raw) } }
	}
	return out
}

func normalizeNode(raw map[string]any, source SourceInput, path string, state *buildState) map[string]any {
	if raw == nil { state.fatal("nil_cached_node", path, "cached node is nil"); return nil }
	body := cloneMap(raw)
	wrapped, isWrapped := body["body"].(map[string]any)
	if isWrapped {
		body = cloneMap(wrapped)
		if body["tag"] == nil {
			body["tag"] = raw["tag"]
		}
	}
	if _, ok := body["type"].(string); !ok {
		state.fatal("node_missing_type", path, "node map must be a parsed sing-box entry, not a source wrapper")
		return nil
	}
	if stringValue(body, "tag") == "" {
		tag := stringValue(raw, "tag")
		if tag == "" {
			tag = stringValue(source.Raw, "tag")
		}
		if tag != "" {
			body["tag"] = tag
			state.add(LevelInfo, "record_tag_hint_applied", path+".tag", "record tag used as node tag hint", tag, false)
		}
	}
	if isWrapped {
		for key := range raw {
			switch key {
			case "type", "tag", "body":
			default:
				state.fatal("node_wrapper_field_unsupported", path+"."+key, "node wrapper field is not interpreted")
			}
		}
	}
	return body
}

func normalizeAutoGroup(raw map[string]any, path string, state *buildState) map[string]any {
	if raw == nil { state.fatal("auto_record_invalid", path, "auto member record is not an object"); return nil }
	if body, ok := raw["body"].(map[string]any); ok {
		result := cloneMap(body)
		if result["tag"] == nil { result["tag"] = raw["tag"] }
		if stringValue(result,"type") == "" { state.fatal("auto_body_type_missing", path+".body.type", "auto body has no sing-box group type"); return nil }
		return result
	}
	group, ok := raw["group"].(map[string]any)
	if !ok { state.fatal("auto_group_missing", path+".group", "auto member has no group record"); return nil }
	kind := stringValue(group,"group_type")
	if kind != "selector" && kind != "urltest" { state.fatal("auto_group_type_unsupported", path+".group.group_type", "unknown group type: "+kind); return nil }
	members := stringsOf(group["members"])
	if _, exists := group["members_rule"]; exists { state.fatal("auto_group_rule_membership_unsupported", path+".group.members_rule", "rule membership requires full node-link group resolution") }
	result := map[string]any{"type":kind,"tag":stringValue(raw,"tag"),"outbounds":members}
	if value, ok := group["default"].(string); ok && value != "" { result["default"] = value }
	if strategy, ok := group["strategy"].(map[string]any); ok { for key, value := range strategy { switch key { case "mode", "url", "interval", "tolerance", "idle_timeout", "interrupt_exist_connections", "pool", "pool_tolerance", "sticky_hash": result[key]=clone(value); default: state.fatal("auto_strategy_field_unsupported", path+".group.strategy."+key,"strategy field cannot be preserved") } } }
	for key := range raw { switch key { case "kind", "tag", "enabled", "group", "warnings": default: state.fatal("auto_record_field_unsupported", path+"."+key,"auto member field is unsupported") } }
	return result
}

func allocate(base string, state *buildState) string { if state.seen[base]==0 { state.seen[base]=1; state.tags=append(state.tags,base); return base }; count:=state.seen[base]+1; tag:=fmt.Sprintf("%s-%d",base,count); for state.seen[tag]>0 { count++; tag=fmt.Sprintf("%s-%d",base,count) }; state.seen[base]=count; state.seen[tag]=1; state.tags=append(state.tags,tag); return tag }
func prefixTag(prefix, tag string) string { prefix=strings.TrimSpace(prefix); if prefix=="" { return tag }; return prefix+" "+tag }
func endpointType(kind string) bool { return kind=="wireguard" || kind=="tailscale" || kind=="openvpn-client" || kind=="openconnect" }
func reference(raw any) string { switch value:=raw.(type) { case string: return value; case map[string]any: tag:=stringValue(value,"tag"); id:=stringValue(value,"folder_id"); if id!="" { return id+"/"+tag }; return tag }; return "" }
func resolveReference(raw, sourceID string, state *buildState)(string,bool){if target,ok:=state.root[raw];ok{return target,true};if sourceID!=""{if target,ok:=state.root[sourceID+"/"+raw];ok{return target,true}};return "",false}
