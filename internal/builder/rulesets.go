package builder

import (
	"encoding/json"
	"fmt"
)

func addRuleSets(route map[string]any, items []any, cache CacheInput, state *buildState) {
	current, _ := route["rule_set"].([]any)
	for index, raw := range items {
		set, ok := raw.(map[string]any)
		if !ok {
			state.fatal("ruleset_invalid", fmt.Sprintf("route.rule_set[%d]", index), "rule_set must be an object")
			continue
		}
		if stringValue(set, "type") == "remote" {
			tag := stringValue(set, "tag")
			payload, ok := cache.RuleSets[tag]
			if !ok {
				state.fatal("offline_ruleset_missing", "route.rule_set."+tag, "remote ruleset has no cached local payload", set["url"])
				continue
			}
			var local map[string]any
			if err := json.Unmarshal(payload, &local); err != nil {
				state.fatal("offline_ruleset_invalid", "cache.rule_sets."+tag, err.Error())
				continue
			}
			local["type"], local["tag"] = "local", tag
			set = local
		}
		current = append(current, set)
	}
	route["rule_set"] = current
}
