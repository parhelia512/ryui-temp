package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Leadaxe/lxbox/app/assets"
	"github.com/Leadaxe/lxbox/app/internal/parser"
	"github.com/Leadaxe/lxbox/app/internal/storage"
)

// migrationDispatch is the runtime entry point for storage.status,
// storage.migrate and storage.recover. The host dispatcher delegates these
// methods here.
func (a *Application) migrationDispatch(ctx context.Context, method string, args json.RawMessage) (any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch method {
	case "storage.status":
		return migrationStatusValue(a.store.MigrationStatus()), nil
	case "storage.migrate":
		a.mutation.Lock()
		defer a.mutation.Unlock()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		options, err := a.migrationOptionsChecked(ctx)
		if err != nil {
			return nil, fmt.Errorf("prepare storage migration facts: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		report, err := a.store.MigrateLegacy(options)
		if report.Migrated && err == nil {
			a.generation++
			a.revision++
			a.refreshAutomation()
			a.events.emit("settings.changed", map[string]any{"reason": "storage.migrate", "revision": a.revision})
		}
		return report, err
	case "storage.recover":
		a.mutation.Lock()
		defer a.mutation.Unlock()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var request struct {
			CorruptSettings bool `json:"corrupt_settings"`
		}
		if len(args) != 0 {
			if err := decode(args, &request); err != nil {
				return nil, fmt.Errorf("storage.recover arguments: %w", err)
			}
		}
		if !request.CorruptSettings {
			return nil, errors.New("storage.recover requires corrupt_settings=true; workspace recovery runs during initialization")
		}
		if err := a.store.RecoverCorruptSettings(); err != nil {
			return migrationStatusValue(a.store.MigrationStatus()), err
		}
		a.generation++
		a.revision++
		a.refreshAutomation()
		a.events.emit("settings.changed", map[string]any{"reason": "storage.recover", "revision": a.revision})
		return migrationStatusValue(a.store.MigrationStatus()), nil
	default:
		return nil, fmt.Errorf("unknown storage migration method %q", method)
	}
}

func migrationStatusValue(status storage.MigrationStatus) map[string]any {
	return map[string]any{"read_only": status.ReadOnly, "report": status.Report}
}

func (a *Application) migrationOptions(ctx context.Context) storage.MigrationOptions {
	options, _ := a.migrationOptionsChecked(ctx)
	return options
}

func (a *Application) migrationOptionsChecked(ctx context.Context) (storage.MigrationOptions, error) {
	options := storage.MigrationOptions{
		NodeLinks:          map[string]map[string]any{},
		PresetIDsByDNSTag:  map[string]string{},
		PresetVarDefaults:  map[string]map[string]string{},
		RuleVarDefaults:    map[string]map[string]string{},
		SubscriptionBodies: map[string][]byte{},
	}
	doc, err := a.store.Snapshot()
	if err != nil {
		return options, err
	}
	if lists, ok := doc["server_lists"].([]any); ok {
		for _, raw := range lists {
			record, ok := raw.(map[string]any)
			if !ok || migrationString(record["type"]) != "subscription" {
				continue
			}
			url := migrationString(record["url"])
			if url == "" {
				continue
			}
			body, _, readErr := a.store.ReadCache(url)
			if readErr == nil && len(body) > 0 {
				options.SubscriptionBodies[url] = body
			}
		}
	}
	migrationTemplateFacts(options)
	migrationNodeLinks(ctx, doc, options)
	return options, nil
}

func migrationTemplateFacts(options storage.MigrationOptions) {
	body, err := assets.Read("wizard_template.json")
	if err != nil {
		return
	}
	var template map[string]any
	if json.Unmarshal(body, &template) != nil {
		return
	}
	dnsOptions, _ := template["dns_options"].(map[string]any)
	for _, raw := range migrationSlice(dnsOptions["servers"]) {
		server, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		definition, _ := server["server"].(map[string]any)
		tag := migrationString(definition["tag"])
		if tag != "" {
			options.PresetVarDefaults[tag] = migrationStringDefaults(server["vars"])
		}
	}
	for _, raw := range migrationSlice(template["selectable_rules"]) {
		preset, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		id := migrationString(preset["preset_id"])
		if id == "" {
			continue
		}
		options.RuleVarDefaults[id] = migrationStringDefaults(preset["vars"])
		for _, dnsRaw := range migrationSlice(preset["dns_servers"]) {
			dns, ok := dnsRaw.(map[string]any)
			if !ok {
				continue
			}
			tag := migrationString(dns["tag"])
			if tag == "" {
				continue
			}
			options.PresetIDsByDNSTag[id+":"+tag] = id
			if _, exists := options.PresetIDsByDNSTag[tag]; !exists {
				options.PresetIDsByDNSTag[tag] = id
			}
		}
	}
}

func migrationStringDefaults(raw any) map[string]string {
	defaults := map[string]string{}
	for _, item := range migrationSlice(raw) {
		declaration, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := migrationString(declaration["name"])
		if name == "" {
			continue
		}
		if value, exists := declaration["default_value"]; exists {
			defaults[name] = fmt.Sprint(value)
		} else if value, exists := declaration["default"]; exists {
			defaults[name] = fmt.Sprint(value)
		}
	}
	return defaults
}

// migrationNodeLinks mirrors the old builder's source order and tag prefixing.
// Ambiguous final tags are deliberately omitted so storage's migration guard
// prevents an unsafe rewrite rather than guessing a target.
func migrationNodeLinks(ctx context.Context, doc map[string]any, options storage.MigrationOptions) {
	if ctx == nil {
		ctx = context.Background()
	}
	seen := map[string]int{"direct-out": 1, "block": 1, "dns-out": 1, "block-out": 1}
	for _, root := range []string{"direct-out", "block", "dns-out", "block-out"} {
		options.NodeLinks[root] = map[string]any{"tag": root}
	}
	for _, key := range []string{"directions", "channels"} {
		for _, raw := range migrationSlice(doc[key]) {
			direction, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			tag := strings.TrimSpace(migrationString(direction["tag"]))
			if tag == "" {
				continue
			}
			options.NodeLinks[tag] = map[string]any{"tag": tag}
			options.NodeLinks[tag+"-auto"] = map[string]any{"tag": tag + "-auto"}
			seen[tag] = 1
			seen[tag+"-auto"] = 1
		}
	}
	candidates := map[string][]map[string]any{}
	fallbackCandidates := map[string][]map[string]any{}
	add := func(prefix, rawTag, containerID string, enabled bool) {
		if strings.TrimSpace(rawTag) == "" {
			return
		}
		base := migrationFinalTag(prefix, rawTag)
		if !enabled {
			link := map[string]any{"tag": rawTag}
			if containerID != "" {
				link["folder_id"] = containerID
			} else {
				link["tag"] = base
			}
			fallbackCandidates[base] = append(fallbackCandidates[base], link)
			return
		}
		final := base
		if seen[base] == 0 {
			seen[base] = 1
		} else {
			count := seen[base] + 1
			final = fmt.Sprintf("%s-%d", base, count)
			for seen[final] != 0 {
				count++
				final = fmt.Sprintf("%s-%d", base, count)
			}
			seen[base] = count
			seen[final] = 1
		}
		link := map[string]any{"tag": rawTag}
		if containerID != "" {
			link["folder_id"] = containerID
		} else {
			link["tag"] = final
		}
		candidates[final] = append(candidates[final], link)
	}
	parse := func(body []byte, source parser.Source) []parser.Node {
		if len(body) == 0 || ctx.Err() != nil {
			return nil
		}
		result := parser.Parse(ctx, body, parser.Options{ContractFS: assets.FS, Source: source, KeepUnknown: true})
		if !result.Recognized || !result.Complete {
			return nil
		}
		return result.Nodes
	}
	for _, raw := range migrationSlice(doc["server_lists"]) {
		record, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		kind := migrationString(record["type"])
		id := migrationString(record["id"])
		prefix := migrationString(record["tag_prefix"])
		enabled := migrationEnabled(record["enabled"])
		switch kind {
		case "subscription":
			url := migrationString(record["url"])
			source := parser.Source{Kind: "subscription", ID: id, Name: migrationString(record["name"]), URL: url}
			for _, node := range parse(options.SubscriptionBodies[url], source) {
				add(prefix, migrationNodeTag(node), id, enabled)
			}
		case "user":
			source := parser.Source{Kind: "file", ID: id, Name: migrationString(record["name"])}
			for _, node := range parse([]byte(migrationString(record["raw_body"])), source) {
				add(prefix, migrationNodeTag(node), "", enabled)
			}
		case "folder":
			for _, memberRaw := range migrationSlice(record["members"]) {
				member, ok := memberRaw.(map[string]any)
				if !ok {
					continue
				}
				text := migrationString(member["raw"])
				if text == "" || strings.HasPrefix(text, "autogroup://") {
					continue
				}
				source := parser.Source{Kind: "file", ID: id, Name: migrationString(member["name"])}
				for _, node := range parse([]byte(text), source) {
					add(prefix, migrationNodeTag(node), id, enabled && migrationEnabled(member["enabled"]))
				}
			}
		}

	}
	for _, raw := range migrationSlice(doc["chains"]) {
		chain, ok := raw.(map[string]any)
		if !ok || !migrationEnabled(chain["enabled"]) {
			continue
		}
		tag := strings.TrimSpace(migrationString(chain["tag"]))
		if tag != "" {
			candidates[tag] = append(candidates[tag], map[string]any{"tag": tag})
		}
	}
	for tag, links := range candidates {
		if len(links) == 1 {
			options.NodeLinks[tag] = links[0]
		} else {
			delete(options.NodeLinks, tag)
		}
	}
	for tag, links := range fallbackCandidates {
		if _, live := candidates[tag]; live {
			continue
		}
		if len(links) == 1 {
			options.NodeLinks[tag] = links[0]
		}
	}
}

func migrationNodeTag(node parser.Node) string {
	entry := node.SingBox()
	return migrationString(entry["tag"])
}

func migrationFinalTag(prefix, tag string) string {
	tag = strings.TrimSpace(tag)
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return tag
	}
	return prefix + " " + tag
}

func migrationEnabled(value any) bool {
	if value == nil {
		return true
	}
	enabled, ok := value.(bool)
	return ok && enabled
}

func migrationString(value any) string {
	text, _ := value.(string)
	return text
}

func migrationSlice(value any) []any {
	items, _ := value.([]any)
	return items
}

// applyNativeSettings keeps the JSON settings document as the source of truth
// and mirrors only fields that the old native preference bridge recognizes.
// Missing fields are omitted; this function never invents native defaults.
func (a *Application) applyNativeSettings(ctx context.Context, doc map[string]any) error {
	if doc == nil {
		return errors.New("native settings document is nil")
	}
	nativeKeys := map[string]bool{
		"auto_start": true, "keep_on_exit": true, "background_mode": true,
		"core_logs_enabled": true, "core_logs_verbose": true, "allow_bypass": true,
		"auto_redirect": true, "memory_limit": true, "notification_stop": true,
		"notification_restart": true, "notification_send": true, "app_theme_mode": true,
	}
	settings := map[string]any{}
	if native, ok := doc["native_prefs"].(map[string]any); ok {
		for key, value := range native {
			if nativeKeys[key] {
				settings[key] = value
			}
		}
	}
	vars := map[string]any{}
	if stored, ok := doc["vars"].(map[string]any); ok {
		for _, key := range []string{
			"appfunctions_enabled", "automation_receive_enabled", "automation_explainer_shown_v1",
			"wizard_battery_v1", "wizard_addtile_v1", "wizard_update_check_v1", "notif_perm_prompted_v1",
		} {
			if value, exists := stored[key]; exists {
				vars[key] = value
			}
		}
	}
	_, err := a.platformCall(ctx, "nativeprefs.apply", map[string]any{
		"native_prefs": settings,
		"vars":         vars,
	})
	if err != nil {
		return fmt.Errorf("apply native preferences: %w", err)
	}
	return nil
}
