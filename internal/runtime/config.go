package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Leadaxe/lxbox/app/assets"
	"github.com/Leadaxe/lxbox/app/internal/builder"
	"github.com/Leadaxe/lxbox/app/internal/model"
	"github.com/Leadaxe/lxbox/app/internal/parser"
)

var errConfigBuildStale = errors.New("settings, sources, or workspace changed during configuration build; build again")

type configBuildSnapshot struct {
	settings   map[string]any
	cache      map[string][]byte
	cacheError map[string]error
	generation uint64
	revision   uint64
}

// buildConfig only reads source material already on disk. Refreshing sources is
// a separate operation; a build must never fetch a URL or register a worker.
func (a *Application) buildConfig(ctx context.Context) (any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snapshot, err := a.snapshotConfigBuild(ctx)
	if err != nil {
		return nil, err
	}
	input, diagnostics, err := prepareConfigBuild(ctx, snapshot)
	response := map[string]any{
		"diagnostics": diagnostics,
		"generated":   map[string]string{},
		"pure":        true,
		"saved":       false,
	}
	if err != nil {
		return response, err
	}
	result, err := builder.Build(ctx, input)
	for _, diagnostic := range result.Diagnostics {
		diagnostics = append(diagnostics, diagnostic)
	}
	response["diagnostics"] = diagnostics
	response["generated"] = result.Generated
	response["emitted_tags"] = result.EmittedTags
	response["pure"] = result.Pure
	if json.Valid(result.Config) {
		// []byte would be base64 on the mobile JSON wire.
		response["config"] = json.RawMessage(result.Config)
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return response, contextErr
	}
	if err != nil {
		return response, err
	}
	if !json.Valid(result.Config) {
		return response, errors.New("configuration builder returned invalid JSON")
	}
	if !configHasNodes(result.Config) {
		diagnostics = append(diagnostics, configDiagnostic("no_nodes", "config", "configuration contains no supported proxy nodes"))
		response["diagnostics"] = diagnostics
		return response, errors.New("configuration contains no supported proxy nodes")
	}
	if err := a.commitConfigBuild(ctx, snapshot, json.RawMessage(result.Config)); err != nil {
		code := "config_commit_failed"
		if errors.Is(err, errConfigBuildStale) {
			code = "config_build_stale"
		}
		diagnostics = append(diagnostics, configDiagnostic(code, "config", err.Error()))
		response["diagnostics"] = diagnostics
		return response, err
	}
	response["saved"] = true
	return response, nil
}

func (a *Application) snapshotConfigBuild(ctx context.Context) (configBuildSnapshot, error) {
	if err := lockConfigBuild(ctx, &a.mutation); err != nil {
		return configBuildSnapshot{}, err
	}
	defer a.mutation.Unlock()
	settings, err := a.store.Snapshot()
	if err != nil {
		return configBuildSnapshot{}, fmt.Errorf("snapshot configuration settings: %w", err)
	}
	snapshot := configBuildSnapshot{
		settings: settings, cache: map[string][]byte{}, cacheError: map[string]error{},
		generation: a.generation, revision: a.revision,
	}
	// Read original cache bodies while holding the same mutation lock as source
	// and cache commits, so a refreshed body cannot be paired with old settings.
	sources, _ := settings["sources"].([]any)
	for _, value := range sources {
		if err := ctx.Err(); err != nil {
			return configBuildSnapshot{}, err
		}
		source, ok := value.(map[string]any)
		if !ok || source["kind"] != "subscription" || source["enabled"] == false {
			continue
		}
		url, _ := source["url"].(string)
		if _, exists := snapshot.cache[url]; exists {
			continue
		}
		if _, exists := snapshot.cacheError[url]; exists {
			continue
		}
		body, _, readErr := a.store.ReadCache(url)
		if readErr != nil {
			snapshot.cacheError[url] = readErr
			continue
		}
		snapshot.cache[url] = append([]byte(nil), body...)
	}
	return snapshot, nil
}

func (a *Application) commitConfigBuild(ctx context.Context, snapshot configBuildSnapshot, config json.RawMessage) error {
	if err := lockConfigBuild(ctx, &a.mutation); err != nil {
		return err
	}
	defer a.mutation.Unlock()
	if a.generation != snapshot.generation || a.revision != snapshot.revision {
		return errConfigBuildStale
	}
	// The existing save path performs a real core validate followed by an atomic
	// save. Keep the commit lock through both to prevent an ownership switch.
	_, err := a.saveConfig(ctx, config, true)
	return err
}

// lockConfigBuild lets a canceled build leave the mutation queue without
// waiting for an unrelated workspace switch or subscription disk commit.
func lockConfigBuild(ctx context.Context, mutation *sync.Mutex) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if mutation.TryLock() {
		if err := ctx.Err(); err != nil {
			mutation.Unlock()
			return err
		}
		return nil
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if mutation.TryLock() {
				if err := ctx.Err(); err != nil {
					mutation.Unlock()
					return err
				}
				return nil
			}
		}
	}
}

type configNodeBudgetInput struct {
	records       []map[string]any
	parsed        map[string][]map[string]any
	memberIndexes map[string][]int
}

func prepareConfigBuild(ctx context.Context, snapshot configBuildSnapshot) (builder.Input, []any, error) {
	input := builder.Input{Settings: snapshot.settings}
	diagnostics := make([]any, 0)
	if err := ctx.Err(); err != nil {
		return input, diagnostics, err
	}
	body, err := assets.Read("wizard_template.json")
	if err != nil {
		return input, diagnostics, fmt.Errorf("read wizard template: %w", err)
	}
	if err := decode(body, &input.Template); err != nil {
		return input, diagnostics, fmt.Errorf("decode wizard template: %w", err)
	}
	records, err := model.ParseSources(snapshot.settings)
	if err != nil {
		diagnostics = append(diagnostics, configDiagnostic("invalid_sources", "sources", err.Error()))
		return input, diagnostics, err
	}
	var failures []error
	budgetInput := configNodeBudgetInput{parsed: map[string][]map[string]any{}, memberIndexes: map[string][]int{}}
	for index, record := range records {
		if err := ctx.Err(); err != nil {
			return input, diagnostics, err
		}
		var source map[string]any
		if err := decode(record.Raw, &source); err != nil {
			return input, diagnostics, err
		}
		path := fmt.Sprintf("sources[%d]", index)
		budgetInput.records = append(budgetInput.records, source)
		prepared, findings, err := prepareConfigSourceBudget(ctx, source, path, snapshot, &budgetInput)
		diagnostics = append(diagnostics, findings...)
		input.Sources = append(input.Sources, prepared)
		if err != nil {
			failures = append(failures, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return input, diagnostics, err
	}
	if len(failures) > 0 {
		return input, diagnostics, errors.Join(failures...)
	}
	limit := NodeBudgetDefault
	if configured, ok := budgetInt(snapshot.settings["node_budget"]); ok {
		limit = configured
	}
	if limit < 1 {
		limit = 1
	}
	allocation, err := AllocateNodeBudget(budgetInput.records, budgetInput.parsed, limit, NodeBudgetOptions{Document: snapshot.settings})
	diagnostics = append(diagnostics, allocation.Diagnostics...)
	if err != nil {
		diagnostics = append(diagnostics, configDiagnostic("node_budget_failed", "sources", err.Error()))
		return input, diagnostics, err
	}
	for index := range input.Sources {
		source := &input.Sources[index]
		switch source.Kind {
		case "subscription", "server":
			source.Nodes = allocation.NodesBySource[source.ID]
		case "folder":
			indexes := budgetInput.memberIndexes[source.ID]
			for mi := range source.Members {
				if source.Members[mi].Node == nil {
					continue
				}
				if mi >= len(indexes) {
					return input, diagnostics, errors.New("node budget folder index mapping is incomplete")
				}
				memberIndex := indexes[mi]
				// Group/chain members have no parsed Node and keep their original
				// raw records. Server members retain per-member enabled/detour.
				for _, detail := range allocation.DetailsBySource[source.ID] {
					if n, ok := budgetInt(detail["member_index"]); ok && n == memberIndex {
						if body, ok := detail["canonical"].(map[string]any); ok {
							source.Members[mi].Node = body
						}
						enabled := budgetBool(detail, "enabled", true)
						source.Members[mi].Enabled = &enabled
						break
					}
				}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return input, diagnostics, err
	}
	return input, diagnostics, nil
}

func prepareConfigSource(ctx context.Context, record map[string]any, path string, snapshot configBuildSnapshot) (builder.SourceInput, []any, error) {
	return prepareConfigSourceBudget(ctx, record, path, snapshot, nil)
}

func prepareConfigSourceBudget(ctx context.Context, record map[string]any, path string, snapshot configBuildSnapshot, budgetInput *configNodeBudgetInput) (builder.SourceInput, []any, error) {
	source := builder.SourceInput{Raw: record, Detour: record["detour"]}
	diagnostics := make([]any, 0)
	fail := func(code, message string) (builder.SourceInput, []any, error) {
		diagnostics = append(diagnostics, configDiagnostic(code, path, message))
		return source, diagnostics, fmt.Errorf("%s: %s", path, message)
	}
	for _, field := range []struct {
		name string
		out  *string
	}{
		{"id", &source.ID}, {"kind", &source.Kind},
		{"name", &source.Name}, {"tag_prefix", &source.TagPrefix},
	} {
		if value, exists := record[field.name]; exists {
			text, ok := value.(string)
			if !ok {
				return fail("invalid_source", field.name+" must be a string")
			}
			*field.out = text
		}
	}
	for _, field := range []struct {
		name string
		out  *map[string]any
	}{
		{"detour_policy", &source.DetourPolicy}, {"replace", &source.Replace},
	} {
		if value, exists := record[field.name]; exists && value != nil {
			object, ok := value.(map[string]any)
			if !ok {
				return fail("invalid_source", field.name+" must be an object")
			}
			*field.out = object
		}
	}
	// Raw retains all unknown record fields; neither stored nodes nor parsed
	// cache projections are trusted as substitutes for the original material.
	if value, exists := record["enabled"]; exists {
		enabled, ok := value.(bool)
		if !ok {
			return fail("invalid_enabled", "enabled must be a boolean")
		}
		source.Enabled = &enabled
	}
	if source.Enabled != nil && !*source.Enabled {
		return source, diagnostics, nil
	}
	metadata := parser.Source{Kind: source.Kind, ID: source.ID, Name: source.Name}
	switch source.Kind {
	case "subscription":
		url, ok := record["url"].(string)
		if !ok || strings.TrimSpace(url) == "" {
			return fail("cache_url_missing", "subscription URL is required to read its offline cache")
		}
		if err := snapshot.cacheError[url]; err != nil {
			return fail("cache_unavailable", fmt.Sprintf("subscription cache is unavailable; refresh the source before building: %v", err))
		}
		body, exists := snapshot.cache[url]
		if !exists {
			return fail("cache_unavailable", "subscription has no offline cache; refresh the source before building")
		}
		nodes, details, findings, err := sourceBodyNodes(ctx, body, record)
		diagnostics = append(diagnostics, findings...)
		// Details retain disabled nodes for budget counting and legacy identity
		// migration. The enabled projection alone would undercount the source.
		if budgetInput != nil {
			budgetInput.parsed[source.ID] = details
		}
		source.Nodes = nodes
		if contextErr := ctx.Err(); contextErr != nil {
			return source, diagnostics, contextErr
		}
		if err != nil {
			return source, diagnostics, fmt.Errorf("%s: %w", path, err)
		}
		if err := configDiagnosticErrors(diagnostics, path); err != nil {
			return source, diagnostics, err
		}
		// All nodes may be intentionally disabled. Other sources can still
		// build; the final configHasNodes guard owns the global empty case.
		return source, diagnostics, nil
	case "server":
		nodes, findings, err := parseConfigRecord(ctx, record, metadata, path)
		diagnostics = append(diagnostics, findings...)
		source.Nodes = nodes
		if budgetInput != nil {
			budgetInput.parsed[source.ID] = nodes
		}
		return source, diagnostics, err
	case "folder":
		members, ok := record["nodes"].([]any)
		if !ok {
			return fail("invalid_folder", "folder nodes must be an array")
		}
		var failures []error
		if budgetInput != nil {
			budgetInput.parsed[source.ID] = []map[string]any{}
		}
		for index, value := range members {
			if err := ctx.Err(); err != nil {
				return source, diagnostics, err
			}
			member, ok := value.(map[string]any)
			memberPath := fmt.Sprintf("%s.nodes[%d]", path, index)
			if !ok {
				diagnostics = append(diagnostics, configDiagnostic("invalid_member", memberPath, "folder member must be an object"))
				failures = append(failures, fmt.Errorf("%s must be an object", memberPath))
				continue
			}
			prepared, findings, err := prepareConfigMember(ctx, member, metadata, memberPath)
			diagnostics = append(diagnostics, findings...)
			if budgetInput != nil {
				for _, entry := range prepared {
					budgetInput.memberIndexes[source.ID] = append(budgetInput.memberIndexes[source.ID], index)
					if entry.Node != nil {
						budgetInput.parsed[source.ID] = append(budgetInput.parsed[source.ID], map[string]any{"canonical": entry.Node, "name": sourceString(entry.Node, "tag"), "member_index": index, "enabled": entry.Enabled == nil || *entry.Enabled})
					}
				}
			}
			source.Members = append(source.Members, prepared...)
			if err != nil {
				failures = append(failures, err)
			}
		}
		return source, diagnostics, errors.Join(failures...)
	case "chain", "auto":
		// These are application records, not subscription documents. The builder
		// owns their references, options, flags and generated groups.
		return source, diagnostics, nil
	default:
		return fail("source_kind_unsupported", fmt.Sprintf("unsupported source kind %q", source.Kind))
	}
}

func prepareConfigMember(ctx context.Context, record map[string]any, metadata parser.Source, path string) ([]builder.MemberInput, []any, error) {
	member := builder.MemberInput{Raw: record}
	fail := func(code, message string) ([]builder.MemberInput, []any, error) {
		return []builder.MemberInput{member}, []any{configDiagnostic(code, path, message)}, fmt.Errorf("%s: %s", path, message)
	}
	if value, exists := record["enabled"]; exists {
		enabled, ok := value.(bool)
		if !ok {
			return fail("invalid_enabled", "enabled must be a boolean")
		}
		member.Enabled = &enabled
		if !enabled {
			return []builder.MemberInput{member}, nil, nil
		}
	}
	member.Detour = record["detour"]
	kind, _ := record["kind"].(string)
	switch kind {
	case "chain", "auto":
		return []builder.MemberInput{member}, nil, nil
	case "server":
		nodes, diagnostics, err := parseConfigRecord(ctx, record, metadata, path)
		if err != nil {
			return []builder.MemberInput{member}, diagnostics, err
		}
		// FolderMember's original invariant is one member -> first parsed node.
		if len(nodes) > 1 {
			nodes = nodes[:1]
		}
		members := make([]builder.MemberInput, 0, len(nodes))
		for _, node := range nodes {
			next := member
			next.Node = node
			members = append(members, next)
		}
		return members, diagnostics, nil
	default:
		return fail("member_kind_unsupported", fmt.Sprintf("unsupported folder member kind %q", kind))
	}
}

func parseConfigRecord(ctx context.Context, record map[string]any, metadata parser.Source, path string) ([]map[string]any, []any, error) {
	var body []byte
	if value, exists := record["origin"]; exists {
		origin, ok := value.(map[string]any)
		if !ok {
			message := "origin must be an object containing raw text"
			return nil, []any{configDiagnostic("invalid_origin", path+".origin", message)}, fmt.Errorf("%s: %s", path, message)
		}
		raw, ok := origin["raw"].(string)
		if !ok || strings.TrimSpace(raw) == "" {
			message := "origin.raw must contain the original source text"
			return nil, []any{configDiagnostic("origin_missing", path+".origin.raw", message)}, fmt.Errorf("%s: %s", path, message)
		}
		body = []byte(raw)
	} else if value, ok := record["body"].(map[string]any); ok && value != nil {
		// Launcher-native records may have a body and no origin at all. They
		// still pass through the same parser; an existing origin always wins.
		var err error
		body, err = json.Marshal(value)
		if err != nil {
			return nil, nil, err
		}
	} else {
		message := "server has no origin.raw or native body to parse"
		return nil, []any{configDiagnostic("origin_missing", path, message)}, fmt.Errorf("%s: %s", path, message)
	}
	return parseConfigNodes(ctx, body, metadata, path)
}

func parseConfigNodes(ctx context.Context, body []byte, source parser.Source, path string) ([]map[string]any, []any, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	result := parser.Parse(ctx, body, parser.Options{ContractFS: assets.FS, Source: source, KeepUnknown: true})
	diagnostics := make([]any, 0, len(result.Diagnostics))
	var failures []error
	for _, diagnostic := range result.Diagnostics {
		diagnostics = append(diagnostics, diagnostic)
		if strings.EqualFold(diagnostic.Severity, "error") {
			failures = append(failures, fmt.Errorf("%s: %s (%s)", path, diagnostic.Message, diagnostic.Code))
		}
	}
	nodes := make([]map[string]any, 0, len(result.Nodes))
	for _, node := range result.Nodes {
		for _, diagnostic := range node.Diagnostics {
			diagnostics = append(diagnostics, diagnostic)
			if strings.EqualFold(diagnostic.Severity, "error") {
				failures = append(failures, fmt.Errorf("%s: %s (%s)", path, diagnostic.Message, diagnostic.Code))
			}
		}
		emitted := node.SingBox()
		if len(emitted) == 0 {
			failures = append(failures, fmt.Errorf("%s: parsed node %q has no sing-box body", path, node.Key))
			continue
		}
		nodes = append(nodes, emitted)
	}
	if err := ctx.Err(); err != nil {
		return nodes, diagnostics, err
	}
	if !result.Complete || !result.Recognized || len(nodes) == 0 {
		message := "source did not produce a complete set of supported nodes"
		diagnostics = append(diagnostics, configDiagnostic("no_supported_nodes", path, message))
		failures = append(failures, fmt.Errorf("%s: %s", path, message))
	}
	return nodes, diagnostics, errors.Join(failures...)
}

// Shared subscription preparation returns wire-shaped findings. Build rejects
// error findings even when other lines produced nodes, preserving diagnostics
// without turning a partially unsupported subscription into a saved success.
func configDiagnosticErrors(diagnostics []any, path string) error {
	var failures []error
	for _, diagnostic := range diagnostics {
		var severity, code, message string
		switch value := diagnostic.(type) {
		case map[string]any:
			severity, _ = value["severity"].(string)
			if severity == "" {
				severity, _ = value["level"].(string)
			}
			code, _ = value["code"].(string)
			message, _ = value["message"].(string)
		case parser.Diagnostic:
			severity, code, message = value.Severity, value.Code, value.Message
		case builder.Diagnostic:
			severity, code, message = string(value.Level), value.Code, value.Message
		}
		if strings.EqualFold(severity, "error") {
			failures = append(failures, fmt.Errorf("%s: %s (%s)", path, message, code))
		}
	}
	return errors.Join(failures...)
}

func configDiagnostic(code, path, message string) builder.Diagnostic {
	return builder.Diagnostic{Level: builder.LevelError, Code: code, Path: path, Message: message, Fatal: true}
}

func configHasNodes(config []byte) bool {
	var value struct {
		Outbounds []map[string]any `json:"outbounds"`
		Endpoints []map[string]any `json:"endpoints"`
	}
	if json.Unmarshal(config, &value) != nil {
		return false
	}
	for _, nodes := range [][]map[string]any{value.Outbounds, value.Endpoints} {
		for _, node := range nodes {
			typ, _ := node["type"].(string)
			switch typ {
			case "", "direct", "block", "dns", "selector", "urltest", "chain":
				continue
			default:
				return true
			}
		}
	}
	return false
}
