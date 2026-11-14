package builder

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Leadaxe/lxbox/app/assets"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

func build(ctx context.Context, in Input) (Result, error) {
	result := Result{Pure: true, Complete: true, Generated: map[string]string{}}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	state := &buildState{seen: map[string]int{}, root: map[string]string{}}
	template, err := loadTemplate(in.Template)
	if err != nil {
		state.fatal("template_unavailable", "template", err.Error())
		template = map[string]any{}
		result.Config = []byte(`{}`)
		result.Diagnostics = state.diagnostics
		result.Complete = false
		return result, &BuildError{Diagnostics: state.diagnostics}
	}
	vars := resolveVars(template, in.Settings, state)
	config, err := expandConfig(template, vars, state)
	if err != nil {
		state.fatal("template_expand_failed", "template.config", err.Error())
	}
	if config == nil {
		config = map[string]any{}
	}
	if err := ctx.Err(); err != nil {
		result.Config = marshal(config)
		result.Diagnostics = state.diagnostics
		result.Complete = false
		return result, err
	}
	entries := emitSources(in.Sources, state)
	for _, entry := range entries {
		key := "outbounds"
		if entry.endpoint {
			key = "endpoints"
		}
		config[key] = appendAny(config[key], entry.body)
	}
	for _, chain := range state.chains {
		if outbound, ok := emitChain(chain, state); ok {
			config["outbounds"] = appendAny(config["outbounds"], outbound)
		}
	}
	applyDirections(config, template, in.Settings, state)
	if err := applyRuleRecords(config, template, in.Settings, in.Cache, state); err != nil {
		state.fatal("route_records_failed", "settings.rules", err.Error())
	}
	if err := applyDNSRecords(config, template, in.Settings, state); err != nil {
		state.fatal("dns_records_failed", "settings.dns", err.Error())
	}
	applyConfigOverrides(config, in.Settings, state)
	validateConfig(config, state)
	result.Config = marshal(config)
	result.EmittedTags = append([]string(nil), state.tags...)
	if in.ValidateCore && !state.hasFatal() {
		coreContext := in.CoreContext
		if coreContext == nil {
			coreContext = include.Context(ctx)
		}
		var options option.Options
		if err := options.UnmarshalJSONContext(coreContext, result.Config); err != nil {
			state.fatal("singbox_option_validation_failed", "config", err.Error())
		}
	}
	result.Diagnostics = state.diagnostics
	if state.hasFatal() {
		result.Complete = false
		return result, &BuildError{Diagnostics: state.diagnostics}
	}
	return result, nil
}

type buildState struct {
	diagnostics []Diagnostic
	vars        map[string]any
	tags        []string
	seen        map[string]int
	root        map[string]string
	chains      []SourceInput
}

func (s *buildState) add(level DiagnosticLevel, code, path, message string, value any, fatal bool) {
	var raw json.RawMessage
	if value != nil {
		raw, _ = json.Marshal(value)
	}
	s.diagnostics = append(s.diagnostics, Diagnostic{Level: level, Code: code, Path: path, Message: message, Value: raw, Fatal: fatal})
}
func (s *buildState) warn(code, path, message string, value any) {
	s.add(LevelWarning, code, path, message, value, false)
}
func (s *buildState) fatal(code, path, message string, values ...any) {
	var value any
	if len(values) > 0 {
		value = values[0]
	}
	s.add(LevelError, code, path, message, value, true)
}
func (s *buildState) hasFatal() bool {
	for _, d := range s.diagnostics {
		if d.Fatal {
			return true
		}
	}
	return false
}

func loadTemplate(provided map[string]any) (map[string]any, error) {
	if provided != nil {
		if len(provided) == 0 {
			return nil, fmt.Errorf("provided template is empty")
		}
		return cloneMap(provided), nil
	}
	data, err := assets.Read("wizard_template.json")
	if err != nil {
		return nil, err
	}
	var template map[string]any
	if err := json.Unmarshal(data, &template); err != nil {
		return nil, err
	}
	return template, nil
}

func marshal(value any) []byte {
	data, _ := json.Marshal(value)
	return data
}
func appendAny(existing any, value any) []any {
	list, _ := existing.([]any)
	return append(list, value)
}
func appendAll(existing any, values []any) []any {
	list, _ := existing.([]any)
	return append(list, values...)
}
func stringValue(m map[string]any, key string) string {
	value, _ := m[key].(string)
	return value
}
func settingString(m map[string]any, key string) string {
	if value := stringValue(m, key); value != "" {
		return value
	}
	vars, _ := m["vars"].(map[string]any)
	return stringValue(vars, key)
}
func contains(xs []string, value string) bool {
	for _, item := range xs {
		if item == value {
			return true
		}
	}
	return false
}
func boolValue(m map[string]any, key string, fallback bool) bool {
	value, ok := m[key].(bool)
	if !ok {
		return fallback
	}
	return value
}
func stringsOf(value any) []string {
	var result []string
	switch xs := value.(type) {
	case []any:
		for _, x := range xs {
			if text, ok := x.(string); ok {
				result = append(result, text)
			}
		}
	case json.Number:
		return []string{xs.String()}
	case []string:
		result = append(result, xs...)
	case string:
		if strings.TrimSpace(xs) != "" {
			for _, part := range strings.Split(xs, ",") {
				if text := strings.TrimSpace(part); text != "" {
					result = append(result, text)
				}
			}
		}
	}
	return result
}
