package parser

// This file is the data-driven contract executor. It intentionally has no
// protocol switch: protocol-specific behavior comes from mappers.* records,
// their includes, and shared registry blocks.

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type mapperInput struct {
	root   map[string]any
	query  map[string][]string
	scheme string
	host   string
	port   any
	path   string
	frag   string
	user   string
	base   map[string]any
	form   string
}

type mapperState struct {
	entry map[string]any
	input mapperInput
	seen  map[string]bool
	diags []Diagnostic
	reg   *registry
}

func mapContractURI(rawURI string, protocol string, source Source, reg *registry) (*Node, []Diagnostic, bool) {
	p := registryProtocolFor(reg, protocol)
	if p == nil || p.raw == nil {
		return nil, nil, false
	}
	mappers, ok := p.raw["mappers"].(map[string]any)
	if !ok {
		return nil, nil, false
	}
	uri, ok := mappers["uri"].(map[string]any)
	if !ok {
		return nil, nil, false
	}
	if mapperForm(rawURI, uri) == "conf_b64" {
		return nil, nil, false
	}
	params, hasParams := uri["params"]
	if !hasParams {
		return nil, nil, false
	}
	_ = params
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, []Diagnostic{{Code: "uri_invalid", Severity: "error", Message: err.Error(), Value: rawURI, Source: source}}, true
	}
	if u.Hostname() == "" {
		return nil, []Diagnostic{{Code: "server_missing", Severity: "error", Message: "URI has no server host", Value: rawURI, Source: source}}, true
	}
	in := mapperInput{root: map[string]any{}, query: queryFold(u.RawQuery), scheme: strings.ToLower(u.Scheme), host: u.Hostname(), path: u.EscapedPath(), frag: u.Fragment, user: ""}
	if u.User != nil {
		in.user, _ = url.PathUnescape(u.User.String())
	}
	if u.Port() != "" {
		in.port = intValue(u.Port())
	}
	if in.path == "" {
		in.path = u.Path
	}
	state := &mapperState{entry: map[string]any{"type": p.singboxType}, input: in, reg: reg, seen: map[string]bool{}}
	if len(p.userInto) > 0 && in.user != "" {
		parts := strings.SplitN(in.user, p.userSep, len(p.userInto))
		for i, target := range p.userInto {
			if i < len(parts) {
				setPath(state.entry, target, parts[i])
			}
		}
	}
	if err := executeMapper(state, p, "uri", uri); err != nil {
		return nil, []Diagnostic{{Code: "mapper_error", Severity: "error", Message: err.Error(), Value: rawURI, Source: source}}, true
	}
	if len(state.diags) > 0 {
		for i := range state.diags {
			state.diags[i].Source = source
		}
	}
	if requiredMissing(state.entry, uri) {
		state.diags = append(state.diags, Diagnostic{Code: "required_field_missing", Severity: "error", Message: "required mapper field is absent", Source: source})
		return nil, state.diags, true
	}
	name := mapperLabel(uri, state, p.singboxType)
	return ptrNode(makeNode(name, p.singboxType, map[string]any{"uri": rawURI}, state.entry, source, "uri")), state.diags, true
}

func mapperForm(rawURI string, uri map[string]any) string {
	forms, _ := uri["forms"].([]any)
	body := rawURI
	if i := strings.IndexByte(body, '#'); i >= 0 {
		body = body[:i]
	}
	if !strings.Contains(body, "@") && !strings.Contains(body, "?") {
		for _, value := range forms {
			form, _ := value.(map[string]any)
			if stringValue(form["id"]) == "conf_b64" {
				return "conf_b64"
			}
		}
	}
	return "url"
}

func mapperHasSpecialContainer(uri map[string]any) bool {
	_, forms := uri["forms"]
	_, user := uri["userinfo"]
	_, params := uri["params"]
	return forms || user || params
}

func mapContractXray(raw map[string]any, protocol string, source Source, reg *registry) ([]Node, []Diagnostic, bool) {
	p := registryProtocolFor(reg, protocol)
	if p == nil || p.raw == nil {
		return nil, nil, false
	}
	mappers, ok := p.raw["mappers"].(map[string]any)
	if !ok {
		return nil, nil, false
	}
	xray, ok := mappers["xray"].(map[string]any)
	if !ok {
		return nil, nil, false
	}
	basePaths := xrayBases(xray, raw)
	if len(basePaths) == 0 {
		return nil, nil, false
	}
	var nodes []Node
	var diags []Diagnostic
	for _, basePath := range basePaths {
		baseValue, baseOK := getPath(raw, basePath)
		base, ok := baseValue.(map[string]any)
		if !baseOK || !ok {
			continue
		}
		in := mapperInput{root: cloneMap(raw), query: map[string][]string{}, scheme: "", base: base, form: "xray"}
		state := &mapperState{entry: map[string]any{"type": p.singboxType, "server": in.host}, input: in, reg: reg, seen: map[string]bool{}}
		if in.port != nil {
			state.entry["server_port"] = in.port
		}
		if err := executeMapper(state, p, "xray", xray); err != nil {
			diags = append(diags, Diagnostic{Code: "mapper_error", Severity: "error", Message: err.Error(), Source: source})
			continue
		}
		state.entry["type"] = p.singboxType
		name := firstString(raw, "tag", "remarks", "name")
		if name == "" {
			name = fmt.Sprintf("%s-%s-%v", p.singboxType, stringValue(state.entry["server"]), state.entry["server_port"])
		}
		n := makeNode(name, p.singboxType, raw, state.entry, source, "xray")
		nodes = append(nodes, n)
		diags = append(diags, state.diags...)
	}
	return nodes, diags, true
}

func xrayBases(xray map[string]any, raw map[string]any) []string {
	forms, _ := xray["forms"].([]any)
	for _, v := range forms {
		f, ok := v.(map[string]any)
		if !ok {
			continue
		}
		b, _ := f["base"].(string)
		if b == "" {
			continue
		}
		if _, ok := getPath(raw, b); ok {
			return expandArrayBase(raw, strings.TrimSuffix(b, ".0"))
		}
	}
	for _, p := range []string{"settings.vnext", "settings.servers", "settings.peers"} {
		if _, ok := getPath(raw, p); ok {
			return expandArrayBase(raw, p)
		}
	}
	return nil
}

func expandArrayBase(raw map[string]any, pathName string) []string {
	value, ok := getPath(raw, pathName)
	if !ok {
		return nil
	}
	list, ok := value.([]any)
	if !ok {
		return []string{pathName}
	}
	out := make([]string, 0, len(list))
	for i := range list {
		out = append(out, fmt.Sprintf("%s.%d", pathName, i))
	}
	return out
}

func executeMapper(state *mapperState, protocol *registryProtocol, dialect string, mapper map[string]any) error {
	if defs, ok := mapper["defaults"].(map[string]any); ok {
		for k, v := range defs {
			setPath(state.entry, k, cloneValue(v))
		}
	}
	includes := stringSlice(mapper["include"])
	for _, inc := range includes {
		parts := strings.SplitN(inc, "#", 2)
		if len(parts) != 2 {
			continue
		}
		shared := state.reg.shared[parts[0]]
		if shared == nil {
			continue
		}
		blocks, _ := shared["blocks"].(map[string]any)
		block, _ := blocks[parts[1]].(map[string]any)
		if block != nil {
			order := state.reg.sharedOrder[parts[0]]
			if err := executeRecords(state, block, order, "blocks."+parts[1]); err != nil {
				return err
			}
		}
	}
	order := protocol.order
	if err := executeRecords(state, mapper, order, "mappers."+dialect); err != nil {
		return err
	}
	return nil
}

func executeRecords(state *mapperState, section map[string]any, orders map[string][]string, pathName string) error {
	keys := orderedKeys(section, orders[pathName])
	for _, key := range keys {
		value := section[key]
		if key == "include" || key == "defaults" || key == "detect" || key == "forms" || key == "body_source" || key == "unknown_key" || key == "emit" || key == "overlays" || key == "note" || key == "params" || key == "label" {
			continue
		}
		record, ok := value.(map[string]any)
		if !ok {
			continue
		}
		if key == "$selector" {
			if err := executeRecords(state, record, orders, pathName+".$selector"); err != nil {
				return err
			}
			continue
		}
		if _, hasSource := record["source"]; !hasSource {
			if _, hasMaps := record["maps_to"]; !hasMaps {
				if err := executeRecords(state, record, orders, pathName+"."+key); err != nil {
					return err
				}
				continue
			}
		}
		if !conditionMatches(record["when"], state) {
			continue
		}
		if source, ok := record["source"]; ok {
			v, found := sourceValue(source, state, record)
			if !found {
				if df, ok := record["default_from"].(string); ok {
					v, found = getSourcePath(df, *state)
				}
			}
			if !found {
				if defaults, ok := record["default_when"].(map[string]any); ok {
					if absent, isBool := defaults["absent"].(bool); isBool && absent {
						v, found = defaults["value"], true
					}
				}
			}

			if found {
				v = coerceMapperValue(v, record, state.reg)
				applyMapperValue(state, record, v)
			}
		}
		if selector, ok := record["selector"].(bool); ok && selector {
			v, found := sourceValue(record["source"], state, record)
			if found {
				applySelectorSets(state, record, v)
			}
		}
	}
	if params, ok := section["params"].(map[string]any); ok {
		return executeRecords(state, params, orders, pathName+".params")
	}
	return nil
}

func orderedKeys(section map[string]any, order []string) []string {
	keys := make([]string, 0, len(section))
	seen := map[string]bool{}
	for _, key := range order {
		if _, ok := section[key]; ok && !seen[key] {
			keys = append(keys, key)
			seen[key] = true
		}
	}
	for key := range section {
		if !seen[key] {
			keys = append(keys, key)
		}
	}
	return keys
}

func sourceValue(spec any, state *mapperState, record map[string]any) (any, bool) {
	for _, candidate := range sourceList(spec) {
		if candidate == "userinfo" {
			if state.input.user != "" {
				return state.input.user, true
			}
			continue
		}
		if v, ok := getSourcePath(candidate, *state); ok {
			return v, true
		}
	}
	return nil, false
}
func sourceList(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var o []string
		for _, v := range x {
			if s, ok := v.(string); ok {
				o = append(o, s)
			}
		}
		return o
	}
	return nil
}
func getSourcePath(pathName string, state mapperState) (any, bool) {
	if strings.HasPrefix(pathName, "query.") {
		key := strings.TrimPrefix(pathName, "query.")
		for k, v := range state.input.query {
			if strings.EqualFold(k, key) && len(v) > 0 {
				return v[len(v)-1], true
			}
		}
		return nil, false
	}
	if pathName == "host" {
		return state.input.host, state.input.host != ""
	}
	if pathName == "port" {
		return state.input.port, state.input.port != nil
	}
	if pathName == "fragment" {
		return state.input.frag, state.input.frag != ""
	}
	if pathName == "path" {
		return state.input.path, state.input.path != ""
	}
	if pathName == "userinfo" {
		return state.input.user, state.input.user != ""
	}
	if strings.HasPrefix(pathName, "json.$base.") {
		return getPath(state.input.base, strings.TrimPrefix(pathName, "json.$base."))
	}
	if strings.HasPrefix(pathName, "json.") {
		return getPath(state.input.root, strings.TrimPrefix(pathName, "json."))
	}
	return getPath(state.entry, pathName)
}
func getPath(root map[string]any, pathName string) (any, bool) {
	if root == nil {
		return nil, false
	}
	var cur any = root
	for _, part := range strings.Split(strings.TrimPrefix(pathName, "."), ".") {
		if index, err := strconv.Atoi(part); err == nil {
			list, ok := cur.([]any)
			if !ok || index < 0 || index >= len(list) {
				return nil, false
			}
			cur = list[index]
			continue
		}
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		var exists bool
		cur, exists = m[part]
		if !exists {
			return nil, false
		}
	}
	return cur, true
}

func queryFold(raw string) map[string][]string {
	values := map[string][]string{}
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		key, value, found := strings.Cut(part, "=")
		if !found {
			value = ""
		}
		k, err := url.QueryUnescape(key)
		if err != nil {
			k = key
		}
		v, err := url.PathUnescape(value)
		if err != nil {
			v = value
		}
		fold := strings.ToLower(k)
		values[fold] = append(values[fold], v)
	}
	return values
}

func applyMapperValue(state *mapperState, record map[string]any, value any) {
	maps, ok := record["maps_to"].(string)
	if !ok || maps == "" {
		if on, ok := record["on_present"].(map[string]any); ok {
			state.diags = append(state.diags, Diagnostic{Code: stringValue(on["code"]), Severity: "info", Message: "contract mapper noted an intentionally unmaterialized field"})
		}
		return
	}
	if value == nil {
		deletePath(state.entry, maps)
		return
	}
	setPath(state.entry, maps, value)
	if implies, ok := record["implies"].(map[string]any); ok {
		for k, v := range implies {
			if vm, ok := v.(map[string]any); ok {
				if val, ok := vm["value"]; ok {
					setPath(state.entry, k, val)
				}
			} else {
				setPath(state.entry, k, v)
			}
		}
	}
	if sets, ok := record["sets"].(map[string]any); ok {
		if selected, ok := sets[stringValue(value)].(map[string]any); ok {
			for k, v := range selected {
				if v == nil {
					deletePath(state.entry, k)
				} else {
					setPath(state.entry, k, v)
				}
			}
		}
	}
}
func applySelectorSets(state *mapperState, record map[string]any, value any) {
	if sets, ok := record["sets"].(map[string]any); ok {
		if selected, ok := sets[stringValue(value)].(map[string]any); ok {
			for k, v := range selected {
				if v == nil {
					deletePath(state.entry, k)
				} else {
					setPath(state.entry, k, v)
				}
			}
		}
	}
}
func deletePath(dst map[string]any, key string) {
	parts := strings.Split(key, ".")
	cur := dst
	for _, p := range parts[:len(parts)-1] {
		next, ok := cur[p].(map[string]any)
		if !ok {
			return
		}
		cur = next
	}
	delete(cur, parts[len(parts)-1])
}
func coerceMapperValue(v any, record map[string]any, reg *registry) any {
	if norm := stringValue(record["normalize"]); norm != "" {
		s := stringValue(v)
		switch norm {
		case "trim":
			v = strings.TrimSpace(s)
		case "trim_lower":
			v = strings.ToLower(strings.TrimSpace(s))
		}
	}
	if vm, ok := record["value_map"].(map[string]any); ok {
		if ref, ok := vm["$ref"].(string); ok {
			if mapped := resolveValueMapRef(reg, ref, stringValue(v)); mapped != nil {
				v = mapped
			}
		} else if mapped, exists := vm[stringValue(v)]; exists {
			v = mapped
		}
	}
	typ := stringValue(record["type"])
	if typ == "int" {
		if i := intValue(v); i != nil {
			v = i
		}
	}
	if typ == "bool_spelled" {
		v = isTrueSpelled(v)
	}
	if list, ok := record["list"].(map[string]any); ok {
		if sep := stringValue(list["sep"]); sep != "" {
			var out []any
			for _, s := range strings.Split(stringValue(v), sep) {
				out = append(out, strings.TrimSpace(s))
			}
			v = out
		}
	}
	return v
}
func isTrueSpelled(v any) bool {
	switch strings.ToLower(strings.TrimSpace(stringValue(v))) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}
func resolveValueMapRef(reg *registry, ref, value string) any {
	if reg == nil {
		return nil
	}
	parts := strings.SplitN(strings.TrimPrefix(ref, ""), ".", 2)
	if len(parts) != 2 {
		return nil
	}
	table := reg.shared[parts[0]]
	if table == nil {
		return nil
	}
	var cur any = table
	for _, part := range strings.Split(parts[1], ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[part]
		if !ok {
			return nil
		}
	}
	if list, ok := cur.([]any); ok {
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				if strings.HasPrefix(strings.ToLower(value), strings.ToLower(stringValue(m["prefix"]))) {
					return strings.TrimPrefix(strings.ToLower(value), strings.ToLower(stringValue(m["prefix"])))
				}
			}
		}
	}
	return nil
}
func requiredMissing(entry, uri map[string]any) bool {
	return requiredMissingInSection(entry, uri)
}

func requiredMissingInSection(entry map[string]any, section map[string]any) bool {
	if required, ok := section["required"].(bool); ok && required {
		if mapsTo, ok := section["maps_to"].(string); ok && mapsTo != "" {
			value, exists := getPath(entry, strings.ReplaceAll(mapsTo, "[]", ".0"))
			if !exists || value == nil || value == "" {
				return true
			}
		}
	}
	for _, value := range section {
		child, ok := value.(map[string]any)
		if ok && requiredMissingInSection(entry, child) {
			return true
		}
	}
	return false
}

func containsAny(values []any, got any) bool {
	for _, value := range values {
		if stringValue(value) == stringValue(got) {
			return true
		}
	}
	return false
}

func conditionMatches(raw any, state *mapperState) bool {
	m, ok := raw.(map[string]any)
	if !ok || len(m) == 0 {
		return true
	}
	for key, want := range m {
		if key == "$value" {
			continue
		}
		got, exists := getSourcePath(key, *state)
		if cond, ok := want.(map[string]any); ok {
			if list, ok := cond["in"].([]any); ok {
				if !containsAny(list, got) {
					return false
				}
			}
			if list, ok := cond["not_in"].([]any); ok {
				if containsAny(list, got) {
					return false
				}
			}
			if _, ok := cond["present"]; ok && (!exists) {
				return false
			}
			continue
		}
		if !exists || stringValue(got) != stringValue(want) {
			return false
		}
	}
	return true
}
func mapperLabel(section map[string]any, state *mapperState, protocol string) string {
	if label, ok := section["label"].(map[string]any); ok {
		if source := label["source"]; source != nil {
			if v, ok := sourceValue(source, state, label); ok {
				return fragmentName(stringValue(v))
			}
		}
		if fallback, ok := label["fallback"].(map[string]any); ok {
			if templ := stringValue(fallback["template"]); templ != "" {
				return strings.ReplaceAll(strings.ReplaceAll(templ, "{scheme}", protocol), "{server}", stringValue(state.entry["server"]))
			}
		}
	}
	return fmt.Sprintf("%s-%s-%v", protocol, stringValue(state.entry["server"]), state.entry["server_port"])
}
func ptrNode(n Node) *Node { return &n }
