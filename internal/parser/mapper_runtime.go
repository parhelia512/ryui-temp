package parser

// This file is the data-driven contract executor. It intentionally has no
// protocol switch: protocol-specific behavior comes from mappers.* records,
// their includes, and shared registry blocks.

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type mapperInput struct {
	root    map[string]any
	query   map[string][]string
	scheme  string
	host    string
	port    any
	portRaw string
	path    string
	frag    string
	user    string
	base    map[string]any
	form    string
}

type mapperState struct {
	entry      map[string]any
	input      mapperInput
	diags      []Diagnostic
	reg        *registry
	dropNode   bool
	dropReason string
}

type mapperURL struct {
	scheme   string
	host     string
	portRaw  string
	queryRaw string
	user     string
	frag     string
	path     string
}

type mapperRecord struct {
	path     string
	record   map[string]any
	priority int
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
	form, parsed, decoded := decodeMapperForm(rawURI, uri, p)
	if form == "" {
		return nil, nil, false
	}
	if form == "conf_b64" {
		return nil, nil, false
	}
	in := mapperInput{root: map[string]any{}, query: queryFold(parsed.queryRaw), scheme: strings.ToLower(parsed.scheme), host: parsed.host, portRaw: parsed.portRaw, path: parsed.path, frag: parsed.frag, form: form}
	if form == "v2rayn" {
		root, ok := decoded.(map[string]any)
		if !ok {
			return nil, nil, false
		}
		in.root = root
	}
	if form == "legacy" || form == "sip002" {
		in.form = form
	}
	in.port = intValue(firstPortNumber(parsed.portRaw))
	if parsed.user != "" {
		in.user = decodeMapperUserinfo(parsed.user, uri)
	} else if form == "sip002" || form == "legacy" {
		in.user = decodeMapperUserinfo(stringValue(decoded), uri)
	}
	if in.host == "" {
		in.host = mapperJSONHost(in)
	}
	if in.host == "" {
		return nil, []Diagnostic{{Code: "server_missing", Severity: "error", Message: "URI has no server host", Value: rawURI, Source: source}}, true
	}
	if in.frag == "" {
		in.frag = mapperFragment(rawURI)
	}
	state := &mapperState{entry: map[string]any{"type": p.singboxType}, input: in, reg: reg}
	if len(p.userInto) > 0 && in.user != "" {
		applyUserinfoInto(state.entry, p, in.user)
	}
	if err := executeMapper(state, p, "uri", uri); err != nil {
		return nil, []Diagnostic{{Code: "mapper_error", Severity: "error", Message: err.Error(), Value: rawURI, Source: source}}, true
	}
	sanitizeMapperBody(state, p.raw)
	for i := range state.diags {
		state.diags[i].Source = source
	}
	if requiredMissing(state.entry, uri) {
		state.diags = append(state.diags, Diagnostic{Code: "required_field_missing", Severity: "error", Message: "required mapper field is absent", Value: rawURI, Source: source})
		return nil, state.diags, true
	}
	if state.dropNode {
		if state.dropReason == "" {
			state.dropReason = "field_missing"
		}
		state.diags = append(state.diags, Diagnostic{Code: state.dropReason, Severity: "error", Message: "node body violates the registry contract", Value: rawURI, Source: source})
		return nil, state.diags, true
	}
	name := mapperLabel(uri, state, p.singboxType)
	return ptrNode(makeNode(name, p.singboxType, map[string]any{"uri": rawURI}, state.entry, source, "uri")), state.diags, true
}

func applyUserinfoInto(entry map[string]any, p *registryProtocol, user string) {
	single := p.userSingleInto
	if single == "" && len(p.userInto) > 0 {
		single = p.userInto[0]
	}
	if single != "" && !strings.Contains(user, p.userSep) {
		if user != "" {
			setPath(entry, single, user)
		}
		return
	}
	parts := strings.SplitN(user, p.userSep, len(p.userInto))
	for i, target := range p.userInto {
		if i < len(parts) && parts[i] != "" {
			setPath(entry, target, parts[i])
		}
	}
}

func mapperJSONHost(in mapperInput) string {
	if in.root == nil {
		return ""
	}
	for _, key := range []string{"add", "server", "address"} {
		if value := stringValue(in.root[key]); value != "" {
			return value
		}
	}
	return ""
}

func decodeMapperForm(rawURI string, uri map[string]any, p *registryProtocol) (string, mapperURL, any) {
	forms, _ := uri["forms"].([]any)
	body := rawURI
	scheme := strings.ToLower(stringValue(p.scheme))
	if i := strings.Index(body, "://"); i >= 0 {
		scheme = strings.ToLower(body[:i])
		body = body[i+3:]
	}
	authority := body
	if i := strings.IndexByte(authority, '#'); i >= 0 {
		authority = authority[:i]
	}
	if i := strings.IndexByte(authority, '?'); i >= 0 {
		authority = authority[:i]
	}
	authority = strings.TrimSuffix(authority, "/")
	matches := func(form map[string]any) bool {
		detect, _ := form["detect"].(map[string]any)
		if detect == nil {
			return false
		}
		if def, _ := detect["default"].(bool); def {
			return true
		}
		return mapperDetectRule(detect, authority, body)
	}
	chosen := ""
	var chosenForm map[string]any
	for _, value := range forms {
		form, _ := value.(map[string]any)
		if form == nil || !matches(form) {
			continue
		}
		id := stringValue(form["id"])
		if id == "url" {
			continue
		}
		chosen, chosenForm = id, form
		break
	}
	if chosen == "" {
		parsed := parseMapperURL(rawURI)
		if strings.HasPrefix(scheme, "naive+") {
			parsed.scheme = scheme
		}
		if chosenForm == nil {
			for _, value := range forms {
				form, _ := value.(map[string]any)
				if form != nil && stringValue(form["id"]) == "url" {
					chosenForm = form
					break
				}
			}
		}
		return "url", parsed, nil
	}
	switch chosen {
	case "conf_b64":
		return "conf_b64", mapperURL{}, nil
	case "v2rayn":
		decoded, ok := decodeBase64Flexible(strings.TrimSpace(authority))
		if !ok {
			return "", mapperURL{}, nil
		}
		var root map[string]any
		if decodeJSONInto(decoded, &root) != nil {
			return "", mapperURL{}, nil
		}
		parsed := mapperURL{scheme: scheme, frag: mapperFragment(rawURI)}
		if value := stringValue(root["add"]); value != "" {
			parsed.host = value
			if port := intValue(root["port"]); port != nil {
				parsed.portRaw = fmt.Sprint(port)
			}
		}
		return "v2rayn", parsed, root
	case "sip002":
		at := strings.LastIndexByte(authority, '@')
		if at < 0 {
			return "", mapperURL{}, nil
		}
		decoded, ok := decodeBase64Flexible(authority[:at])
		if !ok {
			return "", mapperURL{}, nil
		}
		host, portRaw := splitMapperHostPort(authority[at+1:])
		return "sip002", mapperURL{scheme: scheme, host: host, portRaw: portRaw, frag: mapperFragment(rawURI)}, string(decoded)
	case "legacy":
		candidate := strings.TrimSpace(percentDecode(authority))
		decoded, ok := decodeBase64Flexible(candidate)
		if !ok {
			return "", mapperURL{}, nil
		}
		inner := string(decoded)
		at := strings.LastIndexByte(inner, '@')
		if at < 0 {
			return "", mapperURL{}, nil
		}
		userinfo, hostport := inner[:at], inner[at+1:]
		queryRaw := ""
		if i := strings.IndexByte(hostport, '?'); i >= 0 {
			queryRaw, hostport = hostport[i+1:], hostport[:i]
		}
		if i := strings.IndexAny(hostport, "/#"); i >= 0 {
			hostport = hostport[:i]
		}
		host, portRaw := splitMapperHostPort(hostport)
		return "legacy", mapperURL{scheme: scheme, host: host, portRaw: portRaw, queryRaw: queryRaw, user: userinfo, frag: mapperFragment(rawURI)}, inner
	case "wrapped":
		decoded, ok := decodeBase64Flexible(strings.TrimSpace(authority))
		if !ok {
			return "url", parseMapperURL(rawURI), nil
		}
		text := strings.TrimSpace(string(decoded))
		if text == "" {
			return "", mapperURL{}, nil
		}
		parsed := parseMapperURL(scheme + "://" + text)
		parsed.scheme = scheme
		if parsed.frag == "" {
			parsed.frag = mapperFragment(rawURI)
		}
		return "wrapped", parsed, text
	}
	return "", mapperURL{}, nil
}

func mapperDetectRule(detect map[string]any, authority, body string) bool {
	rules := 0
	if pattern := stringValue(detect["regex"]); pattern != "" {
		rules++
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		matched := re.MatchString(strings.TrimSpace(body))
		if !matched {
			if decoded, ok := decodeBase64Flexible(strings.TrimSpace(authority)); ok {
				matched = re.MatchString(strings.TrimSpace(string(decoded)))
			}
		}
		if !matched {
			return false
		}
	}
	if text, ok := detect["text"].(map[string]any); ok {
		rules++
		if contains := stringValue(text["contains"]); contains != "" && !strings.Contains(body, contains) {
			return false
		}
	}
	if jsonDetect, ok := detect["json"].(map[string]any); ok {
		rules++
		if typeOf, ok := jsonDetect["type_of"].(map[string]any); ok && stringValue(typeOf["$root"]) == "object" {
			decoded, ok := decodeBase64Flexible(authority)
			if !ok {
				return false
			}
			var value any
			if decodeJSONInto(decoded, &value) != nil {
				return false
			}
			if _, isObject := value.(map[string]any); !isObject {
				return false
			}
		}
	}
	if all, ok := detect["all"].([]any); ok {
		rules++
		for _, item := range all {
			rule, _ := item.(map[string]any)
			if rule == nil {
				return false
			}
			if !mapperDetectRule(rule, authority, body) {
				return false
			}
		}
	}
	if not, ok := detect["not"].(map[string]any); ok {
		rules++
		if mapperDetectRule(not, authority, body) {
			return false
		}
	}
	if anyRule, ok := detect["any"].([]any); ok {
		rules++
		matched := false
		for _, item := range anyRule {
			rule, _ := item.(map[string]any)
			if rule != nil && mapperDetectRule(rule, authority, body) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return rules > 0
}

func mapperFragment(rawURI string) string {
	if i := strings.IndexByte(rawURI, '#'); i >= 0 {
		return rawURI[i+1:]
	}
	return ""
}

func parseMapperURL(rawURI string) mapperURL {
	out := mapperURL{}
	body := rawURI
	if i := strings.Index(body, "://"); i >= 0 {
		out.scheme = strings.ToLower(body[:i])
		body = body[i+3:]
	}
	if i := strings.IndexByte(body, '#'); i >= 0 {
		out.frag = body[i+1:]
		body = body[:i]
	}
	if i := strings.IndexByte(body, '?'); i >= 0 {
		out.queryRaw = body[i+1:]
		body = body[:i]
	}
	if i := strings.IndexByte(body, '/'); i >= 0 {
		out.path = body[i:]
		body = body[:i]
	}
	if at := strings.LastIndexByte(body, '@'); at >= 0 {
		out.user = body[:at]
		body = body[at+1:]
	}
	out.host, out.portRaw = splitMapperHostPort(body)
	return out
}

func splitMapperHostPort(hostport string) (string, string) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "", ""
	}
	if strings.HasPrefix(hostport, "[") {
		if end := strings.IndexByte(hostport, ']'); end >= 0 {
			host := hostport[1:end]
			rest := hostport[end+1:]
			return host, strings.TrimPrefix(rest, ":")
		}
	}
	if i := strings.IndexByte(hostport, ':'); i >= 0 {
		return hostport[:i], hostport[i+1:]
	}
	return hostport, ""
}

func firstPortNumber(portRaw string) string {
	portRaw = strings.TrimSpace(portRaw)
	if portRaw == "" {
		return ""
	}
	end := 0
	for end < len(portRaw) && portRaw[end] >= '0' && portRaw[end] <= '9' {
		end++
	}
	if end == 0 {
		return ""
	}
	return portRaw[:end]
}

func decodeMapperUserinfo(user string, uri map[string]any) string {
	info, _ := uri["userinfo"].(map[string]any)
	if info == nil {
		return user
	}
	decoders := stringSlice(info["decode"])
	requiresSep := stringValue(info["decode_requires_separator"])
	value := user
	for _, decoder := range decoders {
		switch decoder {
		case "percent":
			value = percentDecode(value)
		case "base64?":
			if requiresSep != "" && strings.Contains(user, requiresSep) {
				continue
			}
			if decoded, ok := decodeBase64Flexible(value); ok {
				text := string(decoded)
				if requiresSep == "" || strings.Contains(text, requiresSep) {
					value = text
				}
			}
		}
	}
	return value
}

func executeMapper(state *mapperState, protocol *registryProtocol, dialect string, mapper map[string]any) error {
	abstractDefaults := map[string]any{}
	if defaults, ok := mapper["defaults"].(map[string]any); ok {
		abstractDefaults = defaults
	}
	for k, v := range abstractDefaults {
		if k == "type" {
			continue
		}
		setPath(state.entry, k, resolveMapperPlaceholders(normalizeIntegral(cloneValue(v)), state))
	}
	if schemeSets, ok := mapper["scheme_sets"].(map[string]any); ok {
		selected, ok := schemeSets[state.input.scheme].(map[string]any)
		if !ok {
			selected, _ = schemeSets["*"].(map[string]any)
		}
		for k, v := range selected {
			if k == "$default_port" {
				if state.input.port == nil {
					state.input.port = intValue(v)
				}
				continue
			}
			setPath(state.entry, k, resolveMapperPlaceholders(normalizeIntegral(cloneValue(v)), state))
		}
	}
	plan := buildMapperPlan(state, protocol, dialect, mapper)
	sort.SliceStable(plan, func(i, j int) bool { return plan[i].priority < plan[j].priority })
	for pass := 0; pass < 2; pass++ {
		for _, item := range plan {
			selector, _ := item.record["selector"].(bool)
			if (pass == 0) != selector {
				continue
			}
			evaluateMapperRecord(state, item.record)
		}
	}
	return nil
}

func resolveMapperPlaceholders(value any, state *mapperState) any {
	switch typed := value.(type) {
	case string:
		if typed == "$host" {
			return state.input.host
		}
		return typed
	case map[string]any:
		out := map[string]any{}
		for k, v := range typed {
			out[k] = resolveMapperPlaceholders(v, state)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, v := range typed {
			out[i] = resolveMapperPlaceholders(v, state)
		}
		return out
	default:
		return value
	}
}

func buildMapperPlan(state *mapperState, protocol *registryProtocol, dialect string, mapper map[string]any) []mapperRecord {
	var plan []mapperRecord
	for _, inc := range stringSlice(mapper["include"]) {
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
			collectMapperPlan(block, state.reg.sharedOrder[parts[0]], "blocks."+parts[1], &plan)
		}
	}
	collectMapperPlan(mapper, protocol.order, "mappers."+dialect, &plan)
	return plan
}

func sourceList(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}

func orderedKeys(section map[string]any, order []string) []string {
	keys := make([]string, 0, len(section))
	seen := make(map[string]bool, len(section))
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

func collectMapperPlan(section map[string]any, orders map[string][]string, pathName string, plan *[]mapperRecord) {
	for _, key := range orderedKeys(section, orders[pathName]) {
		switch key {
		case "include", "defaults", "detect", "forms", "body_source", "unknown_key", "emit", "overlays", "note", "params", "label":
			continue
		}
		record, ok := section[key].(map[string]any)
		if !ok {
			continue
		}
		if key == "$selector" {
			collectMapperPlan(record, orders, pathName+".$selector", plan)
			continue
		}
		if _, hasSource := record["source"]; !hasSource {
			if _, hasMaps := record["maps_to"]; !hasMaps {
				collectMapperPlan(record, orders, pathName+"."+key, plan)
				continue
			}
		}
		priority := 0
		if value, ok := intValue(record["priority"]).(int64); ok {
			priority = int(value)
		}
		*plan = append(*plan, mapperRecord{path: pathName + "." + key, record: record, priority: priority})
	}
}

func getPath(root map[string]any, pathName string) (any, bool) {
	if root == nil {
		return nil, false
	}
	var current any = root
	for _, part := range strings.Split(strings.TrimPrefix(pathName, "."), ".") {
		if index, err := strconv.Atoi(part); err == nil {
			list, ok := current.([]any)
			if !ok || index < 0 || index >= len(list) {
				return nil, false
			}
			current = list[index]
			continue
		}
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		value, ok := object[part]
		if !ok {
			return nil, false
		}
		current = value
	}
	return current, true
}

func evaluateMapperRecord(state *mapperState, record map[string]any) {
	if !conditionMatches(record["when"], state) {
		return
	}
	source, hasSource := record["source"]
	if !hasSource {
		applyMapperImplies(state, record["implies"])
		return
	}
	onInvalid, _ := record["on_invalid"].(map[string]any)
	invalidSeen := false
	var chosen, rawLast any
	found := false
	for _, candidate := range sourceCandidates(source, state) {
		value, ok := sourceValueOne(candidate, state)
		if !ok {
			continue
		}
		value = decodeMapperExtra(value, record)
		if extraction, ok := record["extract"].(map[string]any); ok && !hasSplitInto(record) {
			var extracted any
			extracted, ok = applyMapperExtract(state, value, extraction)
			if !ok {
				continue
			}
			value = extracted
		}
		rawLast = value
		coerced, valid := coerceMapperValue(value, record, state.reg)
		if valid {
			chosen, found = coerced, true
			break
		}
		invalidSeen = true
		if stringValue(onInvalid["action"]) != "default_from" {
			break
		}
	}
	if !found {
		action := stringValue(onInvalid["action"])
		switch {
		case invalidSeen && action == "drop_node":
			state.dropNode = true
			state.dropReason = stringValue(onInvalid["code"])
			return
		case invalidSeen && action == "keep":
			chosen, found = rawLast, true
		case invalidSeen && action == "coerce":
			chosen, found = onInvalid["value"], true
		case action == "default_from" || !invalidSeen:
			if df := stringValue(record["default_from"]); df != "" {
				if value, ok := getSourcePath(df, *state); ok && !isEmptyScalar(value) {
					chosen, found = value, true
				}
			}
		}
	}
	if !found {
		if materialize, _ := record["materialize_default"].(bool); materialize {
			if value, ok := record["default"]; ok {
				chosen, found = value, true
			} else if defaultWhen, ok := record["default_when"].(map[string]any); ok && conditionMatches(defaultWhen["when"], state) {
				chosen, found = defaultWhen["value"], true
			} else if sets, ok := record["sets"].(map[string]any); ok {
				_, found = sets[""]
				if found {
					chosen = ""
				}
			}
		}
	}
	if !found {
		if required, _ := record["required"].(bool); required {
			state.dropNode = true
			state.dropReason = "field_missing"
		}
		return
	}
	if splitInto, ok := record["split_into"].(map[string]any); ok {
		applyMapperSplitInto(state, chosen, splitInto)
		return
	}
	applyMapperValue(state, record, chosen)
}

func hasSplitInto(record map[string]any) bool {
	_, ok := record["split_into"]
	return ok
}

func sourceCandidates(spec any, state *mapperState) []string {
	if forms, ok := spec.(map[string]any); ok {
		spec = forms[state.input.form]
		if spec == nil {
			spec = forms["*"]
		}
	}
	return sourceList(spec)
}

func sourceValueOne(candidate string, state *mapperState) (any, bool) {
	switch candidate {
	case "userinfo":
		return state.input.user, state.input.user != ""
	case "host":
		return state.input.host, state.input.host != ""
	case "port":
		return state.input.port, state.input.port != nil
	case "port_raw":
		return state.input.portRaw, state.input.portRaw != ""
	case "path":
		return state.input.path, state.input.path != ""
	case "fragment":
		return state.input.frag, state.input.frag != ""
	case "scheme":
		return state.input.scheme, state.input.scheme != ""
	case "$form":
		return state.input.form, state.input.form != ""
	}
	return getSourcePath(candidate, *state)
}

func getSourcePath(pathName string, state mapperState) (any, bool) {
	switch pathName {
	case "host":
		return state.input.host, state.input.host != ""
	case "port":
		return state.input.port, state.input.port != nil
	case "port_raw":
		return state.input.portRaw, state.input.portRaw != ""
	case "path":
		return state.input.path, state.input.path != ""
	case "fragment":
		return state.input.frag, state.input.frag != ""
	case "scheme":
		return state.input.scheme, state.input.scheme != ""
	case "$form":
		return state.input.form, state.input.form != ""
	case "$type":
		return state.entry["type"], state.entry["type"] != nil
	}
	if strings.HasPrefix(pathName, "query.") {
		key := strings.TrimPrefix(pathName, "query.")
		for k, values := range state.input.query {
			if strings.EqualFold(k, key) && len(values) > 0 {
				return values[len(values)-1], true
			}
		}
		return nil, false
	}
	if strings.HasPrefix(pathName, "userinfo.") {
		parts := strings.SplitN(state.input.user, ":", 2)
		switch strings.TrimPrefix(pathName, "userinfo.") {
		case "user":
			return parts[0], len(parts) > 0 && parts[0] != ""
		case "pass":
			return parts[1], len(parts) == 2
		}
		return nil, false
	}
	if strings.HasPrefix(pathName, "json.$base.") {
		return getPath(state.input.base, strings.TrimPrefix(pathName, "json.$base."))
	}
	if strings.HasPrefix(pathName, "json.") {
		return getPath(state.input.root, strings.TrimPrefix(pathName, "json."))
	}
	return getPath(state.entry, pathName)
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

func decodeMapperExtra(value any, record map[string]any) any {
	extra, ok := record["decode_extra"].(map[string]any)
	if !ok {
		return value
	}
	if plus, _ := extra["plus_literal"].(bool); plus {
		return value
	}
	mode := stringValue(extra["mode"])
	if mode != "query" {
		return value
	}
	passes := 1
	if raw := extra["passes"]; raw != nil {
		if number, ok := intValue(raw).(int64); ok {
			passes = int(number)
		}
	}
	text := stringValue(value)
	for i := 1; i < passes; i++ {
		decoded, err := url.PathUnescape(text)
		if err != nil || decoded == text {
			break
		}
		text = decoded
	}
	return text
}

func applyMapperExtract(state *mapperState, value any, extraction map[string]any) (any, bool) {
	pattern := stringValue(extraction["re"])
	if pattern == "" {
		return value, true
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return value, false
	}
	into, _ := extraction["into"].(map[string]any)
	if into == nil {
		return value, true
	}
	if _, keyTarget := into["k"]; keyTarget {
		result := map[string]any{}
		for _, item := range mapperStringList(value) {
			match := re.FindStringSubmatch(item)
			if match == nil {
				continue
			}
			fields := extractFields(re, match)
			key := fields["k"]
			if key == "" {
				continue
			}
			result[key] = fields["v"]
		}
		return result, len(result) > 0
	}
	match := re.FindStringSubmatch(stringValue(value))
	if match == nil {
		return value, false
	}
	fields := extractFields(re, match)
	for name, target := range into {
		groupValue := fields[name]
		switch typed := target.(type) {
		case string:
			if groupValue != "" {
				setPath(state.entry, typed, groupValue)
			}
		case map[string]any:
			pathName := stringValue(typed["path"])
			if prepend := stringValue(typed["prepend_group"]); prepend != "" {
				groupValue = fields[prepend] + groupValue
				if groupValue == "" {
					continue
				}
			}
			var valueToSet any = groupValue
			if list, ok := typed["list"].(map[string]any); ok {
				separator := stringValue(list["sep"])
				items := []any{}
				for _, part := range strings.Split(groupValue, separator) {
					part = strings.TrimSpace(part)
					if part == "" {
						continue
					}
					items = append(items, part)
				}
				valueToSet = items
			}
			if normalize := stringValue(typed["normalize"]); normalize != "" {
				valueToSet = normalizeMapperValue(valueToSet, normalize)
			}
			if typ := stringValue(typed["type"]); typ == "int" {
				if number := intValue(valueToSet); number != nil {
					valueToSet = number
				}
			}
			if pathName != "" {
				setPath(state.entry, pathName, valueToSet)
			}
		}
	}
	return value, true
}

func extractFields(re *regexp.Regexp, match []string) map[string]string {
	fields := map[string]string{}
	for index, name := range re.SubexpNames() {
		if index > 0 && name != "" && index < len(match) {
			fields[name] = match[index]
		}
	}
	return fields
}

func applyMapperSplitInto(state *mapperState, value any, split map[string]any) {
	items := mapperStringList(value)
	for target, ruleRaw := range split {
		rule, _ := ruleRaw.(map[string]any)
		condition, _ := rule["when"].(map[string]any)
		itemRule, _ := condition["item"].(map[string]any)
		selected := ""
		for _, item := range items {
			if itemRule != nil {
				if pattern := stringValue(itemRule["not_matches"]); pattern != "" {
					if re, err := regexp.Compile(pattern); err == nil && re.MatchString(item) {
						continue
					}
				}
				if pattern := stringValue(itemRule["matches"]); pattern != "" {
					if re, err := regexp.Compile(pattern); err == nil && !re.MatchString(item) {
						continue
					}
				}
			}
			selected = item
			break
		}
		if selected != "" {
			setPath(state.entry, target, selected)
		}
	}
}

func applyMapperValue(state *mapperState, record map[string]any, value any) {
	maps, _ := record["maps_to"].(string)
	if maps == "" {
		if on, ok := record["on_present"].(map[string]any); ok {
			state.diags = append(state.diags, Diagnostic{Code: stringValue(on["code"]), Severity: "info", Message: "contract mapper noted an intentionally unmaterialized field"})
		}
		return
	}
	if value == nil {
		deletePath(state.entry, maps)
		return
	}
	if isEmptyScalar(value) {
		sets, hasSets := record["sets"].(map[string]any)
		if hasSets {
			if selected, ok := sets[""].(map[string]any); ok {
				applyMapperSets(state, selected)
				return
			}
		}
		if _, optional := record["default"]; !optional {
			deletePath(state.entry, maps)
			return
		}
	}
	switch stringValue(record["merge"]) {
	case "append":
		if previous, exists := getPath(state.entry, maps); exists {
			value = appendMapperValues(previous, value)
		}
	case "keep_first":
		if _, exists := getPath(state.entry, maps); exists {
			return
		}
	}
	setPath(state.entry, maps, value)
	applyMapperImplies(state, record["implies"])
	if sets, ok := record["sets"].(map[string]any); ok {
		if selected, ok := sets[mapperSetKey(value)].(map[string]any); ok {
			applyMapperSets(state, selected)
		}
	}
}

// mapperSetKey renders a mapped value as the key spelling used by `sets`
// tables: booleans and numbers are spelled the way registry JSON writes them.
func mapperSetKey(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	default:
		return stringValue(value)
	}
}

// isEmptyScalar reports whether a mapped scalar means "not set". Booleans are
// never empty: false is a real value the body must keep.
func isEmptyScalar(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case bool:
		return false
	case []any:
		return len(typed) == 0
	case map[string]any:
		return len(typed) == 0
	default:
		return stringValue(value) == ""
	}
}

func applyMapperImplies(state *mapperState, raw any) {
	implies, ok := raw.(map[string]any)
	if !ok {
		return
	}
	for k, v := range implies {
		if vm, ok := v.(map[string]any); ok {
			if val, ok := vm["value"]; ok {
				setPath(state.entry, k, val)
			}
			continue
		}
		setPath(state.entry, k, v)
	}
}

func applyMapperSets(state *mapperState, selected map[string]any) {
	for k, v := range selected {
		if v == nil {
			deletePath(state.entry, k)
			continue
		}
		setPath(state.entry, k, cloneValue(v))
	}
}

func appendMapperValues(previous, value any) any {
	items := mapperAnyList(previous)
	for _, item := range mapperAnyList(value) {
		items = append(items, item)
	}
	return items
}

func mapperAnyList(value any) []any {
	switch typed := value.(type) {
	case []any:
		return append([]any{}, typed...)
	case nil:
		return nil
	default:
		return []any{typed}
	}
}

func mapperStringList(value any) []string {
	var out []string
	for _, item := range mapperAnyList(value) {
		out = append(out, stringValue(item))
	}
	return out
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

func coerceMapperValue(v any, record map[string]any, reg *registry) (any, bool) {
	if list, ok := record["list"].(map[string]any); ok {
		separator := stringValue(list["sep"])
		items := mapperAnyList(v)
		if separator != "" {
			if text, isString := v.(string); isString {
				items = nil
				for _, part := range strings.Split(text, separator) {
					part = strings.TrimSpace(part)
					if part != "" {
						items = append(items, part)
					}
				}
			}
		}
		if norm := stringValue(record["normalize"]); norm != "" {
			for i, item := range items {
				items[i] = normalizeMapperValue(item, norm)
			}
			if norm == "port_range_spec" {
				flat := []any{}
				for _, item := range items {
					flat = append(flat, mapperAnyList(item)...)
				}
				items = flat
			}
		}
		if itemType := stringValue(list["item"]); itemType == "int" {
			numbers := []any{}
			for _, item := range items {
				number := intValue(item)
				if number == nil {
					continue
				}
				numbers = append(numbers, number)
			}
			items = numbers
		}
		if expected, ok := intValue(list["len"]).(int64); ok && int64(len(items)) != expected {
			return nil, false
		}
		v = items
	} else if norm := stringValue(record["normalize"]); norm != "" {
		v = normalizeMapperValue(v, norm)
	}
	if vm, ok := record["value_map"].(map[string]any); ok {
		if ref, ok := vm["$ref"].(string); ok {
			mapped, ok := resolveValueMapRef(reg, ref, stringValue(v))
			if !ok {
				return nil, false
			}
			v = mapped
		} else if mapped, exists := vm[stringValue(v)]; exists {
			if mapped == nil {
				return nil, false
			}
			v = mapped
		}
	}
	typ := stringValue(record["type"])
	switch typ {
	case "int":
		if number := intValue(v); number != nil {
			v = number
		} else if stringValue(v) != "" {
			return nil, false
		}
	case "duration":
		v = normalizeDuration(v)
	case "bool_spelled":
		v = isTrueSpelled(v)
	}
	if onInvalid, ok := record["on_invalid"].(map[string]any); ok {
		if when, ok := onInvalid["when"].(map[string]any); ok {
			if valueRule, ok := when["value"].(map[string]any); ok {
				text := stringValue(v)
				if pattern := stringValue(valueRule["not_matches"]); pattern != "" {
					if re, err := regexp.Compile(pattern); err == nil && !re.MatchString(text) {
						return nil, false
					}
				}
				if pattern := stringValue(valueRule["matches"]); pattern != "" {
					if re, err := regexp.Compile(pattern); err == nil && !re.MatchString(text) {
						return nil, false
					}
				}
			}
		}
	}
	return v, true
}

func normalizeMapperValue(v any, norm string) any {
	switch norm {
	case "trim":
		return strings.TrimSpace(stringValue(v))
	case "trim_lower":
		return strings.ToLower(strings.TrimSpace(stringValue(v)))
	case "duration", "duration_bare_seconds":
		return normalizeDuration(v)
	case "bandwidth_mbps":
		return normalizeBandwidth(v)
	case "port_range_spec":
		return normalizePortRangeSpec(v)
	case "base64_std":
		return normalizeBase64Std(stringValue(v))
	case "base64_rawurl":
		return strings.TrimRight(stringValue(v), "=")
	case "hex_only":
		return normalizeHexOnly(stringValue(v))
	case "cidr_prefix", "cidr_masked":
		return normalizeCIDR(stringValue(v))
	case "range_order":
		return normalizeRangeOrder(stringValue(v))
	}
	return v
}

func normalizeDuration(v any) any {
	switch typed := v.(type) {
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed != "" && isBareNumber(trimmed) {
			return trimmed + "s"
		}
		return trimmed
	default:
		if isBareNumber(fmt.Sprint(v)) {
			return fmt.Sprint(v) + "s"
		}
		return v
	}
}

func normalizeBandwidth(v any) any {
	text := strings.ToLower(strings.TrimSpace(stringValue(v)))
	if text == "" {
		return v
	}
	re := regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)\s*([a-z/]*)`)
	match := re.FindStringSubmatch(text)
	if match == nil {
		return v
	}
	number, err := strconv.ParseFloat(match[1], 64)
	if err != nil {
		return v
	}
	switch match[2] {
	case "", "m", "mbps", "mbit", "mbit/s", "mb":
	case "g", "gbps", "gbit", "gbit/s", "gb":
		number *= 1000
	case "k", "kbps", "kbit", "kbit/s", "kb":
		number /= 1000
	case "bps", "b", "bit", "bit/s":
		number /= 1000000
	default:
		return v
	}
	return int64(number)
}

func normalizePortRangeSpec(v any) any {
	var items []string
	switch typed := v.(type) {
	case []any:
		for _, item := range typed {
			items = append(items, stringValue(item))
		}
	default:
		items = mapperStringList(v)
	}
	out := []any{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		low, high := item, item
		if i := strings.IndexAny(item, "-:"); i > 0 {
			low, high = strings.TrimSpace(item[:i]), strings.TrimSpace(item[i+1:])
		}
		if !isBareNumber(low) || !isBareNumber(high) {
			continue
		}
		lowNumber, lowErr := strconv.ParseInt(low, 10, 64)
		highNumber, highErr := strconv.ParseInt(high, 10, 64)
		if lowErr != nil || highErr != nil || lowNumber > 65535 || highNumber > 65535 {
			continue
		}
		out = append(out, fmt.Sprintf("%d:%d", lowNumber, highNumber))
	}
	return out
}

func normalizeBase64Std(value string) string {
	decoded, ok := decodeBase64Flexible(value)
	if !ok {
		return value
	}
	return base64.StdEncoding.EncodeToString(decoded)
}

func normalizeHexOnly(value string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(value) {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'f' {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func normalizeCIDR(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}
	if strings.Contains(value, "/") {
		return value
	}
	if strings.Contains(value, ":") {
		return value + "/128"
	}
	return value + "/32"
}

func normalizeRangeOrder(value string) string {
	parts := strings.SplitN(value, "-", 2)
	if len(parts) != 2 {
		return value
	}
	low, lowErr := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	high, highErr := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
	if lowErr != nil || highErr != nil {
		return value
	}
	if low > high {
		low, high = high, low
	}
	return fmt.Sprintf("%d-%d", low, high)
}

func isBareNumber(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isTrueSpelled(v any) bool {
	switch strings.ToLower(strings.TrimSpace(stringValue(v))) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

func resolveValueMapRef(reg *registry, ref, value string) (any, bool) {
	if reg == nil {
		return nil, false
	}
	parts := strings.SplitN(ref, ".", 2)
	if len(parts) != 2 {
		return nil, false
	}
	table := reg.shared[parts[0]]
	if table == nil {
		return nil, false
	}
	var cur any = table
	for _, part := range strings.Split(parts[1], ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	if m, ok := cur.(map[string]any); ok {
		if prefixes, ok := m["prefix"].(map[string]any); ok {
			strip := stringSlice(m["strip"])
			normalized := strings.ToLower(strings.TrimSpace(value))
			for _, char := range strip {
				normalized = strings.ReplaceAll(normalized, char, "")
			}
			best := ""
			for prefix := range prefixes {
				if strings.HasPrefix(normalized, prefix) && len(prefix) > len(best) {
					best = prefix
				}
			}
			if best != "" {
				return prefixes[best], true
			}
			return nil, false
		}
	}
	if list, ok := cur.([]any); ok {
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				if strings.HasPrefix(strings.ToLower(value), strings.ToLower(stringValue(m["prefix"]))) {
					return strings.TrimPrefix(strings.ToLower(value), strings.ToLower(stringValue(m["prefix"]))), true
				}
			}
		}
	}
	return nil, false
}

func containsAny(values []any, got any) bool {
	for _, value := range values {
		if scalarEqual(value, got) {
			return true
		}
	}
	return false
}

// scalarEqual compares two decoded JSON scalars. Registry JSON numbers arrive
// as json.Number, while mapped values are int64 or string, so a plain string
// comparison would silently fail on port and enum lists.
func scalarEqual(left, right any) bool {
	if leftNumber := numberValue(left); leftNumber != nil {
		if rightNumber := numberValue(right); rightNumber != nil {
			return *leftNumber == *rightNumber
		}
		return false
	}
	if leftBool, ok := left.(bool); ok {
		rightBool, rightIsBool := right.(bool)
		return rightIsBool && leftBool == rightBool
	}
	return stringValue(left) == stringValue(right)
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
			if list, ok := cond["in"].([]any); ok && !containsAny(list, got) {
				return false
			}
			if list, ok := cond["not_in"].([]any); ok && containsAny(list, got) {
				return false
			}
			if present, ok := cond["present"].(bool); ok {
				if present != exists {
					return false
				}
			}
			if limit, ok := cond["gt"]; ok {
				left, right := numberValue(got), numberValue(limit)
				if left == nil || right == nil || *left <= *right {
					return false
				}
			}
			if limit, ok := cond["lt"]; ok {
				left, right := numberValue(got), numberValue(limit)
				if left == nil || right == nil || *left >= *right {
					return false
				}
			}
			if pattern := stringValue(cond["matches"]); pattern != "" {
				if re, err := regexp.Compile(pattern); err != nil || !re.MatchString(stringValue(got)) {
					return false
				}
			}
			if pattern := stringValue(cond["not_matches"]); pattern != "" {
				if re, err := regexp.Compile(pattern); err == nil && re.MatchString(stringValue(got)) {
					return false
				}
			}
			continue
		}
		if !exists || !scalarEqual(got, want) {
			return false
		}
	}
	return true
}

func numberValue(v any) *float64 {
	switch typed := v.(type) {
	case int:
		value := float64(typed)
		return &value
	case int64:
		value := float64(typed)
		return &value
	case float64:
		return &typed
	case string:
		if parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64); err == nil {
			return &parsed
		}
	}
	return nil
}
func mapperLabel(section map[string]any, state *mapperState, protocol string) string {
	if label, ok := section["label"].(map[string]any); ok {
		spec := label["source"]
		if forms, ok := spec.(map[string]any); ok {
			spec = forms[state.input.form]
			if spec == nil {
				spec = forms["*"]
			}
		}
		for _, candidate := range sourceList(spec) {
			if v, ok := sourceValueOne(candidate, state); ok {
				if name := normalizeLabel(stringValue(v), label["normalize"]); name != "" {
					return applyLabelValueMap(name, label["value_map"])
				}
			}
		}
		if fallback, ok := label["fallback"].(map[string]any); ok {
			if templ := stringValue(fallback["template"]); templ != "" {
				server := stringValue(state.entry["server"])
				if pathName := stringValue(fallback["server_path"]); pathName != "" {
					if v, ok := getPath(state.entry, strings.ReplaceAll(pathName, "[]", ".0")); ok {
						server = stringValue(v)
					}
				}
				port := ""
				if pathName := stringValue(fallback["port_path"]); pathName != "" {
					if v, ok := getPath(state.entry, strings.ReplaceAll(pathName, "[]", ".0")); ok {
						port = fmt.Sprint(v)
					}
				} else {
					port = fmt.Sprint(state.entry["server_port"])
				}
				schemeName := protocol
				if stringValue(fallback["scheme_source"]) == "as_written" && state.input.scheme != "" {
					schemeName = state.input.scheme
				}
				name := strings.ReplaceAll(templ, "{scheme}", schemeName)
				name = strings.ReplaceAll(name, "{server}", server)
				return strings.ReplaceAll(name, "{server_port}", port)
			}
		}
	}
	return fmt.Sprintf("%s-%s-%v", protocol, stringValue(state.entry["server"]), state.entry["server_port"])
}

func normalizeLabel(value string, raw any) string {
	if value == "" {
		return ""
	}
	text := percentDecode(value)
	for _, rule := range stringSlice(raw) {
		switch rule {
		case "trim":
			text = strings.TrimSpace(text)
		case "strip_control":
			text = strings.Map(func(r rune) rune {
				if r < 0x20 || r == 0x7f {
					return -1
				}
				return r
			}, text)
		}
	}
	return text
}

func applyLabelValueMap(value string, raw any) string {
	m, ok := raw.(map[string]any)
	if !ok {
		return value
	}
	if mapped, exists := m[strings.ToUpper(value)]; exists {
		return stringValue(mapped)
	}
	return value
}

func ptrNode(n Node) *Node { return &n }

// mapContractXray applies the mappers.xray section of a protocol record to an
// Xray outbound object. It returns handled=false when the protocol declares no
// xray dialect, so the caller can fall back to the generic document path.
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
		in := mapperInput{root: cloneMap(raw), query: map[string][]string{}, base: base, form: "xray"}
		state := &mapperState{entry: map[string]any{"type": p.singboxType}, input: in, reg: reg}
		if err := executeMapper(state, p, "xray", xray); err != nil {
			diags = append(diags, Diagnostic{Code: "mapper_error", Severity: "error", Message: err.Error(), Source: source})
			continue
		}
		sanitizeMapperBody(state, p.raw)
		if state.dropNode {
			diags = append(diags, Diagnostic{Code: state.dropReason, Severity: "error", Message: "node body violates the registry contract", Source: source})
			continue
		}
		state.entry["type"] = p.singboxType
		name := firstString(raw, "tag", "remarks", "name")
		if name == "" {
			name = fmt.Sprintf("%s-%s-%v", p.singboxType, stringValue(state.entry["server"]), state.entry["server_port"])
		}
		for i := range state.diags {
			state.diags[i].Source = source
		}
		nodes = append(nodes, makeNode(name, p.singboxType, raw, state.entry, source, "xray"))
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
		trimmed := strings.TrimSuffix(b, ".0")
		if _, ok := getPath(raw, trimmed); ok {
			return expandArrayBase(raw, trimmed)
		}
		if _, ok := getPath(raw, b); ok {
			return []string{b}
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

func requiredMissing(entry, uri map[string]any) bool {
	return requiredMissingInSection(entry, uri)
}

func requiredMissingInSection(entry map[string]any, section map[string]any) bool {
	if required, ok := section["required"].(bool); ok && required {
		if mapsTo, ok := section["maps_to"].(string); ok && mapsTo != "" {
			value, exists := getPath(entry, strings.ReplaceAll(mapsTo, "[]", ".0"))
			if !exists || isEmptyScalar(value) {
				return true
			}
		}
	}
	return false
}

// sanitizeMapperBody applies the value rules declared by body.fields: value
// normalization, enum/format checks, required fields, per-field drop or
// drop_node degradation, nested object rules, and list item filters. The
// registry owns these rules; the executor only carries them out.
func sanitizeMapperBody(state *mapperState, protocol map[string]any) {
	body, _ := protocol["body"].(map[string]any)
	fields, _ := body["fields"].(map[string]any)
	if len(fields) == 0 {
		return
	}
	dropParent := sanitizeMapperFields(state, state.entry, fields, "")
	if dropParent {
		state.dropNode = true
		state.dropReason = "field_missing"
	}
}

// sanitizeMapperFields returns true when the enclosing object has to be
// dropped because a nested required field is absent.
func sanitizeMapperFields(state *mapperState, target map[string]any, fields map[string]any, prefix string) bool {
	for name, raw := range fields {
		field, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		pathName := name
		if prefix != "" {
			pathName = prefix + "." + name
		}
		value, exists := target[name]
		if !exists {
			if required, _ := field["required"].(bool); required {
				if form, ok := field["form"].(map[string]any); ok && stringValue(form["block"]) != "" {
					return true
				}
				if code := stringValue(field["code"]); code != "" {
					state.diags = append(state.diags, Diagnostic{Code: code, Severity: "error", Message: "required field is missing", Path: pathName})
				}
				state.dropNode = true
				state.dropReason = "field_missing"
				continue
			}
			if defaultWhen, ok := field["default_when"].(map[string]any); ok {
				if absent, _ := defaultWhen["absent"].(bool); absent && !hasKindCondition(defaultWhen) {
					target[name] = normalizeIntegral(cloneValue(defaultWhen["value"]))
				}
			}
			continue
		}
		if absentValues, ok := field["absent_values"].([]any); ok && containsAny(absentValues, value) {
			delete(target, name)
			continue
		}
		if norm := stringValue(field["normalize"]); norm != "" {
			value = normalizeMapperValue(value, norm)
		}
		typ := stringValue(field["type"])
		if typ == "int" || typ == "uint16" {
			number := intValue(value)
			if number == nil {
				onInvalid, _ := field["on_invalid"].(map[string]any)
				if handleMapperInvalid(state, target, name, pathName, field, onInvalid, value) {
					continue
				}
				continue
			}
			value = number
		}
		if boolean, isBool := value.(bool); isBool && !boolean && typ == "bool" && name != "enabled" {
			if _, hasDefault := field["default"]; hasDefault {
				delete(target, name)
				continue
			}
		}
		if forbidden, ok := field["forbidden_for"].([]any); ok {
			if containsAny(forbidden, state.entry["type"]) {
				delete(target, name)
				continue
			}
		}
		if advisory, ok := field["advisory"].([]any); ok {
			for _, entry := range advisory {
				rule, _ := entry.(map[string]any)
				values, hasValues := rule["values"].([]any)
				if hasValues && !containsAny(values, value) {
					continue
				}
				if code := stringValue(rule["code"]); code != "" {
					state.diags = append(state.diags, Diagnostic{Code: code, Severity: "info", Message: "registry advisory rule matched", Path: pathName, Value: value})
				}
			}
		}
		if values, ok := field["values"].([]any); ok && stringValue(field["type"]) == "enum" {
			if !containsAny(values, value) {
				onInvalid, _ := field["on_invalid"].(map[string]any)
				if handleMapperInvalid(state, target, name, pathName, field, onInvalid, value) {
					continue
				}
			}
		}
		if pattern := stringValue(field["pattern"]); pattern != "" {
			if re, err := regexp.Compile(pattern); err == nil && !re.MatchString(stringValue(value)) {
				onInvalid, _ := field["on_invalid"].(map[string]any)
				if handleMapperInvalid(state, target, name, pathName, field, onInvalid, value) {
					continue
				}
			}
		}
		if format := stringValue(field["format"]); !mapperFormatValid(format, value) {
			onInvalid, _ := field["on_invalid"].(map[string]any)
			if handleMapperInvalid(state, target, name, pathName, field, onInvalid, value) {
				continue
			}
		}
		if coerceWhen, ok := field["coerce_when"].(map[string]any); ok {
			if coerceValues, ok := coerceWhen["values"].([]any); ok && containsAny(coerceValues, value) {
				if conditionMatches(coerceWhen["when"], state) {
					value = coerceWhen["value"]
					if code := stringValue(coerceWhen["code"]); code != "" {
						state.diags = append(state.diags, Diagnostic{Code: code, Severity: "info", Message: "field value was pinned by the registry rule", Path: pathName})
					}
				}
			}
		}
		if list, ok := field["list"].(map[string]any); ok {
			if separator := stringValue(list["sep"]); separator != "" {
				if text, ok := value.(string); ok {
					items := []any{}
					for _, part := range strings.Split(text, separator) {
						part = strings.TrimSpace(part)
						if part != "" {
							items = append(items, part)
						}
					}
					value = items
				}
			}
		}
		if itemPattern := stringValue(field["item_pattern"]); itemPattern != "" {
			if re, err := regexp.Compile(itemPattern); err == nil {
				switch typed := value.(type) {
				case []any:
					filtered := []any{}
					for _, item := range typed {
						if re.MatchString(stringValue(item)) {
							filtered = append(filtered, item)
						}
					}
					value = filtered
				default:
					if !re.MatchString(stringValue(typed)) {
						onInvalid, _ := field["on_invalid"].(map[string]any)
						if handleMapperInvalid(state, target, name, pathName, field, onInvalid, value) {
							continue
						}
					}
				}
			}
		}
		if minimum := numberValue(field["min"]); minimum != nil {
			if current := numberValue(value); current != nil && *current < *minimum {
				onInvalid, _ := field["on_invalid"].(map[string]any)
				if handleMapperInvalid(state, target, name, pathName, field, onInvalid, value) {
					continue
				}
			}
		}
		if maximum := numberValue(field["max"]); maximum != nil {
			if current := numberValue(value); current != nil && *current > *maximum {
				onInvalid, _ := field["on_invalid"].(map[string]any)
				if handleMapperInvalid(state, target, name, pathName, field, onInvalid, value) {
					continue
				}
			}
		}
		if nested, ok := field["fields"].(map[string]any); ok {
			if object, ok := value.(map[string]any); ok {
				if sanitizeMapperFields(state, object, nested, pathName) {
					delete(target, name)
					continue
				}
				if len(object) == 0 {
					delete(target, name)
					continue
				}
			}
		}
		if absentWhen, ok := field["absent_when"].(map[string]any); ok {
			if object, ok := target[name].(map[string]any); ok {
				drop := len(object) > 0
				for key, expected := range absentWhen {
					current, exists := object[key]
					if !exists || mapperSetKey(current) != mapperSetKey(expected) {
						drop = false
						break
					}
				}
				if drop {
					delete(target, name)
					continue
				}
			}
		}
		if ref := stringValue(field["ref"]); ref == "tls" {
			if object, ok := value.(map[string]any); ok {
				sanitizeSharedMapperBlock(state, object, "tls", pathName)
				if len(object) == 0 {
					delete(target, name)
					continue
				}
			}
		}
		if items, ok := field["items"].(map[string]any); ok {
			if list, ok := value.([]any); ok {
				itemFields, _ := items["fields"].(map[string]any)
				cleaned := make([]any, 0, len(list))
				for _, item := range list {
					if itemFields != nil {
						if object, ok := item.(map[string]any); ok {
							if sanitizeMapperFields(state, object, itemFields, pathName) {
								continue
							}
							if len(object) == 0 {
								continue
							}
						}
					}
					cleaned = append(cleaned, item)
				}
				value = cleaned
			}
		}
		if conflicts, ok := field["conflicts"].([]any); ok {
			for _, entry := range conflicts {
				rule, _ := entry.(map[string]any)
				other := stringValue(rule["with"])
				if other == "" {
					continue
				}
				if unlessSet, ok := rule["unless_set"].([]any); ok && len(unlessSet) > 0 {
					skip := false
					for _, pathName := range stringSlice(unlessSet) {
						if present, _ := getPath(state.entry, pathName); !isEmptyScalar(present) {
							skip = true
							break
						}
					}
					if skip {
						continue
					}
				}
				if present, _ := getPath(state.entry, other); !isEmptyScalar(present) {
					delete(target, name)
					if code := stringValue(rule["code"]); code != "" {
						state.diags = append(state.diags, Diagnostic{Code: code, Severity: "info", Message: "field conflicts with another body field", Path: pathName, Value: other})
					}
					break
				}
			}
		}
		if requires, ok := field["requires"].([]any); ok {
			for _, rule := range requires {
				requirement, _ := rule.(map[string]any)
				requiredPath := stringValue(requirement["path"])
				if requiredPath == "" {
					continue
				}
				present, _ := getPath(state.entry, requiredPath)
				equals := stringValue(requirement["equals"])
				if equals != "" && mapperSetKey(present) != equals {
					deletePath(state.entry, pathName)
					break
				}
				if equals == "" && isEmptyScalar(present) {
					deletePath(state.entry, pathName)
					break
				}
			}
			if _, stillThere := getPath(state.entry, pathName); !stillThere {
				continue
			}
		}
		setPath(state.entry, pathName, value)
	}
	return false
}

func hasKindCondition(defaultWhen map[string]any) bool {
	when, ok := defaultWhen["when"].(map[string]any)
	if !ok {
		return false
	}
	_, hasKind := when["source_kind"]
	return hasKind
}
func handleMapperInvalid(state *mapperState, target map[string]any, name, pathName string, field, onInvalid map[string]any, value any) bool {
	action := stringValue(onInvalid["action"])
	code := stringValue(onInvalid["code"])
	if code == "" {
		code = "type_invalid"
	}
	switch action {
	case "drop_node":
		state.dropNode = true
		state.dropReason = code
		state.diags = append(state.diags, Diagnostic{Code: code, Severity: "error", Message: "field value is not usable", Path: pathName, Value: value})
		return true
	case "drop":
		delete(target, name)
		state.diags = append(state.diags, Diagnostic{Code: code, Severity: "warning", Message: "field value was dropped", Path: pathName, Value: value})
		return true
	case "coerce":
		target[name] = onInvalid["value"]
		state.diags = append(state.diags, Diagnostic{Code: code, Severity: "warning", Message: "field value was coerced", Path: pathName, Value: value})
		return true
	case "unwrap":
		if object, ok := value.(map[string]any); ok {
			key := stringValue(onInvalid["key"])
			if nested := stringValue(object[key]); nested != "" {
				target[name] = nested
				return true
			}
		}
		delete(target, name)
		return true
	case "keep", "":
		return false
	}
	return false
}

func mapperFormatValid(format string, value any) bool {
	text := stringValue(value)
	switch format {
	case "base64", "base64_32":
		decoded, ok := decodeBase64Flexible(text)
		if !ok {
			return false
		}
		if format == "base64_32" {
			return len(decoded) == 32
		}
		return true
	case "uuid":
		return regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`).MatchString(text)
	case "host":
		return text != ""
	case "cidr":
		return true
	}
	return true
}

// sanitizeSharedMapperBlock applies the body.field rules of a registry shared
// block (tls, dialer, multiplex) to a nested object, honouring absent_when.
func sanitizeSharedMapperBlock(state *mapperState, object map[string]any, blockName, pathName string) {
	shared := state.reg.shared[blockName]
	if shared == nil {
		return
	}
	body, _ := shared["body"].(map[string]any)
	if body == nil {
		return
	}
	if enabled, ok := object["enabled"].(bool); ok && !enabled {
		absentWhen, _ := body["absent_when"].(map[string]any)
		if raw, exists := absentWhen["enabled"]; exists {
			if expected, ok := raw.(bool); ok && expected == false {
				for key := range object {
					delete(object, key)
				}
				return
			}
		}
	}
	fields, _ := body["fields"].(map[string]any)
	if len(fields) == 0 {
		return
	}
	sanitizeMapperFields(state, object, fields, pathName)
}

func normalizeIntegral(v any) any {
	switch typed := v.(type) {
	case float64:
		if typed == float64(int64(typed)) {
			return int64(typed)
		}
		return typed
	case map[string]any:
		out := map[string]any{}
		for k, value := range typed {
			out[k] = normalizeIntegral(value)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, value := range typed {
			out[i] = normalizeIntegral(value)
		}
		return out
	default:
		return v
	}
}
