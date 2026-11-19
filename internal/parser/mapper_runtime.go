package parser

// This file is the data-driven contract executor. It intentionally has no
// protocol switch: protocol-specific behavior comes from mappers.* records,
// their includes, and shared registry blocks.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type mapperInput struct {
	root      map[string]any
	query     map[string][]string
	queryText map[string][]string
	scheme    string
	host      string
	port      any
	portRaw   string
	path      string
	frag      string
	user      string
	base      map[string]any
	overlays  map[string]map[string]any
	form      string
}

type mapperState struct {
	entry      map[string]any
	input      mapperInput
	diags      []Diagnostic
	reg        *registry
	dropNode   bool
	dropReason string
	// Defaults, implications and selector sets do not claim a destination
	// against later explicit writes (e.g. port, fingerprint or WS header).
	written   map[string]bool
	fallbacks []map[string]any
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
	key      string
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
		if decoded == nil {
			return nil, []Diagnostic{diag("field_missing", "error", "encoded WireGuard configuration is not an INI document", source)}, true
		}
		node, ds := mapWireGuardINI(stringValue(decoded), source, reg, parsed.frag, "", map[string]any{"uri": rawURI}, "uri")
		return node, ds, true
	}
	in := mapperInput{root: map[string]any{}, query: queryFold(parsed.queryRaw, true), queryText: queryFold(parsed.queryRaw, false), scheme: strings.ToLower(parsed.scheme), host: parsed.host, portRaw: parsed.portRaw, path: parsed.path, frag: parsed.frag, form: form}
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
		if p.singboxType == "wireguard" {
			// A base64 credential is URL userinfo, not a form value.
			in.user = percentDecodeExceptPlus(parsed.user)
		} else {
			in.user = decodeMapperUserinfo(parsed.user, uri)
		}
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
	if !state.dropNode && requiredMissing(state.entry, uri) {
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
	limit := p.userLimit
	if limit <= 0 {
		limit = len(p.userInto)
	}
	parts := strings.SplitN(user, p.userSep, limit)
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
		if form["id"] == "conf_b64" {
			// The fragment labels the config; it is not part of the encoded document.
			payload, _, _ := strings.Cut(body, "#")
			return mapperDetectRule(detect, payload, payload)
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
		payload, _, _ := strings.Cut(body, "#")
		decoded, ok := decodeBase64Flexible(strings.TrimSpace(payload))
		parsed := mapperURL{scheme: scheme, frag: mapperFragment(rawURI)}
		if !ok || !isWGIni(string(decoded)) {
			return chosen, parsed, nil
		}
		return chosen, parsed, string(decoded)
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
	if at := strings.LastIndexByte(body, '@'); at >= 0 {
		out.user = body[:at]
		body = body[at+1:]
	}
	if out.scheme == "masque" || out.scheme == "wireguard" || out.scheme == "awg" || out.scheme == "amneziawg" {
		if i := strings.LastIndexByte(body, '/'); i >= 0 && strings.Contains(body[i:], ":") {
			// A raw base64 userinfo may contain '/'; only treat a slash after
			// authority as a path when it follows the host/port portion.
			out.host, out.portRaw = splitMapperHostPort(body)
			return out
		}
	}
	if i := strings.IndexByte(body, '/'); i >= 0 {
		out.path = body[i:]
		body = body[:i]
	}
	out.host, out.portRaw = splitMapperHostPort(body)
	return out
}

// Keep the common interface and each peer's independent source fields. INI
// values are text: only the mapper record decides which numbers to coerce.
func mapperINIValues(text string, commentRule map[string]any) (iface map[string]any, peers []map[string]any, comment string) {
	var current map[string]any
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			if current != nil && len(peers) == 1 && len(current) == 0 && comment == "" {
				name := strings.TrimSpace(line[1:])
				if reject := stringValue(commentRule["require_no"]); reject == "" || !strings.Contains(name, reject) {
					comment = name
				}
			}
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			current = map[string]any{}
			switch {
			case section == "interface":
				if iface != nil {
					return // Only the first interface belongs to this endpoint.
				}
				iface = current
			case section == "peer" || strings.HasPrefix(section, "peer "):
				peers = append(peers, current)
			default:
				current = nil
			}
			continue
		}
		if key, value, ok := strings.Cut(line, "="); ok && current != nil {
			current[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
		}
	}
	return
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

func percentDecodeExceptPlus(value string) string {
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return value
	}
	return decoded
}

func decodeMapperUserinfo(user string, uri map[string]any) string {
	info, _ := uri["userinfo"].(map[string]any)
	if info == nil {
		return percentDecode(user)
	}
	plusLiteral, _ := fieldMap(info, "decode_extra")["plus_literal"].(bool)
	value := user
	if plusLiteral {
		value = percentDecodeExceptPlus(value)
	} else {
		value = percentDecode(value)
	}
	if info == nil {
		return value
	}
	decoders := stringSlice(info["decode"])
	requiresSep := stringValue(info["decode_requires_separator"])
	for _, decoder := range decoders {
		switch decoder {
		case "percent":
			value = percentDecode(value)
		case "base64?":
			if requiresSep != "" && strings.Contains(value, requiresSep) {
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
	applyMapperOverlays(state, mapper)
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
			if k == "version" {
				setPath(state.entry, k, cloneValue(v))
				continue
			}
			setPath(state.entry, k, resolveMapperPlaceholders(normalizeIntegral(cloneValue(v)), state))
		}
	}
	plan := buildMapperPlan(state, protocol, dialect, mapper)
	state.written = make(map[string]bool)
	for i := range plan {
		record := plan[i].record
		if record["materialize_default"] == true && record["default"] == nil && record["default_when"] == nil {
			if _, hasSets := record["sets"]; hasSets {
				continue
			}
			if field, ok := getPath(protocol.raw, "body.fields."+stringValue(record["maps_to"])); ok {
				if field, ok := field.(map[string]any); ok {
					if value, exists := field["default"]; exists {
						record = cloneMap(record)
						record["default"] = value
						plan[i].record = record
					}
				}
			}
		}
	}
	sort.SliceStable(plan, func(i, j int) bool { return plan[i].priority < plan[j].priority })
	for pass := 0; pass < 2; pass++ {
		for _, item := range plan {
			if _, multiport := item.record["_multiport_key"]; multiport && (state.input.portRaw == "" || !strings.ContainsAny(state.input.portRaw, ",-:")) {
				continue
			}
			selector, _ := item.record["selector"].(bool)
			if (pass == 0) != selector {
				continue
			}
			evaluateMapperRecord(state, item.record)
		}
	}
	// default_from reads the finished body. It must not claim a path before
	// another record has had a chance to supply an explicit value.
	for _, record := range state.fallbacks {
		if _, exists := getPath(state.entry, stringValue(record["maps_to"])); exists || !conditionMatches(record["when"], state) {
			continue
		}
		if value, ok := getSourcePath(stringValue(record["default_from"]), *state); ok && !isEmptyScalar(value) {
			applyMapperValue(state, record, value)
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
			collectMapperPlan(block, state.reg.sharedOrder[parts[0]], "blocks."+parts[1], false, &plan)
		}
	}
	var local []mapperRecord
	collectMapperPlan(mapper, protocol.order, "mappers."+dialect, false, &local)
	// A protocol can narrow an included record to specific forms. Compare
	// all declared source names, not just the source for the current form:
	// a legacy-only override must suppress the generic selector on v2rayN.
	overrides := map[string]map[string]bool{}
	for _, item := range local {
		if item.record["merge"] == "overwrite" {
			// A guarded overwrite refines the preceding rule when it fires.
			continue
		}
		if overrides[item.key] == nil {
			overrides[item.key] = map[string]bool{}
		}
		overrides[item.key][mapperSourceSet(item.record["source"])] = true
	}
	included := plan[:0]
	for _, item := range plan {
		if !overrides[item.key][mapperSourceSet(item.record["source"])] {
			included = append(included, item)
		}
	}
	return append(included, local...)
}

func mapperSourceSet(spec any) string {
	names := map[string]bool{}
	if forms, ok := spec.(map[string]any); ok {
		for _, sources := range forms {
			for _, name := range sourceList(sources) {
				names[name] = true
			}
		}
	} else {
		for _, name := range sourceList(spec) {
			names[name] = true
		}
	}
	keys := make([]string, 0, len(names))
	for name := range names {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	return strings.Join(keys, "\x00")
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

func collectMapperPlan(section map[string]any, orders map[string][]string, pathName string, selectorContext bool, plan *[]mapperRecord) {
	for _, key := range orderedKeys(section, orders[pathName]) {
		switch key {
		case "include", "defaults", "detect", "forms", "body_source", "unknown_key", "emit", "overlays", "note", "label", "scheme_sets", "userinfo":
			continue
		case "params":
			if params, ok := section[key].(map[string]any); ok {
				collectMapperPlan(params, orders, pathName+".params", selectorContext, plan)
			}
			continue
		case "$selector":
			if selector, ok := section[key].(map[string]any); ok {
				collectMapperPlan(selector, orders, pathName+".$selector", true, plan)
			}
			continue
		}
		record, ok := section[key].(map[string]any)
		if !ok {
			continue
		}
		if _, hasSource := record["source"]; !hasSource {
			if _, hasMaps := record["maps_to"]; !hasMaps {
				if _, hasImplies := record["implies"]; !hasImplies {
					collectMapperPlan(record, orders, pathName+"."+key, selectorContext, plan)
					continue
				}
			}
		}
		if key == "$multiport" {
			record = cloneMap(record)
			record["_multiport_key"] = true
		}
		if selectorContext {
			record = cloneMap(record)
			record["selector"] = true
		}
		priority := 0
		if value, ok := intValue(record["priority"]).(int64); ok {
			priority = int(value)
		}
		*plan = append(*plan, mapperRecord{path: pathName + "." + key, key: key, record: record, priority: priority})
	}
}

func getPath(root map[string]any, pathName string) (any, bool) {
	if root == nil {
		return nil, false
	}
	var current any = root
	for _, rawPart := range strings.Split(strings.TrimPrefix(pathName, "."), ".") {
		part := strings.TrimSuffix(rawPart, "[]")
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
		if strings.HasSuffix(rawPart, "[]") {
			list, ok := current.([]any)
			if !ok || len(list) == 0 {
				return nil, false
			}
			current = list[0]
		}
	}
	return current, true
}

func setMapperPath(root map[string]any, pathName string, value any) {
	parts := strings.Split(pathName, ".")
	current := root
	for index, rawPart := range parts {
		last := index == len(parts)-1
		isList := strings.HasSuffix(rawPart, "[]")
		key := strings.TrimSuffix(rawPart, "[]")
		if last {
			if isList {
				current[key] = append(mapperAnyList(current[key]), value)
			} else {
				current[key] = value
			}
			return
		}
		if isList {
			list, _ := current[key].([]any)
			if len(list) == 0 {
				list = []any{map[string]any{}}
				current[key] = list
			}
			next, _ := list[0].(map[string]any)
			if next == nil {
				next = map[string]any{}
				list[0] = next
			}
			current = next
			continue
		}
		next, _ := current[key].(map[string]any)
		if next == nil {
			next = map[string]any{}
			current[key] = next
		}
		current = next
	}
}

// applyMapperOverlays builds the extra.* source namespace declared by a mapper
// section. A broken or absent overlay is ignored so the flat query/JSON fields
// keep working; only records that explicitly name extra.* read from it.
func applyMapperOverlays(state *mapperState, mapper map[string]any) {
	overlays, ok := mapper["overlays"].([]any)
	if !ok || len(overlays) == 0 {
		return
	}
	if state.input.overlays == nil {
		state.input.overlays = map[string]map[string]any{}
	}
	for _, raw := range overlays {
		spec, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name := stringValue(spec["name"])
		if name == "" {
			continue
		}
		decodes := stringSlice(spec["decode"])
		var parsed map[string]any
		for _, candidate := range sourceList(spec["source"]) {
			value, found := sourceValueOne(candidate, state)
			if !found || value == nil {
				continue
			}
			switch typed := value.(type) {
			case map[string]any:
				parsed = cloneMap(typed)
			case string:
				// queryFold already unescaped the outer URI. Only peel another
				// layer if this isn't JSON yet; keep literal '+' and '%' in JSON.
				text := typed
				if !json.Valid([]byte(text)) {
					for _, mode := range decodes {
						if mode == "percent" {
							text = percentDecodeExceptPlus(text)
						}
					}
				}
				if !json.Valid([]byte(text)) || decodeJSONInto([]byte(text), &parsed) != nil {
					parsed = nil
				}
			}
			if parsed != nil {
				break
			}
		}
		if parsed == nil {
			continue
		}
		for _, flat := range stringSlice(spec["flatten"]) {
			if nested, ok := parsed[flat].(map[string]any); ok {
				delete(parsed, flat)
				for key, value := range nested {
					parsed[key] = value
				}
			}
		}
		normalizeOverlayNumbers(parsed)
		state.input.overlays[name] = parsed
	}
}

// normalizeOverlayNumbers converts decoded JSON numbers to their canonical
// decimal spelling so string-valued registry fields can read extra.* sources.
func normalizeOverlayNumbers(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			typed[key] = normalizeOverlayNumbers(item)
		}
	case []any:
		for i, item := range typed {
			typed[i] = normalizeOverlayNumbers(item)
		}
	case json.Number:
		text := typed.String()
		if parsed, err := strconv.ParseFloat(text, 64); err == nil && parsed == float64(int64(parsed)) {
			return strconv.FormatInt(int64(parsed), 10)
		}
		return text
	}
	return value
}

func evaluateMapperRecord(state *mapperState, record map[string]any) {
	if !conditionMatches(record["when"], state) {
		return
	}
	source, hasSource := record["source"]
	if !hasSource {
		if _, hasMaps := record["maps_to"]; !hasMaps {
			if _, hasSets := record["sets"]; !hasSets {
				applyMapperImplies(state, record["implies"])
				return
			}
		}
		if _, hasSets := record["sets"]; hasSets {
			applyMapperValue(state, record, "")
		}
		return
	}
	if sourceText, ok := source.(string); ok && sourceText == "scheme" {
		if mapsTo := stringValue(record["maps_to"]); mapsTo != "" {
			if _, exists := getPath(state.entry, mapsTo); exists {
				return
			}
		}
	}
	onInvalid, _ := record["on_invalid"].(map[string]any)
	invalidSeen := false
	var chosen, chosenSource, rawLast any
	found := false
	for _, candidate := range sourceCandidates(source, state, record) {
		value, ok := sourceValueOne(candidate, state)
		if !ok {
			continue
		}
		if strings.HasPrefix(candidate, "query.") {
			extra := fieldMap(record, "decode_extra")
			if extra["plus_literal"] != true && extra["mode"] != "path" && !strings.HasPrefix(stringValue(record["format"]), "base64") {
				key := strings.ToLower(strings.TrimPrefix(candidate, "query."))
				if values := state.input.queryText[key]; len(values) > 0 {
					value = values[len(values)-1]
				}
			}
		}
		if isEmptyScalar(value) && record["default_from"] != nil {
			continue // An empty name does not hide the next source or fallback.
		}
		value = decodeMapperExtra(value, record)
		if !conditionMatchesValue(record["when"], state, value) {
			continue
		}
		if mapperInvalidWhen(record, value, state) {
			invalidSeen = true
			if stringValue(onInvalid["action"]) == "default_from" {
				continue
			}
		}
		if extraction, ok := record["extract"].(map[string]any); ok && !hasSplitInto(record) {
			var extracted any
			if stringValue(record["type"]) == "object" && record["list"] != nil {
				extracted = extractMapperPairList(value, record, state)
			} else {
				var extractionOK bool
				extracted, extractionOK = applyMapperExtract(state, value, extraction, fieldMap(record, "on_no_match"))
				if !extractionOK {
					continue
				}
			}
			value = extracted
		}
		rawLast = value
		coerced, valid := coerceMapperValue(value, record, state.reg)
		if !valid {
			invalidSeen = true
		}
		if valid && mapperRecordValueInvalid(record, coerced) {
			valid = false
			invalidSeen = true
			if stringValue(onInvalid["action"]) == "drop_node" {
				state.dropNode = true
				state.dropReason = stringValue(onInvalid["code"])
				return
			}
		}
		if valid {
			chosen, chosenSource, found = coerced, value, true
			break
		}
		if stringValue(onInvalid["action"]) != "default_from" {
			break
		}
	}
	if !found {
		action := stringValue(onInvalid["action"])
		switch {
		case invalidSeen && (action == "drop_node" || (action == "drop" && record["selector"] == true)):
			state.dropNode = true
			state.dropReason = stringValue(onInvalid["code"])
			return
		case invalidSeen && action == "keep":
			chosen, found = rawLast, true
		case invalidSeen && action == "coerce":
			chosen, found = onInvalid["value"], true
		case action == "default_from" || !invalidSeen:
			if stringValue(record["default_from"]) != "" {
				state.fallbacks = append(state.fallbacks, record)
				return
			}
		}
	}
	if !found && record["materialize_default"] == true {
		var defaultValue any
		hasDefault := false
		if value, ok := record["default"]; ok {
			defaultValue, hasDefault = value, true
		} else if defaultWhen, ok := record["default_when"].(map[string]any); ok && defaultWhen["absent"] == true && conditionMatches(defaultWhen["when"], state) {
			defaultValue, hasDefault = defaultWhen["value"], true
		} else if sets, ok := record["sets"].(map[string]any); ok {
			defaultValue, hasDefault = sets[""]
		}
		if hasDefault {
			if _, fromSets := record["sets"].(map[string]any); fromSets && record["default"] == nil && record["default_when"] == nil {
				chosen, chosenSource, found = "", nil, true
			} else if mapped, ok := coerceMapperValue(defaultValue, record, state.reg); ok {
				chosen, chosenSource, found = mapped, nil, true
			}
		}
	}

	if !found {
		if selector, _ := record["selector"].(bool); selector {
			if sets, ok := record["sets"].(map[string]any); ok {
				if _, exists := sets[""]; exists {
					applyMapperValue(state, record, "")
					return
				}
			}
		}
		if required, _ := record["required"].(bool); required {
			state.dropNode = true
			state.dropReason = "field_missing"
		}
		return
	}
	if chosen == nil {
		return // An explicit null in value_map is a valid no-write.
	}
	if omit, exists := record["omit_default"]; exists && scalarEqual(chosen, omit) {
		return
	}
	if splitInto, ok := record["split_into"].(map[string]any); ok {
		applyMapperSplitInto(state, chosen, splitInto)
		return
	}
	applyMapperValue(state, record, chosen, chosenSource)
}

func mapperInvalidWhen(record map[string]any, value any, state *mapperState) bool {
	onInvalid, _ := record["on_invalid"].(map[string]any)
	when, _ := onInvalid["when"].(map[string]any)
	rule, _ := when["value"].(map[string]any)
	if pattern := stringValue(rule["not_matches"]); pattern != "" {
		re, err := regexp.Compile(pattern)
		return err == nil && !re.MatchString(stringValue(value))
	}
	if pattern := stringValue(rule["matches"]); pattern != "" {
		re, err := regexp.Compile(pattern)
		return err == nil && re.MatchString(stringValue(value))
	}
	return false
}

func mapperRecordValueInvalid(record map[string]any, value any) bool {
	if values, ok := record["values"].([]any); ok && !containsAny(values, value) {
		return true
	}
	if pattern := stringValue(record["pattern"]); pattern != "" {
		if re, err := regexp.Compile(pattern); err == nil && !re.MatchString(stringValue(value)) {
			return true
		}
	}
	return false
}
func hasSplitInto(record map[string]any) bool {
	_, ok := record["split_into"]
	return ok
}

func sourceCandidates(spec any, state *mapperState, record map[string]any) []string {
	if forms, ok := spec.(map[string]any); ok {
		spec = forms[state.input.form]
		if spec == nil {
			spec = forms["*"]
		}
	}
	out := sourceList(spec)
	for _, alias := range stringSlice(record["aliases"]) {
		for _, source := range append([]string(nil), out...) {
			if strings.HasPrefix(source, "query.") {
				out = append(out, "query."+alias)
			}
		}
	}
	return out
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
		if state.input.form == "v2rayn" {
			for k, value := range state.input.root {
				if strings.EqualFold(k, key) && value != nil {
					return value, true
				}
			}
		}
		return nil, false
	}
	if strings.HasPrefix(pathName, "userinfo.") {
		parts := strings.SplitN(state.input.user, ":", 2)
		switch strings.TrimPrefix(pathName, "userinfo.") {
		case "user":
			if state.entry["type"] == "naive" && len(parts) == 1 {
				return nil, false
			}
			return parts[0], len(parts) > 0 && parts[0] != ""
		case "pass":
			if state.entry["type"] == "naive" && len(parts) == 1 {
				return state.input.user, state.input.user != ""
			}
			if len(parts) == 2 {
				return parts[1], true
			}
		}
		return nil, false
	}
	if name, nested, ok := strings.Cut(pathName, "."); ok {
		if overlay, exists := state.input.overlays[name]; exists {
			value, found := getPathFold(overlay, nested)
			return value, found && value != nil
		}
	}
	if strings.HasPrefix(pathName, "ini.") {
		return getPathFold(state.input.root, strings.TrimPrefix(pathName, "ini."))
	}
	if strings.HasPrefix(pathName, "json.$base.") {
		return getPathFold(state.input.base, strings.TrimPrefix(pathName, "json.$base."))
	}
	if strings.HasPrefix(pathName, "json.") {
		return getPathFold(state.input.root, strings.TrimPrefix(pathName, "json."))
	}
	return getPathFold(state.entry, pathName)
}

func getPathFold(root map[string]any, pathName string) (any, bool) {
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
		matched := false
		for key, value := range object {
			if strings.EqualFold(key, part) {
				current = value
				matched = true
				break
			}
		}
		if !matched {
			return nil, false
		}
	}
	return current, true
}

// Decode both views from the raw query so an escaped %2B stays distinct from '+'.
func queryFold(raw string, plusLiteral bool) map[string][]string {
	decode := url.QueryUnescape
	if plusLiteral {
		decode = url.PathUnescape
	}
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
		v, err := decode(value)
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
	if mode != "query" && mode != "path" {
		return value
	}
	passes := 1
	if raw := extra["passes"]; raw != nil {
		if stringValue(raw) == "until_stable" {
			passes = 16
		} else if number, ok := intValue(raw).(int64); ok {
			passes = int(number)
		}
	}
	text := stringValue(value)
	for i := 0; i < passes; i++ {
		decoded, err := url.PathUnescape(text)
		if err != nil || decoded == text {
			break
		}
		text = decoded
	}
	return text
}

func extractMapperPairList(value any, record map[string]any, state *mapperState) map[string]any {
	items := mapperAnyList(value)
	list, _ := record["list"].(map[string]any)
	separator := stringValue(list["sep"])
	if separator != "" {
		if text, ok := value.(string); ok {
			items = nil
			for _, line := range strings.Split(text, separator) {
				if strings.TrimSpace(line) != "" {
					items = append(items, strings.TrimSpace(line))
				}
			}
		}
	}
	extraction, _ := record["extract"].(map[string]any)
	pattern := stringValue(extraction["re"])
	re, err := regexp.Compile(pattern)
	result := map[string]any{}
	invalidCount := 0
	if err != nil {
		return result
	}
	into, _ := extraction["into"].(map[string]any)
	keyName, valueName := stringValue(into["k"]), stringValue(into["v"])
	for _, item := range items {
		match := re.FindStringSubmatch(stringValue(item))
		if match == nil {
			invalidCount++
			continue
		}
		groups := extractFields(re, match)
		key := groups[keyName]
		if key == "" && keyName == "$key" {
			key = groups["k"]
		}
		itemValue := groups[valueName]
		if itemValue == "" && valueName == "$value" {
			itemValue = groups["v"]
		}
		if key == "" {
			invalidCount++
			continue
		}
		result[key] = itemValue
	}
	if invalidCount > 0 {
		if onItemInvalid, ok := record["on_item_invalid"].(map[string]any); ok {
			if stringValue(onItemInvalid["action"]) == "skip" {
				state.diags = append(state.diags, Diagnostic{Code: stringValue(onItemInvalid["code"]), Severity: "warning", Message: "invalid mapper item was skipped"})
			}
		}
	}
	if sortKeys, _ := record["sort_keys"].(bool); sortKeys {
		keys := make([]string, 0, len(result))
		for key := range result {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		ordered := make(map[string]any, len(result))
		for _, key := range keys {
			ordered[key] = result[key]
		}
		return ordered
	}
	return result
}

func applyMapperExtract(state *mapperState, value any, extraction, fallback map[string]any) (any, bool) {
	if object, ok := value.(map[string]any); ok {
		return object, true
	}
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
	if parsed, ok := value.(map[string]any); ok && stringValue(extraction["re"]) == "" {
		return parsed, true
	}
	match := re.FindStringSubmatch(stringValue(value))
	if match == nil {
		if fallback["action"] == "take_all" && stringValue(fallback["into"]) != "" && !isEmptyScalar(value) {
			setMapperPath(state.entry, stringValue(fallback["into"]), value)
			for path, v := range fieldMap(fallback, "defaults") {
				setMapperPath(state.entry, path, normalizeIntegral(v))
			}
			return value, true
		}
		return value, false
	}
	fields := extractFields(re, match)
	for name, target := range into {
		groupValue, exists := fields[name]
		if !exists {
			continue
		}
		switch typed := target.(type) {
		case string:
			if groupValue != "" && !state.written[typed] {
				setPath(state.entry, typed, groupValue)
				state.written[typed] = true
			}
		case map[string]any:
			if groupValue == "" {
				continue
			}
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
				if state.written[pathName] {
					continue
				}
				setMapperPath(state.entry, pathName, valueToSet)
				state.written[pathName] = true
			}
			applyMapperImplies(state, typed["implies"])
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
			setMapperPath(state.entry, target, selected)
		}
	}
}

func applyMapperValue(state *mapperState, record map[string]any, value any, source ...any) {
	sets, _ := record["sets"].(map[string]any)
	selected, _ := sets[mapperSetKey(value)].(map[string]any)
	if len(source) != 0 && source[0] != nil {
		raw := source[0]
		if norm := stringValue(record["normalize"]); norm != "" {
			raw = normalizeMapperValue(raw, norm)
		}
		if branch, ok := sets[mapperSetKey(raw)].(map[string]any); ok {
			selected = branch // e.g. h2 selects TLS before mapping to http.
		}
	}
	maps, _ := record["maps_to"].(string)
	if maps == "private_key_path" || maps == "client_version" {
		return
	}
	if maps == "" {
		if on, ok := record["on_present"].(map[string]any); ok {
			state.diags = append(state.diags, Diagnostic{Code: stringValue(on["code"]), Severity: "info", Message: "contract mapper noted an intentionally unmaterialized field"})
		}
		applyMapperSets(state, selected)
		return
	}
	if value == nil {
		return
	}
	if isEmptyScalar(value) {
		if selected != nil {
			applyMapperSets(state, selected)
			return
		}
		if _, optional := record["default"]; !optional {
			return // No write; only sets with a null target remove an existing path.
		}
	}
	switch stringValue(record["merge"]) {
	case "append":
		if previous, exists := getPath(state.entry, maps); exists {
			value = appendMapperValues(previous, value)
		}
	case "overwrite":
		// Explicit override of a prior mapped value.
	default: // keep_first
		if state.written[maps] {
			return
		}
	}
	setMapperPath(state.entry, maps, value)
	state.written[maps] = true

	applyMapperImplies(state, record["implies"])
	applyMapperSets(state, selected)
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
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
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
				setMapperPath(state.entry, k, val)
			}
			continue
		}
		setMapperPath(state.entry, k, v)
	}
}

func applyMapperSets(state *mapperState, selected map[string]any) {
	for k, v := range selected {
		if v == nil {
			deletePath(state.entry, k)
			continue
		}
		setMapperPath(state.entry, k, cloneValue(v))
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
	current := dst
	for index, rawPart := range parts {
		last := index == len(parts)-1
		isList := strings.HasSuffix(rawPart, "[]")
		name := strings.TrimSuffix(rawPart, "[]")
		if last {
			if isList {
				delete(current, name)
			} else {
				delete(current, name)
			}
			return
		}
		value, exists := current[name]
		if !exists {
			return
		}
		if isList {
			items, ok := value.([]any)
			if !ok || len(items) == 0 {
				return
			}
			next, _ := items[0].(map[string]any)
			if next == nil {
				return
			}
			current = next
			continue
		}
		next, ok := value.(map[string]any)
		if !ok {
			return
		}
		current = next
	}
}

func coerceMapperValue(v any, record map[string]any, reg *registry) (any, bool) {
	if coerce, ok := record["coerce"].(map[string]any); ok {
		if scalarToList, _ := coerce["scalar_to_list"].(bool); scalarToList {
			switch v.(type) {
			case []any:
			case nil:
			default:
				v = []any{v}
			}
		}
	}
	if stringValue(record["type"]) == "object" {
		if parsed, ok := v.(map[string]any); ok {
			return parsed, true
		}
	}
	if list, ok := record["list"].(map[string]any); ok {
		items := mapperAnyList(v)
		if separator := stringValue(list["sep"]); separator != "" {
			if text, ok := v.(string); ok {
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
			for i := range items {
				items[i] = normalizeMapperValue(items[i], norm)
			}
			if norm == "port_range_spec" {
				flat := []any{}
				for _, item := range items {
					flat = append(flat, mapperAnyList(item)...)
				}
				items = flat
			}
		}
		if len(items) == 1 && isEmptyScalar(items[0]) {
			items = nil
		}
		if stringValue(list["item"]) == "int" {
			numbers := []any{}
			for _, item := range items {
				if number := intValue(item); number != nil {
					numbers = append(numbers, number)
				}
			}
			items = numbers
		}
		if expected := intValue(list["len"]); expected != nil && int64(len(items)) != expected.(int64) {
			return nil, false
		}
		if stringValue(record["type"]) == "object" && len(items) > 0 {
			parsed := map[string]any{}
			for _, line := range mapperStringList(items) {
				for _, pair := range strings.Split(line, "\r\n") {
					key, item, ok := strings.Cut(pair, ":")
					if !ok || strings.TrimSpace(key) == "" {
						continue
					}
					parsed[strings.TrimSpace(key)] = strings.TrimSpace(item)
				}
			}
			v = parsed
		} else {
			v = items
		}
	} else if norm := stringValue(record["normalize"]); norm != "" {
		v = normalizeMapperValue(v, norm)
	}
	if vm, ok := record["value_map"].(map[string]any); ok {
		if ref := stringValue(vm["$ref"]); ref != "" {
			mapped, ok := resolveValueMapRef(reg, ref, stringValue(v))
			if !ok {
				return nil, false
			}
			v = mapped
		} else {
			mapped, exists := vm[stringValue(v)]
			if !exists && stringValue(record["value_map_case"]) != "sensitive" {
				for key, candidate := range vm {
					if strings.EqualFold(key, stringValue(v)) {
						mapped, exists = candidate, true
						break
					}
				}
			}
			if !exists {
				allowed, _ := record["allow"].([]any)
				if _, invalidPolicy := record["on_invalid"]; invalidPolicy && !containsAny(allowed, v) {
					return nil, false
				}
			} else if mapped == nil {
				return nil, true
			} else {
				v = mapped
			}
		}
	}
	switch stringValue(record["type"]) {
	case "int":
		if number := intValue(v); number != nil {
			v = number
		} else {
			return nil, false
		}
	case "duration":
		v = normalizeDuration(v)
	case "bool_spelled":
		v = isTrueSpelled(v)
	}
	if onInvalid, ok := record["on_invalid"].(map[string]any); ok {
		if when, ok := onInvalid["when"].(map[string]any); ok {
			if rule, ok := when["value"].(map[string]any); ok {
				text := stringValue(v)
				if pattern := stringValue(rule["not_matches"]); pattern != "" {
					if re, err := regexp.Compile(pattern); err == nil && !re.MatchString(text) {
						return nil, false
					}
				}
				if pattern := stringValue(rule["matches"]); pattern != "" {
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
		if decoded, ok := decodeBase64Flexible(stringValue(v)); ok {
			return base64.RawURLEncoding.EncodeToString(decoded)
		}
	case "hex_only":
		return normalizeHexOnly(stringValue(v))
	case "cidr_prefix", "cidr_masked":
		return normalizeCIDR(stringValue(v))
	case "range_order":
		if text, ok := v.(string); ok {
			return normalizeRangeOrder(text)
		}
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
		if !isBareNumber(low) || !isBareNumber(high) || (len(low) > 1 && low[0] == '0') || (len(high) > 1 && high[0] == '0') {
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
	if flag, ok := v.(bool); ok {
		return flag
	}
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
	if blocks, ok := table["blocks"].(map[string]any); ok {
		if block, exists := blocks[parts[1]]; exists {
			cur = block
			goto valueMapResolved
		}
	}
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
valueMapResolved:
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
			// Prefix tables translate aliases; the body enum judges other spellings.
			return value, true
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
	return conditionMatchesValue(raw, state, nil)
}

func conditionMatchesValue(raw any, state *mapperState, value any) bool {
	m, ok := raw.(map[string]any)
	if !ok || len(m) == 0 {
		return true
	}
	for key, want := range m {
		if key == "$value" {
			if value == nil {
				continue
			}
			if !conditionValueMatches(want, value, true) {
				return false
			}
			continue
		}
		if key == "$impl" {
			continue
		}
		if key == "any_set" || key == "source_kind" {
			// Source kind and body markers are alternative evidence. A marker
			// in the input still counts after its malformed body field is dropped.
			if !mapperAnyPathSet(state, m["any_set"]) && !mapperSourceKindMatches(state, m["source_kind"]) {
				return false
			}
			continue
		}
		got, exists := getSourcePath(key, *state)
		// URL selectors use the empty spelling as the absent-query branch,
		// both for equality (security) and for membership (raw type). Keep
		// the actual existence flag for explicit present/absent predicates.
		if !exists && strings.HasPrefix(key, "query.") {
			if text, ok := want.(string); ok && text == "" {
				continue
			}
			if rule, ok := want.(map[string]any); ok && rule["present"] == nil {
				if _, ok := rule["in"].([]any); ok {
					got, exists = "", true
				}
			}
		}
		if !conditionValueMatches(want, got, exists) {
			return false
		}
	}
	return true
}

func conditionValueMatches(want, got any, exists bool) bool {
	if cond, ok := want.(map[string]any); ok {
		if list, ok := cond["in"].([]any); ok && (!exists || !containsAny(list, got)) {
			return false
		}
		if list, ok := cond["not_in"].([]any); ok && exists && containsAny(list, got) {
			return false
		}
		if present, ok := cond["present"].(bool); ok && present != exists {
			return false
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
		return true
	}
	return exists && scalarEqual(got, want)
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
	case json.Number:
		if parsed, err := typed.Float64(); err == nil {
			return &parsed
		}
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
	wireguard := stringValue(protocol["singbox_type"]) == "wireguard"
	if wireguard {
		prepareWireGuardFields(state, state.entry, body, "")
	}
	var repairs []func()
	if sanitizeMapperFields(state, state.entry, body, "", &repairs) {
		state.dropNode = true
		if state.dropReason == "" {
			state.dropReason = "field_missing"
		}
	}
	// Conditional replacements must see the surviving body, not a rejected sibling.
	for _, repair := range repairs {
		repair()
	}
	if wireguard && !state.dropNode {
		checkWireGuardRelations(state, body)
	}
}

// sanitizeMapperFields returns true when the enclosing object has to be
// dropped because a nested required field is absent.
func sanitizeMapperFields(state *mapperState, target, schema map[string]any, prefix string, repairs *[]func()) bool {
	fields := fieldMap(schema, "fields")
	for _, name := range orderedKeys(fields, stringSlice(schema["order"])) {
		field, ok := fields[name].(map[string]any)
		if !ok {
			continue
		}
		pathName := name
		if prefix != "" {
			pathName = prefix + "." + name
		}
		value, exists := target[name]
		if !exists {
			if defaultWhen, ok := field["default_when"].(map[string]any); ok && defaultWhen["absent"] == true && conditionMatches(defaultWhen["when"], state) {
				value = normalizeIntegral(cloneValue(defaultWhen["value"]))
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
				target[name] = value
				exists = true
			} else if minWhen, ok := field["min_when"].(map[string]any); ok && minWhen["absent_is_zero"] == true && conditionMatches(minWhen["when"], state) {
				if minimum := numberValue(minWhen["min"]); minimum != nil && *minimum > 0 && stringValue(minWhen["action"]) == "drop_node" {
					state.dropNode = true
					state.dropReason = stringValue(minWhen["code"])
					state.diags = append(state.diags, Diagnostic{Code: state.dropReason, Severity: "error", Message: "field value is below the conditional minimum", Path: pathName})
				}
			}
		}
		if !exists {
			continue
		}
		if absent, ok := field["absent_values"].([]any); ok && containsAny(absent, value) {
			delete(target, name)
			continue
		}
		if norm := stringValue(field["normalize"]); norm != "" {
			if list, ok := value.([]any); ok {
				for i := range list {
					list[i] = normalizeMapperValue(list[i], norm)
				}
				value = list
			} else {
				value = normalizeMapperValue(value, norm)
			}
		}
		typ := stringValue(field["type"])
		if typ == "int" || typ == "uint16" {
			number := intValue(value)
			if number == nil {
				if handleMapperInvalid(state, target, name, pathName, field, fieldMap(field, "on_invalid"), value) {
					continue
				}
				continue
			}
			value = number
		}
		if minWhen, ok := field["min_when"].(map[string]any); ok && conditionMatches(minWhen["when"], state) {
			current := numberValue(value)
			if current == nil && minWhen["absent_is_zero"] == true {
				zero := float64(0)
				current = &zero
			}
			limit := numberValue(minWhen["min"])
			if limit != nil && (current == nil || *current < *limit) {
				onInvalid := map[string]any{"action": minWhen["action"], "code": minWhen["code"]}
				if handleMapperInvalid(state, target, name, pathName, field, onInvalid, value) {
					continue
				}
			}
		}
		if maxWhen, ok := field["max_when"].(map[string]any); ok && conditionMatches(maxWhen["when"], state) {
			current := numberValue(value)
			limit := numberValue(maxWhen["max"])
			if limit != nil && current != nil && *current > *limit {
				action := stringValue(maxWhen["action"])
				if action == "" {
					action = "coerce"
				}
				onInvalid := map[string]any{"action": action, "code": maxWhen["code"], "value": maxWhen["max"]}
				if containsAny(stringSliceAny(maxWhen["except_sources"]), state.input.form) {
					state.diags = append(state.diags, Diagnostic{Code: stringValue(maxWhen["note_code"]), Severity: "info", Path: pathName, Value: value})
				} else if handleMapperInvalid(state, target, name, pathName, field, onInvalid, value) {
					continue
				}
			}
		}
		if forbidden, ok := field["forbidden_for"].([]any); ok && containsAny(forbidden, state.entry["type"]) {
			delete(target, name)
			continue
		}
		if boolean, ok := value.(bool); ok && !boolean && typ == "bool" && name != "enabled" {
			if _, exists := field["default"]; exists {
				delete(target, name)
				continue
			}
		}
		if values, ok := field["values"].([]any); ok && (typ == "enum" || typ == "alias_enum") && !containsAny(values, value) {
			if handleMapperInvalid(state, target, name, pathName, field, fieldMap(field, "on_invalid"), value) {
				continue
			}
		}
		if pattern := stringValue(field["pattern"]); pattern != "" {
			if re, err := regexp.Compile(pattern); err == nil && !re.MatchString(stringValue(value)) {
				if handleMapperInvalid(state, target, name, pathName, field, fieldMap(field, "on_invalid"), value) {
					continue
				}
			}
		}
		if field["len_parity"] == "even" && len(stringValue(value))%2 != 0 {
			if handleMapperInvalid(state, target, name, pathName, field, fieldMap(field, "on_invalid"), value) {
				continue
			}
		}
		if format := stringValue(field["format"]); format != "" && !mapperFormatValid(format, value) {
			policy := fieldMap(field, "on_invalid")
			if policy == nil && field["core_rejects"] == true {
				policy = map[string]any{"action": "drop"}
			}
			if handleMapperInvalid(state, target, name, pathName, field, policy, value) {
				continue
			}
		}
		if coerce := fieldMap(field, "coerce_when"); coerce != nil {
			*repairs = append(*repairs, func() {
				if current, exists := target[name]; exists && containsAny(stringSliceAny(coerce["values"]), current) && conditionMatches(coerce["when"], state) {
					target[name] = coerce["value"]
					state.diags = append(state.diags, Diagnostic{Code: stringValue(coerce["code"]), Severity: "warning", Path: pathName, Value: current})
				}
			})
		}
		if advisory, ok := field["advisory"].([]any); ok {
			for _, item := range advisory {
				if rule, ok := item.(map[string]any); ok && (rule["values"] == nil || containsAny(stringSliceAny(rule["values"]), value)) && stringValue(rule["code"]) != "" {
					state.diags = append(state.diags, Diagnostic{Code: stringValue(rule["code"]), Severity: "info", Path: pathName, Value: value})
				}
			}
		}
		if list, ok := field["list"].(map[string]any); ok {
			if sep := stringValue(list["sep"]); sep != "" {
				if text, ok := value.(string); ok {
					items := []any{}
					for _, part := range strings.Split(text, sep) {
						if strings.TrimSpace(part) != "" {
							items = append(items, strings.TrimSpace(part))
						}
					}
					value = items
				}
			}
		}
		if itemPattern := stringValue(field["item_pattern"]); itemPattern != "" {
			if re, err := regexp.Compile(itemPattern); err == nil {
				if list, ok := value.([]any); ok {
					filtered := make([]any, 0, len(list))
					for _, item := range list {
						if re.MatchString(stringValue(item)) {
							filtered = append(filtered, item)
						}
					}
					value = filtered
				}
			}
		}

		if min := numberValue(field["min"]); min != nil {
			if current := numberValue(value); current != nil && *current < *min {
				if handleMapperInvalid(state, target, name, pathName, field, fieldMap(field, "on_invalid"), value) {
					continue
				}
			}
		}
		if max := numberValue(field["max"]); max != nil {
			current := numberValue(value)
			if typ == "string" {
				length := float64(len([]rune(stringValue(value))))
				current = &length
			}
			if current != nil && *current > *max {
				if handleMapperInvalid(state, target, name, pathName, field, fieldMap(field, "on_invalid"), value) {
					continue
				}
			}
		}
		if fieldMap(field, "fields") != nil {
			if object, ok := value.(map[string]any); ok {
				if sanitizeMapperFields(state, object, field, pathName, repairs) {
					delete(target, name)
					continue
				}
				value = object
			}
		}
		if ref := stringValue(field["ref"]); ref == "tls" || ref == "transports" {
			if object, ok := value.(map[string]any); ok && sanitizeSharedMapperBlock(state, object, ref, pathName, repairs) {
				delete(target, name)
				continue
			}
		}
		if items, ok := field["items"].(map[string]any); ok {
			if list, ok := value.([]any); ok {
				itemFields, _ := items["fields"].(map[string]any)
				cleaned := []any{}
				for _, item := range list {
					if object, ok := item.(map[string]any); ok && itemFields != nil {
						if sanitizeMapperFields(state, object, items, pathName, repairs) || len(object) == 0 {
							continue
						}
					}
					cleaned = append(cleaned, item)
				}
				value = cleaned
			}
		}
		if absentWhen, ok := field["absent_when"].(map[string]any); ok {
			if object, ok := value.(map[string]any); ok {
				drop := true
				for key, expected := range absentWhen {
					if current, exists := object[key]; !exists || mapperSetKey(current) != mapperSetKey(expected) {
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
		if conflicts, ok := field["conflicts"].([]any); ok {
			conflicting := false
			for _, item := range conflicts {
				if rule, ok := item.(map[string]any); ok {
					if other := stringValue(rule["with"]); other != "" {
						present, _ := getPath(state.entry, other)
						unless := false
						for _, path := range stringSlice(rule["unless_set"]) {
							if v, exists := getPath(state.entry, path); exists && !isEmptyScalar(v) {
								unless = true
								break
							}
						}
						if !isEmptyScalar(present) && !unless {
							conflicting = true
							break
						}
					}
				}
			}
			if conflicting {
				delete(target, name)
				continue
			}
		}
		if requires, ok := field["requires"].([]any); ok {
			missing := false
			for _, item := range requires {
				if rule, ok := item.(map[string]any); ok && conditionMatches(rule["when"], state) {
					if requiredPath := stringValue(rule["path"]); requiredPath != "" {
						present, _ := getPath(state.entry, requiredPath)
						if desired, exists := rule["set"]; exists {
							if !scalarEqual(desired, present) {
								setMapperPath(state.entry, requiredPath, desired)
							}
							continue
						}
						expected, exact := rule["equals"]
						if isEmptyScalar(present) || (exact && !scalarEqual(present, expected)) {
							state.diags = append(state.diags, Diagnostic{Code: stringValue(rule["code"]), Severity: "warning", Path: pathName, Value: value})
							missing = true
							break
						}
					}
				}
			}
			if missing {
				delete(target, name)
				continue
			}
		}
		target[name] = value
	}
	// A required field may have been removed by normalization or validation.
	for name, raw := range fields {
		field, _ := raw.(map[string]any)
		if field["required"] == true && isEmptyScalar(target[name]) {
			if policy := fieldMap(field, "on_invalid"); policy["action"] == "drop_node" && !state.dropNode {
				handleMapperInvalid(state, target, name, strings.TrimPrefix(prefix+"."+name, "."), field, policy, nil)
			}
			return true
		}
	}
	return false
}

func fieldMap(field map[string]any, key string) map[string]any {
	value, _ := field[key].(map[string]any)
	return value
}
func stringSliceAny(value any) []any {
	if list, ok := value.([]any); ok {
		return list
	}
	return nil
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
	case "url_path":
		_, err := url.Parse(text)
		return err == nil
	case "uuid":
		return regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`).MatchString(text)
	case "host":
		return text != ""
	case "cidr":
		return true
	}
	return true
}

func sanitizeSharedMapperBlock(state *mapperState, object map[string]any, blockName, pathName string, repairs *[]func()) bool {
	shared := state.reg.shared[blockName]
	if shared == nil {
		return false
	}
	body, _ := shared["body"].(map[string]any)
	if body == nil {
		return false
	}
	if enabled, ok := object["enabled"].(bool); ok && !enabled && fieldMap(body, "absent_when")["enabled"] == false {
		return true
	}
	if discriminator := stringValue(body["discriminator"]); discriminator != "" {
		body = fieldMap(fieldMap(body, "variants"), stringValue(object[discriminator]))
	}
	return sanitizeMapperFields(state, object, body, pathName, repairs)
}

func normalizeIntegral(v any) any {
	switch typed := v.(type) {
	case float64:
		if typed == float64(int64(typed)) {
			return int64(typed)
		}
		return typed
	case json.Number:
		if parsed, err := typed.Int64(); err == nil {
			return parsed
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
