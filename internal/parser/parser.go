// Package parser converts subscription bodies and share links into cacheable
// node maps. It deliberately depends only on the standard library plus the
// repository's existing yaml.v3 dependency; application models are not needed.
package parser

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"path"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

type Source struct {
	Kind string `json:"kind,omitempty"`
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

type Diagnostic struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Path     string `json:"path,omitempty"`
	Value    any    `json:"value,omitempty"`
	Line     int    `json:"line,omitempty"`
	NodeKey  string `json:"node_key,omitempty"`
	Source   Source `json:"source,omitempty"`
}

type Node struct {
	Key         string         `json:"key"`
	Name        string         `json:"name,omitempty"`
	Protocol    string         `json:"protocol,omitempty"`
	Raw         map[string]any `json:"raw"`
	Canonical   map[string]any `json:"canonical,omitempty"`
	Source      Source         `json:"source"`
	Origin      string         `json:"origin,omitempty"`
	Diagnostics []Diagnostic   `json:"diagnostics,omitempty"`
}

// IsEndpoint reports whether the emitted entry belongs in a sing-box
// config's endpoints array rather than outbounds. WireGuard is the current
// endpoint protocol in the shared contract.
func (n Node) IsEndpoint() bool {
	return n.Protocol == "wireguard" || stringValue(n.Canonical["type"]) == "wireguard"
}

// SingBox returns a deep copy of the node as a directly usable sing-box entry.
// The returned map is an entry, not a full config: callers put it in
// outbounds, or in endpoints when IsEndpoint is true. It includes `type` and
// `tag`; it does not add a top-level outbounds/endpoints wrapper.
func (n Node) SingBox() map[string]any { return Emit(n) }

// Emit converts a parsed node to one sing-box outbound/endpoint entry. Raw
// input is never mutated. A nil return means the node has no usable canonical
// protocol body; Parse reports that condition as a diagnostic before emitting
// such a node.
func Emit(n Node) map[string]any {
	if n.Canonical == nil && n.Protocol == "" {
		return nil
	}
	entry := cloneMap(n.Canonical)
	if entry == nil {
		entry = map[string]any{}
	}
	if stringValue(entry["type"]) == "" && n.Protocol != "" {
		entry["type"] = n.Protocol
	}
	if n.Name != "" {
		entry["tag"] = n.Name
	}
	return entry
}

// Example entry shapes produced by Emit:
//
//   ss://YWVzLTI1Ni1nY206cGFzcw==@ss.example:443#office
//   => {"type":"shadowsocks","tag":"office","server":"ss.example", ...}
//
//   vless://uuid@example:443?security=tls&type=ws&path=%2Fedge#edge
//   => {"type":"vless","tag":"edge","server":"example", ...}
//
//   wireguard://<private-key>@wg.example:51820?publickey=<peer-key>&address=10.0.0.2%2F32
//   => {"type":"wireguard","tag":"...","server":"wg.example", ...}
//
// WireGuard entries are endpoint entries; the other examples are outbound
// entries. `Raw` still contains the original URI, while `Canonical` is the
// normalized entry body before Emit adds `tag`.

type Result struct {
	Source      Source                    `json:"source"`
	Format      string                    `json:"format,omitempty"`
	Recognized  bool                      `json:"recognized"`
	Complete    bool                      `json:"complete"`
	Nodes       []Node                    `json:"nodes"`
	NodesByKey  map[string]map[string]any `json:"nodes_by_key"`
	RawByKey    map[string]map[string]any `json:"raw_by_key"`
	Diagnostics []Diagnostic              `json:"diagnostics"`
}

type Options struct {
	// ContractFS may be rooted at app/assets, app/assets/contract, or a test
	// fstest.MapFS containing registry/protocols/*.json.
	ContractFS fs.FS
	Source     Source
	MaxDepth   int
	KeepUnknown bool
}

func Parse(ctx context.Context, input []byte, options Options) Result {
	result := Result{Source: options.Source, Nodes: []Node{}, NodesByKey: map[string]map[string]any{}, RawByKey: map[string]map[string]any{}, Diagnostics: []Diagnostic{}, Complete: true}
	if result.Source.Kind == "" {
		result.Source.Kind = "subscription"
	}
	options.Source = result.Source
	if ctx == nil {
		ctx = context.Background()
	}
	if len(input) == 0 || strings.TrimSpace(string(input)) == "" {
		result.Complete = false
		result.Diagnostics = append(result.Diagnostics, diag("empty_input", "error", "input is empty", result.Source))
		return result
	}
	registry, registryErr := loadRegistry(options.ContractFS)
	if registryErr != nil {
		result.Complete = false
		result.Diagnostics = append(result.Diagnostics, diag("contract_load_failed", "error", registryErr.Error(), result.Source))
		return result
	}
	depth := options.MaxDepth
	if depth <= 0 {
		depth = 2
	}
	result = parseBody(ctx, input, options, registry, depth, result)
	if len(result.Nodes) == 0 && len(result.Diagnostics) == 0 {
		result.Diagnostics = append(result.Diagnostics, diag("no_nodes", "error", "input was recognized but produced no supported nodes", result.Source))
	}
	if len(result.Nodes) > 0 {
		result.Recognized = true
	}
	if hasErrorDiagnostics(result) { result.Complete = false }
	return result
}

func hasErrorDiagnostics(result Result) bool {
	for _, diagnostic := range result.Diagnostics { if diagnostic.Severity == "error" { return true } }
	for _, node := range result.Nodes { for _, diagnostic := range node.Diagnostics { if diagnostic.Severity == "error" { return true } } }
	return false
}

func ParseString(ctx context.Context, input string, options Options) Result {
	return Parse(ctx, []byte(input), options)
}

func ParseBytes(ctx context.Context, input []byte, options Options) Result {
	return Parse(ctx, input, options)
}

func parseBody(ctx context.Context, input []byte, options Options, registry *registry, depth int, result Result) Result {
	if err := ctx.Err(); err != nil {
		result.Complete = false
		result.Diagnostics = append(result.Diagnostics, diag("cancelled", "error", err.Error(), result.Source))
		return result
	}
	text := strings.TrimSpace(string(input))
	if text == "" {
		result.Diagnostics = append(result.Diagnostics, diag("empty_input", "error", "input is empty", result.Source))
		return result
	}
	if value, err := decodeJSON(text); err == nil {
		result.Format = "json"
		result.Recognized = true
		return extractDocument(ctx, value, "json", options, registry, result)
	}
	if looksLikeYAML(text) {
		var value any
		if err := yaml.Unmarshal([]byte(text), &value); err == nil {
			value = normalizeValue(value)
			if m, ok := value.(map[string]any); ok && documentLike(m) {
				result.Format = "yaml"
				result.Recognized = true
				return extractDocument(ctx, m, "yaml", options, registry, result)
			}
		} else {
			result.Format = "yaml"
			result.Diagnostics = append(result.Diagnostics, diag("document_invalid", "error", err.Error(), result.Source))
			return result
		}
	}
		if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
			result.Format = "json"
			result.Diagnostics = append(result.Diagnostics, diag("document_invalid", "error", "JSON document is malformed or has an unsupported root", result.Source))
			return result
		}
		if strings.HasPrefix(strings.ToLower(text), "vpn://") {
			nodes, diags, handled := decodeAmneziaProfile(text)
			if handled {
				result.Format = "amnezia"
				result.Recognized = true
				result.Diagnostics = append(result.Diagnostics, diags...)
				for _, node := range nodes { node.Source = result.Source; result = addNode(result, node) }
				return result
			}
		}
		if isWGIni(text) {
		result.Format = "wg_ini"
		if node, ok := parseINI(text, options.Source, registry, "wg_ini", result.Source); ok {
			result = addNode(result, node)
			result.Recognized = true
		} else {
			result.Diagnostics = append(result.Diagnostics, diag("form_unrecognized", "error", "WireGuard INI has no usable peer", result.Source))
		}
		return result
	}
	if depth > 0 && looksLikeBase64(text) {
		if decoded, ok := decodeBase64(text); ok && plausiblePayload(string(decoded)) {
			inner := result
			inner.Diagnostics = nil
inner.Nodes = nil
				inner.NodesByKey = map[string]map[string]any{}
				inner.RawByKey = map[string]map[string]any{}
			inner = parseBody(ctx, decoded, options, registry, depth-1, inner)
			if len(inner.Nodes) > 0 || inner.Recognized {
				inner.Format = "base64/" + inner.Format
				return inner
			}
			result.Diagnostics = append(result.Diagnostics, diag("base64_unrecognized", "error", "base64 decoded but payload is not a supported document", result.Source))
			return result
		}
	}
	return parseURILines(ctx, text, options, registry, result)
}

func extractDocument(ctx context.Context, value any, format string, options Options, registry *registry, result Result) Result {
	if arr, ok := value.([]any); ok {
		for i, item := range arr {
			if err := ctx.Err(); err != nil {
				result.Complete = false
				result.Diagnostics = append(result.Diagnostics, diag("cancelled", "error", err.Error(), result.Source))
				return result
			}
			if m, ok := item.(map[string]any); ok {
				if nested, exists := m["outbounds"]; exists {
					result = extractEntries(ctx, nested, "singbox", options, registry, result, fmt.Sprintf("[%d].outbounds", i))
					continue
				}
				result = appendDocumentNode(m, format, options, registry, result, fmt.Sprintf("[%d]", i))
			}
		}
		if len(result.Nodes) == 0 {
			result.Diagnostics = append(result.Diagnostics, diag("document_empty", "error", "JSON array contains no supported outbound objects", result.Source))
		}
		return result
	}
	m, ok := value.(map[string]any)
	if !ok {
		result.Diagnostics = append(result.Diagnostics, diag("document_unrecognized", "error", "document root must be an object or array", result.Source))
		return result
	}
	if proxies, ok := m["proxies"].([]any); ok {
		return extractEntries(ctx, proxies, "clash", options, registry, result, "proxies")
	}
	if proxies, ok := m["proxies"].([]map[string]any); ok {
		items := make([]any, 0, len(proxies))
		for _, p := range proxies { items = append(items, p) }
		return extractEntries(ctx, items, "clash", options, registry, result, "proxies")
	}
	if outbounds, ok := m["outbounds"].([]any); ok {
		kind := "singbox"
		for _, entry := range outbounds {
			if em, ok := entry.(map[string]any); ok {
				if _, hasProtocol := em["protocol"]; hasProtocol { kind = "xray"; break }
			}
		}
		result = extractEntries(ctx, outbounds, kind, options, registry, result, "outbounds")
	}
	if endpoints, ok := m["endpoints"].([]any); ok {
		result = extractEntries(ctx, endpoints, "singbox", options, registry, result, "endpoints")
	}
	if _, hasType := m["type"]; hasType {
		return appendDocumentNode(m, format, options, registry, result, "$self")
	}
	if _, hasProtocol := m["protocol"]; hasProtocol {
		return appendDocumentNode(m, "xray", options, registry, result, "$self")
	}
	if len(result.Nodes) == 0 {
		result.Diagnostics = append(result.Diagnostics, diag("document_unrecognized", "error", "JSON/YAML has no outbounds, endpoints, proxies, type, or protocol", result.Source))
	}
	return result
}

func extractEntries(ctx context.Context, raw any, kind string, options Options, registry *registry, result Result, basePath string) Result {
	list, ok := raw.([]any)
	if !ok {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: "field_type", Severity: "error", Message: "outbound collection is not an array", Path: basePath, Source: result.Source})
		return result
	}
	for i, item := range list {
		if err := ctx.Err(); err != nil {
			result.Complete = false
			result.Diagnostics = append(result.Diagnostics, diag("cancelled", "error", err.Error(), result.Source))
			return result
		}
		if m, ok := item.(map[string]any); ok {
			protocol := stringValue(m["protocol"])
			if protocol != "" {
				if mapped, mapperDiags, handled := mapContractXray(m, protocol, result.Source, registry); handled {
					for _, node := range mapped { result = addNode(result, node) }
					result.Diagnostics = append(result.Diagnostics, mapperDiags...)
					continue
				}
			}
			result = appendDocumentNode(m, kind, options, registry, result, fmt.Sprintf("%s[%d]", basePath, i))
		}
	}
	return result
}

func appendDocumentNode(raw map[string]any, origin string, options Options, registry *registry, result Result, pathName string) Result {
	protocol := stringValue(raw["type"])
	if protocol == "" { protocol = stringValue(raw["protocol"]) }
	if protocol == "" { protocol = stringValue(raw["proxy-type"]) }
	if protocol == "" {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: "protocol_missing", Severity: "error", Message: "outbound has no type/protocol", Path: pathName, Source: result.Source})
		return result
	}
	canonical := cloneMap(raw)
	if origin == "clash" {
		canonical = clashCanonical(raw)
		if protocol == "socks5" { protocol = "socks"; canonical["type"] = "socks" }
		if protocol == "ss" { protocol = "shadowsocks"; canonical["type"] = "shadowsocks" }
	}
	if origin == "xray" {
		canonical = xrayCanonical(raw, protocol)
	}
	if registry != nil {
		if p := registry.byScheme[strings.ToLower(protocol)]; p != nil {
			protocol = p.singboxType
			canonical["type"] = protocol
		}
	}
	if !supportedProtocol(protocol, registry) {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: "protocol_unsupported", Severity: "error", Message: "protocol is not declared by the contract", Path: pathName, Value: protocol, Source: result.Source})
		return result
	}
	delete(canonical, "tag")
	if origin == "singbox" { origin = "singbox" }
	name := firstString(raw, "tag", "name", "ps", "remarks", "remark")
	if name == "" { name = firstString(canonical, "tag", "name", "ps") }
	if name == "" { name = fmt.Sprintf("%s-%s-%v", protocol, stringValue(canonical["server"]), canonical["server_port"]) }
	node := makeNode(name, protocol, raw, canonical, options.Source, origin)
	result = addNode(result, node)
	return result
}

func parseURILines(ctx context.Context, text string, options Options, registry *registry, result Result) Result {
	result.Format = "uri_lines"
	seenLine := false
	for lineNo, rawLine := range strings.Split(text, "\n") {
		if err := ctx.Err(); err != nil {
			result.Complete = false
			result.Diagnostics = append(result.Diagnostics, diag("cancelled", "error", err.Error(), result.Source))
			return result
		}
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, ";") { continue }
		seenLine = true
		if strings.HasPrefix(strings.ToLower(line), "routing:") || strings.HasPrefix(strings.ToLower(line), "routing-enable:") { continue }
		if serviceLine(line) {
			result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: "service_record_ignored", Severity: "info", Message: "service record is not a proxy node", Line: lineNo + 1, Value: line, Source: result.Source})
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "vpn://") {
			nodes, ds, handled := decodeAmneziaProfile(line)
			if handled {
				for i := range ds { ds[i].Line = lineNo + 1; ds[i].Source = result.Source }
				result.Diagnostics = append(result.Diagnostics, ds...)
				for _, node := range nodes { node.Source = result.Source; result = addNode(result, node) }
				continue
			}
		}
		node, ds := parseURI(line, options.Source, registry)
		for i := range ds { ds[i].Line = lineNo + 1; ds[i].Source = result.Source }
		if node == nil {
			result.Diagnostics = append(result.Diagnostics, ds...)
			continue
		}
		node.Diagnostics = append(node.Diagnostics, ds...)
		result = addNode(result, *node)
	}
	if !seenLine { result.Diagnostics = append(result.Diagnostics, diag("no_parseable_content", "error", "no URI lines remain after comments and blanks", result.Source)) }
	return result
}

func parseURI(rawURI string, source Source, registry *registry) (*Node, []Diagnostic) {
	diagnostics := []Diagnostic{}
	sep := strings.Index(rawURI, "://")
	if sep <= 0 { return nil, []Diagnostic{diag("scheme_unsupported", "error", "URI has no supported scheme separator", source)} }
	scheme := strings.ToLower(rawURI[:sep])
	if scheme == "vpn" { return parseVPN(rawURI, source, registry) }
	protocol := normalizeProtocol(scheme)
	if registry != nil {
		if p := registry.byScheme[scheme]; p != nil { protocol = p.singboxType } else {
			return nil, []Diagnostic{{Code: "scheme_unsupported", Severity: "error", Message: "scheme is not declared by the contract", Value: scheme, Source: source}}
		}
	}
	if !supportedProtocol(protocol, registry) { return nil, []Diagnostic{{Code:"scheme_unsupported", Severity:"error", Message:"scheme is not supported", Value:scheme, Source:source}} }
	if mapped, mapperDiags, handled := mapContractURI(rawURI, protocol, source, registry); handled {
		return mapped, mapperDiags
	}
	if scheme == "vmess" { return parseVMess(rawURI, source, registry) }
	if scheme == "ss" { return parseShadowsocks(rawURI, source, registry) }
	if scheme == "wireguard" || scheme == "wg" || scheme == "awg" || scheme == "amneziawg" { return parseWireguardURI(rawURI, source, registry) }
	u, err := url.Parse(rawURI)
	if err != nil { return nil, []Diagnostic{{Code: "uri_invalid", Severity: "error", Message: err.Error(), Value: rawURI, Source: source}} }
	if u.Hostname() == "" { return nil, []Diagnostic{{Code: "server_missing", Severity: "error", Message: "URI has no server host", Value: rawURI, Source: source}} }
	m := map[string]any{"type": protocol, "server": u.Hostname()}
	port := u.Port()
	if port != "" { if n, e := strconv.Atoi(port); e == nil { m["server_port"] = n } }
	if u.User != nil { applyUserinfo(m, protocol, u.User.String(), registry) }
	applyQuery(m, protocol, u.Query(), registry)
	if scheme == "socks" || scheme == "socks4" || scheme == "socks4a" || scheme == "socks5" {
		m["version"] = map[string]string{"socks4":"4", "socks4a":"4a"}[scheme]
		if m["version"] == nil { m["version"] = "5" }
	}
	if scheme == "http" || scheme == "proxy-http" || scheme == "proxy+http" { m["tls"] = nil }
	if scheme == "https" || scheme == "proxy-https" || scheme == "proxy+https" { m["tls"] = map[string]any{"enabled": true} }
	if protocol == "trojan" && m["tls"] == nil { m["tls"] = map[string]any{"enabled": true} }
	applyProtocolDefaults(m, protocol, scheme)
	name := fragmentName(u.Fragment)
	if name == "" { name = fmt.Sprintf("%s-%s-%v", protocol, u.Hostname(), m["server_port"]) }
	if m["server_port"] == nil { diagnostics = append(diagnostics, Diagnostic{Code: "server_port_default", Severity: "info", Message: "server port was not present; core default may apply"}) }
	if registry != nil && !registry.supports(protocol) { diagnostics = append(diagnostics, Diagnostic{Code: "protocol_unsupported", Severity: "error", Message: "protocol is not declared by the contract", Value: protocol}); return nil, diagnostics }
	node := makeNode(name, protocol, map[string]any{"uri": rawURI}, m, source, "uri")
	return &node, diagnostics
}

func parseShadowsocks(rawURI string, source Source, registry *registry) (*Node, []Diagnostic) {
	body := strings.TrimPrefix(rawURI, rawURI[:strings.Index(rawURI, "://")+3])
	fragment := ""
	if i := strings.IndexByte(body, '#'); i >= 0 { fragment, body = body[i+1:], body[:i] }
	m := map[string]any{"type": "shadowsocks"}
	if at := strings.LastIndexByte(body, '@'); at >= 0 {
		userinfo, hostport := body[:at], body[at+1:]
		userinfo = percentDecode(userinfo)
		if decoded, ok := decodeBase64Flexible(userinfo); ok { userinfo = string(decoded) }
		parts := strings.SplitN(userinfo, ":", 2)
		if len(parts) != 2 { return nil, []Diagnostic{{Code: "credentials_missing", Severity: "error", Message: "Shadowsocks userinfo must contain method and password", Source: source}} }
		m["method"], m["password"] = parts[0], parts[1]
		setHostPort(m, hostport)
	} else {
		decoded, ok := decodeBase64Flexible(percentDecode(body))
		if !ok { return nil, []Diagnostic{{Code: "form_unrecognized", Severity: "error", Message: "Shadowsocks payload is not valid base64", Source: source}} }
		parts := strings.SplitN(string(decoded), "@", 2)
		if len(parts) != 2 { return nil, []Diagnostic{{Code: "form_unrecognized", Severity: "error", Message: "legacy Shadowsocks payload has no host", Source: source}} }
		cred := strings.SplitN(parts[0], ":", 2)
		if len(cred) != 2 { return nil, []Diagnostic{{Code: "credentials_missing", Severity: "error", Message: "Shadowsocks credentials are incomplete", Source: source}} }
		m["method"], m["password"] = cred[0], cred[1]
		setHostPort(m, parts[1])
	}
	if m["server"] == nil || m["method"] == "" || m["password"] == "" { return nil, []Diagnostic{{Code: "form_unrecognized", Severity: "error", Message: "Shadowsocks node is missing server, method, or password", Source: source}} }
	name := fragmentName(fragment); if name == "" { name = fmt.Sprintf("shadowsocks-%s-%v", m["server"], m["server_port"]) }
	node := makeNode(name, "shadowsocks", map[string]any{"uri": rawURI}, m, source, "uri")
	return &node, nil
}

func parseVMess(rawURI string, source Source, registry *registry) (*Node, []Diagnostic) {
	body := strings.TrimPrefix(rawURI, rawURI[:strings.Index(rawURI, "://")+3])
	fragment := ""; if i := strings.IndexByte(body, '#'); i >= 0 { fragment, body = body[i+1:], body[:i] }
	decoded, ok := decodeBase64Flexible(body)
	if !ok { return nil, []Diagnostic{{Code: "form_unrecognized", Severity: "error", Message: "VMess payload is not valid base64", Source: source}} }
	var raw map[string]any
	if decodeJSONInto(decoded, &raw) == nil {
		m := map[string]any{"type": "vmess"}
		for k, v := range raw { mapVMessField(m, k, v) }
		if m["server"] == nil { m["server"] = raw["add"] }
		if m["server_port"] == nil { m["server_port"] = intValue(raw["port"]) }
		if m["uuid"] == nil { m["uuid"] = raw["id"] }
		name := stringValue(raw["ps"]); if name == "" { name = fragmentName(fragment) }
		if name == "" { name = fmt.Sprintf("vmess-%s-%v", m["server"], m["server_port"]) }
		if m["server"] == nil || m["uuid"] == nil { return nil, []Diagnostic{{Code: "required_field_missing", Severity: "error", Message: "VMess JSON requires add and id", Source: source}} }
		node := makeNode(name, "vmess", map[string]any{"uri": rawURI, "container": raw}, m, source, "uri")
		return &node, nil
	}
	legacy := string(decoded)
	u, err := url.Parse("vmess://" + legacy)
	if err != nil || u.User == nil || u.Hostname() == "" { return nil, []Diagnostic{{Code: "form_unrecognized", Severity: "error", Message: "VMess legacy payload is not method:uuid@host:port", Source: source}} }
	parts := strings.SplitN(u.User.String(), ":", 2)
	m := map[string]any{"type":"vmess", "server":u.Hostname(), "uuid":""}
	if len(parts) == 2 { m["security"], m["uuid"] = parts[0], parts[1] }
	if p := u.Port(); p != "" { m["server_port"] = intValue(p) }
	applyQuery(m, "vmess", u.Query(), registry)
	name := fragmentName(fragment); if name == "" { name = fmt.Sprintf("vmess-%s-%v", m["server"], m["server_port"]) }
	node := makeNode(name, "vmess", map[string]any{"uri": rawURI}, m, source, "uri")
	return &node, nil
}

func parseWireguardURI(rawURI string, source Source, registry *registry) (*Node, []Diagnostic) {
	body := rawURI[strings.Index(rawURI, "://")+3:]
	fragment := ""; if i := strings.IndexByte(body, '#'); i >= 0 { fragment, body = body[i+1:], body[:i] }
	if !strings.Contains(body, "@") && !strings.Contains(body, "?") {
		if decoded, ok := decodeBase64Flexible(body); ok && isWGIni(string(decoded)) {
			if node, ok := parseINI(string(decoded), source, registry, "wg_ini", source); ok {
				if fragment != "" { node.Name = fragment; node.Raw["name"] = fragment }
				return &node, nil
			}
		}
	}
	u, err := url.Parse(rawURI); if err != nil || u.Hostname() == "" { return nil, []Diagnostic{{Code:"form_unrecognized", Severity:"error", Message:"WireGuard URI has no usable server", Source:source}} }
	m := map[string]any{"type":"wireguard", "server":u.Hostname()}
	if u.Port() != "" { m["server_port"] = intValue(u.Port()) }
	if u.User != nil { m["private_key"] = percentDecode(u.User.String()) }
	applyQuery(m, "wireguard", u.Query(), registry)
	if address, ok := m["address"].(string); ok { m["address"] = []any{address} }
	if m["peers"] == nil { m["peers"] = []any{map[string]any{}} }
	if peerList, ok := m["peers"].([]any); ok && len(peerList) > 0 {
		peer, _ := peerList[0].(map[string]any)
		if peer == nil { peer = map[string]any{}; peerList[0] = peer }
		if peer["allowed_ips"] == nil { peer["allowed_ips"] = []any{"0.0.0.0/0", "::/0"} }
		if host := stringValue(m["server"]); host != "" { peer["address"] = host }
		if port := m["server_port"]; port != nil { peer["port"] = port }
		delete(m, "server")
		delete(m, "server_port")
	}
	name := fragmentName(fragment); if name == "" { name = stringValue(m["name"]) }; if name == "" { name = fmt.Sprintf("wireguard-%s", firstPeerAddress(m)) }
	node := makeNode(name, "wireguard", map[string]any{"uri":rawURI}, m, source, "uri")
	return &node, nil
}

func parseVPN(rawURI string, source Source, registry *registry) (*Node, []Diagnostic) {
	body := rawURI[strings.Index(rawURI, "://")+3:]
	if decoded, ok := decodeBase64Flexible(body); ok {
		text := string(decoded)
		if isWGIni(text) {
			node, parsed := parseINI(text, source, registry, "wg_ini", source)
			if !parsed { return nil, []Diagnostic{{Code:"form_unrecognized", Severity:"error", Message:"WireGuard configuration is incomplete", Source:source}} }
			return &node, nil
		}
		var profile map[string]any
		if decodeJSONInto(decoded, &profile) == nil {
			if containers, ok := profile["containers"].([]any); ok {
				for _, c := range containers {
					if cm, ok := c.(map[string]any); ok {
						if ini := stringValue(cm["config"]); ini != "" && isWGIni(ini) {
							node, parsed := parseINI(ini, source, registry, "wg_ini", source)
							if parsed { return &node, nil }
						}
					}
				}
			}
		}
	}
	return nil, []Diagnostic{{Code:"form_unrecognized", Severity:"error", Message:"vpn payload is not a supported WireGuard/Amnezia profile", Source:source}}
}

func parseINI(text string, source Source, registry *registry, origin string, diagSource Source) (Node, bool) {
	var interfaceFields map[string]string
	var peerSections []map[string]string
	var current map[string]string
	var commentName string
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" { continue }
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			if commentName == "" { commentName = strings.TrimSpace(strings.TrimLeft(line, "#; ")) }
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section := strings.ToLower(strings.TrimSpace(line[1:len(line)-1]))
			current = map[string]string{}
			switch {
			case section == "interface": interfaceFields = current
			case section == "peer" || strings.HasPrefix(section, "peer "): peerSections = append(peerSections, current)
			}
			continue
		}
		if i := strings.IndexByte(line, '='); i > 0 && current != nil {
			current[strings.ToLower(strings.TrimSpace(line[:i]))] = strings.TrimSpace(line[i+1:])
		}
	}
	if interfaceFields == nil { return Node{}, false }
	m := map[string]any{"type":"wireguard"}
	copyINI(m, interfaceFields, "privatekey", "private_key")
	copyINI(m, interfaceFields, "address", "address")
	copyINI(m, interfaceFields, "mtu", "mtu")
	copyINI(m, interfaceFields, "listenport", "listen_port")
	for key, value := range interfaceFields {
		if strings.HasPrefix(key, "j") || strings.HasPrefix(key, "s") || strings.HasPrefix(key, "h") || strings.HasPrefix(key, "i") || key == "headerprotectionkey" || key == "contentpaddingaddition" { m[key] = parseScalar(value) }
	}
	peers := make([]any, 0, len(peerSections))
	for _, fields := range peerSections {
		peer := map[string]any{}
		copyINI(peer, fields, "publickey", "public_key")
		copyINI(peer, fields, "presharedkey", "pre_shared_key")
		copyINI(peer, fields, "allowedips", "allowed_ips")
		copyINI(peer, fields, "persistentkeepalive", "persistent_keepalive_interval")
		if endpoint := strings.TrimSpace(fields["endpoint"]); endpoint != "" { setPeerEndpoint(peer, endpoint) }
		if peer["allowed_ips"] == nil { peer["allowed_ips"] = []any{"0.0.0.0/0", "::/0"} }
		peers = append(peers, peer)
	}
	if len(peers) > 0 { m["peers"] = peers }
	name := commentName
	if name == "" { name = fmt.Sprintf("wireguard-%s", firstPeerAddress(m)) }
	node := makeNode(name, "wireguard", map[string]any{"ini":text}, m, source, origin)
	return node, m["private_key"] != nil && len(peers) > 0
}

func setPeerEndpoint(peer map[string]any, endpoint string) {
	host, port, err := splitHostPortLoose(strings.TrimSpace(endpoint))
	if err != nil { peer["address"] = strings.Trim(endpoint, "[]"); return }
	peer["address"] = strings.Trim(host, "[]")
	if value, err := strconv.ParseInt(port, 10, 64); err == nil { peer["port"] = value }
}

func firstPeerAddress(m map[string]any) string {
	if peers, ok := m["peers"].([]any); ok && len(peers)>0 { if peer,ok:=peers[0].(map[string]any);ok { return stringValue(peer["address"]) } }
	return "peer"
}

func copyINI(dst map[string]any, src map[string]string, from, to string) { if value := src[from]; value != "" { if strings.Contains(value, ",") { var list []any; for _, item := range strings.Split(value, ",") { list = append(list, strings.TrimSpace(item)) }; dst[to] = list } else { dst[to] = parseScalar(value) } } }
func firstPeer(peers []any) map[string]any { if len(peers) == 0 { return nil }; m, _ := peers[0].(map[string]any); return m }

func mapVMessField(dst map[string]any, key string, value any) { switch strings.ToLower(key) { case "add": dst["server"] = value; case "port": dst["server_port"] = intValue(value); case "id": dst["uuid"] = value; case "aid": dst["alter_id"] = intValue(value); case "scy", "security": dst["security"] = value; case "net", "network": dst["transport"] = map[string]any{"type":value}; case "host": dst["transport"] = mergeNested(dst["transport"], "headers", map[string]any{"Host":value}); case "path": dst["transport"] = mergeNested(dst["transport"], "path", value); case "tls": if stringValue(value) != "" { dst["tls"] = map[string]any{"enabled":true} }; case "sni": dst["tls"] = mergeNested(dst["tls"], "server_name", value); case "alpn": dst["tls"] = mergeNested(dst["tls"], "alpn", strings.Split(stringValue(value), ",")); case "type", "v": default: dst[key] = value } }

func applyUserinfo(dst map[string]any, protocol, raw string, registry *registry) {
	raw = percentDecode(raw)
	if registry != nil {
		if p := registry.byType[protocol]; p != nil && len(p.userInto) > 0 {
			parts := strings.SplitN(raw, p.userSep, len(p.userInto))
			if len(p.userInto) == 1 { setPath(dst, p.userInto[0], raw); return }
			for i, name := range p.userInto { if i < len(parts) { setPath(dst, name, parts[i]) } }
			return
		}
	}
	switch protocol {
	case "vless": dst["uuid"] = strings.SplitN(raw, ":", 2)[0]
	case "trojan", "hysteria2", "anytls": dst["password"] = raw
	case "tuic": parts := strings.SplitN(raw, ":", 2); if len(parts)>0 { dst["uuid"] = parts[0] }; if len(parts)==2 { dst["password"] = parts[1] }
	case "wireguard": dst["private_key"] = raw
	case "socks", "http": parts := strings.SplitN(raw, ":", 2); dst["username"] = parts[0]; if len(parts)==2 { dst["password"] = parts[1] }
	}
}

func applyQuery(dst map[string]any, protocol string, values url.Values, registry *registry) {
	for key, list := range values {
		if len(list) == 0 { continue }; value := list[len(list)-1]
		canonical := key
		if registry != nil { canonical = registry.mapParam(protocol, key) }
		if canonical == "" { canonical = key }
		valueAny := parseQueryValue(value)
		if strings.EqualFold(key, "security") {
			security := strings.ToLower(stringValue(valueAny))
			if security == "none" || security == "" { delete(dst, "tls") } else if security == "tls" || security == "reality" { dst["security"] = security }
			continue
		}
		setPath(dst, canonical, valueAny)
	}
	if p := registryProtocol(registry, protocol); p != nil { for key, param := range p.params { if _, exists := values[key]; !exists && param.defaultSet {
			setPath(dst, param.mapsTo, param.defaultValue)
		} } }
}

func applyProtocolDefaults(m map[string]any, protocol, scheme string) {
	if m["server_port"] == nil {
		switch protocol {
		case "trojan", "vless", "anytls", "hysteria2": m["server_port"] = 443
		case "socks": m["server_port"] = 1080
		case "http": if strings.Contains(scheme, "https") { m["server_port"] = 443 } else { m["server_port"] = 80 }
		}
	}
	security := strings.ToLower(stringValue(m["security"]))
	if security == "tls" || security == "reality" {
		m["tls"] = mergeNested(m["tls"], "enabled", true)
		if security == "reality" { m["tls"] = mergeNested(m["tls"], "reality", map[string]any{"enabled":true}) }
	} else if security == "none" {
		delete(m, "tls")
	}
	if flow := stringValue(m["flow"]); flow == "xtls-rprx-vision-udp443" { m["flow"] = "xtls-rprx-vision"; m["packet_encoding"] = "xudp" }
}

func supportedProtocol(protocol string, contract *registry) bool {
	if contract != nil { return contract.supports(protocol) }
	switch protocol {
	case "shadowsocks", "vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "wireguard", "socks", "http", "anytls", "ssh", "naive", "masque", "openvpn", "openconnect", "tailscale", "trusttunnel": return true
	default: return false
	}
}

func xrayCanonical(raw map[string]any, protocol string) map[string]any {
	entry := map[string]any{"type": protocol}
	if settings, ok := raw["settings"].(map[string]any); ok {
		var server map[string]any
		switch protocol {
		case "vmess": if list, ok := settings["vnext"].([]any); ok && len(list)>0 { server,_ = list[0].(map[string]any); if users,ok:=server["users"].([]any);ok&&len(users)>0 { if user,ok:=users[0].(map[string]any);ok { copyField(entry,"uuid",user,"id"); copyField(entry,"alter_id",user,"alterId"); copyField(entry,"security",user,"security"); copyField(entry,"level",user,"level") } } }
		case "vless", "trojan": key := "vnext"; if protocol == "trojan" { key = "servers" }; if list,ok:=settings[key].([]any);ok&&len(list)>0 { server,_ = list[0].(map[string]any); if users,ok:=server["users"].([]any);ok&&len(users)>0 { if user,ok:=users[0].(map[string]any);ok { copyField(entry,"uuid",user,"id"); copyField(entry,"password",user,"password"); copyField(entry,"flow",user,"flow") } } }
		case "shadowsocks": if list,ok:=settings["servers"].([]any);ok&&len(list)>0 { server,_=list[0].(map[string]any); copyField(entry,"method",server,"method"); copyField(entry,"password",server,"password") }
		case "socks", "http": if list,ok:=settings["servers"].([]any);ok&&len(list)>0 { server,_=list[0].(map[string]any); copyField(entry,"username",server,"users"); copyField(entry,"password",server,"password") }
		}
		if server != nil { copyField(entry,"server",server,"address"); copyField(entry,"server_port",server,"port") }
	}
	stream, _ := raw["streamSettings"].(map[string]any)
	if stream != nil {
		network := stringValue(stream["network"])
		if network != "" && network != "tcp" { entry["transport"] = map[string]any{"type":network} }
		if transport,ok:=entry["transport"].(map[string]any);ok { key:=network+"Settings"; if settings,ok:=stream[key].(map[string]any);ok { switch network { case "ws": if path,ok:=settings["path"].(string);ok{transport["path"]=path}; if headers,ok:=settings["headers"].(map[string]any);ok{transport["headers"]=headers}; case "grpc": if name,ok:=settings["serviceName"].(string);ok{transport["service_name"]=name}; case "http", "h2": if hosts,ok:=settings["host"].([]any);ok{transport["host"]=hosts}; if paths,ok:=settings["path"].([]any);ok&&len(paths)>0{transport["path"]=paths[0]} } } }
		if tlsSettings,ok:=stream["tlsSettings"].(map[string]any);ok { tls:=map[string]any{"enabled":true}; copyField(tls,"server_name",tlsSettings,"serverName"); copyField(tls,"alpn",tlsSettings,"alpn"); copyField(tls,"insecure",tlsSettings,"allowInsecure"); entry["tls"]=tls }
		if reality,ok:=stream["realitySettings"].(map[string]any);ok { tls,_:=entry["tls"].(map[string]any);if tls==nil{tls=map[string]any{"enabled":true}};tls["reality"]=map[string]any{"enabled":true,"public_key":reality["publicKey"],"short_id":reality["shortId"]};entry["tls"]=tls }
	}
	if tag:=stringValue(raw["tag"]);tag!=""{entry["tag"]=tag}
	return entry
}

func copyField(dst map[string]any, target string, src map[string]any, key string) { if value,ok:=src[key];ok { dst[target]=cloneValue(value) } }

func clashCanonical(raw map[string]any) map[string]any {
	m := map[string]any{}
	typ := strings.ToLower(stringValue(raw["type"]))
	switch typ { case "ss": typ = "shadowsocks"; case "socks5", "socks4", "socks4a": typ = "socks" }
	m["type"] = typ
	copyField(m, "server", raw, "server")
	if port := intValue(raw["port"]); port != nil { m["server_port"] = port }
	copyField(m, "uuid", raw, "uuid")
	copyField(m, "password", raw, "password")
	copyField(m, "method", raw, "cipher")
	copyField(m, "username", raw, "username")
	if value, ok := raw["tls"].(bool); ok && value { m["tls"] = map[string]any{"enabled": true} }
	if value, ok := raw["skip-cert-verify"].(bool); ok && value { m["tls"] = mergeNested(m["tls"], "insecure", true) }
	if sni := stringValue(raw["sni"]); sni != "" { m["tls"] = mergeNested(m["tls"], "server_name", sni) }
	if network := stringValue(raw["network"]); network != "" && network != "tcp" { m["transport"] = map[string]any{"type": network} }
	if ws, ok := raw["ws-opts"].(map[string]any); ok {
		transport, _ := m["transport"].(map[string]any)
		if transport == nil { transport = map[string]any{"type":"ws"}; m["transport"] = transport }
		if p := stringValue(ws["path"]); p != "" { transport["path"] = p }
		if headers, ok := ws["headers"].(map[string]any); ok { transport["headers"] = cloneMap(headers) }
	}
	if grpc, ok := raw["grpc-opts"].(map[string]any); ok {
		transport, _ := m["transport"].(map[string]any); if transport == nil { transport = map[string]any{"type":"grpc"}; m["transport"] = transport }
		if service := stringValue(grpc["grpc-service-name"]); service != "" { transport["service_name"] = service }
	}
	return m
}
func setHostPort(m map[string]any, hostport string) { hostport = strings.TrimSpace(hostport); if hostport == "" { return }; host := hostport; port := ""; if h, p, err := splitHostPortLoose(hostport); err == nil { host, port = h, p }; host = strings.Trim(host, "[]"); m["server"] = host; if port != "" { if n, err := strconv.Atoi(port); err == nil { m["server_port"] = n } } }
func splitHostPortLoose(s string) (string,string,error) { if strings.HasPrefix(s,"[") { i:=strings.LastIndex(s,"]:"); if i<0{return s,"",errors.New("missing port")}; return s[1:i],s[i+2:],nil }; i:=strings.LastIndexByte(s,':'); if i<0{return s,"",errors.New("missing port")}; return s[:i],s[i+1:],nil }
func makeNode(name, protocol string, raw, canonical map[string]any, source Source, origin string) Node { if source.Kind == "" { source.Kind = origin }; key := stableKey(protocol, name, canonical); return Node{Key:key, Name:name, Protocol:protocol, Raw:cloneMap(raw), Canonical:cloneMap(canonical), Source:source, Origin:origin} }
func addNode(result Result, node Node) Result {
	if _, exists := result.NodesByKey[node.Key]; exists {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Code:"duplicate_node", Severity:"info", Message:"duplicate node collapsed in cache", NodeKey:node.Key, Source:result.Source})
		return result
	}
	result.Nodes = append(result.Nodes, node)
	result.NodesByKey[node.Key] = Emit(node)
	result.RawByKey[node.Key] = cloneMap(node.Raw)
	return result
}
func stableKey(protocol, name string, m map[string]any) string { h:=sha256.New(); h.Write([]byte(protocol)); h.Write([]byte("\x00")); h.Write([]byte(name)); h.Write([]byte("\x00")); b,_:=json.Marshal(m); h.Write(b); return hex.EncodeToString(h.Sum(nil)[:16]) }
func diag(code, severity, message string, source Source) Diagnostic { return Diagnostic{Code:code, Severity:severity, Message:message, Source:source} }

func decodeJSON(s string) (any,error) {
	var value any
	decoder := json.NewDecoder(strings.NewReader(s))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil { return nil, err }
	return value, nil
}

func decodeJSONInto(data []byte, destination any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	return decoder.Decode(destination)
}
func normalizeValue(v any) any { switch x:=v.(type) { case map[string]any: for k,vv:=range x { x[k]=normalizeValue(vv) }; case map[any]any: m:=map[string]any{}; for k,vv:=range x { m[fmt.Sprint(k)]=normalizeValue(vv) }; return m; case []any: for i,vv:=range x { x[i]=normalizeValue(vv) } }; return v }
func looksLikeYAML(s string) bool { low:=strings.ToLower(strings.TrimSpace(s)); return strings.Contains(low,"proxies:") || strings.Contains(low,"outbounds:") || strings.Contains(low,"endpoints:") || strings.HasPrefix(low,"mixed-port:") || strings.HasPrefix(low,"port:") }
func documentLike(m map[string]any) bool { _,a:=m["proxies"]; _,b:=m["outbounds"]; _,c:=m["endpoints"]; _,d:=m["type"]; return a||b||c||d }
func isWGIni(s string) bool { for _,line:=range strings.Split(strings.ReplaceAll(s,"\r",""),"\n") { t:=strings.TrimSpace(line); if t==""||strings.HasPrefix(t,"#")||strings.HasPrefix(t,";"){continue}; return strings.EqualFold(t,"[interface]") }; return false }
func looksLikeBase64(s string) bool { if len(s)<16{return false}; for _,r:=range s { if unicode.IsSpace(r){continue}; if !(r>='A'&&r<='Z'||r>='a'&&r<='z'||r>='0'&&r<='9'||strings.ContainsRune("+/_=-",r)){return false} }; return true }
func plausiblePayload(s string) bool { t:=strings.TrimSpace(s); return strings.Contains(t,"://")||strings.HasPrefix(t,"{")||strings.HasPrefix(t,"[")||isWGIni(t) }
func decodeBase64(s string) ([]byte,bool) { return decodeBase64Flexible(strings.Join(strings.Fields(s),"")) }
func decodeBase64Flexible(s string) ([]byte,bool) { s=strings.TrimSpace(s); for _,enc:=range []*base64.Encoding{base64.RawStdEncoding,base64.StdEncoding,base64.RawURLEncoding,base64.URLEncoding} { if b,e:=enc.DecodeString(strings.TrimRight(s,"=")); e==nil{return b,true} }; return nil,false }
func percentDecode(s string) string { if v,e:=url.QueryUnescape(s); e==nil{return v}; if v,e:=url.PathUnescape(s);e==nil{return v}; return s }
func fragmentName(s string) string { return strings.TrimSpace(percentDecode(s)) }
func serviceLine(s string) bool { low:=strings.ToLower(s); return (strings.HasPrefix(low,"incy://routing/")||strings.HasPrefix(low,"happ://routing/")) }
func normalizeProtocol(scheme string) string {
	switch strings.ToLower(scheme) {
	case "socks4", "socks4a", "socks5": return "socks"
	case "proxy-http", "proxy-https", "proxy+http", "proxy+https": return "http"
	case "hy2": return "hysteria2"
	case "ss": return "shadowsocks"
	case "wg", "awg", "amneziawg": return "wireguard"
	default: return strings.ToLower(scheme)
	}
}

func stringValue(v any) string { s,_:=v.(string); return s }
func firstString(m map[string]any, keys ...string) string { for _,k:=range keys { if s:=strings.TrimSpace(stringValue(m[k]));s!=""{return s} }; return "" }
func parseScalar(s string) any { if b,e:=strconv.ParseBool(strings.ToLower(s));e==nil{return b}; if i,e:=strconv.Atoi(s);e==nil{return i}; return s }
func parseQueryValue(s string) any { if b,e:=strconv.ParseBool(strings.ToLower(s));e==nil{return b}; if i,e:=strconv.Atoi(s);e==nil{return i}; if strings.Contains(s, ",") { parts:=strings.Split(s, ","); out:=make([]any,0,len(parts)); for _,part:=range parts { out=append(out,strings.TrimSpace(part)) }; return out }; return s }
func intValue(v any) any {
	switch x := v.(type) {
	case int: return x
	case int64: return x
	case json.Number:
		if i, err := x.Int64(); err == nil { return i }
		return x
	case float64: return int64(x)
	case string:
		if i, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64); err == nil { return i }
	}
	return nil
}
func setPath(dst map[string]any, key string, value any) {
	if key == "" { return }
	parts := strings.Split(key, ".")
	cur := dst
	for i, part := range parts {
		isList := strings.HasSuffix(part, "[]")
		name := strings.TrimSuffix(part, "[]")
		last := i == len(parts)-1
		if last {
			if isList {
				if existing, ok := cur[name].([]any); ok { cur[name] = append(existing, value) } else { cur[name] = []any{value} }
			} else { cur[name] = value }
			return
		}
		if isList {
			list, ok := cur[name].([]any)
			if !ok || len(list) == 0 { list = []any{map[string]any{}}; cur[name] = list }
			item, ok := list[0].(map[string]any)
			if !ok { item = map[string]any{}; list[0] = item }
			cur = item
			continue
		}
		next, ok := cur[name].(map[string]any)
		if !ok { next = map[string]any{}; cur[name] = next }
		cur = next
	}
}
func mergeNested(existing any, key string, value any) map[string]any { m,_:=existing.(map[string]any);if m==nil{m=map[string]any{}};m[key]=value;return m }
func cloneMap(m map[string]any) map[string]any { out:=map[string]any{};for k,v:=range m{out[k]=cloneValue(v)};return out }
func cloneValue(v any) any { switch x:=v.(type){case map[string]any:return cloneMap(x);case []any:o:=make([]any,len(x));for i,vv:=range x{o[i]=cloneValue(vv)};return o;default:return x} }

// The following registry reader is intentionally local to parser: it keeps the
// public package independent from either the sing-box module path or an app
// package that may be introduced by the host runtime.
type registryProtocol struct {
	scheme, singboxType string
	aliases []string
	userInto []string
	userSep string
	params map[string]registryParam
	raw map[string]any
	order map[string][]string
}
type registryParam struct { mapsTo string; aliases []string; defaultValue any; defaultSet bool }
type registry struct {
	byScheme map[string]*registryProtocol
	byType map[string]*registryProtocol
	shared map[string]map[string]any
	sharedOrder map[string]map[string][]string
}

func loadRegistry(fsys fs.FS) (*registry, error) {
	if fsys == nil { return nil, nil }
	for _, root := range []string{"", "contract/"} {
		pattern := path.Join(root, "registry/protocols/*.json")
		files, err := fs.Glob(fsys, pattern)
		if err != nil { return nil, fmt.Errorf("list contract protocols: %w", err) }
		if len(files) == 0 { continue }
				r := &registry{byScheme: map[string]*registryProtocol{}, byType: map[string]*registryProtocol{}, shared: map[string]map[string]any{}, sharedOrder: map[string]map[string][]string{}}
				for _, sharedName := range []string{"transports", "tls", "dialer", "multiplex"} {
					sharedPath := path.Join(root, "registry", sharedName+".json")
					if sharedBytes, sharedErr := fs.ReadFile(fsys, sharedPath); sharedErr == nil {
						sharedMap, sharedOrder, decodeErr := decodeOrderedMap(sharedBytes)
						if decodeErr != nil { return nil, fmt.Errorf("decode shared contract %s: %w", sharedPath, decodeErr) }
							if overlayBytes, overlayErr := fs.ReadFile(fsys, path.Join("contract_draft", "uri", sharedName+".json")); overlayErr == nil {
								var overlayMap map[string]any
								if decodeErr := decodeJSONInto(overlayBytes, &overlayMap); decodeErr != nil { return nil, fmt.Errorf("decode shared contract overlay %s: %w", sharedName, decodeErr) }
								mergeParserMap(sharedMap, overlayMap)
							}
						r.shared[sharedName] = sharedMap
						r.sharedOrder[sharedName] = sharedOrder
						}
				}
				loaded := 0
				for _, file := range files {
			b, err := fs.ReadFile(fsys, file)
			if err != nil { return nil, fmt.Errorf("read contract %s: %w", file, err) }
				m, order, err := decodeOrderedMap(b)
				if err != nil { return nil, fmt.Errorf("decode contract %s: %w", file, err) }
				base := strings.TrimSuffix(path.Base(file), path.Ext(file))
				for _, draftRoot := range []string{"", root} {
				draftName := path.Join(draftRoot, "contract_draft/uri", base+".json")
				draftBytes, draftErr := fs.ReadFile(fsys, draftName)
				if draftErr != nil { continue }
				var overlay map[string]any
				if err := decodeJSONInto(draftBytes, &overlay); err != nil { return nil, fmt.Errorf("decode contract overlay %s: %w", draftName, err) }
				mergeParserMap(m, overlay)
				break
			}
				p := registryFromMap(m)
				p.order = order
				if p.singboxType == "" { continue }
			loaded++
			r.byType[p.singboxType] = p
			if p.scheme != "" { r.byScheme[strings.ToLower(p.scheme)] = p }
			for _, alias := range p.aliases { r.byScheme[strings.ToLower(alias)] = p }
			if mapperSections, ok := m["mappers"].(map[string]any); ok {
				if uri, ok := mapperSections["uri"].(map[string]any); ok {
					if detect, ok := uri["detect"].(map[string]any); ok {
						for _, scheme := range stringSlice(detect["scheme_in"]) { r.byScheme[strings.ToLower(scheme)] = p }
					}
				}
			}
		}
			if loaded == 0 { return nil, fmt.Errorf("contract filesystem contains no protocol records") }
			return r, nil
		}
		return nil, fmt.Errorf("contract filesystem has no registry/protocols/*.json")
}

func stringSlice(value any) []string {
	var out []string
	if values, ok := value.([]any); ok { for _, item := range values { if text, ok := item.(string); ok { out = append(out, text) } } }
	return out
}
func mergeParserMap(dst, src map[string]any) {
	for key, value := range src {
		srcMap, srcOK := value.(map[string]any)
		dstMap, dstOK := dst[key].(map[string]any)
		if srcOK && dstOK { mergeParserMap(dstMap, srcMap); continue }
		dst[key] = value
	}
}

func registryFromMap(m map[string]any)*registryProtocol { p:=&registryProtocol{raw:m,order:map[string][]string{}};p.scheme=stringValue(m["scheme"]);p.singboxType=stringValue(m["singbox_type"]);if a,ok:=m["aliases"].([]any);ok{for _,v:=range a{if s,ok:=v.(string);ok{p.aliases=append(p.aliases,s)}}};p.userSep=":";p.params=map[string]registryParam{};if uri,ok:=m["uri"].(map[string]any);ok{if ui,ok:=uri["userinfo"].(map[string]any);ok{if into,ok:=ui["into"].([]any);ok{for _,v:=range into{if s,ok:=v.(string);ok{p.userInto=append(p.userInto,s)}}};if split,ok:=ui["split"].(map[string]any);ok{p.userSep=stringValue(split["sep"])} };if q,ok:=uri["query"].(map[string]any);ok{for k,v:=range q{if mm,ok:=v.(map[string]any);ok{p.params[k]=paramFromRegistryMap(mm)}}}};if ms,ok:=m["mappers"].(map[string]any);ok{if um,ok:=ms["uri"].(map[string]any);ok{if q,ok:=um["params"].(map[string]any);ok{for k,v:=range q{if mm,ok:=v.(map[string]any);ok{p.params[k]=paramFromRegistryMap(mm)}}};if defs,ok:=um["defaults"].(map[string]any);ok{for k,v:=range defs{p.params[k]=registryParam{mapsTo:k,defaultValue:v,defaultSet:true}}}}};return p }
func paramFromRegistryMap(m map[string]any)registryParam { p:=registryParam{mapsTo:stringValue(m["maps_to"])};if p.mapsTo==""{p.mapsTo=""};if a,ok:=m["aliases"].([]any);ok{for _,v:=range a{if s,ok:=v.(string);ok{p.aliases=append(p.aliases,s)}}};if d,ok:=m["default"];ok&&d!=nil{p.defaultValue=d;p.defaultSet=true};return p }
func (r *registry) supports(protocol string)bool{if r==nil{return true};_,ok:=r.byType[protocol];if ok{return true};_,ok=r.byScheme[strings.ToLower(protocol)];return ok}
func registryProtocolFor(r *registry, protocol string)*registryProtocol{if r==nil{return nil};if p:=r.byType[protocol];p!=nil{return p};return r.byScheme[strings.ToLower(protocol)]}
func (r *registry) mapParam(protocol,key string)string{p:=registryProtocolFor(r,protocol);if p==nil{return key};for name,def:=range p.params{if strings.EqualFold(name,key){if def.mapsTo!=""{return def.mapsTo};return name};for _,a:=range def.aliases{if strings.EqualFold(a,key){if def.mapsTo!=""{return def.mapsTo};return name}}};switch strings.ToLower(key){case "server","add":return "server";case "port":return "server_port"};return key}
func registryProtocol(r *registry,protocol string)*registryProtocol{return registryProtocolFor(r,protocol)}
