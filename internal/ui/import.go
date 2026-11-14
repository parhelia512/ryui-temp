package ui

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/ryui/camera"
	"github.com/egoist/ryui/scan"
	"github.com/egoist/ryui/signal"
	ryui "github.com/egoist/ryui/ui"
)

func (s *session) scanQR(nav *ryui.Navigator, found func(string)) {
	nav.Push(func() ryui.Node {
		q := s.scope()
		value := signal.New("")
		return page(section("Scan QR code", camera.View(camera.ViewProps{
			Style: ryui.Style{Height: ryui.Pt(360)},
			OnError: func(message string) { if q.ctx.Err() == nil { q.err.Set(message) } },
			Scan: scan.Codes(func(code scan.Code) { if q.ctx.Err() == nil { value.Set(code.Value) } }, scan.QR),
		}), field("Scanned text", value, true),
		primary("Use", func() { text := value.Peek(); nav.Pop(); found(text) }, signal.Func(func() bool { return value.Get() == "" })), q.feedback()))
	}, ryui.ScreenOptions{Title: ryui.Val(tr("Scan QR code"))})
}

// openDocument keeps SAF bytes and base64 decoding off the main thread. The
// platform owns permission/picker UI and returns actual copied file contents.
func (q *scope) openDocument(done func(string)) {
	q.work(func(ctx context.Context) (reply, error) {
		r, err := dispatch(ctx, "transfer.saf.import", object{"mime_types": []string{"application/json", "text/*", "application/octet-stream"}, "allow_multiple": false})
		if err != nil { return r, err }
		items := listOf(r.value, "payloads", "items", "files")
		if len(items) == 0 { return r, errors.New(tr("No file selected")) }
		item := asObject(items[0])
		if content := text(item["text"]); content != "" { return reply{value: content, text: content}, nil }
		data, err := base64.StdEncoding.DecodeString(text(item["bytes"]))
		if err != nil { return r, err }
		return reply{value: string(data), text: string(data)}, nil
	}, func(r reply) { done(text(r.value)) })
}

func (q *scope) saveDocument(name, data string) {
	q.work(func(ctx context.Context) (reply, error) {
		return dispatch(ctx, "transfer.saf.export", object{"payload": object{"kind": "file", "name": name, "mime": "application/json", "bytes": base64.StdEncoding.EncodeToString([]byte(data))}})
	}, nil)
}

func (s *session) serverWizard() ryui.Node {
	q := s.scope()
	step := signal.New(0)
	kind := signal.New("socks")
	name := signal.New("")
	server := signal.New("")
	port := signal.New("")
	username := signal.New("")
	password := signal.New("")
	uuid := signal.New("")
	method := signal.New("")
	tls := signal.New(false)
	sni := signal.New("")
	draft := signal.New("")
	nav := ryui.UseNavigator()
	prepare := func() {
		q.err.Set("")
		p, err := strconv.Atoi(port.Peek())
		if err != nil || p < 1 || p > 65535 { q.err.Set(tr("Port must be between 1 and 65535")); return }
		if !required(server, name) { q.err.Set(tr("Name and server are required")); return }
		node := object{"type": kind.Peek(), "tag": name.Peek(), "server": strings.TrimSpace(server.Peek()), "server_port": p}
		switch kind.Peek() {
		case "socks", "http":
			if username.Peek() != "" { node["username"] = username.Peek() }
			if password.Peek() != "" { node["password"] = password.Peek() }
			if kind.Peek() == "socks" { node["version"] = "5" }
		case "shadowsocks": node["method"], node["password"] = method.Peek(), password.Peek()
		case "trojan", "hysteria2", "anytls": node["password"] = password.Peek()
		case "vless", "vmess": node["uuid"] = uuid.Peek()
		}
		if tls.Peek() { node["tls"] = object{"enabled": true, "server_name": sni.Peek()} }
		draft.Set(pretty(object{"outbounds": []any{node}}))
		step.Set(1)
	}
	return page(section("Add server", ryui.Dynamic(func() ryui.Node {
		if step.Get() == 1 {
			return ryui.Column(ryui.Style{Gap: 10}, field("Configuration JSON", draft, true), actions(
				button("Back", func() { step.Set(0) }, q.busy),
				primary("Import", func() { q.run("sources.import", object{"text": draft.Peek(), "name": name.Peek()}, nil) }, q.busy)))
		}
		return ryui.Column(ryui.Style{Gap: 10}, choice("Protocol", kind,
			[]string{"socks", "http", "shadowsocks", "trojan", "vless", "vmess", "hysteria2", "anytls"},
			[]string{"SOCKS5", "HTTP", "Shadowsocks", "Trojan", "VLESS", "VMess", "Hysteria2", "AnyTLS"}),
			field("Name", name, false), field("Server", server, false), field("Port", port, false),
			ryui.Dynamic(func() ryui.Node {
				switch kind.Get() {
				case "socks", "http": return ryui.Column(ryui.Style{Gap: 10}, field("Username", username, false), secret("Password", password))
				case "vless", "vmess": return field("UUID", uuid, false)
				case "shadowsocks": return ryui.Column(ryui.Style{Gap: 10}, field("Encryption method", method, false), secret("Password", password))
				default: return secret("Password", password)
				}
			}),
			ryui.Row(ryui.Style{Gap: 12}, ryui.StaticText(tr("TLS")), ryui.Toggle(ryui.ToggleProps{Value: tls})),
			ryui.Show(tls, func() ryui.Node { return field("Server name (SNI)", sni, false) }),
			primary("Review JSON", prepare, q.busy), button("Scan QR code", func() { s.scanQR(nav, func(raw string) { draft.Set(raw); step.Set(1) }) }, q.busy))
	}), q.feedback(), jsonView(q.result)))
}

func (s *session) sourceDetails(source object) ryui.Node {
	q := s.scope()
	nav := ryui.UseNavigator()
	query := signal.New("")
	return page(section("Source", ryui.StaticText(nameOf(source)), ryui.StaticText(text(source["format"])), field("Filter", query, false),
		button("Edit", func() { s.sourceEditor(nav, source, func(){}) }, q.busy)),
		ryui.Dynamic(func() ryui.Node {
			var nodes []ryui.Node
			for _, value := range listOf(source, "nodes") {
				if search := strings.ToLower(query.Get()); search != "" && !strings.Contains(strings.ToLower(pretty(value)), search) { continue }
				node := asObject(value)
				tag := text(first(node, "tag", "Tag"))
				nodes = append(nodes, section(nameOf(node), ryui.StaticText(pretty(node), ryui.Style{Font: ryui.Footnote}), actions(
					button("Enable in source", func() { q.sourceNodeEnabled(source, tag, true) }, q.busy),
					button("Disable in source", func() { q.sourceNodeEnabled(source, tag, false) }, q.busy),
					button("Test", func() { q.core("ccUrlTestOutbound", object{"tag": tag, "link": "", "timeoutMs": 10000}, nil) }, q.busy),
					button("Details", func() { s.pushNode(nav, tag) }, q.busy))))
			}
			return ryui.Column(ryui.Style{Gap: 10}, nodes...)
		}), section("Diagnostics", ryui.StaticText(pretty(source["diagnostics"])), q.feedback(), jsonView(q.result)))
}

func (q *scope) sourceNodeEnabled(source object, tag string, enabled bool) {
	original := source
	if raw, ok := source["source"].(map[string]any); ok { original = raw }
	q.work(func(ctx context.Context) (reply, error) {
		latest, err := dispatch(ctx, "sources.list", nil)
		if err != nil { return latest, err }
		current := original
		for _, value := range listOf(latest.value, "sources", "items") {
			item := asObject(value)
			if item["id"] == original["id"] { if raw, ok := item["source"].(map[string]any); ok { current = raw } else { current = item }; break }
		}
		var record object
		if err := json.Unmarshal([]byte(pretty(current)), &record); err != nil { return reply{}, err }
		disabled := asObject(record["disabled"])
		if enabled { delete(disabled, tag) } else { disabled[tag] = time.Now().Unix() }
		record["disabled"] = disabled
		return dispatch(ctx, "sources.save", record)
	}, nil)
}

func (s *session) ruleSets() ryui.Node {
	q := s.scope()
	id := signal.New("")
	url := signal.New("")
	conditional := signal.New(true)
	args := func() object { return object{"id": id.Peek(), "url": url.Peek(), "conditional": conditional.Peek()} }
	return page(section("Rule sets", field("ID", id, false), field("URL", url, false),
		ryui.Row(ryui.Style{Gap: 10}, ryui.StaticText(tr("Conditional request")), ryui.Toggle(ryui.ToggleProps{Value: conditional})),
		actions(button("Download", func() { q.run("rulesets.download", args(), nil) }, q.busy),
			button("Read cached", func() { q.run("rulesets.read", args(), nil) }, q.busy),
			button("Metadata", func() { q.run("rulesets.metadata", args(), nil) }, q.busy)), q.feedback(), jsonView(q.result)))
}
