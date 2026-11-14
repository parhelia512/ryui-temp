package ui

import (
	"encoding/json"
	"strings"

	"github.com/egoist/ryui/signal"
	ryui "github.com/egoist/ryui/ui"
)

func (s *session) eventPanel(title string, match func(string) bool) ryui.Node {
	query := signal.New("")
	paused := signal.New(false)
	frozen := signal.NewFunc([]event{}, nil)
	visible := signal.Func(func() []event { if paused.Get() { return frozen.Get() }; return s.events.Get() })
	return section(title, actions(field("Filter", query, false),
		button("Pause / Resume", func() { if !paused.Peek() { frozen.Set(s.events.Peek()) }; paused.Set(!paused.Peek()) }, nil),
		button("Clear", func() { s.events.Set([]event{}); frozen.Set([]event{}) }, nil),
		button("Share", func() { ryui.Share(pretty(visible.Get())) }, nil)),
		ryui.Text(s.streamErr, ryui.Style{Color: ryui.Red}),
		ryui.Dynamic(func() ryui.Node {
			var nodes []ryui.Node
			list := visible.Get()
			filter := strings.ToLower(query.Get())
			for i := len(list)-1; i >= 0 && len(nodes) < 150; i-- {
				e := list[i]
				if !match(strings.ToLower(e.Type)) { continue }
				line := e.Time+"  "+e.Type+"\n"+string(e.Data)
				if filter != "" && !strings.Contains(strings.ToLower(line), filter) { continue }
				nodes = append(nodes, ryui.StaticText(line, ryui.Style{Font: ryui.Custom("monospace", ryui.Footnote)}))
			}
			if len(nodes) == 0 { nodes = append(nodes, ryui.StaticText(tr("No events"), ryui.Style{Color: ryui.SecondaryLabel})) }
			return ryui.Column(ryui.Style{Gap: 10}, nodes...)
		}))
}

func (s *session) logs() ryui.Node {
	q := s.scope()
	return page(section("Core logs", button("Refresh", func() { q.core("ccGetLogs", nil, nil) }, q.busy), q.feedback(), jsonView(q.result)),
		s.eventPanel("Logs", func(kind string) bool { return strings.Contains(kind, "log") || strings.Contains(kind, "error") || strings.Contains(kind, "diagnostic") }))
}

func (s *session) connections() ryui.Node {
	q := s.scope()
	id := signal.New("")
	return page(section("Connections", field("Connection ID", id, false), actions(
		button("Refresh", func() { q.core("ccGetConnections", nil, nil) }, q.busy),
		button("Close connection", func() { q.core("ccCloseConnection", object{"id": id.Peek()}, nil) }, signal.Func(func() bool { return q.busy.Get() || id.Get() == "" })),
		button("Close all connections", func() { confirm("Close all connections?", func() { q.core("ccCloseConnections", nil, nil) }) }, q.busy)), q.feedback(), jsonView(q.result)),
		s.eventPanel("Live events", func(kind string) bool { return strings.Contains(kind, "connection") || strings.Contains(kind, "trace") }))
}

func (s *session) statistics() ryui.Node {
	q := s.scope()
	return page(section("Statistics", actions(
		button("Traffic status", func() { q.core("ccGetStatus", nil, nil) }, q.busy),
		button("Status", func() { q.run("vpn.status", nil, nil) }, q.busy),
		button("Outbounds", func() { q.core("ccGetOutbounds", nil, nil) }, q.busy)), q.feedback(), jsonView(q.result)),
		s.eventPanel("Traffic by outbound", func(kind string) bool { return strings.Contains(kind, "traffic") || strings.Contains(kind, "status") || strings.Contains(kind, "stat") || strings.Contains(kind, "profile") }))
}

func (s *session) routing() ryui.Node {
	nav := ryui.UseNavigator()
	q := s.scope()
	return page(section("Routing", actions(
		button("Rules", func() { q.core("ccGetRules", nil, nil) }, q.busy),
		button("Groups", func() { q.core("ccGetGroups", nil, nil) }, q.busy),
		button("Rule sets", func() { nav.Push(s.ruleSets, ryui.ScreenOptions{Title: ryui.Val(tr("Rule sets"))}) }, q.busy),
		button("Edit rules", func() { nav.Push(func() ryui.Node { return s.configSection("Routing", "route") }, ryui.ScreenOptions{Title: ryui.Val(tr("Routing"))}) }, q.busy),
		button("Directions and groups", func() { nav.Push(func() ryui.Node { return s.documentSection("Directions and groups", "directions") }, ryui.ScreenOptions{Title: ryui.Val(tr("Directions and groups"))}) }, q.busy)),
		q.feedback(), jsonView(q.result)))
}

func (s *session) dns() ryui.Node {
	nav := ryui.UseNavigator()
	q := s.scope()
	host := signal.New("")
	return page(section("DNS", field("Domain", host, false), actions(
		button("DNS groups", func() { q.core("ccGetDnsGroups", nil, nil) }, q.busy),
		button("Rules", func() { q.core("ccGetRules", nil, nil) }, q.busy),
		button("Lookup", func() { q.run("diagnostics.run", object{"kind": "dns", "host": host.Peek()}, nil) }, signal.Func(func() bool { return q.busy.Get() || host.Get() == "" })),
		button("DNS server editor", func() { nav.Push(s.dnsEditor, ryui.ScreenOptions{Title: ryui.Val(tr("DNS server editor"))}) }, q.busy),
		button("Edit DNS", func() { nav.Push(func() ryui.Node { return s.configSection("DNS", "dns") }, ryui.ScreenOptions{Title: ryui.Val(tr("DNS"))}) }, q.busy)), q.feedback(), jsonView(q.result)),
		s.eventPanel("DNS events", func(kind string) bool { return strings.Contains(kind, "dns") }))
}

// configSection performs a read/modify/write on the latest configuration, so
// editing route or DNS does not replace unrelated sections with an old copy.
func (s *session) configSection(title, key string) ryui.Node {
	return s.sectionEditor(title, key, "config.get", "config.save")
}

func (s *session) documentSection(title, key string) ryui.Node {
	return s.sectionEditor(title, key, "settings.get", "settings.save")
}

func (s *session) sectionEditor(title, key, getMethod, saveMethod string) ryui.Node {
	q := s.scope()
	draft := signal.New("")
	load := func() { q.run(getMethod, nil, func(r reply) { value := asObject(r.value)[key]; if value == nil { value = object{} }; draft.Set(pretty(value)) }) }
	load()
	return page(section(title, actions(button("Reload", load, q.busy),
		primary("Save", func() {
			raw := draft.Peek()
			q.run(getMethod, nil, func(r reply) {
				original := asObject(r.value)
				original[key] = json.RawMessage(raw)
				q.run(saveMethod, original, nil)
			})
		}, q.busy), button("Format JSON", func() { q.formatJSON(draft) }, q.busy)), field("JSON", draft, true), q.feedback(), jsonView(q.result)))
}

func (s *session) diagnostics() ryui.Node {
	q := s.scope()
	target := signal.New("")
	tag := signal.New("")
	return page(section("Diagnostics", ryui.StaticText(tr("Application network requests follow the current VPN and routing settings."), ryui.Style{Color: ryui.SecondaryLabel}), field("URL or host", target, false), field("Outbound tag", tag, false), actions(
		button("URL check", func() { q.run("diagnostics.run", object{"kind": "url", "url": target.Peek(), "host": target.Peek(), "tag": tag.Peek()}, nil) }, q.busy),
		button("DNS lookup", func() { q.run("diagnostics.run", object{"kind": "dns", "host": target.Peek()}, nil) }, q.busy),
		button("TCP connect", func() { q.run("diagnostics.run", object{"kind": "tcp", "host": target.Peek()}, nil) }, q.busy),
		button("Path MTU (physical network)", func() { q.run("diagnostics.run", object{"kind": "path_mtu", "target": target.Peek()}, nil) }, q.busy),
		button("URL test via outbound", func() { q.core("ccUrlTestOutbound", object{"tag": tag.Peek(), "link": target.Peek(), "timeoutMs": 10000}, nil) }, q.busy),
		button("Fetch via outbound", func() { q.core("ccGetUrlViaOutbound", object{"tag": tag.Peek(), "link": target.Peek(), "timeoutMs": 15000, "maxBytes": 262144}, nil) }, q.busy)),
		q.feedback(), jsonView(q.result)), s.eventPanel("Diagnostics events", func(kind string) bool { return strings.Contains(kind, "test") || strings.Contains(kind, "diagnostic") }))
}

func (s *session) automation() ryui.Node {
	q := s.scope()
	settings := object{}
	keys := []string{"automation_receive_enabled", "automation_emit_lifecycle", "automation_emit_state", "automation_emit_subs", "automation_emit_health"}
	labels := []string{"Receive automation commands", "Lifecycle events", "State events", "Subscription events", "Health events"}
	values := make([]*signal.Signal[bool], len(keys))
	for i := range values { values[i] = signal.New(false) }
	load := func() { q.run("automation.get", nil, func(r reply) {
		settings = asObject(r.value)
		for i, key := range keys { value, _ := settings[key].(bool); values[i].Set(value) }
	}) }
	load()
	var toggles []ryui.Node
	for i := range keys { toggles = append(toggles, ryui.Row(ryui.Style{Gap: 12, Align: ryui.AlignCenter}, ryui.StaticText(tr(labels[i]), ryui.Style{Grow: 1}), ryui.Toggle(ryui.ToggleProps{Value: values[i]}))) }
	method := signal.New("")
	args := signal.New("{}")
	toggles = append(toggles, actions(primary("Save", func() {
		for i, key := range keys { settings[key] = values[i].Peek() }
		q.run("automation.save", settings, nil)
	}, q.busy), button("Reload", load, q.busy)), q.feedback())
	return page(section("Automation", toggles...), section("Run action", field("Command", method, false), field("Arguments JSON", args, true),
		button("Run", func() { q.run("automation.run", object{"method": method.Peek(), "cmd": method.Peek(), "args": json.RawMessage(args.Peek())}, nil) }, q.busy), jsonView(q.result)))
}

func (s *session) advanced() ryui.Node {
	nav := ryui.UseNavigator()
	q := s.scope()
	method := signal.New("")
	args := signal.New("{}")
	return page(section("Advanced settings", actions(
		button("VPN Settings", func() { nav.Push(s.templateSettings, ryui.ScreenOptions{Title: ryui.Val(tr("VPN Settings"))}) }, nil),
		button("Tunnel apps", func() { nav.Push(s.appPicker, ryui.ScreenOptions{Title: ryui.Val(tr("Tunnel apps"))}) }, nil),
		button("Node editor", func() { nav.Push(func() ryui.Node { return s.registryEditor("Node editor", "outbounds") }, ryui.ScreenOptions{Title: ryui.Val(tr("Node editor"))}) }, nil),
		button("Endpoint editor", func() { nav.Push(func() ryui.Node { return s.registryEditor("Endpoint editor", "endpoints") }, ryui.ScreenOptions{Title: ryui.Val(tr("Endpoint editor"))}) }, nil),
		button("Device transfer", func() { nav.Push(s.deviceTransfer, ryui.ScreenOptions{Title: ryui.Val(tr("Device transfer"))}) }, nil),
		button("Reports", func() { nav.Push(s.reports, ryui.ScreenOptions{Title: ryui.Val(tr("Reports"))}) }, nil),
		button("Data migration", func() { nav.Push(s.migration, ryui.ScreenOptions{Title: ryui.Val(tr("Data migration"))}) }, nil),
		button("Mixins", func() { nav.Push(func() ryui.Node { return s.documentSection("Mixins", "mixins") }, ryui.ScreenOptions{Title: ryui.Val(tr("Mixins"))}) }, nil),
		button("Variables", func() { nav.Push(func() ryui.Node { return s.documentSection("Variables", "vars") }, ryui.ScreenOptions{Title: ryui.Val(tr("Variables"))}) }, nil),
		button("Node groups", func() { nav.Push(func() ryui.Node { return s.configSection("Node groups", "outbounds") }, ryui.ScreenOptions{Title: ryui.Val(tr("Node groups"))}) }, nil),
		button("Endpoints", func() { nav.Push(func() ryui.Node { return s.configSection("Endpoints", "endpoints") }, ryui.ScreenOptions{Title: ryui.Val(tr("Endpoints"))}) }, nil),
		button("Inbounds", func() { nav.Push(func() ryui.Node { return s.configSection("Inbounds", "inbounds") }, ryui.ScreenOptions{Title: ryui.Val(tr("Inbounds"))}) }, nil))),
		section("Core API", field("Method", method, false), field("Arguments JSON", args, true),
		button("Run", func() { q.core(method.Peek(), json.RawMessage(args.Peek()), nil) }, signal.Func(func() bool { return q.busy.Get() || method.Get() == "" })),
		q.feedback(), jsonView(q.result)))
}
