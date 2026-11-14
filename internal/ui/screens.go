package ui

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/ryui/signal"
	ryui "github.com/egoist/ryui/ui"
)

func (s *session) home() ryui.Node {
	nav := ryui.UseNavigator()
	q := s.scope()
	status := signal.New("")
	groups := signal.NewFunc([]any{}, nil)
	filter := signal.New("")
	refresh := func() { q.run("vpn.status", nil, func(r reply) { status.Set(r.text) }) }
	refresh()
	// Polling belongs to this screen and stops when navigating away.
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-q.ctx.Done():
				return
			case <-ticker.C:
			}
			if !s.foreground.Load() {
				continue
			}
			ryui.Post(func() {
				if q.ctx.Err() == nil && !q.busy.Peek() {
					refresh()
				}
			})
		}
	}()
	vpn := func(method string) func() {
		return func() { q.run(method, nil, func(r reply) { status.Set(r.text) }) }
	}
	loadGroups := func() { q.core("ccGetGroups", nil, func(r reply) { groups.Set(listOf(r.value, "groups")) }) }
	return page(
		section("VPN", jsonView(status), actions(
			primary("Connect", vpn("vpn.start"), q.busy),
			button("Disconnect", vpn("vpn.stop"), q.busy),
			button("Reload", vpn("vpn.reload"), q.busy),
			button("Refresh", refresh, q.busy)), q.feedback()),
		section("Nodes", field("Filter", filter, false), actions(
			button("Refresh", loadGroups, q.busy),
			button("Servers", func() { s.selected.Set(1) }, nil),
			button("Config Editor", func() { s.selected.Set(2) }, nil)),
			ryui.Dynamic(func() ryui.Node {
				query := strings.ToLower(filter.Get())
				var rows []ryui.Node
				for _, item := range groups.Get() {
					group := asObject(item)
					if query != "" && !strings.Contains(strings.ToLower(pretty(group)), query) {
						continue
					}
					rows = append(rows, s.groupCard(q, nav, group))
				}
				if len(rows) == 0 {
					rows = append(rows, ryui.StaticText(tr("No data"), ryui.Style{Color: ryui.SecondaryLabel}))
				}
				return ryui.Column(ryui.Style{Gap: 12}, rows...)
			})),
	)
}

func (s *session) groupCard(q *scope, nav *ryui.Navigator, group object) ryui.Node {
	tag := text(group["tag"])
	if tag == "" {
		tag = nameOf(group)
	}
	var nodes []ryui.Node
	nodes = append(nodes, ryui.StaticText(nameOf(group), ryui.Style{Font: ryui.Headline}),
		ryui.StaticText(tr("Selected")+": "+text(group["selected"]), ryui.Style{Color: ryui.SecondaryLabel}),
		button("Test group", func() { q.core("ccUrlTestGroup", object{"tag": tag}, nil) }, q.busy))
	for _, item := range listOf(group, "items", "outbounds", "members") {
		node := asObject(item)
		nodeTag := text(first(node, "tag", "Tag"))
		if nodeTag == "" {
			nodeTag = text(item)
		}
		currentTag := nodeTag
		nodes = append(nodes, ryui.Row(ryui.Style{Gap: 8, Wrap: true, Align: ryui.AlignCenter},
			ryui.StaticText(nodeTag, ryui.Style{Grow: 1}),
			button("Select", func() { q.core("ccSelectOutbound", object{"group": tag, "tag": currentTag}, nil) }, q.busy),
			button("Test", func() { q.core("ccUrlTestOutbound", object{"tag": currentTag, "link": "", "timeoutMs": 10000}, nil) }, q.busy),
			button("Details", func() { s.pushNode(nav, currentTag) }, q.busy)))
	}
	return ryui.Column(ryui.Style{Gap: 8, Padding: ryui.All(12), Background: ryui.Background, CornerRadius: 10}, nodes...)
}

func (s *session) pushNode(nav *ryui.Navigator, tag string) {
	nav.Push(func() ryui.Node {
		q := s.scope()
		return page(section("Node", ryui.StaticText(tag), actions(
			button("Status", func() { q.core("ccGetWireGuardStatus", object{"tag": tag}, nil) }, q.busy),
			button("Enable", func() { q.core("ccSetEndpointEnabled", object{"tag": tag, "enabled": true}, nil) }, q.busy),
			button("Disable", func() { q.core("ccSetEndpointEnabled", object{"tag": tag, "enabled": false}, nil) }, q.busy),
			button("Test", func() { q.core("ccUrlTestOutbound", object{"tag": tag, "link": "", "timeoutMs": 10000}, nil) }, q.busy),
			button("Pool", func() { q.core("ccGetPool", object{"tag": tag}, nil) }, q.busy)), q.feedback(), jsonView(q.result)))
	}, ryui.ScreenOptions{Title: ryui.Val(tag)})
}

func (s *session) sources() ryui.Node {
	q := s.scope()
	items := signal.NewFunc([]any{}, nil)
	filter := signal.New("")
	refresh := func() { q.run("sources.list", nil, func(r reply) { items.Set(listOf(r.value, "sources", "items")) }) }
	refresh()
	nav := ryui.UseNavigator()
	return page(section("Subscriptions & proxy", actions(
		primary("Add", func() { s.sourceEditor(nav, nil, refresh) }, q.busy),
		button("Import", func() {
			nav.Push(func() ryui.Node { return s.importSources(refresh) }, ryui.ScreenOptions{Title: ryui.Val(tr("Import"))})
		}, q.busy),
		button("Refresh", refresh, q.busy),
		button("Add server", func() { nav.Push(s.serverWizard, ryui.ScreenOptions{Title: ryui.Val(tr("Add server"))}) }, q.busy),
		button("Refresh all", func() { q.run("sources.refreshAll", nil, func(reply) { refresh() }) }, q.busy)),
		field("Filter", filter, false), q.feedback(),
		ryui.Dynamic(func() ryui.Node {
			var rows []ryui.Node
			query := strings.ToLower(filter.Get())
			for _, value := range items.Get() {
				item := asObject(value)
				if query != "" && !strings.Contains(strings.ToLower(pretty(item)), query) {
					continue
				}
				id := item["id"]
				rows = append(rows, section(nameOf(item),
					ryui.StaticText(text(item["kind"])+" · "+text(item["url"]), ryui.Style{Color: ryui.SecondaryLabel}),
					actions(button("Details", func() {
						nav.Push(func() ryui.Node { return s.sourceDetails(item) }, ryui.ScreenOptions{Title: ryui.Val(nameOf(item))})
					}, q.busy),
						button("Edit", func() { s.sourceEditor(nav, item, refresh) }, q.busy),
						button("Refresh", func() { q.run("sources.refresh", object{"id": id}, func(reply) { refresh() }) }, q.busy),
						button("Delete", func() {
							confirm("Delete source?", func() { q.run("sources.delete", object{"id": id}, func(reply) { refresh() }) })
						}, q.busy))))
			}
			if len(rows) == 0 {
				rows = append(rows, ryui.StaticText(tr("No data")))
			}
			return ryui.Column(ryui.Style{Gap: 12}, rows...)
		}), jsonView(q.result)))
}

func (s *session) sourceEditor(nav *ryui.Navigator, source object, onSaved func()) {
	nav.Push(func() ryui.Node {
		q := s.scope()
		copySource := object{}
		original := source
		if raw, ok := source["source"].(map[string]any); ok {
			original = raw
		}
		for k, v := range original {
			copySource[k] = v
		}
		name := signal.New(text(copySource["name"]))
		url := signal.New(text(copySource["url"]))
		kind := signal.New(text(copySource["kind"]))
		if kind.Peek() == "" {
			kind.Set("subscription")
		}
		enabled, exists := copySource["enabled"].(bool)
		if !exists {
			enabled = true
		}
		on := signal.New(enabled)
		prefix := signal.New(text(asObject(copySource["tag_policy"])["prefix"]))
		interval := signal.New(text(asObject(copySource["update"])["interval_hours"]))
		if interval.Peek() == "" {
			interval.Set("24")
		}
		updateAction := signal.New(text(copySource["on_update_action"]))
		if updateAction.Peek() == "" {
			updateAction.Set("rebuild")
		}
		body := signal.New(text(asObject(copySource["origin"])["raw"]))
		importRules := signal.New(pretty(copySource["import_rules"]))
		if importRules.Peek() == "null" {
			importRules.Set("[]")
		}
		rulesOn := signal.New(copySource["import_rules_enabled"] != false)
		raw := signal.New(pretty(copySource))
		save := func() {
			copySource["name"], copySource["url"], copySource["kind"], copySource["enabled"] = name.Peek(), url.Peek(), kind.Peek(), on.Peek()
			copySource["tag_policy"] = object{"prefix": prefix.Peek()}
			if kind.Peek() == "subscription" {
				hours, err := strconv.Atoi(interval.Peek())
				if err != nil || hours < 0 {
					q.err.Set(tr("Refresh interval must be a non-negative number of hours"))
					return
				}
				copySource["update"], copySource["on_update_action"] = object{"interval_hours": hours}, updateAction.Peek()
				copySource["import_rules"], copySource["import_rules_enabled"] = json.RawMessage(importRules.Peek()), rulesOn.Peek()
			} else if body.Peek() != "" {
				origin := asObject(copySource["origin"])
				origin["raw"] = body.Peek()
				if origin["kind"] == nil {
					origin["kind"] = "singbox"
				}
				copySource["origin"] = origin
			}
			q.run("sources.save", copySource, func(reply) { nav.Pop(); onSaved() })
		}
		return page(section("Source", field("Name", name, false), field("URL", url, false), choice("Type", kind, []string{"subscription", "server", "folder", "chain"}, []string{"Subscription", "Server", "Folder", "Chain"}),
			field("Tag prefix", prefix, false),
			ryui.Dynamic(func() ryui.Node {
				if kind.Get() == "subscription" {
					return ryui.Column(ryui.Style{Gap: 10}, field("Refresh interval (hours, 0 disables)", interval, false),
						choice("After automatic refresh", updateAction, []string{"rebuild", "reload", "none"}, []string{"Rebuild", "Reload VPN", "None"}),
						ryui.Row(ryui.Style{Gap: 10}, ryui.StaticText(tr("Import rules")), ryui.Toggle(ryui.ToggleProps{Value: rulesOn})),
						field("Import rules JSON", importRules, true), button("Add conditional rule", func() { s.addImportRule(nav, importRules) }, q.busy))
				}
				return field("Source text", body, true)
			}),
			ryui.Row(ryui.Style{Gap: 12}, ryui.StaticText(tr("Enabled")), ryui.Toggle(ryui.ToggleProps{Value: on})),
			primary("Save", save, q.busy), q.feedback()),
			section("Advanced", field("JSON", raw, true), button("Save JSON", func() {
				q.run("sources.save", json.RawMessage(raw.Peek()), func(reply) { nav.Pop(); onSaved() })
			}, q.busy)))
	}, ryui.ScreenOptions{Title: ryui.Val(tr("Edit source"))})
}

func (s *session) importSources(onSaved func()) ryui.Node {
	q := s.scope()
	name := signal.New("")
	input := signal.New("")
	nav := ryui.UseNavigator()
	return page(section("Import", actions(
		button("Open file…", func() { q.openDocument(func(raw string) { input.Set(raw) }) }, q.busy),
		button("Scan QR code", func() { s.scanQR(nav, func(raw string) { input.Set(raw) }) }, q.busy)), field("Name", name, false), field("Subscription URL, links or configuration", input, true),
		primary("Import", func() {
			q.run("sources.import", object{"text": input.Peek(), "name": name.Peek()}, func(reply) { onSaved() })
		},
			signal.Func(func() bool { return q.busy.Get() || strings.TrimSpace(input.Get()) == "" })), q.feedback(), jsonView(q.result)))
}

// jsonEditor is the real read/write fallback for complex launcher documents.
// It keeps the full JSON including unknown extension fields, supports local
// formatting, and delegates semantic validation and persistence to runtime.
func (s *session) jsonEditor(title, getMethod, saveMethod string, initial any, extra func(*scope, *signal.Signal[string]) []ryui.Node) ryui.Node {
	q := s.scope()
	draft := signal.New("")
	base := signal.New("")
	load := func() { q.run(getMethod, nil, func(r reply) { draft.Set(r.text); base.Set(r.text) }) }
	if getMethod != "" {
		load()
	} else if initial != nil {
		draft.Set(pretty(initial))
		base.Set(draft.Peek())
	}
	var buttons []ryui.Node
	if saveMethod != "" {
		buttons = append(buttons, primary("Save", func() {
			q.run(saveMethod, json.RawMessage(draft.Peek()), func(reply) { base.Set(draft.Peek()) })
		}, signal.Func(func() bool { return q.busy.Get() || strings.TrimSpace(draft.Get()) == "" })))
	}
	if getMethod != "" {
		buttons = append(buttons, button("Reload", func() {
			if draft.Peek() != base.Peek() {
				confirm("Discard changes?", load)
			} else {
				load()
			}
		}, q.busy))
	}
	buttons = append(buttons, button("Open file…", func() { q.openDocument(func(raw string) { draft.Set(raw) }) }, q.busy),
		button("Save to file…", func() { q.saveDocument("lxbox.json", draft.Peek()) }, q.busy),
		button("Format JSON", func() { q.formatJSON(draft) }, q.busy),
		button("Share", func() { ryui.Share(draft.Peek()) }, signal.Func(func() bool { return draft.Get() == "" })))
	if extra != nil {
		buttons = append(buttons, extra(q, draft)...)
	}
	return page(section(title, actions(buttons...),
		ryui.Text(signal.Func(func() string {
			if draft.Get() != base.Get() {
				return tr("Unsaved changes")
			}
			return ""
		}), ryui.Style{Color: ryui.Orange}),
		q.feedback(), field("JSON", draft, true)),
		section("Result", jsonView(q.result)))
}

func (q *scope) formatJSON(draft *signal.Signal[string]) {
	if q.busy.Peek() {
		return
	}
	input := draft.Peek()
	q.busy.Set(true)
	q.err.Set("")
	go func() {
		var value any
		decoder := json.NewDecoder(strings.NewReader(input))
		decoder.UseNumber()
		err := decoder.Decode(&value)
		if err == nil && decoder.Decode(new(any)) != io.EOF {
			err = io.ErrUnexpectedEOF
		}
		var formatted string
		if err == nil {
			formatted = pretty(value)
		}
		ryui.Post(func() {
			if q.ctx.Err() != nil {
				return
			}
			q.busy.Set(false)
			if err != nil {
				q.err.Set(err.Error())
				return
			}
			draft.Set(formatted)
		})
	}()
}

func (s *session) configuration() ryui.Node {
	return s.jsonEditor("Config Editor", "config.get", "config.save", nil, func(q *scope, draft *signal.Signal[string]) []ryui.Node {
		return []ryui.Node{
			button("Build", func() {
				q.run("config.build", nil, func(r reply) {
					if config := asObject(r.value)["config"]; config != nil {
						draft.Set(pretty(config))
					}
				})
			}, q.busy),
			button("Validate", func() { q.run("config.validate", json.RawMessage(draft.Peek()), nil) }, q.busy),
			button("Running config", func() {
				q.core("ccGetRunningConfig", nil, func(r reply) {
					if v, ok := r.value.(string); ok {
						draft.Set(v)
					} else {
						draft.Set(r.text)
					}
				})
			}, q.busy),
		}
	})
}

func (s *session) settings() ryui.Node {
	return s.preferences()
}

func (s *session) workspaces() ryui.Node {
	q := s.scope()
	items := signal.NewFunc([]any{}, nil)
	name := signal.New("")
	refresh := func() {
		q.run("workspaces.list", nil, func(r reply) { items.Set(listOf(r.value, "workspaces", "items")) })
	}
	refresh()
	return page(section("Workspaces", field("Name", name, false), actions(
		primary("Save workspace", func() { q.run("workspaces.save", object{"name": name.Peek()}, func(reply) { refresh() }) },
			signal.Func(func() bool { return q.busy.Get() || strings.TrimSpace(name.Get()) == "" })), button("Refresh", refresh, q.busy)), q.feedback(),
		ryui.Dynamic(func() ryui.Node {
			var rows []ryui.Node
			for _, value := range items.Get() {
				item := asObject(value)
				id := item["id"]
				label := nameOf(item)
				if item["current"] == true {
					label += " · " + tr("Current")
				}
				rows = append(rows, section(label, actions(
					button("Load", func() {
						confirm("Load workspace?", func() { q.run("workspaces.load", object{"id": id}, func(reply) { s.changedWorkspace() }) })
					}, q.busy),
					button("Delete", func() {
						confirm("Delete workspace?", func() { q.run("workspaces.delete", object{"id": id}, func(reply) { refresh() }) })
					}, q.busy))))
			}
			if len(rows) == 0 {
				rows = append(rows, ryui.StaticText(tr("No data")))
			}
			return ryui.Column(ryui.Style{Gap: 12}, rows...)
		})))
}

func (s *session) backup() ryui.Node {
	q := s.scope()
	data := signal.New("")
	replace := signal.New(false)
	format := signal.New("portable")
	categories := signal.NewFunc([]any{}, nil)
	selected := map[string]*signal.Signal[bool]{}
	q.run("backup.list", nil, func(r reply) {
		for _, value := range listOf(r.value, "categories") {
			id := text(asObject(value)["id"])
			selected[id] = signal.New(true)
		}
		categories.Set(listOf(r.value, "categories"))
	})
	chosen := func() []string {
		values := []string{}
		for id, on := range selected {
			if on.Peek() {
				values = append(values, id)
			}
		}
		return values
	}
	return page(section("Backup & Restore", choice("Format", format, []string{"portable", "snapshot"}, []string{"Portable LX backup", "Full snapshot"}), actions(
		primary("Export", func() {
			q.run("backup.export", object{"format": format.Peek(), "categories": chosen()}, func(r reply) { data.Set(text(asObject(r.value)["data"])) })
		}, q.busy),
		button("Open file…", func() { q.openDocument(func(raw string) { data.Set(raw) }) }, q.busy),
		button("Save to file…", func() { q.saveDocument("lxbox-backup.json", data.Peek()) }, signal.Func(func() bool { return q.busy.Get() || data.Get() == "" })),
		button("Share", func() { ryui.Share(data.Peek()) }, signal.Func(func() bool { return data.Get() == "" }))),
		field("Backup JSON", data, true),
		ryui.Dynamic(func() ryui.Node {
			var rows []ryui.Node
			for _, value := range categories.Get() {
				item := asObject(value)
				id := text(item["id"])
				rows = append(rows, ryui.Row(ryui.Style{Gap: 10}, ryui.StaticText(id+" ("+text(item["count"])+")", ryui.Style{Grow: 1}), ryui.Toggle(ryui.ToggleProps{Value: selected[id]})))
			}
			return ryui.Column(ryui.Style{Gap: 8}, rows...)
		}),
		ryui.Row(ryui.Style{Gap: 12}, ryui.StaticText(tr("Replace existing data")), ryui.Toggle(ryui.ToggleProps{Value: replace})),
		button("Preview", func() {
			q.run("backup.preview", object{"data": data.Peek(), "categories": chosen(), "replace": replace.Peek()}, nil)
		}, q.busy),
		button("Restore", func() {
			confirm("Restore backup?", func() {
				q.run("backup.import", object{"data": data.Peek(), "replace": replace.Peek(), "categories": chosen()}, func(reply) { s.changedWorkspace() })
			})
		}, signal.Func(func() bool { return q.busy.Get() || strings.TrimSpace(data.Get()) == "" })), q.feedback(), jsonView(q.result)))
}
