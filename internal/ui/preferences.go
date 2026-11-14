package ui

import (
	"github.com/egoist/ryui/signal"
	ryui "github.com/egoist/ryui/ui"
	"strconv"
)

func (s *session) preferences() ryui.Node {
	q := s.scope()
	doc := object{}
	language := signal.New("system")
	theme := signal.New("system")
	keys := []string{"auto_start", "keep_on_exit", "core_logs_enabled", "core_logs_verbose", "allow_bypass", "auto_redirect", "notification_stop", "notification_restart", "notification_send"}
	labels := []string{"Start on boot", "Keep VPN on exit", "Core logs", "Verbose core logs", "Allow VPN bypass", "Auto redirect", "Stop notification action", "Restart notification action", "Send notification action"}
	values := make([]*signal.Signal[bool], len(keys))
	for i := range values {
		values[i] = signal.New(false)
	}
	background := signal.New("never")
	memory := signal.New("auto")
	budget := signal.New("1000")
	load := func() {
		q.run("settings.get", nil, func(r reply) {
			doc = asObject(r.value)
			if value := text(doc["node_budget"]); value != "" {
				budget.Set(value)
			}
			language.Set(text(asObject(doc["vars"])["app_language"]))
			if language.Peek() == "" {
				language.Set("system")
			}
			prefs := asObject(doc["native_prefs"])
			theme.Set(text(prefs["app_theme_mode"]))
			if theme.Peek() == "" {
				theme.Set("system")
			}
			background.Set(text(prefs["background_mode"]))
			if background.Peek() == "" {
				background.Set("never")
			}
			memory.Set(text(prefs["memory_limit"]))
			if memory.Peek() == "" {
				memory.Set("auto")
			}
			for i, key := range keys {
				value, ok := prefs[key].(bool)
				if !ok {
					value = key == "keep_on_exit" || key == "notification_stop" || key == "notification_restart" || key == "notification_send"
				}
				values[i].Set(value)
			}
		})
	}
	load()
	save := func() {
		limit, err := strconv.Atoi(budget.Peek())
		if err != nil || limit < 1 {
			q.err.Set(tr("Node budget must be a positive integer"))
			return
		}
		// Re-read at commit so toggles do not overwrite concurrently refreshed
		// sources or unrelated settings written while this form was open.
		q.run("settings.get", nil, func(r reply) {
			doc = asObject(r.value)
			vars := asObject(doc["vars"])
			prefs := asObject(doc["native_prefs"])
			vars["app_language"] = language.Peek()
			prefs["app_theme_mode"] = theme.Peek()
			prefs["background_mode"] = background.Peek()
			prefs["memory_limit"] = memory.Peek()
			for i, key := range keys {
				prefs[key] = values[i].Peek()
			}
			q.run("settings.save", object{"vars": vars, "native_prefs": prefs, "node_budget": limit}, func(reply) {
				doc["vars"], doc["native_prefs"] = vars, prefs
				s.applyPreferences(doc)
			})
		})
	}
	var rows []ryui.Node
	for i, label := range labels {
		rows = append(rows, ryui.Row(ryui.Style{Gap: 12, Align: ryui.AlignCenter}, ryui.StaticText(tr(label), ryui.Style{Grow: 1}), ryui.Toggle(ryui.ToggleProps{Value: values[i]})))
	}
	nav := ryui.UseNavigator()
	return page(section("Appearance", choice("Language", language, []string{"system", "en", "ru", "zh"}, []string{"System", "English", "Russian", "Chinese"}),
		choice("Theme", theme, []string{"system", "light", "dark"}, []string{"System", "Light", "Dark"})),
		section("General", append(rows, field("Node budget", budget, false))...), section("Background", choice("Background mode", background, []string{"never", "lazy", "always"}, []string{"Never", "When needed", "Always"}), field("Memory limit (MB, auto or off)", memory, false)),
		section("App Settings", actions(primary("Save", save, q.busy), button("Reload", load, q.busy),
			button("JSON", func() {
				nav.Push(func() ryui.Node {
					return s.jsonEditor("App Settings", "settings.get", "settings.save", nil, func(q *scope, draft *signal.Signal[string]) []ryui.Node {
						return []ryui.Node{button("Apply appearance", func() {
							q.run("settings.get", nil, func(r reply) { s.applyPreferences(asObject(r.value)) })
						}, q.busy)}
					})
				}, ryui.ScreenOptions{Title: ryui.Val(tr("App Settings"))})
			}, q.busy)), q.feedback(), jsonView(q.result)))
}

func choice(label string, selected *signal.Signal[string], keys, labels []string) ryui.Node {
	var buttons []ryui.Node
	for i, key := range keys {
		value := key
		buttons = append(buttons, button(labels[i], func() { selected.Set(value) }, signal.Func(func() bool { return selected.Get() == value })))
	}
	return ryui.Column(ryui.Style{Gap: 6}, ryui.StaticText(tr(label), ryui.Style{Font: ryui.Footnote}), actions(buttons...))
}
