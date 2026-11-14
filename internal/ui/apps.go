package ui

import (
	"sort"
	"strings"

	"github.com/egoist/ryui/signal"
	ryui "github.com/egoist/ryui/ui"
)

func (s *session) appPicker() ryui.Node {
	q := s.scope()
	apps := signal.NewFunc([]any{}, nil)
	selected := signal.NewFunc(map[string]bool{}, nil)
	query := signal.New("")
	system := signal.New(false)
	mode := signal.New("off")
	config := object{}
	loadApps := func() {
		q.run("platform.call", object{"method": "apps.list", "args": object{}}, func(r reply) { apps.Set(listOf(r.value, "apps", "items")) })
	}
	q.run("settings.get", nil, func(r reply) {
		config = asObject(asObject(r.value)["tun_apps"])
		if v := text(config["mode"]); v != "" {
			mode.Set(v)
		}
		values := map[string]bool{}
		for _, value := range listOf(config, "packages") {
			values[text(value)] = true
		}
		selected.Set(values)
		loadApps()
	})
	save := func() {
		packages := []string{}
		for name, on := range selected.Peek() {
			if on {
				packages = append(packages, name)
			}
		}
		sort.Strings(packages)
		config["mode"], config["packages"] = mode.Peek(), packages
		q.run("settings.save", object{"tun_apps": config}, nil)
	}
	return ryui.SafeArea(ryui.Style{Grow: 1, Gap: 10, Padding: ryui.All(12)},
		choice("Tunnel apps", mode, []string{"off", "allow", "deny"}, []string{"Off", "Allow-list", "Deny-list"}),
		field("Search apps", query, false),
		ryui.Row(ryui.Style{Gap: 10, Align: ryui.AlignCenter}, ryui.StaticText(tr("Show system apps")), ryui.Toggle(ryui.ToggleProps{Value: system})),
		actions(primary("Save", save, q.busy), button("Refresh", loadApps, q.busy), button("Clear selection", func() { selected.Set(map[string]bool{}) }, q.busy)),
		ryui.Text(signal.Func(func() string { return tr("Selected") + ": " + text(len(selected.Get())) }), ryui.Style{Font: ryui.Footnote}), q.feedback(),
		ryui.List(ryui.ListProps{}, signal.Func(func() []any {
			var items []any
			search := strings.ToLower(query.Get())
			for _, value := range apps.Get() {
				item := asObject(value)
				if !system.Get() && item["system"] == true && !selected.Get()[text(item["packageName"])] {
					continue
				}
				if search != "" && !strings.Contains(strings.ToLower(text(item["label"])+" "+text(item["packageName"])), search) {
					continue
				}
				items = append(items, value)
			}
			return items
		}), func(value any) string { return text(asObject(value)["packageName"]) }, func(item signal.Accessor[any], _ signal.Accessor[int]) ryui.Node {
			return ryui.View(ryui.ViewProps{Style: ryui.Style{Padding: ryui.All(10), Gap: 4}, OnPress: func() {
				pkg := text(asObject(item.Get())["packageName"])
				selected.Update(func(old map[string]bool) map[string]bool {
					next := map[string]bool{}
					for k, v := range old {
						next[k] = v
					}
					if next[pkg] {
						delete(next, pkg)
					} else {
						next[pkg] = true
					}
					return next
				})
			}}, ryui.Text(signal.Func(func() string {
				v := asObject(item.Get())
				prefix := ""
				if selected.Get()[text(v["packageName"])] {
					prefix = "[x] "
				}
				return prefix + text(v["label"])
			}), ryui.Style{Font: ryui.Headline}),
				ryui.Text(signal.Func(func() string { v := asObject(item.Get()); return text(v["packageName"]) + " · UID " + text(v["uid"]) }), ryui.Style{Font: ryui.Footnote, Color: ryui.SecondaryLabel}))
		}))
}
