package ui

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/egoist/ryui/signal"
	ryui "github.com/egoist/ryui/ui"
)

func (s *session) addImportRule(nav *ryui.Navigator, rules *signal.Signal[string]) {
	nav.Push(func() ryui.Node {
		q := s.scope()
		path := signal.New("tag")
		op := signal.New("contains")
		pattern := signal.New("")
		negate := signal.New(false)
		caseSensitive := signal.New(false)
		action := signal.New("disable")
		target := signal.New("tag")
		replacement := signal.New("")
		mode := signal.New("set")
		return page(section("Conditional import rule", field("Field path", path, false),
			choice("Operator", op, []string{"contains", "equals", "matches"}, []string{"Contains", "Equals", "Regex"}),
			field("Pattern", pattern, false),
			ryui.Row(ryui.Style{Gap: 12}, ryui.StaticText(tr("Negate")), ryui.Toggle(ryui.ToggleProps{Value: negate})),
			ryui.Row(ryui.Style{Gap: 12}, ryui.StaticText(tr("Case sensitive")), ryui.Toggle(ryui.ToggleProps{Value: caseSensitive})),
			choice("Action", action, []string{"disable", "enable", "replace"}, []string{"Disable", "Enable", "Replace"}),
			ryui.Show(signal.Func(func() bool { return action.Get() == "replace" }), func() ryui.Node {
				return ryui.Column(ryui.Style{Gap: 10}, field("Target path", target, false), field("Replacement", replacement, false),
					choice("Replace mode", mode, []string{"set", "substitute"}, []string{"Set", "Substitute"}))
			}),
			primary("Add rule", func() {
				input := rules.Peek()
				rule := object{"conditions": []any{object{"path": path.Peek(), "op": op.Peek(), "pattern": pattern.Peek(), "negate": negate.Peek(), "case_sensitive": caseSensitive.Peek()}}, "action": action.Peek()}
				if action.Peek() == "replace" { rule["target_path"], rule["replacement"], rule["replace_mode"] = target.Peek(), replacement.Peek(), mode.Peek() }
				q.work(func(context.Context) (reply, error) {
					var entries []any
					if err := json.Unmarshal([]byte(input), &entries); err != nil { return reply{}, err }
					entries = append(entries, rule)
					return reply{value: entries, text: pretty(entries)}, nil
				}, func(r reply) { rules.Set(r.text); nav.Pop() })
			}, signal.Func(func() bool { return q.busy.Get() || strings.TrimSpace(pattern.Get()) == "" })), q.feedback()))
	}, ryui.ScreenOptions{Title: ryui.Val(tr("Conditional import rule"))})
}

func (q *scope) previewBackup(data *signal.Signal[string]) {
	q.run("backup.preview", object{"data": data.Peek()}, nil)
}

// Reports is a native, discoverable entry into saved crash/OOM diagnostics.
// Runtime owns file validation and pprof capture, including all disk work.
func (s *session) reports() ryui.Node {
	q := s.scope()
	items := signal.NewFunc([]any{}, nil)
	typeName := signal.New("all")
	profile := signal.New("heap")
	artifact := signal.New("")
	refresh := func() { q.run("reports.list", object{"kind": typeName.Peek()}, func(r reply) { items.Set(listOf(r.value, "reports", "items")) }) }
	refresh()
	return page(section("Reports", choice("Report type", typeName, []string{"all", "crash", "oom"}, []string{"All", "Crashes", "Out of memory"}),
		choice("Profile",profile,[]string{"heap","allocs","goroutine","profile","block","mutex","threadcreate"},[]string{"Heap","Allocations","Goroutines","CPU","Blocking","Mutex","Threads"}), actions(
		button("Refresh", refresh, q.busy), button("Memory", func() { q.run("memory.get", nil, nil) }, q.busy),
		button("Capture pprof", func() { q.run("pprof.capture", object{"kind": profile.Peek()}, func(r reply){artifact.Set(text(asObject(r.value)["data"]))}) }, q.busy),
		button("Save profile…",func(){q.run("transfer.saf.export",object{"payload":object{"kind":"file","name":profile.Peek()+".pprof","mime":"application/octet-stream","bytes":artifact.Peek()}},nil)},signal.Func(func()bool{return q.busy.Get()||artifact.Get()==""}))), q.feedback()),
		ryui.Dynamic(func() ryui.Node {
			var nodes []ryui.Node
			for _, value := range items.Get() {
				item := asObject(value)
				if typeName.Get()!="all" && text(item["kind"])!=typeName.Get(){continue}
				id := first(item, "id", "name", "path")
				args := object{"id": id, "name": id, "kind": first(item, "kind", "type")}
				nodes = append(nodes, section(nameOf(item), ryui.StaticText(pretty(item), ryui.Style{Font: ryui.Footnote}), actions(
					button("Read", func() { q.run("reports.read", args, nil) }, q.busy),
					button("Share", func() { q.run("reports.share", args, func(r reply) { if content := text(asObject(r.value)["data"]); content != "" { ryui.Share(content) } }) }, q.busy),
					button("Delete", func() { confirm("Delete report?", func() { q.run("reports.delete", args, func(reply) { refresh() }) }) }, q.busy))))
			}
			return ryui.Column(ryui.Style{Gap: 10}, nodes...)
		}), section("Result", jsonView(q.result)))
}
