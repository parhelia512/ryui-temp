package ui

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/egoist/ryui/signal"
	ryui "github.com/egoist/ryui/ui"
)

func (s *session) deviceTransfer() ryui.Node {
	q := s.scope()
	code := signal.New("")
	data := signal.New("")
	name := signal.New("LxBox")
	receiving := signal.New(false)
	status := signal.New("")
	preview := signal.New("")
	replace := signal.New(false)
	var after uint64
	signal.Effect(func() {
		for _, e := range s.events.Get() {
			if e.ID <= after {
				continue
			}
			after = e.ID
			if e.Type != "transfer.received" || !receiving.Get() {
				continue
			}
			var value object
			if json.Unmarshal(e.Data, &value) != nil {
				continue
			}
			status.Set(text(value["status"]))
			if text(value["status"]) == "received" {
				data.Set(text(value["data"]))
				preview.Set(pretty(value["preview"]))
			}
			receiving.Set(false)
		}
	})
	signal.OnCleanup(func() {
		if receiving.Peek() {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, _ = dispatch(ctx, "transfer.receive.stop", nil)
			}()
		}
	})
	nav := ryui.UseNavigator()
	return page(section("Device transfer", field("Device name", name, false), actions(
		primary("Receive", func() {
			q.run("transfer.receive.start", object{"name": name.Peek()}, func(r reply) {
				code.Set(text(asObject(r.value)["code"]))
				receiving.Set(true)
				status.Set(tr("Waiting for transfer"))
			})
		}, signal.Func(func() bool { return q.busy.Get() || receiving.Get() })),
		button("Stop receiving", func() { q.run("transfer.receive.stop", nil, func(reply) { receiving.Set(false) }) }, q.busy)),
		field("Transfer code", code, true), actions(button("Scan QR code", func() { s.scanQR(nav, func(raw string) { code.Set(raw) }) }, q.busy), button("Share code", func() { ryui.Share(code.Peek()) }, signal.Func(func() bool { return code.Get() == "" }))),
		ryui.Text(status), q.feedback()),
		section("Send backup", actions(button("Export backup", func() {
			q.run("backup.export", object{"format": "portable"}, func(r reply) { data.Set(text(asObject(r.value)["data"])) })
		}, q.busy),
			button("Send", func() {
				q.run("transfer.send_backup", object{"code": strings.TrimSpace(code.Peek()), "data": data.Peek()}, nil)
			}, signal.Func(func() bool { return q.busy.Get() || code.Get() == "" || data.Get() == "" }))),
			field("Backup JSON", data, true)),
		section("Review received backup", button("Preview", func() { q.run("backup.preview", object{"data": data.Peek()}, func(r reply) { preview.Set(r.text) }) }, q.busy), jsonView(preview),
			ryui.Row(ryui.Style{Gap: 10}, ryui.StaticText(tr("Replace existing data")), ryui.Toggle(ryui.ToggleProps{Value: replace})),
			button("Restore", func() {
				confirm("Restore received backup?", func() {
					q.run("backup.import", object{"data": data.Peek(), "replace": replace.Peek()}, func(reply) { s.changedWorkspace() })
				})
			}, signal.Func(func() bool { return q.busy.Get() || data.Get() == "" }))),
		section("Result", jsonView(q.result)))
}
