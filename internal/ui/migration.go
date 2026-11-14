package ui

import (
	"github.com/egoist/ryui/signal"
	ryui "github.com/egoist/ryui/ui"
)

func (s *session) migration() ryui.Node {
	q := s.scope()
	status := signal.New("")
	refresh := func() { q.run("storage.status", nil, func(r reply) { status.Set(r.text) }) }
	refresh()
	return page(section("Data migration", jsonView(status), actions(
		button("Refresh", refresh, q.busy),
		primary("Migrate saved data", func() { confirm("Migrate saved data?", func() { q.run("storage.migrate", nil, func(reply) { s.changedWorkspace() }) }) }, q.busy),
		button("Recover corrupt settings", func() { confirm("Recover corrupt settings?", func() { q.run("storage.recover", object{"corrupt_settings": true}, func(reply) { s.changedWorkspace() }) }) }, q.busy)), q.feedback(), jsonView(q.result)))
}
