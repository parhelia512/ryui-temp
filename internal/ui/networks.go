package ui

import (
	"strconv"
	"strings"

	"github.com/egoist/ryui/signal"
	ryui "github.com/egoist/ryui/ui"
)

func (s *session) tailscale() ryui.Node {
	q := s.scope()
	tag := signal.New("")
	key := signal.New("")
	exit := signal.New("")
	peerIP := signal.New("")
	status := signal.NewFunc[any](nil, nil)
	return page(section("Tailscale", field("Endpoint tag", tag, false), actions(
		primary("Refresh", func() {
			q.core("ccGetTailscaleStatus", object{"tag": tag.Peek()}, func(r reply) { status.Set(r.value) })
		}, q.busy),
		button("Enable", func() { q.core("ccSetEndpointEnabled", object{"tag": tag.Peek(), "enabled": true}, nil) }, q.busy),
		button("Disable", func() { q.core("ccSetEndpointEnabled", object{"tag": tag.Peek(), "enabled": false}, nil) }, q.busy)),
		secret("Auth key", key), actions(
			button("Log in", func() {
				q.core("ccTailscaleLogin", object{"tag": tag.Peek(), "auth_key": key.Peek()}, func(reply) { key.Set("") })
			}, q.busy),
			button("Log out", func() { confirm("Log out?", func() { q.core("ccTailscaleLogout", object{"tag": tag.Peek()}, nil) }) }, q.busy)),
		field("Exit node ID", exit, false), button("Set exit node", func() { q.core("ccSetTailscaleExitNode", object{"tag": tag.Peek(), "stable_id": exit.Peek()}, nil) }, q.busy),
		field("Peer IP", peerIP, false), actions(
			button("Ping", func() { q.core("ccStartTailscalePing", object{"tag": tag.Peek(), "peer_ip": peerIP.Peek()}, nil) }, q.busy),
			button("Stop ping", func() { q.core("ccStopTailscalePing", nil, nil) }, q.busy)), q.feedback(), jsonView(q.result)),
		ryui.Dynamic(func() ryui.Node {
			var nodes []ryui.Node
			snapshotValue := status.Get()
			if auth := text(first(asObject(snapshotValue), "authUrl", "auth_url")); auth != "" {
				nodes = append(nodes, button("Open sign-in page", func() { ryui.OpenURL(auth) }, q.busy))
			}
			peers := append([]any{}, listOf(snapshotValue, "peers", "devices")...)
			for _, group := range listOf(status.Get(), "userGroups", "user_groups") {
				peers = append(peers, listOf(group, "peers")...)
			}
			for _, value := range peers {
				peer := asObject(value)
				stableID := text(first(peer, "stable_id", "stableId", "id"))
				nodes = append(nodes, section(nameOf(peer), ryui.StaticText(pretty(peer), ryui.Style{Font: ryui.Footnote}),
					button("Use as exit node", func() {
						exit.Set(stableID)
						q.core("ccSetTailscaleExitNode", object{"tag": tag.Peek(), "stable_id": stableID}, nil)
					}, q.busy)))
			}
			return ryui.Column(ryui.Style{Gap: 10}, nodes...)
		}),
		s.eventPanel("Network events", func(kind string) bool { return strings.Contains(kind, "tailscale") }))
}

func (s *session) taildrop() ryui.Node {
	q := s.scope()
	tag := signal.New("")
	peer := signal.New("")
	peerName := signal.New("")
	message := signal.New("")
	inbox := signal.NewFunc[any](nil, nil)
	s.clientEvents(q, "taildrop.inbox", func(value any) { inbox.Set(value) })
	refresh := func() {
		q.core("ccTaildropInboxSnapshot", object{"tag": tag.Peek()}, func(r reply) {
			if asObject(r.value)["files"] != nil {
				inbox.Set(r.value)
			}
		})
	}
	return page(section("Taildrop", field("Endpoint tag", tag, false), actions(
		primary("Refresh inbox", refresh, q.busy),
		button("Mark read", func() { q.core("ccTaildropMarkRead", object{"tag": tag.Peek()}, nil) }, q.busy)),
		field("Peer ID", peer, false), field("Peer name", peerName, false),
		button("Send file…", func() {
			q.core("ccTaildropPickAndSend", object{"tag": tag.Peek(), "peer_id": peer.Peek(), "peer_name": peerName.Peek()}, nil)
		}, q.busy),
		field("Message", message, true), button("Send text", func() {
			q.core("ccTaildropSendBytes", object{"tag": tag.Peek(), "peer_id": peer.Peek(), "peer_name": peerName.Peek(), "text": message.Peek(), "wait_ms": 60000}, nil)
		}, q.busy), q.feedback(), jsonView(q.result)),
		ryui.Dynamic(func() ryui.Node {
			var nodes []ryui.Node
			for _, value := range listOf(inbox.Get(), "files", "items") {
				item := asObject(value)
				name := text(item["name"])
				nodes = append(nodes, section(name, ryui.StaticText(pretty(item), ryui.Style{Font: ryui.Footnote}), actions(
					button("Save", func() { q.core("ccTaildropSave", object{"tag": tag.Peek(), "name": name}, func(reply) { refresh() }) }, q.busy),
					button("Delete", func() {
						confirm("Delete file?", func() { q.core("ccTaildropDelete", object{"tag": tag.Peek(), "name": name}, func(reply) { refresh() }) })
					}, q.busy))))
			}
			for _, value := range listOf(inbox.Get(), "receiving") {
				item := asObject(value)
				nodes = append(nodes, section(nameOf(item), ryui.StaticText(pretty(item)), button("Cancel transfer", func() {
					q.core("ccTaildropCancelReceiving", object{"tag": tag.Peek(), "name": item["name"], "sender_id": first(item, "sender_id", "senderId")}, nil)
				}, q.busy)))
			}
			return ryui.Column(ryui.Style{Gap: 10}, nodes...)
		}), s.eventPanel("Transfer events", func(kind string) bool { return strings.Contains(kind, "taildrop") }))
}

func (s *session) openConnect() ryui.Node {
	q := s.scope()
	snapshot := signal.NewFunc[any](nil, nil)
	s.clientEvents(q, "openconnect.status", func(value any) { snapshot.Set(value) })
	refresh := func() {
		q.core("ccGetOpenConnectStatus", nil, func(r reply) {
			if asObject(r.value)["endpoints"] != nil {
				snapshot.Set(r.value)
			}
		})
	}
	refresh()
	return page(section("OpenConnect", button("Refresh", refresh, q.busy), q.feedback()),
		ryui.Dynamic(func() ryui.Node {
			var nodes []ryui.Node
			for _, value := range listOf(snapshot.Get(), "endpoints") {
				item := asObject(value)
				tag := text(first(item, "tag", "endpointTag"))
				challenge := asObject(item["challenge"])
				id := text(challenge["id"])
				var fields []ryui.Node
				fields = append(fields, ryui.StaticText(text(first(item, "state_text", "stateText", "state"))), ryui.StaticText(text(challenge["banner"])), ryui.StaticText(text(challenge["message"])))
				var entries []object
				var inputs []*signal.Signal[string]
				for _, fv := range listOf(challenge, "form", "fields") {
					f := asObject(fv)
					input := signal.New(text(f["value"]))
					inputKey := text(first(f, "submission_key", "name"))
					label := text(first(f, "label", "name"))
					entries = append(entries, object{"key": inputKey})
					inputs = append(inputs, input)
					if text(f["kind"]) == "password" {
						fields = append(fields, secret(label, input))
					} else {
						fields = append(fields, field(label, input, false))
					}
					if choices := listOf(f, "options"); len(choices) > 0 {
						var buttons []ryui.Node
						for _, cv := range choices {
							c := asObject(cv)
							option := text(c["value"])
							buttons = append(buttons, button(text(first(c, "label", "value")), func() { input.Set(option) }, q.busy))
						}
						fields = append(fields, actions(buttons...))
					}
				}
				if len(inputs) > 0 {
					fields = append(fields, primary("Submit", func() {
						values := make([]object, len(entries))
						for i, entry := range entries {
							values[i] = object{"key": entry["key"], "value": inputs[i].Peek()}
						}
						q.core("ccSubmitOpenConnectForm", object{"tag": tag, "challenge_id": id, "values": values}, func(reply) { refresh() })
					}, q.busy))
				}
				browser := asObject(challenge["browser"])
				if url := text(browser["url"]); url != "" {
					port := signal.New("29786")
					fields = append(fields, field("Callback port", port, false), actions(
						button("Open sign-in page", func() { ryui.OpenURL(url) }, q.busy),
						button("Start callback listener", func() {
							p, err := strconv.Atoi(port.Peek())
							if err != nil {
								q.err.Set(err.Error())
								return
							}
							q.core("ccStartOpenConnectCallback", object{"tag": tag, "challenge_id": id, "port": p, "prefixes": browser["callback_url_prefixes"]}, nil)
						}, q.busy), button("Stop callback listener", func() { q.core("ccStopOpenConnectCallback", nil, nil) }, q.busy)))
				}
				if id != "" {
					fields = append(fields, button("Cancel challenge", func() {
						q.core("ccCancelOpenConnectChallenge", object{"tag": tag, "challenge_id": id}, func(reply) { refresh() })
					}, q.busy))
				}
				nodes = append(nodes, section(tag, fields...))
			}
			if len(nodes) == 0 {
				nodes = append(nodes, ryui.StaticText(tr("No pending challenges")))
			}
			return ryui.Column(ryui.Style{Gap: 12}, nodes...)
		}), section("Result", jsonView(q.result)))
}

func (s *session) warp() ryui.Node {
	q := s.scope()
	license := signal.New("")
	endpoint := signal.New("")
	result := signal.New("")
	masque := signal.New(false)
	obfuscate := signal.New(false)
	register := func() {
		method := "warp.register"
		if masque.Peek() {
			method = "warp.register.masque"
		}
		q.run(method, object{"license": license.Peek(), "endpoint": endpoint.Peek(), "obfuscate": obfuscate.Peek()}, func(r reply) { result.Set(r.text) })
	}
	importAccount := func() {
		method := "warp.account.uri"
		if masque.Peek() {
			method = "warp.masque.uri"
		}
		q.run(method, object{"account_json": result.Peek(), "include_reserved": true}, func(r reply) {
			q.run("sources.import", object{"text": text(asObject(r.value)["uri"]), "name": "WARP"}, nil)
		})
	}
	return page(section("WARP", secret("License key", license), field("Endpoint", endpoint, false),
		ryui.Row(ryui.Style{Gap: 10}, ryui.StaticText(tr("MASQUE")), ryui.Toggle(ryui.ToggleProps{Value: masque})),
		ryui.Row(ryui.Style{Gap: 10}, ryui.StaticText(tr("Amnezia obfuscation")), ryui.Toggle(ryui.ToggleProps{Value: obfuscate})),
		actions(primary("Register", register, q.busy), button("Random endpoint", func() {
			q.run("warp.endpoint.random", nil, func(r reply) { endpoint.Set(text(asObject(r.value)["endpoint"])) })
		}, q.busy)),
		q.feedback(), field("Account JSON", result, true), actions(
			button("Import", importAccount, signal.Func(func() bool { return q.busy.Get() || result.Get() == "" })),
			button("Share", func() { ryui.Share(result.Peek()) }, signal.Func(func() bool { return result.Get() == "" }))), jsonView(q.result)))
}

func secret(label string, value *signal.Signal[string]) ryui.Node {
	return ryui.Column(ryui.Style{Gap: 5}, ryui.StaticText(tr(label), ryui.Style{Font: ryui.Footnote, Color: ryui.SecondaryLabel}),
		ryui.TextField(ryui.TextFieldProps{Value: value, Placeholder: ryui.Val(tr(label)), Secure: true, Autocapitalize: ryui.CapitalizeNone, Autocorrect: ryui.AutocorrectNo}))
}

func first(v object, keys ...string) any {
	for _, key := range keys {
		if value := v[key]; value != nil && text(value) != "" {
			return value
		}
	}
	return nil
}
