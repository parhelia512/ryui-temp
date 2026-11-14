package core

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/sagernet/sing-box/experimental/libbox"
)

func (c *Controller) disposeClient(scope string) error {
	if scope == "" {
		return errors.New("client_id is required")
	}
	prefix := scope + "|"
	c.clientMu.Lock()
	entry := c.clients[scope]
	delete(c.clients, scope)
	var pings []*libbox.TailscalePingSession
	var inboxes []*libbox.TaildropInboxSubscription
	var opens []*libbox.OpenConnectStatusSubscription
	var tests []*libbox.ConnectionTestSession
	for key, session := range c.pingSessions {
		if strings.HasPrefix(key, prefix) {
			pings = append(pings, session)
			delete(c.pingSessions, key)
		}
	}
	for key, session := range c.inboxSessions {
		if strings.HasPrefix(key, prefix) {
			inboxes = append(inboxes, session)
			delete(c.inboxSessions, key)
		}
	}
	for key, session := range c.openSessions {
		if strings.HasPrefix(key, prefix) {
			opens = append(opens, session)
			delete(c.openSessions, key)
		}
	}
	for key, session := range c.probeSessions {
		if strings.HasPrefix(key, prefix) {
			tests = append(tests, session)
			delete(c.probeSessions, key)
		}
	}
	c.clientMu.Unlock()
	for _, session := range pings {
		_ = session.Close()
	}
	for _, session := range inboxes {
		_ = session.Close()
	}
	for _, session := range opens {
		_ = session.Close()
	}
	for _, session := range tests {
		_ = session.Close()
	}
	if entry != nil {
		return entry.close()
	}
	return nil
}

func (c *Controller) startTailscalePing(cc *libbox.CommandClient, closeClient func() error, tag, peerIP, scope string) (any, error) {
	if scope == "" {
		return nil, errors.New("client_id is required")
	}
	key := scope + "|tailscale.ping"
	s, err := cc.StartTailscalePing(tag, peerIP, &tailscalePingHandler{emit: func(kind string, data any) { c.emitClient(scope, kind, data) }})
	if err != nil {
		_ = closeClient()
		return nil, err
	}
	c.clientMu.Lock()
	old := c.pingSessions[key]
	c.pingSessions[key] = s
	c.clientMu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return map[string]any{"session_id": scope}, nil
}
func (c *Controller) stopTailscalePing(scope string) error {
	return c.closePing(scope + "|tailscale.ping")
}
func (c *Controller) closePing(key string) error {
	c.clientMu.Lock()
	s := c.pingSessions[key]
	delete(c.pingSessions, key)
	c.clientMu.Unlock()
	if s != nil {
		return s.Close()
	}
	return nil
}

type tailscalePingHandler struct{ emit func(string, any) }

func (h *tailscalePingHandler) OnPingResult(v *libbox.TailscalePingResult) {
	if v == nil {
		return
	}
	h.emit("tailscale.ping.result", map[string]any{"latencyMs": v.LatencyMs, "isDirect": v.IsDirect, "endpoint": v.Endpoint, "peerRelay": v.PeerRelay, "derpRegionId": v.DERPRegionID, "derpRegionCode": v.DERPRegionCode, "error": v.Error})
}
func (h *tailscalePingHandler) OnError(s string) {
	h.emit("tailscale.ping.error", map[string]any{"message": s})
}

func (c *Controller) startTaildropInbox(cc *libbox.CommandClient, closeClient func() error, tag, scope string) (any, error) {
	if scope == "" {
		return nil, errors.New("client_id is required")
	}
	key := scope + "|taildrop.inbox"
	s, err := cc.SubscribeTaildropInbox(tag, &taildropInboxHandler{emit: func(data any) { c.emitClient(scope, "taildrop.inbox", data) }, error: func(msg string) { c.emitClient(scope, "taildrop.error", map[string]any{"message": msg}) }})
	if err != nil {
		_ = closeClient()
		return nil, err
	}
	c.clientMu.Lock()
	old := c.inboxSessions[key]
	c.inboxSessions[key] = s
	c.clientMu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return map[string]any{"session_id": scope}, nil
}

type taildropInboxHandler struct {
	emit  func(any)
	error func(string)
}

func (h *taildropInboxHandler) OnInboxUpdate(v *libbox.TaildropInbox) { h.emit(taildropInboxJSON(v)) }
func (h *taildropInboxHandler) OnError(msg string)                    { h.error(msg) }
func taildropInboxJSON(v *libbox.TaildropInbox) any {
	if v == nil {
		return nil
	}
	files := []any{}
	fi := v.Files()
	for fi != nil && fi.HasNext() {
		f := fi.Next()
		if f != nil {
			files = append(files, map[string]any{"name": f.Name, "size": f.Size, "senderName": f.SenderName, "modifiedAt": f.ModifiedAt, "senderId": f.SenderID})
		}
	}
	receiving := []any{}
	ri := v.Receiving()
	for ri != nil && ri.HasNext() {
		f := ri.Next()
		if f != nil {
			receiving = append(receiving, map[string]any{"name": f.Name, "size": f.Size, "receivedBytes": f.ReceivedBytes, "senderId": f.SenderID, "senderName": f.SenderName})
		}
	}
	return map[string]any{"endpointTag": v.EndpointTag, "files": files, "receiving": receiving}
}

func (c *Controller) startOpenConnectStatus(cc *libbox.CommandClient, closeClient func() error, scope string) (any, error) {
	if scope == "" {
		return nil, errors.New("client_id is required")
	}
	key := scope + "|openconnect.status"
	s, err := cc.SubscribeOpenConnectStatus(&openConnectHandler{emit: func(v any) { c.emitClient(scope, "openconnect.status", v) }, error: func(msg string) { c.emitClient(scope, "openconnect.error", map[string]any{"message": msg}) }})
	if err != nil {
		_ = closeClient()
		return nil, err
	}
	c.clientMu.Lock()
	old := c.openSessions[key]
	c.openSessions[key] = s
	c.clientMu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return map[string]any{"session_id": scope}, nil
}

type openConnectHandler struct {
	emit  func(any)
	error func(string)
}

func (h *openConnectHandler) OnStatusUpdate(s *libbox.OpenConnectStatusUpdate) {
	if s == nil {
		return
	}
	items := []any{}
	it := s.Endpoints()
	for it != nil && it.HasNext() {
		e := it.Next()
		if e == nil {
			continue
		}
		item := map[string]any{"endpointTag": e.EndpointTag, "state": e.State, "stateText": e.StateText, "error": e.Error}
		if ch := e.AuthChallenge; ch != nil {
			challenge := map[string]any{"id": ch.ID, "banner": ch.Banner, "message": ch.Message, "error": ch.Error}
			if f := ch.Form; f != nil {
				fields := []any{}
				fi := f.Fields()
				for fi != nil && fi.HasNext() {
					field := fi.Next()
					if field == nil {
						continue
					}
					options := []any{}
					oi := field.Options()
					for oi != nil && oi.HasNext() {
						o := oi.Next()
						if o != nil {
							options = append(options, map[string]any{"value": o.Value, "label": o.Label})
						}
					}
					fields = append(fields, map[string]any{"submissionKey": field.SubmissionKey, "name": field.Name, "label": field.Label, "kind": field.Kind, "value": field.Value, "options": options})
				}
				challenge["form"] = map[string]any{"fields": fields}
			}
			if b := ch.Browser; b != nil {
				challenge["browser"] = map[string]any{"url": b.URL, "finalUrl": b.FinalURL, "cacheId": b.CacheID, "cookieNames": libboxStrings(b.CookieNames()), "earlyCookieNames": libboxStrings(b.EarlyCookieNames()), "headerNames": libboxStrings(b.HeaderNames()), "callbackUrlPrefixes": libboxStrings(b.CallbackURLPrefixes())}
			}
			item["challenge"] = challenge
		}
		items = append(items, item)
	}
	h.emit(map[string]any{"endpoints": items})
}
func (h *openConnectHandler) OnError(msg string) { h.error(msg) }
func libboxStrings(it libbox.StringIterator) []string {
	out := []string{}
	for it != nil && it.HasNext() {
		out = append(out, it.Next())
	}
	return out
}
func (c *Controller) submitOpenConnectForm(cc *libbox.CommandClient, tag, challenge string, raw json.RawMessage) error {
	var entries []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return err
	}
	values := libbox.NewOpenConnectFormValues()
	for _, v := range entries {
		values.Add(v.Key, v.Value)
	}
	return cc.SubmitOpenConnectAuthResponse(tag, challenge, libbox.NewOpenConnectAuthFormResponse(values))
}

func (c *Controller) startConnectionTest(cc *libbox.CommandClient, closeClient func() error, p map[string]json.RawMessage, scope string) (any, error) {
	if scope == "" {
		return nil, errors.New("client_id is required")
	}
	key := scope + "|connection-test"
	getS := func(k string) string { var v string; _ = json.Unmarshal(p[k], &v); return v }
	getI := func(k string) int32 { var v int32; _ = json.Unmarshal(p[k], &v); return v }
	getB := func(k string) bool { var v bool; _ = json.Unmarshal(p[k], &v); return v }
	r := libbox.NewConnectionTestRequest()
	r.SetLink(getS("link"))
	r.SetOutboundTag(getS("outbound_tag"))
	r.SetPackageName(getS("package_name"))
	r.SetConnectIP(getS("connect_ip"))
	r.SetNetwork(getS("network"))
	r.SetTimeout(getI("timeout_ms"))
	r.SetMaxBytes(getI("max_bytes"))
	r.SetFresh(getB("fresh"))
	r.SetAppDNS(getB("app_dns"))
	r.SetDepth(getI("depth"))
	s, err := cc.StartConnectionTest(r, &connectionTestHandler{emit: func(kind string, data any) { c.emitClient(scope, kind, data) }})
	if err != nil {
		_ = closeClient()
		return nil, err
	}
	c.clientMu.Lock()
	old := c.probeSessions[key]
	c.probeSessions[key] = s
	c.clientMu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return map[string]any{"session_id": scope}, nil
}

type connectionTestHandler struct{ emit func(string, any) }

func (h *connectionTestHandler) OnStage(v *libbox.ConnectionTestStage) {
	if v != nil {
		h.emit("connection-test.stage", map[string]any{"id": v.ID(), "parent": v.Parent(), "kind": v.Kind(), "subject": v.Subject(), "startMs": v.StartMs(), "durationMs": v.DurationMs(), "result": v.Result(), "error": v.ErrorMessage()})
	}
}
func (h *connectionTestHandler) OnResult(v *libbox.ConnectionTestResult) {
	if v != nil {
		h.emit("connection-test.result", map[string]any{"error": v.ErrorMessage(), "rootCause": v.RootCause(), "httpStatus": v.HTTPStatus(), "body": string(v.Body()), "truncated": v.Truncated(), "contentType": v.ContentType(), "elapsedMs": v.ElapsedMs(), "stagesTruncated": v.StagesTruncated()})
	}
}
func (h *connectionTestHandler) OnError(msg string) {
	h.emit("connection-test.error", map[string]any{"message": msg})
}
func (c *Controller) stopConnectionTest(scope string) error {
	key := scope + "|connection-test"
	c.clientMu.Lock()
	s := c.probeSessions[key]
	delete(c.probeSessions, key)
	c.clientMu.Unlock()
	if s != nil {
		return s.Close()
	}
	return nil
}
func (c *Controller) emitClient(scope, kind string, data any) {
	c.emit(kind, map[string]any{"client_id": scope, "session_id": scope, "data": data})
}
func (c *Controller) urlTestAll(ctx context.Context, cc *libbox.CommandClient) (any, error) {
	groups, err := cc.GetGroups()
	if err != nil {
		return nil, err
	}
	var tags []string
	for groups != nil && groups.HasNext() {
		g := groups.Next()
		if g == nil {
			continue
		}
		items := g.GetItems()
		for items != nil && items.HasNext() {
			item := items.Next()
			if item != nil {
				tags = append(tags, item.Tag)
			}
		}
	}
	for _, tag := range tags {
		if err := ctx.Err(); err != nil {
			return map[string]any{"tested": 0}, err
		}
		if err := cc.URLTest(tag); err != nil {
			return map[string]any{"tested": 0, "failedTag": tag}, err
		}
	}
	return map[string]any{"tested": len(tags)}, nil
}
func (c *Controller) statusSnapshot(scope string) (any, error) {
	c.clientMu.Lock()
	s := c.streams[scope]
	c.clientMu.Unlock()
	if s == nil {
		return nil, errors.New("stream client is not initialized")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status, nil
}
func (c *Controller) logsSnapshot(scope string) (any, error) {
	c.clientMu.Lock()
	s := c.streams[scope]
	c.clientMu.Unlock()
	if s == nil {
		return nil, errors.New("stream client is not initialized")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]map[string]any(nil), s.logs...), nil
}
func (c *Controller) connectionsSnapshot(scope string) (any, error) {
	c.clientMu.Lock()
	s := c.streams[scope]
	c.clientMu.Unlock()
	if s == nil {
		return nil, errors.New("stream client is not initialized")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []any{}
	for _, v := range s.connections {
		out = append(out, connectionJSON(v))
	}
	return out, nil
}
