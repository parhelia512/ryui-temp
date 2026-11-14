// Package ui implements the native RyUI application. All application work goes
// through runtime.Dispatch; owners cancel requests when their screens disappear.
package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Leadaxe/lxbox/app/assets"
	appruntime "github.com/Leadaxe/lxbox/app/internal/runtime"
	"github.com/egoist/ryui/app"
	"github.com/egoist/ryui/signal"
	ryui "github.com/egoist/ryui/ui"
)

type object = map[string]any

type reply struct {
	value any
	text  string
}

type event struct {
	ID   uint64          `json:"id"`
	Type string          `json:"type"`
	Time string          `json:"time"`
	Data json.RawMessage `json:"data"`
}

type session struct {
	ctx        context.Context
	cancel     context.CancelFunc
	workspace  context.Context
	stopSpace  context.CancelFunc
	revision   *signal.Signal[int]
	selected   *signal.Signal[int]
	events     *signal.Signal[[]event]
	streamErr  *signal.Signal[string]
	foreground atomic.Bool
	epoch atomic.Uint64
}

// App is mounted by the Go main entry point, on RyUI's main thread.
func App() ryui.Node {
	ctx, cancel := context.WithCancel(context.Background())
	space, stopSpace := context.WithCancel(ctx)
	s := &session{ctx: ctx, cancel: cancel, workspace: space, stopSpace: stopSpace,
		revision: signal.New(0), selected: signal.New(0),
		events: signal.NewFunc([]event{}, nil), streamErr: signal.New("")}
	s.foreground.Store(true)
	signal.OnCleanup(func() { s.stopSpace(); s.cancel() })
	app.OnLifecycle(func(state app.State) {
		if s.ctx.Err() != nil { return }
		if state == app.Background { s.foreground.Store(false) }
		if state == app.Foreground { s.foreground.Store(true) }
	})
	ryui.SetLanguages("en", "ru", "zh")
	go func() {
		loadCatalog()
		r, err := dispatch(s.ctx, "settings.get", nil)
		ryui.Post(func() {
			if s.ctx.Err() != nil { return }
			if err == nil { s.applyPreferences(asObject(r.value)) }
		})
	}()
	go s.pollEvents()
	return ryui.Dynamic(func() ryui.Node {
		_ = s.revision.Get()
		return s.navigation()
	})
}

func (s *session) navigation() ryui.Node {
	dest := func(title string, icon ryui.Icon, screen func() ryui.Node) ryui.Destination {
		return ryui.Destination{Title: ryui.Val(tr(title)), Icon: icon, Content: screen}
	}
	return ryui.SplitView(ryui.SplitViewProps{Title: ryui.Val("LxBox"), Selected: s.selected, Sections: []ryui.SidebarSection{
		{Title: ryui.Val(tr("VPN")), Destinations: []ryui.Destination{
			dest("Home", ryui.IconHome, s.home),
			dest("Servers", ryui.IconList, s.sources),
			dest("Config Editor", ryui.IconDocument, s.configuration),
			dest("Routing", ryui.IconGlobe, s.routing),
			dest("DNS", ryui.IconSearch, s.dns),
		}},
		{Title: ryui.Val(tr("Diagnostics")), Destinations: []ryui.Destination{
			dest("Connections", ryui.IconPeople, s.connections),
			dest("Logs", ryui.IconList, s.logs),
			dest("Statistics", ryui.IconList, s.statistics),
			dest("Diagnostics", ryui.IconSearch, s.diagnostics),
		}},
		{Title: ryui.Val(tr("Network")), Destinations: []ryui.Destination{
			dest("Tailscale", ryui.IconGlobe, s.tailscale),
			dest("Taildrop", ryui.IconDocument, s.taildrop),
			dest("OpenConnect", ryui.IconLock, s.openConnect),
			dest("WARP", ryui.IconGlobe, s.warp),
		}},
		{Title: ryui.Val(tr("App Settings")), Destinations: []ryui.Destination{
			dest("App Settings", ryui.IconSettings, s.settings),
			dest("Automation", ryui.IconSettings, s.automation),
			dest("Workspaces", ryui.IconDocument, s.workspaces),
			dest("Backup & Restore", ryui.IconDocument, s.backup),
			dest("Advanced", ryui.IconSettings, s.advanced),
		}},
	}})
}

func (s *session) changedWorkspace() {
	s.epoch.Add(1)
	s.stopSpace()
	s.workspace, s.stopSpace = context.WithCancel(s.ctx)
	s.events.Set([]event{})
	s.revision.Update(func(n int) int { return n + 1 })
	ctx := s.workspace
	go func() {
		r, err := dispatch(ctx, "settings.get", nil)
		ryui.Post(func() { if ctx.Err() == nil && err == nil { s.applyPreferences(asObject(r.value)) } })
	}()
}

// scope is owned by one screen. Only its main-thread callbacks touch signals.
// Workers return canonical JSON so all runtime response types are accepted.
type scope struct {
	ctx context.Context
	cancel context.CancelFunc
	clientID string
	usesCore bool
	operation context.CancelFunc
	busy *signal.Signal[bool]
	err *signal.Signal[string]
	result *signal.Signal[string]
}

var nextClient atomic.Uint64

func (s *session) scope() *scope {
	ctx, cancel := context.WithCancel(s.workspace)
	q := &scope{ctx: ctx, cancel: cancel, clientID: fmt.Sprintf("ui-%d", nextClient.Add(1)), busy: signal.New(false), err: signal.New(""), result: signal.New("")}
	signal.OnCleanup(func() {
		cancel()
		if q.usesCore {
			go func() {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				_, _ = dispatch(cleanup, "core.call", object{"method": "ccDisposeClient", "args": object{"client_id": q.clientID}})
			}()
		}
	})
	return q
}

func dispatch(ctx context.Context, method string, args any) (reply, error) {
	if args == nil { args = object{} }
	payload, err := json.Marshal(args)
	if err != nil { return reply{}, err }
	v, callErr := appruntime.Dispatch(ctx, method, payload)
	encoded, err := json.MarshalIndent(v, "", "  ")
	if err != nil { return reply{}, err }
	var decoded any
	if err = json.Unmarshal(encoded, &decoded); err != nil { return reply{}, err }
	return reply{value: decoded, text: string(encoded)}, callErr
}

func (q *scope) run(method string, args any, done func(reply)) {
	q.work(func(ctx context.Context) (reply, error) { return dispatch(ctx, method, args) }, done)
}

func (q *scope) work(work func(context.Context) (reply, error), done func(reply)) {
	if q.ctx.Err() != nil || q.busy.Peek() { return }
	ctx, cancel := context.WithCancel(q.ctx)
	q.operation = cancel
	q.busy.Set(true)
	q.err.Set("")
	q.result.Set("")
	go func() {
		r, err := work(ctx)
		ryui.Post(func() {
			defer cancel()
			if q.ctx.Err() != nil { return }
			q.operation = nil
			q.busy.Set(false)
			if r.value != nil { q.result.Set(r.text) }
			if err != nil { q.err.Set(err.Error()); return }
			if ctx.Err() != nil { return }
			q.result.Set(r.text)
			if done != nil { done(r) }
		})
	}()
}

func (q *scope) core(method string, args any, done func(reply)) {
	q.usesCore = true
	clientID := q.clientID
	q.work(func(ctx context.Context) (reply, error) {
		payload := object{}
		if args != nil {
			encoded, err := json.Marshal(args)
			if err != nil { return reply{}, err }
			if err := json.Unmarshal(encoded, &payload); err != nil { return reply{}, err }
		}
		if payload == nil { payload = object{} }
		payload["client_id"] = clientID
		if _, exists := payload["session_id"]; !exists { payload["session_id"] = clientID }
		return dispatch(ctx, "core.call", object{"method": method, "args": payload})
	}, done)
}

func (q *scope) cancelRequest() {
	if q.operation != nil { q.operation() }
}

func (q *scope) feedback() ryui.Node {
	return ryui.Column(ryui.Style{Gap: 8},
		ryui.Show(q.busy, func() ryui.Node {
			return ryui.Row(ryui.Style{Gap: 8, Align: ryui.AlignCenter},
				ryui.StaticText(tr("Loading…")), button("Cancel", q.cancelRequest, nil))
		}),
		ryui.Show(signal.Func(func() bool { return q.err.Get() != "" }), func() ryui.Node {
			return ryui.Text(q.err, ryui.Style{Color: ryui.Red})
		}),
	)
}

func (s *session) clientEvents(q *scope, kind string, receive func(any)) {
	var after uint64
	signal.Effect(func() {
		for _, e := range s.events.Get() {
			if e.ID <= after { continue }
			after = e.ID
			if e.Type != kind { continue }
			var envelope object
			if json.Unmarshal(e.Data, &envelope) != nil { continue }
			if text(envelope["client_id"]) != q.clientID { continue }
			receive(envelope["data"])
		}
	})
}

func (s *session) pollEvents() {
	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()
	var cursor uint64
	for {
		if s.foreground.Load() {
			epoch := s.epoch.Load()
			ctx, cancel := context.WithTimeout(s.ctx, 20*time.Second)
			r, err := dispatch(ctx, "events.poll", object{"after": cursor})
			cancel()
			if s.ctx.Err() != nil { return }
			if err != nil {
				message := err.Error()
				ryui.Post(func() { if s.ctx.Err() == nil { s.streamErr.Set(message) } })
			} else {
				var batch struct { Cursor uint64 `json:"cursor"`; Events []event `json:"events"`; Resync bool `json:"resync"` }
				if err := json.Unmarshal([]byte(r.text), &batch); err == nil {
					cursor = batch.Cursor
					ryui.Post(func() {
						if s.ctx.Err() != nil || s.epoch.Load() != epoch { return }
						s.streamErr.Set("")
						if len(batch.Events) == 0 { return }
						s.events.Update(func(old []event) []event {
							if batch.Resync { old = nil }
							all := append(append([]event{}, old...), batch.Events...)
							if len(all) > 500 { all = all[len(all)-500:] }
							return all
						})
					})
				}
			}
		}
		select { case <-s.ctx.Done(): return; case <-ticker.C: }
	}
}

// The retained natural-key catalogs keep English as the source language.
// Dictionaries are decoded off-thread, then selected from the persisted prefs.
var catalog atomic.Value
var currentLanguage atomic.Value

func loadCatalog() {
	languages := map[string]map[string]string{}
	for _, language := range []string{"zh", "ru"} {
		data, err := assets.Read("l10n/"+language+"/ui.json")
		if err != nil { continue }
		var entries map[string]struct { Value json.RawMessage `json:"value"` }
		if json.Unmarshal(data, &entries) != nil { continue }
		messages := map[string]string{}
		for source, entry := range entries {
			var value string
			if json.Unmarshal(entry.Value, &value) != nil {
				var plural map[string]string
				if json.Unmarshal(entry.Value, &plural) == nil { value = plural["other"] }
			}
			if value != "" { messages[source] = value }
		}
		languages[language] = messages
	}
	catalog.Store(languages)
}

func tr(source string) string {
	language, _ := currentLanguage.Load().(string)
	if language == "" || language == "system" { language = ryui.Locale() }
	language = strings.Split(strings.ReplaceAll(language, "_", "-"), "-")[0]
	if languages, ok := catalog.Load().(map[string]map[string]string); ok {
		if translated := languages[language][source]; translated != "" { return translated }
	}
	return source
}

func (s *session) applyPreferences(doc object) {
	language := text(asObject(doc["vars"])["app_language"])
	if language != "zh" && language != "ru" && language != "en" { language = "system" }
	previous, _ := currentLanguage.Load().(string)
	currentLanguage.Store(language)
	if language == "system" { ryui.SetLocale("") } else { ryui.SetLocale(language) }
	switch text(asObject(doc["native_prefs"])["app_theme_mode"]) {
	case "light": ryui.SetColorScheme(ryui.ColorSchemeLight)
	case "dark": ryui.SetColorScheme(ryui.ColorSchemeDark)
	default: ryui.SetColorScheme(ryui.ColorSchemeSystem)
	}
	if previous != language { s.revision.Update(func(n int) int { return n+1 }) }
}

func button(title string, action func(), disabled signal.Accessor[bool]) ryui.Node {
	return ryui.Button(ryui.ButtonProps{Title: ryui.Val(tr(title)), Variant: ryui.ButtonTinted, OnPress: action, Disabled: disabled})
}

func primary(title string, action func(), disabled signal.Accessor[bool]) ryui.Node {
	return ryui.Button(ryui.ButtonProps{Title: ryui.Val(tr(title)), Variant: ryui.ButtonFilled, OnPress: action, Disabled: disabled})
}

func page(kids ...ryui.Node) ryui.Node {
	return ryui.Scroll(ryui.ScrollProps{Style: ryui.Style{Grow: 1}},
		ryui.SafeArea(ryui.Style{Padding: ryui.All(16), Gap: 16}, kids...))
}

func section(title string, kids ...ryui.Node) ryui.Node {
	return ryui.Column(ryui.Style{Gap: 10, Padding: ryui.All(14), Background: ryui.SecondaryBackground, CornerRadius: 12},
		append([]ryui.Node{ryui.StaticText(tr(title), ryui.Style{Font: ryui.Headline})}, kids...)...)
}

func actions(kids ...ryui.Node) ryui.Node {
	return ryui.Row(ryui.Style{Gap: 8, Wrap: true, Align: ryui.AlignCenter}, kids...)
}

func field(label string, value *signal.Signal[string], multiline bool) ryui.Node {
	style := ryui.Style{}
	if multiline { style.Lines = 16 }
	return ryui.Column(ryui.Style{Gap: 5},
		ryui.StaticText(tr(label), ryui.Style{Font: ryui.Footnote, Color: ryui.SecondaryLabel}),
		ryui.TextField(ryui.TextFieldProps{Value: value, Placeholder: ryui.Val(tr(label)), Multiline: multiline,
			Autocapitalize: ryui.CapitalizeNone, Autocorrect: ryui.AutocorrectNo,
			Style: style}))
}

func jsonView(value signal.Accessor[string]) ryui.Node {
	return ryui.Text(value, ryui.Style{Font: ryui.Custom("monospace", ryui.Footnote)})
}

func confirm(title string, action func()) {
	ryui.Alert(ryui.AlertProps{Title: tr(title), Message: tr("This changes saved data."), Actions: []ryui.Action{
		{Title: ryui.Val(tr("Cancel")), Role: ryui.ActionCancel},
		{Title: ryui.Val(tr("Continue")), Role: ryui.ActionDestructive, OnPress: action},
	}})
}

func asObject(value any) object {
	if v, ok := value.(map[string]any); ok { return v }
	return object{}
}

func text(value any) string {
	if value == nil { return "" }
	if v, ok := value.(string); ok { return v }
	return fmt.Sprint(value)
}

func nameOf(value any) string {
	v := asObject(value)
	for _, key := range []string{"name", "tag", "hostName", "Tag", "title", "id"} {
		if name := text(v[key]); name != "" { return name }
	}
	return tr("Details")
}

func listOf(value any, keys ...string) []any {
	if list, ok := value.([]any); ok { return list }
	v := asObject(value)
	for _, key := range keys { if list, ok := v[key].([]any); ok { return list } }
	return nil
}

func pretty(value any) string {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil { return text(value) }
	return string(encoded)
}

func required(values ...*signal.Signal[string]) bool {
	for _, value := range values { if strings.TrimSpace(value.Peek()) == "" { return false } }
	return true
}
