package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Leadaxe/lxbox/app/internal/builder"
)

type sourceUpdater struct {
	app        *Application
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	mu         sync.Mutex
	ticker     *time.Ticker
	vpn        *time.Timer
	closed     bool
	started    bool
	running    bool
	generation uint64
	fails      map[string]int
}

func (a *Application) updaterState() *sourceUpdater {
	updatersMu.Lock()
	defer updatersMu.Unlock()
	if u := updaters[a]; u != nil {
		return u
	}
	parent := a.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	u := &sourceUpdater{app: a, ctx: ctx, cancel: cancel, done: make(chan struct{}), fails: map[string]int{}}
	updaters[a] = u
	return u
}

// The host calls startUpdater after workspace recovery, onVPNState on actual
// VPN transitions, and Close before shutting down the application.
func (a *Application) startUpdater() {
	u := a.updaterState()
	u.mu.Lock()
	if u.started || u.closed {
		u.mu.Unlock()
		return
	}
	u.started = true
	u.ticker = time.NewTicker(time.Hour)
	u.mu.Unlock()
	go func() {
		defer close(u.done)
		go u.refresh()
		for {
			select {
			case <-u.ctx.Done():
				return
			case <-u.ticker.C:
				u.refresh()
			}
		}
	}()
}
func (u *sourceUpdater) refresh() {
	_, err := u.app.refreshAll(u.ctx, mustJSON(map[string]any{"auto": true}))
	if err != nil && !errors.Is(err, context.Canceled) {
		u.app.events.emit("sources.refresh_failed", map[string]any{"error": err.Error()})
	}
}
func (a *Application) onVPNState(connected bool) {
	u := a.updaterState()
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return
	}
	if u.vpn != nil {
		u.vpn.Stop()
		u.vpn = nil
	}
	if connected {
		u.vpn = time.AfterFunc(2*time.Minute, func() { u.refresh() })
		u.mu.Unlock()
		return
	}
	u.mu.Unlock()
	go u.refresh()
}

// Close owns the scheduler only. It cancels its fetch contexts and timers; the
// application shutdown path separately closes core/platform resources.
func (a *Application) Close() error {
	updatersMu.Lock()
	u := updaters[a]
	updatersMu.Unlock()
	if u == nil {
		return nil
	}
	u.mu.Lock()
	u.closed = true
	u.cancel()
	if u.vpn != nil {
		u.vpn.Stop()
	}
	if u.ticker != nil {
		u.ticker.Stop()
	}
	started := u.started
	u.mu.Unlock()
	if started {
		select {
		case <-u.done:
		case <-time.After(2 * time.Second):
			return errors.New("subscription scheduler did not stop")
		}
	}
	return nil
}

func (a *Application) refreshAll(ctx context.Context, raw json.RawMessage) (any, error) {
	ctx, cancel := a.sourceContext(ctx)
	defer cancel()
	var p sourceInput
	if err := decode(raw, &p); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	u := a.updaterState()
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil, context.Canceled
	}
	if u.running {
		u.mu.Unlock()
		return map[string]any{"skipped": true, "reason": "refresh-all already running", "results": []any{}}, nil
	}
	u.running = true
	u.mu.Unlock()
	defer func() { u.mu.Lock(); u.running = false; u.mu.Unlock() }()
	// A scheduler Close also cancels externally initiated passes sharing its
	// state; request cancellation and the application lifetime remain respected.
	passCtx, passCancel := context.WithCancel(ctx)
	stop := context.AfterFunc(u.ctx, passCancel)
	defer func() { stop(); passCancel() }()
	ctx = passCtx
	a.mutation.Lock()
	generation := a.generation
	records, err := sourceRecords(a)
	doc, settingsErr := a.store.Snapshot()
	a.mutation.Unlock()
	if err != nil {
		return nil, err
	}
	if settingsErr != nil {
		return nil, settingsErr
	}
	if p.Auto && !p.Force && !settingBool(sourceSetting(doc, "auto_update_subs", true), true) {
		return map[string]any{"skipped": true, "reason": "auto-update disabled", "results": []any{}}, nil
	}
	includeDisabled := p.IncludeDisabled || settingBool(sourceSetting(doc, "auto_update_disabled_subs", false), false)
	u.mu.Lock()
	if u.generation != generation {
		u.generation = generation
		u.fails = map[string]int{}
	}
	if !p.Auto || p.Force {
		u.fails = map[string]int{}
	}
	fails := map[string]int{}
	for k, v := range u.fails {
		fails[k] = v
	}
	u.mu.Unlock()
	// A URL is fetched once per pass. Identity mismatches are reported rather
	// than silently handing one account/device response to a different identity.
	groups := map[string][]map[string]any{}
	order := []string{}
	for _, record := range records {
		if sourceKind(record) != "subscription" {
			continue
		}
		if !sourceBool(record, "enabled", true) && !includeDisabled {
			continue
		}
		address := sourceString(record, "url")
		if address == "" {
			continue
		}
		if p.Auto && !p.Force && !sourceDue(record, fails[address], time.Now()) {
			continue
		}
		if _, ok := groups[address]; !ok {
			order = append(order, address)
		}
		groups[address] = append(groups[address], record)
	}
	results := []any{}
	updated := 0
	action := "none"
	var failures []error
	for groupIndex, address := range order {
		if err := ctx.Err(); err != nil {
			return map[string]any{"results": results, "updated": updated}, err
		}
		if p.Auto {
			a.mutation.Lock()
			currentSettings, settingsErr := a.store.Snapshot()
			a.mutation.Unlock()
			if settingsErr != nil {
				return map[string]any{"results": results, "updated": updated}, settingsErr
			}
			if !settingBool(sourceSetting(currentSettings, "auto_update_subs", true), true) {
				return map[string]any{"results": results, "updated": updated, "skipped": true, "reason": "auto-update disabled during pass"}, nil
			}
		}
		if generation != a.currentGeneration() {
			return map[string]any{"results": results, "updated": updated}, errSourceConflict
		}
		group := groups[address]
		first := group[0]
		firstID := sourceString(first, "id")
		fetchGeneration, snapshot, key, already, reserveErr := a.reserveSourceRefresh(firstID)
		if reserveErr != nil {
			failures = append(failures, reserveErr)
			results = append(results, map[string]any{"id": firstID, "error": reserveErr.Error()})
			continue
		}
		if already {
			results = append(results, map[string]any{"id": firstID, "skipped": true, "reason": "already refreshing"})
			continue
		}
		if fetchGeneration != generation || !sourceEqual(snapshot, first) {
			a.releaseSourceRefresh(key)
			failures = append(failures, errSourceConflict)
			results = append(results, map[string]any{"id": firstID, "error": errSourceConflict.Error()})
			continue
		}
		fetch, fetchErr := a.fetchRecord(ctx, snapshot, generation, p.Offline)
		fetchFailed := fetchErr != nil
		cacheWritten := false
		for _, record := range group {
			id := sourceString(record, "id")
			if err := ctx.Err(); err != nil {
				a.releaseSourceRefresh(key)
				return map[string]any{"results": results, "updated": updated}, err
			}
			if fetchErr != nil {
				value, e := a.finishSourceFailure(ctx, record, generation, fetchErr)
				results = append(results, value)
				if e != nil {
					failures = append(failures, e)
				}
				continue
			}
			a.mutation.Lock()
			identity := a.sourceHeaders(record)
			a.mutation.Unlock()
			if isHTTPURL(address) && !equalStringMap(identity, fetch.requestHeaders) {
				e := fmt.Errorf("%w: sources sharing a URL have different HTTP identities", errSourceConflict)
				results = append(results, map[string]any{"id": id, "error": e.Error()})
				failures = append(failures, e)
				continue
			}
			parsed, parseErr := parseSourceBody(ctx, fetch.body, record)
			if parseErr == nil && len(parsed.details) == 0 {
				parseErr = fmt.Errorf("source produced no supported nodes: %s", diagnosticsText(parsed.diagnostics))
			}
			if parseErr != nil {
				fetchFailed = true
				value, e := a.finishSourceFailure(ctx, record, generation, parseErr)
				results = append(results, value)
				if e != nil {
					failures = append(failures, e)
				}
				continue
			}
			perRecord := fetch
			if cacheWritten {
				perRecord.writeCache = false
			}
			value, e := a.commitSourceRefresh(ctx, record, perRecord, parsed, generation)
			if e != nil {
				results = append(results, map[string]any{"id": id, "error": e.Error()})
				failures = append(failures, e)
				continue
			}
			cacheWritten = cacheWritten || perRecord.writeCache
			results = append(results, value)
			updated++
			if response, ok := value.(map[string]any); ok && response["changed"] == true && sourceBool(record, "enabled", true) {
				action = strongerSourceAction(action, a.updateAction(record))
			}
		}
		a.releaseSourceRefresh(key)
		u.mu.Lock()
		if fetchFailed {
			u.fails[address]++
		} else {
			delete(u.fails, address)
		}
		u.mu.Unlock()
		if p.Auto && groupIndex+1 < len(order) {
			if err = sleepContext(ctx, 10*time.Second); err != nil {
				return map[string]any{"results": results, "updated": updated}, err
			}
		}
	}
	response := map[string]any{"results": results, "updated": updated, "generation": generation}
	if generation != a.currentGeneration() {
		return response, errSourceConflict
	}
	if action != "none" {
		if err := a.applySourceReaction(ctx, generation, action); err != nil {
			response["reaction_error"] = err.Error()
			failures = append(failures, err)
		}
	}
	return response, errors.Join(failures...)
}
func (a *Application) currentGeneration() uint64 {
	a.mutation.Lock()
	defer a.mutation.Unlock()
	return a.generation
}
func sourceDue(record map[string]any, fails int, now time.Time) bool {
	if fails >= 5 {
		return false
	}
	hours := int64(24)
	if update, ok := record["update"].(map[string]any); ok {
		if n, ok := numberInt(update["interval_hours"]); ok {
			hours = n
		}
	}
	if hours == 0 {
		hours = 24
		if meta, ok := record["meta"].(map[string]any); ok {
			if n, ok := numberInt(meta["update_interval_hours"]); ok {
				hours = n
			}
		}
	}
	if hours <= 0 {
		return false
	}
	if hours > 24*365*100 {
		hours = 24 * 365 * 100
	}
	lastAttempt, _ := time.Parse(time.RFC3339Nano, sourceString(record, "last_update_attempt"))
	if !lastAttempt.IsZero() && now.Sub(lastAttempt) < 15*time.Minute {
		return false
	}
	last, _ := time.Parse(time.RFC3339Nano, sourceString(record, "last_updated"))
	return last.IsZero() || now.Sub(last) >= time.Duration(hours)*time.Hour
}
func numberInt(value any) (int64, bool) {
	switch n := value.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), true
	case json.Number:
		v, e := n.Int64()
		return v, e == nil
	case string:
		v, e := strconv.ParseInt(n, 10, 64)
		return v, e == nil
	}
	return 0, false
}
func equalStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
func strongerSourceAction(a, b string) string {
	if a == "reload" || b == "reload" {
		return "reload"
	}
	if a == "rebuild" || b == "rebuild" {
		return "rebuild"
	}
	return "none"
}
func (a *Application) updateAction(record map[string]any) string {
	doc, _ := a.store.Snapshot()
	if settingBool(sourceSetting(doc, "auto_reload_on_change", false), false) {
		return "reload"
	}
	switch sourceString(record, "on_update_action") {
	case "none":
		return "none"
	case "reload":
		return "reload"
	default:
		return "rebuild"
	}
}
func (a *Application) applySourceReaction(ctx context.Context, generation uint64, action string) error {
	if action == "none" {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	snapshot, err := a.snapshotConfigBuild(ctx)
	if err != nil {
		return err
	}
	if snapshot.generation != generation {
		return errSourceConflict
	}
	before, _ := a.readConfig()
	input, diagnostics, err := prepareConfigBuild(ctx, snapshot)
	if err != nil {
		a.events.emit("sources.reaction_failed", map[string]any{"error": err.Error(), "diagnostics": diagnostics})
		return fmt.Errorf("source update committed; configuration rebuild failed: %w", err)
	}
	built, err := builder.Build(ctx, input)
	if err != nil {
		return fmt.Errorf("source update committed; configuration rebuild failed: %w", err)
	}
	if !json.Valid(built.Config) || !configHasNodes(built.Config) {
		return errors.New("source update committed; rebuilt configuration has no supported proxy nodes")
	}
	if err = a.commitConfigBuild(ctx, snapshot, json.RawMessage(built.Config)); err != nil {
		return err
	}
	if action != "reload" {
		return nil
	}
	a.mutation.Lock()
	defer a.mutation.Unlock()
	if generation != a.generation || snapshot.revision != a.revision {
		return errSourceConflict
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.core == nil {
		return errors.New("core controller is unavailable")
	}
	var status map[string]any
	_ = json.Unmarshal(mustJSON(a.core.Status()), &status)
	state := sourceString(status, "state")
	if state != "running" && state != "connected" {
		return nil
	}
	config, err := a.readConfig()
	if err != nil {
		return err
	}
	if string(before) == string(config) {
		return nil
	}
	_, err = a.platformCall(ctx, "vpn.reload", map[string]any{"config": config})
	return err
}

// Import rules operate on the emitted sing-box JSON, never provider text.
// Unsupported regex constructs produce diagnostics and reject the operation.
func applySourceImportRules(node map[string]any, enabled bool, record map[string]any) (map[string]any, bool, []any) {
	findings := []any{}
	if !sourceBool(record, "import_rules_enabled", true) {
		return node, enabled, findings
	}
	rules, _ := record["import_rules"].([]any)
	for index, value := range rules {
		rule, ok := value.(map[string]any)
		if !ok || !sourceBool(rule, "enabled", true) {
			continue
		}
		conditions, _ := rule["conditions"].([]any)
		legacy := false
		if len(conditions) == 0 && sourceString(rule, "pattern") != "" {
			legacy = true
			op := "contains"
			if sourceBool(rule, "is_regex", false) {
				op = "matches"
			}
			conditions = []any{map[string]any{"path": "tag", "op": op, "pattern": rule["pattern"], "case_sensitive": rule["case_sensitive"]}}
		}
		anyMode := sourceString(rule, "match") == "any"
		matched := !anyMode
		usable := 0
		captures := map[string][]string{}
		var ruleErr error
		for _, value := range conditions {
			condition, ok := value.(map[string]any)
			if !ok || sourceString(condition, "pattern") == "" {
				continue
			}
			usable++
			path := sourceString(condition, "path")
			actual, exists := sourcePath(node, path)
			okMatch, capture, err := sourceCondition(actual, exists, condition)
			if err != nil {
				ruleErr = err
				break
			}
			if len(capture) > 0 {
				captures[path] = capture
			}
			if anyMode {
				matched = matched || okMatch
			} else {
				matched = matched && okMatch
			}
		}
		if ruleErr != nil {
			findings = append(findings, map[string]any{"severity": "error", "code": "import_rule_invalid", "path": fmt.Sprintf("import_rules[%d]", index), "message": ruleErr.Error()})
			continue
		}
		if usable == 0 || !matched {
			continue
		}
		switch sourceString(rule, "action") {
		case "disable":
			enabled = false
		case "enable":
			enabled = true
		default:
			path := sourceString(rule, "target_path")
			mode := sourceString(rule, "replace_mode")
			needle := sourceString(rule, "substitute")
			if legacy {
				path = "tag"
				mode = "substitute"
				needle = sourceString(rule, "pattern")
			}
			replacement := expandSourceCaptures(sourceString(rule, "replacement"), captures[path])
			actual, exists := sourcePath(node, path)
			if mode == "substitute" {
				var matching map[string]any
				for _, value := range conditions {
					c, ok := value.(map[string]any)
					if ok && sourceString(c, "path") == path {
						matching = c
						break
					}
				}
				if needle == "" && matching != nil {
					needle = sourceString(matching, "pattern")
				}
				if needle == "" {
					continue
				}
				pattern := regexp.QuoteMeta(needle)
				if matching != nil && sourceString(matching, "op") == "matches" {
					pattern = needle
				}
				if matching == nil || !sourceBool(matching, "case_sensitive", false) {
					pattern = "(?i)" + pattern
				}
				re, e := regexp.Compile(pattern)
				if e != nil {
					findings = append(findings, map[string]any{"severity": "error", "code": "import_rule_invalid", "message": e.Error()})
					continue
				}
				text := sourceValueText(actual)
				template := sourceString(rule, "replacement")
				replacement = re.ReplaceAllStringFunc(text, func(s string) string {
					groups := re.FindStringSubmatch(s)
					if groups == nil {
						return s
					}
					return expandSourceCaptures(template, groups)
				})
			}
			if path == "" {
				if mode != "substitute" {
					continue
				}
				var next map[string]any
				if err := decode([]byte(replacement), &next); err != nil || next == nil {
					findings = append(findings, map[string]any{"severity": "error", "code": "import_rule_invalid_json", "message": "whole-node replacement did not produce a JSON object"})
				} else {
					node = next
				}
				continue
			}
			if !exists {
				continue
			}
			sourceWritePath(node, path, replacement, actual)
		}
	}
	return node, enabled, findings
}
func expandSourceCaptures(template string, captures []string) string {
	for i := 9; i >= 1; i-- {
		replacement := ""
		if i < len(captures) {
			replacement = captures[i]
		}
		template = strings.ReplaceAll(template, "$"+strconv.Itoa(i), replacement)
	}
	return template
}
func sourceCondition(value any, exists bool, c map[string]any) (bool, []string, error) {
	pattern := sourceString(c, "pattern")
	actual := sourceValueText(value)
	op := sourceString(c, "op")
	sensitive := sourceBool(c, "case_sensitive", false)
	var capture []string
	matched := false
	if exists {
		switch op {
		case "matches":
			if !sensitive {
				pattern = "(?i)" + pattern
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return false, nil, err
			}
			capture = re.FindStringSubmatch(actual)
			matched = capture != nil
		case "equals":
			if sensitive {
				matched = actual == pattern
			} else {
				matched = strings.EqualFold(actual, pattern)
			}
		default:
			if !sensitive {
				actual = strings.ToLower(actual)
				pattern = strings.ToLower(pattern)
			}
			matched = strings.Contains(actual, pattern)
		}
	}
	if sourceBool(c, "negate", false) {
		matched = !matched
	}
	return matched, capture, nil
}
func sourcePath(node map[string]any, path string) (any, bool) {
	if path == "" {
		return node, true
	}
	var current any = node
	for _, part := range strings.Split(path, ".") {
		switch v := current.(type) {
		case map[string]any:
			next, ok := v[part]
			if !ok {
				return nil, false
			}
			current = next
		case []any:
			i, e := strconv.Atoi(part)
			if e != nil || i < 0 || i >= len(v) {
				return nil, false
			}
			current = v[i]
		default:
			return nil, false
		}
	}
	return current, current != nil
}
func sourceValueText(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return string(mustJSON(value))
}
func sourceWritePath(node map[string]any, path, replacement string, old any) {
	parts := strings.Split(path, ".")
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, "//") {
			return
		}
	}
	current := node
	for _, part := range parts[:len(parts)-1] {
		next, ok := current[part].(map[string]any)
		if !ok {
			return
		}
		current = next
	}
	var value any = replacement
	switch old.(type) {
	case json.Number, int, int64, float64:
		if n, e := strconv.ParseFloat(replacement, 64); e == nil {
			value = n
		}
	case bool:
		if b, e := strconv.ParseBool(replacement); e == nil {
			value = b
		}
	}
	current[parts[len(parts)-1]] = value
}
