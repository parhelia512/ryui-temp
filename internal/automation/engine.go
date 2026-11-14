package automation

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// LocaleBundleKey is the sole key stored in twofortyfouram's Bundle.
	LocaleBundleKey      = "com.leadaxe.lxbox.plugin.CONFIG"
	LocaleBundleMaxBytes = 25_000
	LocaleBundleVersion  = 1
	EventPrefix          = "com.leadaxe.lxbox.event."
)

// Engine owns automation admission, serial command dispatch and outgoing event
// policy. The original Flutter app had no recipe DB or condition scheduler.
type Engine struct {
	mu       sync.Mutex
	gate     chan struct{}
	dispatch Dispatcher
	events   EventSink
	logger   Logger
	clock    func() time.Time
	settings Settings
	running  bool
	stopping bool
	root     context.Context
	cancel   context.CancelFunc
	stopDone chan struct{}
	inflight sync.WaitGroup
	lastEmit map[string]time.Time
}

type Option func(*Engine)

func WithEventSink(sink EventSink) Option { return func(e *Engine) { e.events = sink } }
func WithLogger(logger Logger) Option     { return func(e *Engine) { e.logger = logger } }
func WithClock(clock func() time.Time) Option {
	return func(e *Engine) {
		if clock != nil {
			e.clock = clock
		}
	}
}
func WithSettings(settings Settings) Option { return func(e *Engine) { e.settings = settings } }
func WithConfig(config Config) Option       { return func(e *Engine) { e.settings = config } }

// NewEngine constructs a stopped engine. All four event gates and command
// intake are false unless supplied by persisted settings.
func NewEngine(dispatch Dispatcher, opts ...Option) *Engine {
	e := &Engine{dispatch: dispatch, gate: make(chan struct{}, 1), clock: time.Now, lastEmit: make(map[string]time.Time)}
	for _, opt := range opts {
		if opt != nil {
			opt(e)
		}
	}
	return e
}

// Start activates the engine until ctx is cancelled or Stop is called.
func (e *Engine) Start(ctx context.Context) error {
	if ctx == nil {
		return invalid("context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	e.mu.Lock()
	if e.running || e.stopping {
		e.mu.Unlock()
		return ErrAlreadyRunning
	}
	e.root, e.cancel = context.WithCancel(ctx)
	root := e.root
	e.stopDone = make(chan struct{})
	e.running = true
	e.mu.Unlock()
	go func() {
		<-root.Done()
		e.mu.Lock()
		if e.root != root {
			e.mu.Unlock()
			return
		}
		e.running = false
		e.stopping = true
		e.mu.Unlock()
		e.inflight.Wait()
		e.mu.Lock()
		if e.root == root {
			e.stopping = false
			close(e.stopDone)
			e.stopDone = nil
		}
		e.mu.Unlock()
	}()
	return nil
}

// Stop prevents new work, cancels and waits for in-flight work up to ctx's
// deadline. A timed-out dispatcher remains counted until it actually returns.
func (e *Engine) Stop(ctx context.Context) error {
	if ctx == nil {
		return invalid("context is nil")
	}
	e.mu.Lock()
	if e.running {
		e.running = false
		e.stopping = true
		if e.cancel != nil {
			e.cancel()
		}
	}
	done := e.stopDone
	if done == nil && !e.stopping {
		e.mu.Unlock()
		return nil
	}
	e.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SetSettings updates the persisted security gate and emit categories at once.
func (e *Engine) SetSettings(settings Settings) { e.mu.Lock(); e.settings = settings; e.mu.Unlock() }
func (e *Engine) SetConfig(config Config)       { e.SetSettings(config) }
func (e *Engine) Settings() Settings            { e.mu.Lock(); defer e.mu.Unlock(); return e.settings }
func (e *Engine) Config() Config                { return e.Settings() }
func (e *Engine) Running() bool                 { e.mu.Lock(); defer e.mu.Unlock(); return e.running }

// Dispatch executes one supported wire command through the public automation
// intake. Calls are serialized, bounded by ctx, and cancelled when the engine
// stops. The intake setting is fail-closed; host applications should load
// persisted automation_receive_enabled before Start.
func (e *Engine) Dispatch(ctx context.Context, name string, args json.RawMessage) (any, error) {
	if strings.HasPrefix(name, "http.") {
		return nil, invalid("HTTP method envelope is not an automation action")
	}
	return e.dispatchCommand(ctx, name, args, true)
}

// Run executes an explicit JSON command envelope. A missing action is always a
// bad request; args never supplies an implicit/default action.
func (e *Engine) Run(ctx context.Context, input RunInput) (any, error) {
	if strings.TrimSpace(input.Action) == "" {
		return nil, invalid("action is required")
	}
	return e.Dispatch(ctx, input.Action, input.Args)
}

// DecodeRunInput validates the explicit `{action,args}` envelope used by
// in-process/runtime adapters. `cmd` is intentionally not accepted here: the
// legacy alias belongs only to the Android Locale setting decoder.
func DecodeRunInput(raw []byte) (RunInput, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return RunInput{}, invalid("action is required")
	}
	var input RunInput
	if err := json.Unmarshal(raw, &input); err != nil {
		return RunInput{}, invalid("run input must be a JSON object")
	}
	if strings.TrimSpace(input.Action) == "" {
		return RunInput{}, invalid("action is required")
	}
	if len(input.Args) == 0 {
		input.Args = json.RawMessage(`{}`)
	}
	if _, err := canonicalArgs(input.Args); err != nil {
		return RunInput{}, err
	}
	return input, nil
}

// EncodeConfig and DecodeConfig preserve the flat persisted field names used by
// SettingsStorage and backup/restore. Missing fields decode to false.
func EncodeConfig(config Config) ([]byte, error) { return json.Marshal(config) }
func DecodeConfig(raw []byte) (Config, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return Config{}, invalid("automation config must be a JSON object")
	}
	var config Config
	if err := json.Unmarshal(raw, &config); err != nil {
		return Config{}, invalid("automation config must be a JSON object")
	}
	return config, nil
}

// DispatchDebug is the shared action entry used by Debug HTTP. Debug HTTP has
// its own bearer-token boundary and does not inherit the Android intake toggle.
func (e *Engine) DispatchDebug(ctx context.Context, name string, args json.RawMessage) (any, error) {
	return e.DispatchDebugMethod(ctx, name, args)
}

// DispatchDebugMethod exposes non-automation Debug handlers to an application
// adapter while preserving the same cancellable serialized execution lane.
// Unknown action endpoints still fail explicitly; this is not a success stub.
func (e *Engine) DispatchDebugMethod(ctx context.Context, method string, args json.RawMessage) (any, error) {
	normalized := NormalizeAction(method)
	if isKnownCommand(normalized) {
		return e.dispatchCommand(ctx, normalized, args, false)
	}
	if ctx == nil {
		return nil, invalid("context is nil")
	}
	if strings.TrimSpace(method) == "" {
		return nil, invalid("method is required")
	}
	e.mu.Lock()
	running, stopping, root := e.running, e.stopping, e.root
	if running && !stopping {
		e.inflight.Add(1)
	}
	e.mu.Unlock()
	if !running {
		return nil, ErrNotRunning
	}
	if stopping {
		return nil, ErrNotRunning
	}
	defer e.inflight.Done()
	if e.dispatch == nil {
		return nil, ErrNoDispatcher
	}
	payload, err := canonicalArgs(args)
	if err != nil {
		return nil, err
	}
	callCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(root, cancel)
	defer func() { stop(); cancel() }()
	select {
	case e.gate <- struct{}{}:
	case <-callCtx.Done():
		return nil, callCtx.Err()
	}
	defer func() { <-e.gate }()
	result, err := e.dispatch(callCtx, method, payload)
	if err != nil {
		return nil, PublicError(err)
	}
	return result, nil
}

// DispatchAutomation is an explicit alias for Android Intent/Locale callers.
// It documents the security boundary while keeping Dispatch source-compatible.
func (e *Engine) DispatchAutomation(ctx context.Context, name string, args json.RawMessage) (any, error) {
	return e.dispatchCommand(ctx, name, args, true)
}

// DispatchIntent adapts the original Android receiver contract. Empty required
// extras are errors rather than silently successful no-ops; the native receiver
// itself historically drops these before calling Dart.
func (e *Engine) DispatchIntent(ctx context.Context, intentAction string, extras map[string]any) (any, error) {
	name := NormalizeAction(intentAction)
	var args json.RawMessage
	var err error
	if extras == nil {
		args = json.RawMessage(`{}`)
	} else {
		args, err = json.Marshal(extras)
	}
	if err != nil {
		return nil, invalid("intent extras must be JSON values")
	}
	return e.Dispatch(ctx, name, args)
}

// DispatchSetting executes Locale's v1 `{v,cmd,args}` setting bundle.
func (e *Engine) DispatchSetting(ctx context.Context, raw []byte) (any, error) {
	setting, err := DecodeSetting(raw)
	if err != nil {
		return nil, err
	}
	args, err := json.Marshal(setting.Args)
	if err != nil {
		return nil, invalid("plugin args must be JSON values")
	}
	return e.Dispatch(ctx, setting.Cmd, args)
}

func (e *Engine) dispatchCommand(ctx context.Context, name string, args json.RawMessage, requireIntake bool) (any, error) {
	if ctx == nil {
		return nil, invalid("context is nil")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, invalid("action is required")
	}
	name = NormalizeAction(name)
	if !isKnownCommand(name) {
		return nil, fmt.Errorf("%w: %s", ErrUnknownAction, name)
	}
	e.mu.Lock()
	running, root, enabled := e.running, e.root, e.settings.ReceiveEnabled
	if running && (!requireIntake || enabled) {
		e.inflight.Add(1)
	}
	e.mu.Unlock()
	if !running {
		return nil, ErrNotRunning
	}
	if requireIntake && !enabled {
		return nil, ErrAutomationOff
	}
	defer e.inflight.Done()
	if e.dispatch == nil {
		return nil, ErrNoDispatcher
	}
	payload, err := canonicalArgs(args)
	if err != nil {
		return nil, err
	}
	payload, err = normalizeActionArgs(name, payload)
	if err != nil {
		return nil, err
	}
	if err := validateAction(name, payload); err != nil {
		return nil, err
	}
	callCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(root, cancel)
	defer func() { stop(); cancel() }()
	select {
	case e.gate <- struct{}{}:
	case <-callCtx.Done():
		return nil, callCtx.Err()
	}
	defer func() { <-e.gate }()
	if err := callCtx.Err(); err != nil {
		return nil, err
	}
	result, err := e.dispatch(callCtx, name, payload)
	if err != nil {
		public := PublicError(err)
		e.log("warn", "automation action failed", map[string]any{"action": name, "code": public.Code})
		if requireIntake {
			_ = e.EmitVPNError(context.WithoutCancel(callCtx), public.Code, public.Message)
		}
		return nil, public
	}
	e.log("info", "automation action completed", map[string]any{"action": name})
	return result, nil
}

// NormalizeAction accepts Dart command names, Locale plugin commands, and the
// public Android Intent names, returning a stable lower-case dispatcher name.
func NormalizeAction(name string) string {
	name = strings.TrimSpace(name)
	const prefix = "com.leadaxe.lxbox."
	if strings.HasPrefix(name, prefix) {
		switch strings.TrimPrefix(name, prefix) {
		case "START_VPN":
			return "start-vpn"
		case "STOP_VPN":
			return "stop-vpn"
		case "TOGGLE_VPN":
			return "toggle-vpn"
		case "SWITCH_NODE":
			return "switch-node"
		case "SET_GROUP":
			return "set-group"
		case "REBUILD_CONFIG":
			return "rebuild-config"
		case "REFRESH_SUBS":
			return "refresh-subs"
		case "RESET_NETWORK":
			return "reset-network"
		case "URLTEST_GROUP":
			return "urltest-group"
		case "URLTEST_ALL":
			return "urltest-all"
		}
	}
	return name
}

func canonicalArgs(raw json.RawMessage) (json.RawMessage, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return json.RawMessage(`{}`), nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, invalid("args must be a JSON object")
	}
	return json.Marshal(obj)
}

func normalizeActionArgs(name string, raw json.RawMessage) (json.RawMessage, error) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil || values == nil {
		return nil, invalid("args must be a JSON object")
	}
	if name == "refresh-subs" {
		force := false
		if rawForce, ok := values["force"]; ok {
			var b bool
			if json.Unmarshal(rawForce, &b) == nil {
				force = b
			} else {
				var s string
				if json.Unmarshal(rawForce, &s) == nil {
					switch strings.ToLower(s) {
					case "true", "1", "yes":
						force = true
					}
				}
			}
		}
		encoded, err := json.Marshal(force)
		if err != nil {
			return nil, err
		}
		values["force"] = encoded
	}
	return json.Marshal(values)
}

func validateAction(name string, args json.RawMessage) error {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(args, &values); err != nil {
		return invalid("args must be a JSON object")
	}
	if name == "switch-node" || name == "urltest-group" {
		if emptyString(values["tag"]) && name == "switch-node" {
			return invalid(`"tag" empty`)
		}
		if emptyString(values["group"]) && name == "urltest-group" {
			return invalid(`"group" empty`)
		}
	}
	if name == "set-group" && emptyString(values["group"]) {
		return invalid(`"group" empty`)
	}
	if name == "refresh-subs" && len(values["force"]) > 0 && !validBool(values["force"]) {
		return invalid(`"force" must be boolean`)
	}
	return nil
}
func emptyString(raw json.RawMessage) bool {
	var s string
	return len(raw) == 0 || json.Unmarshal(raw, &s) != nil || s == ""
}
func validBool(raw json.RawMessage) bool {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return true
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return false
	}
	switch strings.ToLower(s) {
	case "true", "false", "1", "0", "yes", "no":
		return true
	}
	return false
}

// DecodeSetting and EncodeSetting preserve the Locale setting wire fields
// `{ "v":1, "cmd":"switch-node", "args":{...} }`.
func DecodeSetting(raw []byte) (Setting, error) {
	if len(raw) > LocaleBundleMaxBytes {
		return Setting{}, invalid("plugin bundle exceeds 25000 bytes")
	}
	var s Setting
	if err := json.Unmarshal(raw, &s); err != nil || s.Cmd == "" {
		return Setting{}, invalid("invalid plugin setting bundle")
	}
	if s.Version == 0 {
		s.Version = LocaleBundleVersion
	}
	if s.Version != LocaleBundleVersion {
		return Setting{}, invalid("unsupported plugin setting version")
	}
	if s.Args == nil {
		s.Args = map[string]any{}
	}
	s.Cmd = NormalizeAction(s.Cmd)
	return s, nil
}
func EncodeSetting(s Setting) ([]byte, error) {
	if s.Version == 0 {
		s.Version = LocaleBundleVersion
	}
	if s.Cmd == "" {
		return nil, invalid("setting cmd is required")
	}
	if s.Args == nil {
		s.Args = map[string]any{}
	}
	return json.Marshal(s)
}

// DecodeCondition and EncodeCondition preserve `{v,check,equals}` for Locale.
func DecodeCondition(raw []byte) (Condition, error) {
	if len(raw) > LocaleBundleMaxBytes {
		return Condition{}, invalid("plugin bundle exceeds 25000 bytes")
	}
	var c Condition
	if err := json.Unmarshal(raw, &c); err != nil || c.Check == "" {
		return Condition{}, invalid("invalid plugin condition bundle")
	}
	if c.Version == 0 {
		c.Version = LocaleBundleVersion
	}
	if c.Version != LocaleBundleVersion {
		return Condition{}, invalid("unsupported plugin condition version")
	}
	return c, nil
}
func EncodeCondition(c Condition) ([]byte, error) {
	if c.Version == 0 {
		c.Version = LocaleBundleVersion
	}
	if c.Check == "" {
		return nil, invalid("condition check is required")
	}
	return json.Marshal(c)
}

// EvaluateCondition implements the native Locale condition result contract:
// missing expected/cached node or group is UNKNOWN, never UNSATISFIED.
func EvaluateCondition(c Condition, state ConditionState) ConditionResult {
	switch c.Check {
	case "vpn-up":
		if state.VPNUp {
			return ConditionSatisfied
		}
		return ConditionUnsatisfied
	case "active-node":
		return compareCached(state.ActiveNode, c.Equals)
	case "active-group":
		return compareCached(state.ActiveGroup, c.Equals)
	default:
		return ConditionUnknown
	}
}
func compareCached(cached *string, expected string) ConditionResult {
	if cached == nil || *cached == "" || expected == "" {
		return ConditionUnknown
	}
	if *cached == expected {
		return ConditionSatisfied
	}
	return ConditionUnsatisfied
}

// Emit applies category gates and the original one-minute per-subscription
// throttle for SUB_REFRESH_FAILED. Other events are not rate limited.
func (e *Engine) Emit(ctx context.Context, name string, extras map[string]any) error {
	if ctx == nil {
		return invalid("context is nil")
	}
	if extras == nil {
		extras = map[string]any{}
	}
	category, key := eventCategory(name), ""
	if category == "" {
		return invalid("unknown automation event")
	}
	e.mu.Lock()
	gates := e.settings.Gates()
	allowed := map[string]bool{"lifecycle": gates.Lifecycle, "state": gates.State, "subs": gates.Subs, "health": gates.Health}[category]
	if !allowed {
		e.mu.Unlock()
		return nil
	}
	if name == "SUB_REFRESH_FAILED" {
		sub := fmt.Sprint(extras["sub_id"])
		key = name + ":" + sub
		if last, ok := e.lastEmit[key]; ok && e.clock().Sub(last) < time.Minute {
			e.mu.Unlock()
			e.log("info", "automation event throttled", map[string]any{"event": name})
			return nil
		}
		e.lastEmit[key] = e.clock()
	}
	sink := e.events
	e.mu.Unlock()
	if sink == nil {
		return ErrNoEventSink
	}
	event := Event{Name: name, Extras: sanitizeExtras(extras), At: e.clock().UTC()}
	if err := sink(ctx, event); err != nil {
		e.log("warn", "automation event delivery failed", map[string]any{"event": name})
		return err
	}
	e.log("info", "automation event sent", map[string]any{"event": name})
	return nil
}

func (e *Engine) EmitVPNConnected(ctx context.Context) error {
	return e.Emit(ctx, "VPN_CONNECTED", nil)
}
func (e *Engine) EmitVPNDisconnected(ctx context.Context, reason string) error {
	return e.Emit(ctx, "VPN_DISCONNECTED", map[string]any{"reason": reason})
}
func (e *Engine) EmitVPNError(ctx context.Context, code, message string) error {
	if code != "tunnel_error" {
		if code == "" {
			code = "error"
		}
		if message == "" {
			message = "internal error"
		}
	}
	return e.Emit(ctx, "VPN_ERROR", map[string]any{"code": code, "message": message})
}
func (e *Engine) EmitVPNRevoked(ctx context.Context) error { return e.Emit(ctx, "VPN_REVOKED", nil) }
func (e *Engine) EmitUpdateAvailable(ctx context.Context, version, rawURL string) error {
	return e.Emit(ctx, "UPDATE_AVAILABLE", map[string]any{"version": version, "url": rawURL})
}
func (e *Engine) EmitPermissionNeeded(ctx context.Context, permission string) error {
	return e.Emit(ctx, "PERMISSION_NEEDED", map[string]any{"permission": permission})
}
func (e *Engine) EmitNodeChanged(ctx context.Context, oldTag *string, newTag, group, reason string) error {
	return e.Emit(ctx, "ACTIVE_NODE_CHANGED", map[string]any{"old_tag": oldTag, "new_tag": newTag, "group": group, "reason": reason})
}
func (e *Engine) EmitNodeAlreadyActive(ctx context.Context, tag, group string) error {
	return e.Emit(ctx, "NODE_ALREADY_ACTIVE", map[string]any{"tag": tag, "group": group})
}
func (e *Engine) EmitGroupChanged(ctx context.Context, oldGroup *string, newGroup, reason string) error {
	return e.Emit(ctx, "ACTIVE_GROUP_CHANGED", map[string]any{"old_group": oldGroup, "new_group": newGroup, "reason": reason})
}
func (e *Engine) EmitSubRefreshed(ctx context.Context, subID string, nodesCount, deltaCount int) error {
	return e.Emit(ctx, "SUB_REFRESHED", map[string]any{"sub_id": subID, "nodes_count": nodesCount, "delta_count": deltaCount})
}
func (e *Engine) EmitSubRefreshFailed(ctx context.Context, subID, errText string) error {
	return e.Emit(ctx, "SUB_REFRESH_FAILED", map[string]any{"sub_id": subID, "error": errText})
}
func (e *Engine) EmitHeartbeatFailed(ctx context.Context, fails int) error {
	return e.Emit(ctx, "HEARTBEAT_FAILED", map[string]any{"fails": fails})
}
func (e *Engine) EmitLatencyDegraded(ctx context.Context, tag string, latencyMS int) error {
	return e.Emit(ctx, "LATENCY_DEGRADED", map[string]any{"tag": tag, "latency_ms": latencyMS})
}

func eventCategory(name string) string {
	switch name {
	case "VPN_CONNECTED", "VPN_DISCONNECTED", "VPN_ERROR", "VPN_REVOKED", "UPDATE_AVAILABLE", "PERMISSION_NEEDED":
		return "lifecycle"
	case "ACTIVE_NODE_CHANGED", "ACTIVE_GROUP_CHANGED", "NODE_ALREADY_ACTIVE":
		return "state"
	case "SUB_REFRESHED", "SUB_REFRESH_FAILED":
		return "subs"
	case "HEARTBEAT_FAILED", "LATENCY_DEGRADED", "UNATTRIBUTED_BURST":
		return "health"
	default:
		return ""
	}
}

func sanitizeExtras(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "token") || strings.Contains(lk, "secret") || strings.Contains(lk, "auth") || lk == "key" || strings.Contains(lk, "password") {
			out[k] = "***"
			continue
		}
		if v == nil {
			continue
		}
		switch value := v.(type) {
		case string:
			switch {
			case k == "sub_id":
				out[k] = maskSubscription(value)
			case k == "error":
				out[k] = credentialPattern.ReplaceAllString(value, "$1***")
			case k == "message" && in["code"] == "tunnel_error":
				out[k] = sanitizeErrorText(value)
			default:
				out[k] = value
			}
		default:
			out[k] = v
		}
	}
	return out
}
func maskSubscription(raw string) string {
	if strings.HasPrefix(raw, "file:") {
		return "file:<local>"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		if strings.Contains(raw, "://") {
			return "***"
		}
		return raw
	}
	return u.Scheme + "://" + u.Host + "/***"
}
func sanitizeURL(raw string) string {
	if strings.HasPrefix(raw, "file:") {
		return "file:<local>"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "***"
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.Path = "/***"
	u.RawPath = ""
	return u.String()
}
func sanitizeErrorText(raw string) string {
	raw = maskAddresses(raw)
	return credentialPattern.ReplaceAllString(raw, "$1***")
}

var credentialPattern = regexp.MustCompile(`(?i)([?&](?:token|secret|auth|key|password)=)[^&\s]+`)

func maskAddresses(s string) string {
	// Match hostnames and IPv4/IPv6 address forms while retaining ports and
	// surrounding diagnostic text (same privacy boundary as the Dart client).
	return networkAddressPattern.ReplaceAllStringFunc(s, func(address string) string {
		trimmed := strings.Trim(address, "[]")
		if strings.Contains(trimmed, ":") {
			if _, port, err := net.SplitHostPort(trimmed); err == nil && port != "" {
				return "***:" + port
			}
			if ip := net.ParseIP(trimmed); ip != nil {
				return "***"
			}
			if i := strings.LastIndex(trimmed, ":"); i >= 0 && i < len(trimmed)-1 {
				if _, err := strconv.Atoi(trimmed[i+1:]); err == nil {
					return "***" + trimmed[i:]
				}
			}
		}
		return "***"
	})
}

var networkAddressPattern = regexp.MustCompile(`(?i)\[[0-9a-f:.%]+\]|(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?|(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::[0-9]+)?\b`)

func (e *Engine) log(level, message string, fields map[string]any) {
	if e.logger != nil {
		e.logger(level, message, fields)
	}
}

// ParseQueryArgs turns query values into the JSON object format accepted by
// Dispatcher. Repeated query keys retain the final value, like the original
// DebugRequest.queryParameters contract.
func ParseQueryArgs(values url.Values) (json.RawMessage, error) {
	m := make(map[string]any, len(values))
	for k, v := range values {
		if len(v) > 0 {
			m[k] = v[len(v)-1]
		}
	}
	b, err := json.Marshal(m)
	return b, err
}
