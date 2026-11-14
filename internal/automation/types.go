// Package automation contains the runtime-independent LxBox automation contract.
//
// The package deliberately does not import the sing-box runtime, Android, or
// any application controller.  Application code supplies Dispatcher and an
// optional event sink.  This keeps the package usable by the app module and
// prevents the runtime/application import cycle that existed at the Dart
// boundary.
package automation

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Dispatcher is the integration seam used by automation and Debug HTTP.
// method is a stable wire action name and args is the original JSON object.
// Implementations must return an error for an action they do not support;
// callers must never turn an unsupported action into a successful response.
type Dispatcher func(context.Context, string, json.RawMessage) (any, error)

// ActionDispatcher is the named form used by application adapters.
type ActionDispatcher = Dispatcher

// EventSink receives an outgoing automation event.  The sink is called after
// gates and throttling have been applied.  The event payload is sanitized
// before it is passed to the sink.
type EventSink func(context.Context, Event) error

// Logger is intentionally structured.  Implementations should avoid printing
// fields that are not supplied by this package; credentials are never placed
// in fields by the package.
type Logger func(level, message string, fields map[string]any)

// Event is the public automation event.  Extras uses the original event field
// names (for example old_tag/new_tag, sub_id, and latency_ms).
type Event struct {
	Name  string         `json:"event"`
	Extras map[string]any `json:"extras,omitempty"`
	At    time.Time      `json:"at"`
}

// Config mirrors every persisted automation setting in the original app.
// Defaults are false when loaded from absent JSON keys.
type Config struct {
	ReceiveEnabled      bool `json:"automation_receive_enabled"`
	EventGates
	ExplainerShownV1    bool `json:"automation_explainer_shown_v1"`
	AppFunctionsEnabled bool `json:"appfunctions_enabled"`
}

// EventGates is the runtime view of the four independent event switches. It is
// embedded in Config so existing adapters can initialize the settings with the
// original field grouping while JSON retains the original flat keys.
type EventGates struct {
	Lifecycle bool `json:"automation_emit_lifecycle"`
	State     bool `json:"automation_emit_state"`
	Subs      bool `json:"automation_emit_subs"`
	Health    bool `json:"automation_emit_health"`
}

// Settings is kept as an alias for callers that already use the name from the
// first migration draft. Use Config for new integration code.
type Settings = Config

func (c Config) Gates() EventGates { return c.EventGates }

// ConditionState is the small native cache exposed to Locale/Tasker
// condition checks.  Node/group values are unknown when nil or empty.
type ConditionState struct {
	VPNUp       bool
	ActiveNode  *string
	ActiveGroup *string
}

// ConditionResult is the twofortyfouram ordered-broadcast result code.
type ConditionResult int

const (
	ConditionSatisfied   ConditionResult = 16
	ConditionUnsatisfied ConditionResult = 17
	ConditionUnknown    ConditionResult = 18
)

// Setting is the JSON stored in Locale's EXTRA_BUNDLE.
type Setting struct {
	Version int            `json:"v"`
	Cmd     string         `json:"cmd"`
	Args    map[string]any `json:"args"`
}

// Condition is the JSON stored in Locale's EXTRA_BUNDLE.
type Condition struct {
	Version int    `json:"v"`
	Check   string `json:"check"`
	Equals  string `json:"equals,omitempty"`
}

// RunInput is the explicit in-process command envelope. Action is required;
// callers must not rely on an empty action being inferred from args.
type RunInput struct {
	Action string          `json:"action"`
	Args   json.RawMessage `json:"args"`
}

var (
	ErrNotRunning     = errors.New("automation engine is not running")
	ErrAlreadyRunning = errors.New("automation engine is already running")
	ErrNoDispatcher   = errors.New("automation dispatcher is not configured")
	ErrNoEventSink    = errors.New("automation event sink is not configured")
	ErrAutomationOff  = errors.New("automation command intake is disabled")
	ErrUnknownAction  = errors.New("unknown automation action")
	ErrInvalidInput   = errors.New("invalid automation input")
)

// Error is a safe, public error.  Message is suitable for an external caller.
// Cause is retained for the application log but is never rendered by the
// default HTTP/event contracts.
type Error struct {
	Code    string
	Message string
	Cause   error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Code == "" {
		return e.Message
	}
	return e.Code + ": " + e.Message
}

func (e *Error) Unwrap() error { if e == nil { return nil }; return e.Cause }

func invalid(message string) error { return &Error{Code: "bad_request", Message: message} }
func conflict(message string) error { return &Error{Code: "conflict", Message: message} }
func notFound(message string) error { return &Error{Code: "not_found", Message: message} }

// PublicError converts arbitrary adapter errors to the non-leaking public
// form.  Runtime errors (which may contain URLs, tokens, or config snippets)
// are retained only as Cause for an application logger.
func PublicError(err error) *Error {
	if err == nil {
		return nil
	}
	var pe *Error
	if errors.As(err, &pe) {
		return pe
	}
	return &Error{Code: "internal", Message: "internal error", Cause: err}
}

func isKnownCommand(method string) bool {
	switch method {
	case "start-vpn", "stop-vpn", "toggle-vpn", "switch-node", "set-group",
		"rebuild-config", "refresh-subs", "reset-network", "urltest-group",
		"urltest-all", "vpn-stop-requested":
		return true
	default:
		return false
	}
}
