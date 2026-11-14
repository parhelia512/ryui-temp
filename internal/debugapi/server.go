// Package debugapi provides the loopback-only Debug HTTP transport.
//
// It owns transport policy (loopback binding, Host validation, bearer auth,
// body/time limits, JSON/SSE framing) and delegates business operations to a
// runtime-independent automation.Dispatcher. It deliberately does not import
// sing-box runtime packages.
package debugapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Leadaxe/lxbox/app/internal/automation"
)

const (
	DefaultPort                 = 9269
	DefaultRequestTimeout       = 30 * time.Second
	DefaultMaxBodyBytes   int64 = 1024 * 1024
)

var (
	ErrTokenRequired    = errors.New("debug API token is required")
	ErrInvalidPort      = errors.New("debug API port must be between 0 and 65535")
	ErrAlreadyRunning   = errors.New("debug API is already running")
	ErrNotRunning       = errors.New("debug API is not running")
	ErrUnsupportedRoute = errors.New("debug API route is not supported")
)

// Config mirrors the persisted Dart debug_* settings and transport defaults.
// Address is intentionally absent: binding is always 127.0.0.1 and cannot be
// changed by a caller or a config file.
type Config struct {
	Port                 int
	Token                string
	RequestTimeout       time.Duration
	MaxBodyBytes         int64
	UnauthenticatedPaths map[string]bool
}

func DefaultConfig(token string) Config {
	return Config{Port: DefaultPort, Token: token, RequestTimeout: DefaultRequestTimeout, MaxBodyBytes: DefaultMaxBodyBytes, UnauthenticatedPaths: map[string]bool{"/ping": true, "/help": true}}
}

func (c Config) normalized() (Config, error) {
	if c.Port < 0 || c.Port > 65535 {
		return Config{}, ErrInvalidPort
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = DefaultRequestTimeout
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if c.UnauthenticatedPaths == nil {
		c.UnauthenticatedPaths = map[string]bool{"/ping": true, "/help": true}
	}
	return c, nil
}

// Server is safe for a single Start/Stop lifecycle and concurrent HTTP calls.
type Server struct {
	mu        sync.RWMutex
	config    Config
	dispatch  automation.Dispatcher
	http      *http.Server
	listener  net.Listener
	startedAt time.Time
	serveDone chan error
	hub       *eventHub
}

// NewServer creates a stopped server. dispatch is the only business-layer
// dependency; adapters should return an explicit error for unsupported methods.
func NewServer(config Config, dispatch automation.Dispatcher) *Server {
	normalized, err := config.normalized()
	if err != nil {
		normalized = config
	}
	return &Server{config: normalized, dispatch: dispatch, hub: newEventHub()}
}

func (s *Server) Config() Config { s.mu.RLock(); defer s.mu.RUnlock(); return s.config }
func (s *Server) Running() bool  { s.mu.RLock(); defer s.mu.RUnlock(); return s.http != nil }
func (s *Server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}
func (s *Server) Port() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.listener == nil {
		return 0
	}
	return s.listener.Addr().(*net.TCPAddr).Port
}

// Start binds only 127.0.0.1. Port 0 is accepted for in-process tests and
// callers can read the assigned port through Port/Addr.
func (s *Server) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("debug API context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.http != nil {
		s.mu.Unlock()
		return ErrAlreadyRunning
	}
	config, err := s.config.normalized()
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if strings.TrimSpace(config.Token) == "" {
		s.mu.Unlock()
		return ErrTokenRequired
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(config.Port)))
	if err != nil {
		s.mu.Unlock()
		return err
	}
	server := &http.Server{Handler: http.HandlerFunc(s.serveHTTP), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	s.config, s.listener, s.http, s.startedAt, s.serveDone = config, listener, server, time.Now(), make(chan error, 1)
	done := s.serveDone
	s.mu.Unlock()
	go func() {
		err := server.Serve(listener)
		if !errors.Is(err, http.ErrServerClosed) {
			done <- err
		} else {
			done <- nil
		}
		close(done)
	}()
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Stop(context.Background())
		case <-done:
		}
	}()
	return nil
}

// Stop closes the listener and active HTTP connections. In-flight dispatcher
// work observes the request context and is cancelled by net/http.
func (s *Server) Stop(ctx context.Context) error {
	if ctx == nil {
		return errors.New("debug API context is nil")
	}
	s.mu.Lock()
	server := s.http
	if server == nil {
		s.mu.Unlock()
		return nil
	}
	s.http, s.listener = nil, nil
	s.mu.Unlock()
	closeErr := server.Shutdown(ctx)
	if closeErr != nil {
		_ = server.Close()
		return closeErr
	}
	return nil
}

// Dispatch is the integration API used by runtime services and tests. It
// validates JSON object input and delegates without silently accepting unknown
// methods; the dispatcher owns the supported business method set.
func (s *Server) Dispatch(ctx context.Context, method string, args json.RawMessage) (any, error) {
	if ctx == nil {
		return nil, errors.New("debug API context is nil")
	}
	method = strings.TrimSpace(method)
	if method == "" {
		return nil, &automation.Error{Code: "bad_request", Message: "method is required"}
	}
	if s.dispatch == nil {
		return nil, errors.New("debug API dispatcher is not configured")
	}
	payload, err := objectJSON(args)
	if err != nil {
		return nil, err
	}
	result, err := s.dispatch(ctx, method, payload)
	if err != nil {
		return nil, publicError(err)
	}
	return result, nil
}

// DispatchInput executes the explicit `{method,args}` in-process envelope.
// Missing method is a bad request and never inferred from args.
func (s *Server) DispatchInput(ctx context.Context, input struct {
	Method string          `json:"method"`
	Args   json.RawMessage `json:"args"`
}) (any, error) {
	if strings.TrimSpace(input.Method) == "" {
		return nil, &automation.Error{Code: "bad_request", Message: "method is required"}
	}
	return s.Dispatch(ctx, input.Method, input.Args)
}

func objectJSON(raw json.RawMessage) (json.RawMessage, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return json.RawMessage(`{}`), nil
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, &automation.Error{Code: "bad_request", Message: "args must be a JSON object"}
	}
	return json.Marshal(obj)
}

// PublishEvent feeds authenticated /events SSE clients. It is safe to call
// when the server is stopped; no event is retained or replayed, matching the
// original Debug SSE stream's no-replay behavior.
func (s *Server) PublishEvent(ctx context.Context, event automation.Event) error {
	if ctx == nil {
		return errors.New("debug API context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if event.Name == "" {
		return &automation.Error{Code: "bad_request", Message: "event name is required"}
	}
	return s.hub.publish(ctx, event)
}

func (s *Server) EventSink() automation.EventSink { return s.PublishEvent }

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if !isLoopbackHost(r.Host) {
		writeError(w, &automation.Error{Code: "invalid_host", Message: "request host must be 127.0.0.1 or localhost"})
		return
	}
	config := s.Config()
	if !config.UnauthenticatedPaths[path] && !validBearer(r.Header.Get("Authorization"), config.Token) {
		writeErrorStatus(w, http.StatusUnauthorized, &automation.Error{Code: "unauthorized", Message: "valid Bearer token required"})
		return
	}
	if path == "/events" || path == "/automation/events" {
		s.handleEvents(w, r)
		return
	}
	if path == "/ping" {
		s.handlePing(w, r)
		return
	}
	if path == "/help" {
		s.handleHelp(w, r)
		return
	}
	body, err := readBody(r, config.MaxBodyBytes)
	if err != nil {
		writeError(w, err)
		return
	}
	args, err := mergeArgs(r, body)
	if err != nil {
		writeError(w, err)
		return
	}
	method, ok := routeMethod(path)
	if !ok {
		writeErrorStatus(w, http.StatusNotFound, &automation.Error{Code: "not_found", Message: "route: " + path})
		return
	}
	if path == "/action" || strings.HasPrefix(path, "/action/") {
		if r.Method != http.MethodPost {
			writeErrorStatus(w, http.StatusBadRequest, &automation.Error{Code: "bad_request", Message: "actions require POST"})
			return
		}
	} else if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodDelete {
		writeErrorStatus(w, http.StatusBadRequest, &automation.Error{Code: "bad_request", Message: "unsupported HTTP method"})
		return
	}
	timeout := config.RequestTimeout
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	isAction := strings.HasPrefix(path, "/action/") || strings.HasPrefix(path, "/dispatch/")
	dispatchName := dispatchMethod(r.Method, method)
	if isAction {
		dispatchName = automation.NormalizeAction(method)
	}
	result, dispatchErr := s.Dispatch(ctx, dispatchName, args)
	if dispatchErr != nil {
		writeMappedError(w, dispatchErr)
		return
	}
	if body, ok := result.([]byte); ok {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return
	}
	if isAction {
		writeJSON(w, http.StatusOK, actionResponse(method, result))
	} else {
		writeJSON(w, http.StatusOK, result)
	}

}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorStatus(w, http.StatusBadRequest, &automation.Error{Code: "bad_request", Message: "ping requires GET"})
		return
	}
	s.mu.RLock()
	started := s.startedAt
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"pong": true, "server": "lxbox-debug", "uptime_seconds": int(time.Since(started).Seconds())})
}
func (s *Server) handleHelp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorStatus(w, http.StatusBadRequest, &automation.Error{Code: "bad_request", Message: "help requires GET"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"server": "lxbox-debug", "bind": "127.0.0.1", "auth": "Bearer token required except /ping and /help", "actions": []string{"start-vpn", "stop-vpn", "toggle-vpn", "switch-node", "set-group", "rebuild-config", "refresh-subs", "reset-network", "urltest-group", "urltest-all"}, "events": []string{"/events", "/automation/events"}})
}

func routeMethod(path string) (string, bool) {
	if path == "/action" {
		return "action", true
	}
	if strings.HasPrefix(path, "/dispatch/") {
		m := strings.TrimPrefix(path, "/dispatch/")
		if m != "" && !strings.Contains(m, "/") {
			return automation.NormalizeAction(m), true
		}
	}
	if strings.HasPrefix(path, "/action/") {
		m := strings.TrimPrefix(path, "/action/")
		if m != "" && !strings.Contains(m, "/") {
			return automation.NormalizeAction(m), true
		}
	}
	// Generic read/write routes are delegated as stable names so adapters may
	// expose the corresponding original Debug handlers without this transport
	// importing runtime state types.
	for _, prefix := range []string{"/state", "/device", "/config", "/logs", "/pool", "/nodes", "/directions", "/chains", "/folders", "/core_reject", "/settings", "/wifi_history", "/profiler", "/support", "/taildrop", "/backup", "/rules", "/subs", "/files", "/diag", "/warp", "/mixins"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return strings.TrimPrefix(path, "/"), true
		}
	}
	return "", false
}

func dispatchMethod(httpMethod, route string) string {
	if strings.HasPrefix(route, "action/") || route == "action" {
		return automation.NormalizeAction(strings.TrimPrefix(route, "action/"))
	}
	return "http." + strings.ToUpper(httpMethod) + " /" + route
}

func mergeArgs(r *http.Request, body []byte) (json.RawMessage, error) {
	obj := map[string]any{}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
			return nil, &automation.Error{Code: "bad_request", Message: "body must be JSON object"}
		}
	}
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			obj[k] = v[len(v)-1]
		}
	}
	return json.Marshal(obj)
}
func readBody(r *http.Request, max int64) ([]byte, error) {
	if max <= 0 {
		max = DefaultMaxBodyBytes
	}
	limited := io.LimitReader(r.Body, max+1)
	b, err := io.ReadAll(limited)
	if err != nil {
		return nil, &automation.Error{Code: "bad_request", Message: "request body could not be read"}
	}
	if int64(len(b)) > max {
		return nil, &automation.Error{Code: "payload_too_large", Message: fmt.Sprintf("body exceeds %d bytes", max)}
	}
	return b, nil
}
func isLoopbackHost(raw string) bool {
	host, _, err := net.SplitHostPort(raw)
	if err != nil {
		host = raw
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback() && ip.To4() != nil
}
func validBearer(header, token string) bool {
	const prefix = "Bearer "
	if token == "" || !strings.HasPrefix(header, prefix) {
		return false
	}
	given := strings.TrimPrefix(header, prefix)
	return len(given) == len(token) && subtle.ConstantTimeCompare([]byte(given), []byte(token)) == 1
}
func actionResponse(method string, result any) map[string]any {
	out := map[string]any{"ok": true, "action": method}
	if m, ok := result.(map[string]any); ok {
		for k, v := range m {
			if k != "ok" && k != "action" {
				out[k] = v
			}
		}
	} else if result != nil {
		out["result"] = result
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, err error) { writeMappedError(w, err) }
func writeMappedError(w http.ResponseWriter, err error) {
	pub := publicError(err)
	writeErrorStatus(w, statusFor(pub), pub)
}
func writeErrorStatus(w http.ResponseWriter, status int, err *automation.Error) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": err.Code, "message": err.Message}})
}
func publicError(err error) *automation.Error {
	if err == nil {
		return nil
	}
	pe := automation.PublicError(err)
	if pe.Code != "internal" || pe.Message != "internal error" {
		return pe
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &automation.Error{Code: "timeout", Message: "request timed out"}
	}
	if errors.Is(err, context.Canceled) {
		return &automation.Error{Code: "conflict", Message: "request canceled"}
	}
	if errors.Is(err, automation.ErrUnknownAction) {
		return &automation.Error{Code: "not_found", Message: "unsupported action"}
	}
	if errors.Is(err, automation.ErrAutomationOff) {
		return &automation.Error{Code: "conflict", Message: "automation command intake is disabled"}
	}
	if errors.Is(err, automation.ErrNoDispatcher) {
		return &automation.Error{Code: "conflict", Message: "dispatcher not ready"}
	}
	return pe
}
func statusFor(err *automation.Error) int {
	switch err.Code {
	case "bad_request":
		return 400
	case "unauthorized":
		return 401
	case "invalid_host":
		return 403
	case "not_found":
		return 404
	case "conflict":
		return 409
	case "payload_too_large":
		return 413
	case "timeout":
		return 504
	case "upstream_error":
		return 502
	default:
		return 500
	}
}

// eventHub is a bounded, best-effort fanout. A slow SSE consumer loses the
// oldest event rather than blocking the app's state mutation path.
type eventHub struct {
	mu      sync.Mutex
	next    int
	clients map[int]chan automation.Event
}

func newEventHub() *eventHub { return &eventHub{clients: make(map[int]chan automation.Event)} }
func (h *eventHub) subscribe() (int, <-chan automation.Event, func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	id := h.next
	h.next++
	ch := make(chan automation.Event, 32)
	h.clients[id] = ch
	return id, ch, func() {
		h.mu.Lock()
		if c, ok := h.clients[id]; ok {
			delete(h.clients, id)
			close(c)
		}
		h.mu.Unlock()
	}
}
func (h *eventHub) publish(ctx context.Context, e automation.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ch := range h.clients {
		select {
		case ch <- e:
		default:
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- e:
			default:
			}
		}
	}
	return nil
}
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorStatus(w, 400, &automation.Error{Code: "bad_request", Message: "events requires GET"})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErrorStatus(w, 500, &automation.Error{Code: "internal", Message: "streaming is unavailable"})
		return
	}
	_, events, unsubscribe := s.hub.subscribe()
	defer unsubscribe()
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-events:
			if !ok {
				return
			}
			data, _ := json.Marshal(e)
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", safeEventName(e.Name), data)
			flusher.Flush()
		}
	}
}
func safeEventName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "message"
	}
	return b.String()
}
