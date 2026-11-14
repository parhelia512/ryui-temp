// Package transfer contains the device-transfer wire protocol and platform
// seams used by the app. It intentionally does not parse/apply backup contents;
// the caller must supply that parser, and Android SAF is exposed as callbacks.
package transfer

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	Version       = 1
	Scheme        = "lxbox-transfer"
	AAD           = "lxbox-transfer/1"
	Path          = "/transfer"
	KeySize       = 32
	MaxBodyBytes  = 32 << 20
	MaxRejects    = 5
	SessionTTL    = 10 * time.Minute
	DefaultConnectTimeout = 5 * time.Second
	DefaultResponseTimeout = 60 * time.Second
)

var (
	ErrInvalidCode = errors.New("transfer: invalid transfer code")
	ErrBadEnvelope = errors.New("transfer: malformed envelope")
	ErrAuthentication = errors.New("transfer: envelope authentication failed")
	ErrUnsupported = errors.New("transfer: requested platform callback is not configured")
	ErrCancelled = errors.New("transfer: operation cancelled")
	ErrNoPicker = errors.New("transfer: no SAF picker available")
)

type Endpoint struct { Host string `json:"host"`; Port int `json:"port"` }
func (e Endpoint) String() string { return net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) }

type TransferCode struct {
	Addresses []Endpoint `json:"addresses"`
	Key []byte `json:"key,omitempty"`
	Name string `json:"name"`
}

func NewTransferKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil { return nil, fmt.Errorf("transfer: secure random key: %w", err) }
	return key, nil
}
func EncodeTransferKey(key []byte) (string, error) {
	if len(key) != KeySize { return "", fmt.Errorf("transfer: key must be %d bytes", KeySize) }
	return base64.RawURLEncoding.EncodeToString(key), nil
}
func DecodeTransferKey(text string) ([]byte, error) {
	key, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil || len(key) != KeySize { return nil, ErrInvalidCode }
	return key, nil
}

func (code TransferCode) Encode() (string, error) {
	if len(code.Addresses) == 0 { return "", ErrInvalidCode }
	key, err := EncodeTransferKey(code.Key); if err != nil { return "", err }
	addresses := make([]string, len(code.Addresses))
	for i, ep := range code.Addresses { if err := validateEndpoint(ep); err != nil { return "", err }; addresses[i] = ep.Host+":"+strconv.Itoa(ep.Port) }
	return Scheme + ":" + strconv.Itoa(Version) + "?a=" + strings.Join(addresses, ",") + "&k=" + key + "&n=" + url.QueryEscape(code.Name), nil
}

func ParseCode(text string) (*TransferCode, error) {
	text = strings.TrimSpace(text)
	prefix := Scheme+":"+strconv.Itoa(Version)+"?"
	if !strings.HasPrefix(text, prefix) { return nil, ErrInvalidCode }
	params, err := url.ParseQuery(strings.TrimPrefix(text, prefix)); if err != nil { return nil, ErrInvalidCode }
	key, err := DecodeTransferKey(params.Get("k")); if err != nil { return nil, err }
	rawAddresses := strings.Split(params.Get("a"), ",")
	if len(rawAddresses) == 0 || rawAddresses[0] == "" { return nil, ErrInvalidCode }
	code := &TransferCode{Key:key, Name:strings.TrimSpace(params.Get("n"))}
	for _, raw := range rawAddresses {
		host, rawPort, ok := strings.Cut(strings.TrimSpace(raw), ":"); if !ok { return nil, ErrInvalidCode }
		port, parseErr := strconv.Atoi(rawPort); ep := Endpoint{Host:host, Port:port}
		if parseErr != nil || validateEndpoint(ep) != nil { return nil, ErrInvalidCode }
		code.Addresses = append(code.Addresses, ep)
	}
	return code, nil
}
func validateEndpoint(ep Endpoint) error {
	ip := net.ParseIP(ep.Host)
	if ip == nil || ip.To4() == nil || ep.Port < 1 || ep.Port > 65535 { return ErrInvalidCode }
	return nil
}
func (code TransferCode) String() string {
	addresses := make([]string, len(code.Addresses)); for i, ep := range code.Addresses { addresses[i] = ep.String() }
	return Scheme+":"+strconv.Itoa(Version)+"?a="+strings.Join(addresses, ",")+"&k=***&n="+code.Name
}

// Seal uses AES-256-GCM and the exact Dart wire representation: nonce is
// base64, ciphertext and tag are concatenated in ct, with lxbox-transfer/1 AAD.
func Seal(plaintext, key []byte) (string, error) {
	if len(key) != KeySize { return "", fmt.Errorf("transfer: key must be %d bytes", KeySize) }
	block, err := aes.NewCipher(key); if err != nil { return "", err }
	gcm, err := cipher.NewGCM(block); if err != nil { return "", err }
	nonce := make([]byte, gcm.NonceSize()); if _, err = rand.Read(nonce); err != nil { return "", err }
	sealed := gcm.Seal(nil, nonce, plaintext, []byte(AAD))
	return jsonString(struct { V int `json:"v"`; Nonce string `json:"nonce"`; CT string `json:"ct"` }{Version, base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(sealed)})
}
func jsonString(v any) (string, error) { b, err := json.Marshal(v); return string(b), err }

func Open(envelope string, key []byte) ([]byte, error) {
	if len(key) != KeySize { return nil, fmt.Errorf("transfer: key must be %d bytes", KeySize) }
	var box struct { V int `json:"v"`; Nonce string `json:"nonce"`; CT string `json:"ct"` }
	decoder := json.NewDecoder(strings.NewReader(envelope)); decoder.DisallowUnknownFields()
	if decoder.Decode(&box) != nil || box.V != Version { return nil, ErrBadEnvelope }
	var extra any; if decoder.Decode(&extra) != io.EOF { return nil, ErrBadEnvelope }
	nonce, nonceErr := base64.StdEncoding.DecodeString(box.Nonce); ct, ctErr := base64.StdEncoding.DecodeString(box.CT)
	block, err := aes.NewCipher(key); if err != nil { return nil, err }
	gcm, err := cipher.NewGCM(block); if err != nil { return nil, err }
	if nonceErr != nil || ctErr != nil || len(nonce) != gcm.NonceSize() || len(ct) < gcm.Overhead() { return nil, ErrBadEnvelope }
	clear, err := gcm.Open(nil, nonce, ct, []byte(AAD)); if err != nil { return nil, ErrAuthentication }
	return clear, nil
}

// Payload models a share-sheet item without interpreting or re-encoding the
// contents. Exactly one of Text or Bytes should be populated according to Kind.
type PayloadKind string
const ( TextPayloadKind PayloadKind = "text"; FilePayloadKind PayloadKind = "file" )
type Payload struct { Kind PayloadKind `json:"kind"`; Name string `json:"name,omitempty"`; MIME string `json:"mime,omitempty"`; Text string `json:"text,omitempty"`; Bytes []byte `json:"bytes,omitempty"` }
func TextPayload(text string) Payload { return Payload{Kind:TextPayloadKind, MIME:"text/plain", Text:text} }
func FilePayload(name, mime string, data []byte) Payload { return Payload{Kind:FilePayloadKind, Name:name, MIME:mime, Bytes:append([]byte(nil), data...)} }
func (p Payload) Validate() error {
	switch p.Kind {
	case TextPayloadKind:
		if p.Bytes != nil || p.Name != "" { return errors.New("transfer: malformed text payload") }
		if !utf8.ValidString(p.Text) { return errors.New("transfer: text payload is not UTF-8") }
	case FilePayloadKind: if p.Name == "" || p.Text != "" { return errors.New("transfer: malformed file payload") }
	default: return fmt.Errorf("transfer: unsupported payload kind %q", p.Kind)
	}
	return nil
}

// SAFCallbacks bridge Android's document provider. Callbacks must return a
// real result or an error; absent callbacks are reported as unsupported.
type SAFDocument struct { URI string `json:"uri"`; Name string `json:"name"`; MIME string `json:"mime"` }
type SAFOpenRequest struct { MIMETypes []string; AllowMultiple bool }
type SAFSaveRequest struct { Name string; MIME string }
type SAFCallbacks struct {
	Pick func(context.Context, SAFOpenRequest) ([]SAFDocument, bool, error)
	Read func(context.Context, string) ([]byte, error)
	Create func(context.Context, SAFSaveRequest) (SAFDocument, bool, error)
	Write func(context.Context, string, []byte) error
}
func (s SAFCallbacks) Import(ctx context.Context, request SAFOpenRequest) ([]Payload, error) {
	if s.Pick == nil || s.Read == nil { return nil, ErrUnsupported }
	documents, ok, err := s.Pick(ctx, request); if err != nil { return nil, err }; if !ok { return nil, ErrCancelled }
	payloads := make([]Payload, 0, len(documents))
	for _, doc := range documents {
		if doc.URI == "" { return nil, errors.New("transfer: SAF picker returned empty URI") }
		data, err := s.Read(ctx, doc.URI); if err != nil { return nil, err }
		mime := doc.MIME; if mime == "" { mime = "application/octet-stream" }
		payloads = append(payloads, FilePayload(doc.Name, mime, data))
	}
	if len(payloads) == 0 { return nil, ErrCancelled }
	return payloads, nil
}
func (s SAFCallbacks) Export(ctx context.Context, payload Payload) (SAFDocument, error) {
	if err := payload.Validate(); err != nil { return SAFDocument{}, err }
	if s.Create == nil || s.Write == nil { return SAFDocument{}, ErrUnsupported }
	if payload.Kind != FilePayloadKind { return SAFDocument{}, errors.New("transfer: SAF export requires a file payload") }
	doc, ok, err := s.Create(ctx, SAFSaveRequest{Name:payload.Name, MIME:payload.MIME}); if err != nil { return SAFDocument{}, err }; if !ok { return SAFDocument{}, ErrCancelled }
	if doc.URI == "" { return SAFDocument{}, errors.New("transfer: SAF create callback returned empty URI") }
	if err := s.Write(ctx, doc.URI, payload.Bytes); err != nil { return SAFDocument{}, err }
	return doc, nil
}

type SendStatus string
const (
	Sent SendStatus = "sent"; Unreachable SendStatus = "unreachable"; Expired SendStatus = "expired"; Rejected SendStatus = "rejected"; TooLarge SendStatus = "too_large"; Invalid SendStatus = "invalid"; Busy SendStatus = "busy"; SendFailed SendStatus = "failed"
)
type SendResult struct { Status SendStatus `json:"status"`; HTTPStatus int `json:"http_status,omitempty"`; Detail string `json:"detail,omitempty"` }
func ResultForResponse(status int, body string) SendResult {
	switch status { case 200: return SendResult{Status:Sent, HTTPStatus:status}; case 403: return SendResult{Status:Rejected, HTTPStatus:status}; case 409: return SendResult{Status:Expired, HTTPStatus:status}; case 413: return SendResult{Status:TooLarge, HTTPStatus:status}; case 422: return SendResult{Status:Invalid, HTTPStatus:status, Detail:strings.TrimSpace(body)}; case 503: return SendResult{Status:Busy, HTTPStatus:status}; default: return SendResult{Status:SendFailed, HTTPStatus:status} }
}

type LANOutcomeKind string
const ( LANResponse LANOutcomeKind = "response"; LANRefused LANOutcomeKind = "refused"; LANUnreachable LANOutcomeKind = "unreachable"; LANNoNetwork LANOutcomeKind = "no_network" )
type LANOutcome struct { Kind LANOutcomeKind; Status int; Body string; Detail string }
type LANPost func(context.Context, Endpoint, []byte) (LANOutcome, error)
type SenderOption func(*Sender)
func SenderWithHTTPClient(client *http.Client) SenderOption { return func(s *Sender) { if client != nil { s.http = client } } }
func SenderWithNativePost(post LANPost) SenderOption { return func(s *Sender) { s.native = post } }
func SenderWithTimeouts(connect, response time.Duration) SenderOption { return func(s *Sender) { if connect > 0 { s.connectTimeout = connect }; if response > 0 { s.responseTimeout = response } } }
type Sender struct { http *http.Client; native LANPost; directFallback bool; connectTimeout, responseTimeout time.Duration }
func NewSender(options ...SenderOption) *Sender {
	s := &Sender{connectTimeout:DefaultConnectTimeout, responseTimeout:DefaultResponseTimeout}
	for _, option := range options { if option != nil { option(s) } }; return s
}
func NewSenderWithNativePost(post LANPost, options ...SenderOption) *Sender {
	all := append([]SenderOption{SenderWithNativePost(post)}, options...)
	return NewSender(all...)
}
func SenderWithDirectFallback(enabled bool) SenderOption { return func(s *Sender) { s.directFallback = enabled } }
func (s *Sender) Send(ctx context.Context, code TransferCode, envelope string) SendResult {
	if len(code.Addresses) == 0 || len(code.Key) != KeySize {
		return SendResult{Status:SendFailed, Detail:ErrInvalidCode.Error()}
	}
	if ctx == nil { ctx = context.Background() }
	body := []byte(envelope)
	refused := false
	var detail string
	for _, endpoint := range code.Addresses {
		if err := validateEndpoint(endpoint); err != nil { detail = err.Error(); continue }
		var outcome LANOutcome
		var err error
		if s.native != nil {
			outcome, err = s.native(ctx, endpoint, body)
			if err == nil && outcome.Kind == LANNoNetwork && s.directFallback {
				outcome, err = s.postHTTP(ctx, endpoint, body)
			}
		} else {
			if !s.directFallback { return SendResult{Status:Unreachable, Detail:"physical LAN callback is not configured"} }
			outcome, err = s.postHTTP(ctx, endpoint, body)
		}
		if err != nil { detail = err.Error(); continue }
		switch outcome.Kind {
		case LANResponse: return ResultForResponse(outcome.Status, outcome.Body)
		case LANRefused: refused = true
		case LANUnreachable: detail = outcome.Detail
		case LANNoNetwork: detail = "no physical LAN network"
		default: detail = "physical LAN post returned no outcome"
		}
	}
	if refused { return SendResult{Status:Expired} }
	return SendResult{Status:Unreachable, Detail:detail}
}
func (s *Sender) postHTTP(ctx context.Context, endpoint Endpoint, body []byte) (LANOutcome, error) {
	if ctx == nil { ctx = context.Background() }
	ctx, cancel := context.WithTimeout(ctx, s.responseTimeout)
	defer cancel()
	url := "http://"+endpoint.String()+Path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body)); if err != nil { return LANOutcome{}, err }
	req.Header.Set("Content-Type", "application/json"); req.Header.Set("User-Agent", "LxBox/Go")
	client := s.http
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DialContext = (&net.Dialer{Timeout:s.connectTimeout, KeepAlive:30*time.Second}).DialContext
		transport.ResponseHeaderTimeout = s.responseTimeout
		client = &http.Client{Transport:transport, Timeout:s.responseTimeout}
	}
	response, err := client.Do(req); if err != nil { return LANOutcome{Kind:LANUnreachable, Detail:err.Error()}, nil }
	defer response.Body.Close()
	limited, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10)); if readErr != nil { return LANOutcome{Kind:LANUnreachable, Detail:readErr.Error()}, nil }
	return LANOutcome{Kind:LANResponse, Status:response.StatusCode, Body:string(limited)}, nil
}

// Receiver parser is mandatory. It should validate exactly the same backup
// format used by file import and return an application-owned preview object.
type ParseBackup func(context.Context, string) (any, error)
type SessionEndKind string
const ( Received SessionEndKind = "received"; SessionExpired SessionEndKind = "expired"; RejectedTooOften SessionEndKind = "rejected_too_often"; SessionCancelled SessionEndKind = "cancelled" )
type SessionResult struct { Kind SessionEndKind; Raw string; Parsed any }
type ReceiverOptions struct { BindAddress string; Key []byte; TTL time.Duration; MaxBody int64; MaxRejected int; Parse ParseBackup }
type Receiver struct {
	server *http.Server
	listener net.Listener
	key []byte
	parse ParseBackup
	maxBody int64
	maxRejected int
	timer *time.Timer
	mu sync.Mutex
	busy bool
	accepted bool
	closed bool
	rejected int
	done chan SessionResult
	once sync.Once
}
func NewReceiver(ctx context.Context, options ReceiverOptions) (*Receiver, error) {
	if ctx == nil { ctx = context.Background() }
	if err := ctx.Err(); err != nil { return nil, err }
	if options.Parse == nil { return nil, errors.New("transfer: receiver backup parser is required") }
	address := options.BindAddress; if address == "" { address = "0.0.0.0:0" }
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", address); if err != nil { return nil, err }
	key := append([]byte(nil), options.Key...); if key == nil { key, err = NewTransferKey(); if err != nil { listener.Close(); return nil, err } }; if len(key) != KeySize { listener.Close(); return nil, fmt.Errorf("transfer: key must be %d bytes", KeySize) }
	ttl := options.TTL; if ttl <= 0 { ttl = SessionTTL }; maxBody := options.MaxBody; if maxBody <= 0 { maxBody = MaxBodyBytes }; maxRejected := options.MaxRejected; if maxRejected <= 0 { maxRejected = MaxRejects }
	rx := &Receiver{listener:listener, key:key, parse:options.Parse, maxBody:maxBody, maxRejected:maxRejected, done:make(chan SessionResult, 1)}
	rx.server = &http.Server{Handler:http.HandlerFunc(rx.handle), ReadHeaderTimeout:5*time.Second}
	rx.timer = time.AfterFunc(ttl, func() { rx.finish(SessionResult{Kind:SessionExpired}, true) })
	if ctx.Done() != nil {
		context.AfterFunc(ctx, func() { rx.finish(SessionResult{Kind:SessionCancelled}, true) })
	}
	go func() { _ = rx.server.Serve(listener) }()
	return rx, nil
}
func (r *Receiver) Port() int { return r.listener.Addr().(*net.TCPAddr).Port }
func (r *Receiver) Key() []byte { return append([]byte(nil), r.key...) }
func (r *Receiver) CodeFor(hosts []string, name string) (TransferCode, error) {
	code := TransferCode{Key:r.Key(), Name:name}
	for _, host := range hosts {
		ep := Endpoint{Host:host, Port:r.Port()}
		if err := validateEndpoint(ep); err != nil { return TransferCode{}, err }
		code.Addresses = append(code.Addresses, ep)
	}
	if len(code.Addresses) == 0 { return TransferCode{}, ErrInvalidCode }
	return code, nil
}
func (r *Receiver) Done() <-chan SessionResult { return r.done }
func (r *Receiver) Close() { r.finish(SessionResult{Kind:SessionCancelled}, true) }
func (r *Receiver) finish(result SessionResult, force bool) {
	r.once.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.mu.Unlock()
		if r.timer != nil { r.timer.Stop() }
		finishDone := func() { r.done <- result; close(r.done) }
		if force {
			_ = r.server.Close()
			finishDone()
			return
		}
		// Shutdown waits for active handlers. Run it off-handler so the handler
		// that accepted the backup can return before Shutdown completes.
		go func() { _ = r.server.Shutdown(context.Background()); finishDone() }()
	})
}
func (r *Receiver) handle(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost || req.URL.Path != Path { http.Error(w, "not found", http.StatusNotFound); return }
	r.mu.Lock()
	if r.closed || r.accepted { r.mu.Unlock(); http.Error(w, "session closed", http.StatusConflict); return }
	if r.busy { r.mu.Unlock(); http.Error(w, "busy", http.StatusServiceUnavailable); return }
	r.busy = true
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.busy = false; r.mu.Unlock() }()
	if req.ContentLength > r.maxBody { http.Error(w, "too large", http.StatusRequestEntityTooLarge); return }
	body, err := io.ReadAll(io.LimitReader(req.Body, r.maxBody+1)); if err != nil { http.Error(w, "bad request", http.StatusBadRequest); return }
	if int64(len(body)) > r.maxBody { http.Error(w, "too large", http.StatusRequestEntityTooLarge); return }
	clear, err := Open(string(body), r.key)
	if err != nil {
		if errors.Is(err, ErrAuthentication) { r.reject(w, http.StatusForbidden, "wrong key") } else { r.reject(w, http.StatusBadRequest, "bad envelope") }; return
	}
	if !utf8.Valid(clear) { http.Error(w, "backup must be UTF-8", http.StatusUnprocessableEntity); return }
	parseCtx, cancel := context.WithTimeout(req.Context(), DefaultResponseTimeout)
	defer cancel()
	parsed, err := r.parse(parseCtx, string(clear)); if err != nil { http.Error(w, err.Error(), http.StatusUnprocessableEntity); return }
	r.mu.Lock(); if r.closed || r.accepted { r.mu.Unlock(); http.Error(w, "session closed", http.StatusConflict); return }; r.accepted = true; r.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8"); w.Header().Set("Connection", "close"); w.WriteHeader(http.StatusOK); _, _ = io.WriteString(w, "ok")
	go r.finish(SessionResult{Kind:Received, Raw:string(clear), Parsed:parsed}, false)
}
func (r *Receiver) reject(w http.ResponseWriter, status int, message string) {
	http.Error(w, message, status)
	r.mu.Lock(); r.rejected++; shouldClose := r.rejected >= r.maxRejected && !r.closed; r.mu.Unlock()
	if shouldClose { go r.finish(SessionResult{Kind:RejectedTooOften}, false) }
}

// Client gathers optional native and SAF callbacks. A zero-value Client remains
// useful for code parsing and encryption; operations needing platform support
// return ErrUnsupported rather than pretending to succeed.
type Option func(*Client)
type Client struct { sender *Sender; saf SAFCallbacks }
func New(options ...Option) *Client { c := &Client{sender:NewSender()}; for _, option := range options { if option != nil { option(c) } }; return c }
func WithSender(sender *Sender) Option { return func(c *Client) { if sender != nil { c.sender = sender } } }
func WithSAF(callbacks SAFCallbacks) Option { return func(c *Client) { c.saf = callbacks } }
func (c *Client) Sender() *Sender { return c.sender }
func (c *Client) ImportSAF(ctx context.Context, request SAFOpenRequest) ([]Payload, error) { return c.saf.Import(ctx, request) }
func (c *Client) ExportSAF(ctx context.Context, payload Payload) (SAFDocument, error) { return c.saf.Export(ctx, payload) }
func (c *Client) Dispatch(ctx context.Context, method string, args map[string]any) (any, error) {
	switch method {
	case "code.parse":
		text, _ := args["text"].(string)
		return ParseCode(text)
	case "envelope.seal":
		plain, ok := plaintextArg(args["plaintext"])
		if !ok { return nil, errors.New("transfer: plaintext must be string or byte array") }
		key, ok := keyArg(args["key"])
		if !ok { return nil, errors.New("transfer: key must be 32 raw bytes or base64 string") }
		return Seal(plain, key)
	case "envelope.open":
		envelope, _ := args["envelope"].(string)
		key, ok := keyArg(args["key"])
		if !ok { return nil, errors.New("transfer: key must be 32 raw bytes or base64 string") }
		return Open(envelope, key)
	case "send":
		code, ok := transferCodeArg(args["code"])
		if !ok { return nil, errors.New("transfer: code must be TransferCode, *TransferCode, encoded string, or transfer-code map") }
		envelope, _ := args["envelope"].(string)
		return c.sender.Send(ctx, code, envelope), nil
	case "saf.import":
		mimeTypes, ok := stringSliceArg(args["mime_types"])
		if !ok { return nil, errors.New("transfer: mime_types must be a string array") }
		allow, _ := args["allow_multiple"].(bool)
		return c.ImportSAF(ctx, SAFOpenRequest{MIMETypes:mimeTypes, AllowMultiple:allow})
	case "saf.export":
		payload, err := payloadArg(args["payload"])
		if err != nil { return nil, err }
		return c.ExportSAF(ctx, payload)
	default:
		return nil, fmt.Errorf("transfer: unsupported dispatch method %q", method)
	}
}

func byteArg(value any) ([]byte, bool) {
	switch v := value.(type) {
	case []byte:
		return append([]byte(nil), v...), true
	case string:
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil { decoded, err = base64.RawStdEncoding.DecodeString(v) }
		if err != nil { return nil, false }
		return decoded, true
	case []any:
		out := make([]byte, len(v))
		for i, item := range v { n, ok := numericByte(item); if !ok { return nil, false }; out[i] = n }
		return out, true
	case []int:
		out := make([]byte, len(v))
		for i, n := range v { if n < 0 || n > 255 { return nil, false }; out[i] = byte(n) }
		return out, true
	}
	return nil, false
}

func plaintextArg(value any) ([]byte, bool) {
	if text, ok := value.(string); ok { return []byte(text), true }
	return byteArg(value)
}

func keyArg(value any) ([]byte, bool) {
	if text, ok := value.(string); ok {
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			key, err := encoding.DecodeString(text)
			if err == nil && len(key) == KeySize { return key, true }
		}
		return nil, false
	}
	key, ok := byteArg(value)
	return key, ok && len(key) == KeySize
}

func stringSliceArg(value any) ([]string, bool) {
	switch items := value.(type) {
	case nil: return nil, true
	case []string: return append([]string(nil), items...), true
	case []any:
		out := make([]string, len(items))
		for i, item := range items { text, ok := item.(string); if !ok { return nil, false }; out[i] = text }
		return out, true
	default: return nil, false
	}
}

func numericByte(value any) (byte, bool) {
	switch n := value.(type) {
	case float64:
		if n < 0 || n > 255 || n != float64(byte(n)) { return 0, false }; return byte(n), true
	case int:
		if n < 0 || n > 255 { return 0, false }; return byte(n), true
	case uint8: return n, true
	case json.Number:
		parsed, err := n.Int64(); if err != nil || parsed < 0 || parsed > 255 { return 0, false }; return byte(parsed), true
	}
	return 0, false
}

func transferCodeArg(value any) (TransferCode, bool) {
	switch code := value.(type) {
	case TransferCode: return code, len(code.Key) == KeySize && len(code.Addresses) > 0
	case *TransferCode: if code != nil { return transferCodeArg(*code) }
	case string: parsed, err := ParseCode(code); if err == nil { return *parsed, true }
	case map[string]any: return transferCodeMapArg(code)
	}
	return TransferCode{}, false
}

func transferCodeMapArg(value map[string]any) (TransferCode, bool) {
	key, ok := keyArg(value["key"])
	if !ok { return TransferCode{}, false }
	name, _ := value["name"].(string)
	code := TransferCode{Key:key, Name:name}
	switch addresses := value["addresses"].(type) {
	case []Endpoint:
		code.Addresses = append(code.Addresses, addresses...)
	case []any:
		for _, item := range addresses {
			endpoint, ok := item.(map[string]any); if !ok { return TransferCode{}, false }
			host, _ := endpoint["host"].(string)
			port, ok := numericPort(endpoint["port"]); if !ok { return TransferCode{}, false }
			code.Addresses = append(code.Addresses, Endpoint{Host:host, Port:port})
		}
	default: return TransferCode{}, false
	}
	if len(code.Addresses) == 0 { return TransferCode{}, false }
	for _, endpoint := range code.Addresses { if validateEndpoint(endpoint) != nil { return TransferCode{}, false } }
	return code, true
}

func numericPort(value any) (int, bool) {
	switch n := value.(type) {
	case float64: if n != float64(int(n)) { return 0, false }; return int(n), n >= 1 && n <= 65535
	case int: return n, n >= 1 && n <= 65535
	case json.Number: parsed, err := n.Int64(); if err != nil { return 0, false }; return int(parsed), parsed >= 1 && parsed <= 65535
	default: return 0, false
	}
}

func payloadArg(value any) (Payload, error) {
	switch payload := value.(type) {
	case Payload: return payload, payload.Validate()
	case *Payload: if payload != nil { return *payload, payload.Validate() }
	case map[string]any:
		kind, _ := payload["kind"].(string)
		name, _ := payload["name"].(string)
		mime, _ := payload["mime"].(string)
		text, _ := payload["text"].(string)
		var data []byte
		if encoded, ok := payload["bytes"].(string); ok {
			var err error
			for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
				data, err = encoding.DecodeString(encoded)
				if err == nil { break }
			}
			if err != nil { return Payload{}, errors.New("transfer: payload bytes must be valid base64") }
		} else if payload["bytes"] != nil {
			var ok bool
			data, ok = byteArg(payload["bytes"])
			if !ok { return Payload{}, errors.New("transfer: payload bytes must be base64 or a numeric byte array") }
		}
		p := Payload{Kind:PayloadKind(kind), Name:name, MIME:mime, Text:text, Bytes:data}
		return p, p.Validate()
	}
	return Payload{}, errors.New("transfer: payload must be Payload or payload map")
}

func Dispatch(ctx context.Context, method string, args map[string]any) (any, error) { return New().Dispatch(ctx, method, args) }
