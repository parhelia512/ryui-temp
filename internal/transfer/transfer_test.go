package transfer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func testCode(t *testing.T, host string) TransferCode {
	t.Helper()
	key, err := NewTransferKey(); if err != nil { t.Fatal(err) }
	return TransferCode{Addresses:[]Endpoint{{Host:host, Port:54321}}, Key:key, Name:"TV & den"}
}

func TestCodeAndEnvelopeDartWireRoundTripAndAuthentication(t *testing.T) {
	code := testCode(t, "192.168.1.20")
	encoded, err := code.Encode(); if err != nil { t.Fatal(err) }
	parsed, err := ParseCode(encoded); if err != nil { t.Fatal(err) }
	if parsed.Name != code.Name || parsed.Addresses[0] != code.Addresses[0] || string(parsed.Key) != string(code.Key) { t.Fatalf("code round trip mismatch: %#v", parsed) }
	if strings.Contains(code.String(), base64.RawURLEncoding.EncodeToString(code.Key)) { t.Fatal("String leaked transfer key") }

	plain := []byte(`{"app":"lxbox","kind":"backup","storage":{}}`)
	envelope, err := Seal(plain, code.Key); if err != nil { t.Fatal(err) }
	var wire map[string]any
	if err := json.Unmarshal([]byte(envelope), &wire); err != nil { t.Fatal(err) }
	if wire["v"] != float64(1) { t.Fatalf("wire version = %v", wire["v"]) }
	nonce, err := base64.StdEncoding.DecodeString(wire["nonce"].(string)); if err != nil || len(nonce) != 12 { t.Fatalf("nonce = %v, err=%v", nonce, err) }
	clear, err := Open(envelope, code.Key); if err != nil || string(clear) != string(plain) { t.Fatalf("open result %q, %v", clear, err) }
	foreign, _ := NewTransferKey()
	if _, err := Open(envelope, foreign); !errors.Is(err, ErrAuthentication) { t.Fatalf("wrong-key error = %v", err) }
}

func TestParseCodeRejectsMalformedAndStringNeverShowsKey(t *testing.T) {
	code := testCode(t, "192.168.1.2")
	encoded, _ := code.Encode()
	for _, bad := range []string{"https://example.com", strings.Replace(encoded, "lxbox-transfer:1", "lxbox-transfer:2", 1), strings.Replace(encoded, "192.168.1.2:54321", "300.1.1.2:54321", 1), strings.Replace(encoded, "192.168.1.2:54321", "host.local:54321", 1)} {
		if _, err := ParseCode(bad); !errors.Is(err, ErrInvalidCode) { t.Errorf("ParseCode(%q) error=%v", bad, err) }
	}
}

func TestReceiverHTTPStatusFlowAndHandlerDoesNotWaitOnItself(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background()); defer cancel()
	rx, err := NewReceiver(ctx, ReceiverOptions{BindAddress:"127.0.0.1:0", TTL:time.Minute, Parse:func(_ context.Context, raw string) (any, error) {
		if raw == "bad backup" { return nil, errors.New("invalid backup") }; return map[string]string{"raw":raw}, nil
	}})
	if err != nil { t.Fatal(err) }
	defer rx.Close()

	code := TransferCode{Addresses:[]Endpoint{{Host:"127.0.0.1", Port:rx.Port()}}, Key:rx.Key()}
	foreign, _ := NewTransferKey()
	badEnvelope, _ := Seal([]byte("backup"), foreign)
	if status, _ := post(t, code.Addresses[0], badEnvelope); status != http.StatusForbidden { t.Fatalf("wrong key status = %d", status) }
	if status, _ := post(t, code.Addresses[0], "not-json"); status != http.StatusBadRequest { t.Fatalf("bad envelope status = %d", status) }
	invalid, _ := Seal([]byte("bad backup"), code.Key)
	if status, _ := post(t, code.Addresses[0], invalid); status != http.StatusUnprocessableEntity { t.Fatalf("invalid backup status = %d", status) }

	good, _ := Seal([]byte("valid backup"), code.Key)
	statusCh := make(chan int, 1)
	go func() { status, _ := post(t, code.Addresses[0], good); statusCh <- status }()
	select {
	case status := <-statusCh: if status != http.StatusOK { t.Fatalf("success status=%d", status) }
	case <-time.After(2*time.Second): t.Fatal("handler deadlocked while closing receiver")
	}
	select { case result := <-rx.Done(): if result.Kind != Received || result.Raw != "valid backup" { t.Fatalf("session result = %#v", result) }; case <-time.After(2*time.Second): t.Fatal("receiver session did not finish") }
}

func post(t *testing.T, ep Endpoint, body string) (int, string) {
	t.Helper()
	client := &http.Client{Timeout:2*time.Second}
	response, err := client.Post("http://"+ep.String()+Path, "application/json", strings.NewReader(body)); if err != nil { t.Fatal(err) }
	defer response.Body.Close(); data, err := io.ReadAll(response.Body); if err != nil { t.Fatal(err) }; return response.StatusCode, string(data)
}

func TestReceiverCancellationAndSizeLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	rx, err := NewReceiver(ctx, ReceiverOptions{BindAddress:"127.0.0.1:0", Parse:func(context.Context, string) (any, error) { return nil, nil }, MaxBody:20})
	if err != nil { t.Fatal(err) }
	large, _ := Seal([]byte(strings.Repeat("x", 200)), rx.Key())
	status, _ := post(t, Endpoint{Host:"127.0.0.1", Port:rx.Port()}, large)
	if status != http.StatusRequestEntityTooLarge { t.Fatalf("large request status=%d", status) }
	cancel()
	select { case result := <-rx.Done(): if result.Kind != SessionCancelled { t.Fatalf("cancel result = %#v", result) }; case <-time.After(time.Second): t.Fatal("context cancellation did not close session") }
}

func TestReceiverRejectsInvalidUTF8BeforeParser(t *testing.T) {
	rx, err := NewReceiver(context.Background(), ReceiverOptions{
		BindAddress:"127.0.0.1:0",
		Parse:func(context.Context, string) (any, error) { t.Fatal("parser called for invalid UTF-8"); return nil, nil },
		MaxRejected:2,
	})
	if err != nil { t.Fatal(err) }
	defer rx.Close()
	envelope, err := Seal([]byte{0xff, 0xfe}, rx.Key())
	if err != nil { t.Fatal(err) }
	status, _ := post(t, Endpoint{Host:"127.0.0.1", Port:rx.Port()}, envelope)
	if status != http.StatusUnprocessableEntity { t.Fatalf("invalid UTF-8 status=%d", status) }
}

func TestSAFCallbacksImportMultipleAndExportPreservesBytes(t *testing.T) {
	want := []byte{0, 1, 0xff, 0x7b}
	callbacks := SAFCallbacks{
		Pick:func(context.Context, SAFOpenRequest) ([]SAFDocument, bool, error) { return []SAFDocument{{URI:"content://provider/a", Name:"rules.srs", MIME:"application/octet-stream"}}, true, nil },
		Read:func(_ context.Context, uri string) ([]byte, error) { if uri != "content://provider/a" { t.Fatalf("URI=%q", uri) }; return want, nil },
		Create:func(_ context.Context, req SAFSaveRequest) (SAFDocument, bool, error) { if req.Name != "rules.srs" { t.Fatalf("save request=%#v", req) }; return SAFDocument{URI:"content://provider/out", Name:req.Name}, true, nil },
		Write:func(_ context.Context, uri string, data []byte) error { if uri != "content://provider/out" || string(data) != string(want) { t.Fatalf("write %q: %v", uri, data) }; return nil },
	}
	payloads, err := callbacks.Import(context.Background(), SAFOpenRequest{AllowMultiple:true}); if err != nil { t.Fatal(err) }
	if len(payloads) != 1 || string(payloads[0].Bytes) != string(want) { t.Fatalf("payloads=%#v", payloads) }
	if _, err := callbacks.Export(context.Background(), payloads[0]); err != nil { t.Fatal(err) }
	cancelled := SAFCallbacks{Pick:func(context.Context, SAFOpenRequest) ([]SAFDocument, bool, error) { return nil, false, nil }, Read:callbacks.Read}
	if _, err := cancelled.Import(context.Background(), SAFOpenRequest{}); !errors.Is(err, ErrCancelled) { t.Fatalf("cancel error=%v", err) }
}

func TestJSONDispatchAcceptsJSONByteRepresentationsAndRequiresPhysicalLAN(t *testing.T) {
	key, _ := NewTransferKey()
	plain := []byte("hello")
	for _, input := range []any{base64.StdEncoding.EncodeToString(plain), []any{float64(104), float64(101), float64(108), float64(108), float64(111)}, "hello"} {
		result, err := New().Dispatch(context.Background(), "envelope.seal", map[string]any{"plaintext":input, "key":base64.StdEncoding.EncodeToString(key)})
		if err != nil { t.Fatalf("seal with %T: %v", input, err) }
		opened, err := New().Dispatch(context.Background(), "envelope.open", map[string]any{"envelope":result.(string), "key":base64.StdEncoding.EncodeToString(key)})
		if err != nil || string(opened.([]byte)) != string(plain) { t.Fatalf("dispatch open=%v, err=%v", opened, err) }
	}
	code := TransferCode{Addresses:[]Endpoint{{Host:"192.168.1.5", Port:1234}}, Key:key}
	if sent := NewSender().Send(context.Background(), code, "{}"); sent.Status != Unreachable || !strings.Contains(sent.Detail, "physical LAN") { t.Fatalf("default send unexpectedly bypassed network policy: %#v", sent) }
}

func TestDispatchSAFMIMEAnyArrayAndJSONPayloadBytes(t *testing.T) {
	var gotMIMEs []string
	var written []byte
	callbacks := SAFCallbacks{
		Pick:func(_ context.Context, request SAFOpenRequest) ([]SAFDocument, bool, error) { gotMIMEs = request.MIMETypes; return []SAFDocument{{URI:"content://provider/file", Name:"b.json", MIME:"application/json"}}, true, nil },
		Read:func(context.Context, string) ([]byte, error) { return []byte{0, 1, 255}, nil },
		Create:func(context.Context, SAFSaveRequest) (SAFDocument, bool, error) { return SAFDocument{URI:"content://provider/out"}, true, nil },
		Write:func(_ context.Context, _ string, data []byte) error { written = append([]byte(nil), data...); return nil },
	}
	client := New(WithSAF(callbacks))
	result, err := client.Dispatch(context.Background(), "saf.import", map[string]any{"mime_types":[]any{"application/json", "text/plain"}, "allow_multiple":true})
	if err != nil { t.Fatal(err) }
	if len(gotMIMEs) != 2 || gotMIMEs[1] != "text/plain" { t.Fatalf("mimes = %#v", gotMIMEs) }
	payloads := result.([]Payload)
	_, err = client.Dispatch(context.Background(), "saf.export", map[string]any{"payload":map[string]any{"kind":"file", "name":"b.json", "mime":"application/json", "bytes":"AAH/"}})
	if err != nil { t.Fatal(err) }
	if len(written) != 3 || written[2] != 255 { t.Fatalf("written bytes = %v; import result %v", written, payloads[0].Bytes) }
}

func TestDispatchAcceptsTransferCodeJSONMap(t *testing.T) {
	key, _ := NewTransferKey()
	client := New(WithSender(NewSenderWithNativePost(func(_ context.Context, ep Endpoint, _ []byte) (LANOutcome, error) {
		if ep.Host != "192.168.1.44" || ep.Port != 23456 { t.Fatalf("endpoint=%#v", ep) }
		return LANOutcome{Kind:LANResponse, Status:http.StatusOK}, nil
	})))
	result, err := client.Dispatch(context.Background(), "send", map[string]any{
		"code":map[string]any{"addresses":[]any{map[string]any{"host":"192.168.1.44", "port":float64(23456)}}, "key":base64.RawURLEncoding.EncodeToString(key), "name":"TV"},
		"envelope":"encrypted-envelope",
	})
	if err != nil { t.Fatal(err) }
	if result.(SendResult).Status != Sent { t.Fatalf("send result=%#v", result) }
}

func TestNativePhysicalPostIsTheOnlyDefaultLANRoute(t *testing.T) {
	code := testCode(t, "192.168.1.20")
	calls := 0
	sender := NewSenderWithNativePost(func(_ context.Context, endpoint Endpoint, body []byte) (LANOutcome, error) {
		calls++; if endpoint.Host != "192.168.1.20" || string(body) != "sealed" { t.Fatalf("post args: %#v %q", endpoint, body) }
		return LANOutcome{Kind:LANResponse, Status:http.StatusOK}, nil
	})
	result := sender.Send(context.Background(), code, "sealed")
	if result.Status != Sent || calls != 1 { t.Fatalf("result=%#v calls=%d", result, calls) }
}
