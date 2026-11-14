package debugapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Leadaxe/lxbox/app/internal/automation"
)

func TestServerLoopbackAuthAndDispatch(t *testing.T) {
	var called string
	s := NewServer(Config{Port: 0, Token: "test-token", RequestTimeout: time.Second}, func(_ context.Context, method string, args json.RawMessage) (any, error) {
		called = method + ":" + string(args)
		return map[string]any{"accepted": true}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(context.Background())
	base := "http://" + s.Addr()
	res, err := http.Get(base + "/ping")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("ping status %d", res.StatusCode)
	}
	res, err = http.Post(base+"/action/start-vpn", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatalf("unauthorized status %d", res.StatusCode)
	}
	req, err := http.NewRequest(http.MethodPost, base+"/action/switch-node?tag=n", strings.NewReader(`{"extra":true}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-token")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("dispatch status %d body %s", res.StatusCode, b)
	}
	if called != `switch-node:{"extra":true,"tag":"n"}` && called != `switch-node:{"tag":"n","extra":true}` {
		t.Fatalf("unexpected dispatch %q", called)
	}
}

func TestServerRejectsNonLoopbackHostAndOversizedBody(t *testing.T) {
	s := NewServer(Config{Port: 0, Token: "t", MaxBodyBytes: 3}, func(context.Context, string, json.RawMessage) (any, error) { return nil, nil })
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	base := "http://" + s.Addr()
	req, _ := http.NewRequest(http.MethodPost, base+"/action/start-vpn", strings.NewReader(`{}`))
	req.Host = "evil.example"
	req.Header.Set("Authorization", "Bearer t")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 403 {
		t.Fatalf("host status %d", res.StatusCode)
	}
	res.Body.Close()
	req, _ = http.NewRequest(http.MethodPost, base+"/action/start-vpn", strings.NewReader(`{"x":1}`))
	req.Header.Set("Authorization", "Bearer t")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 413 {
		t.Fatalf("body status %d", res.StatusCode)
	}
	res.Body.Close()
}

func TestServerErrorMappingDoesNotLeakDispatcherCause(t *testing.T) {
	s := NewServer(Config{Port: 0, Token: "t"}, func(context.Context, string, json.RawMessage) (any, error) {
		return nil, errors.New("https://user:secret@example.invalid/sub/token")
	})
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(context.Background())
	req, _ := http.NewRequest(http.MethodPost, "http://"+s.Addr()+"/action/start-vpn", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer t")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 500 {
		t.Fatalf("status %d", res.StatusCode)
	}
	if strings.Contains(string(body), "secret") || strings.Contains(string(body), "example.invalid") {
		t.Fatalf("cause leaked: %s", body)
	}
}

func TestServerDispatchRejectsNonObject(t *testing.T) {
	s := NewServer(DefaultConfig("t"), nil)
	if _, err := s.Dispatch(context.Background(), "x", json.RawMessage(`[]`)); err == nil {
		t.Fatal("array accepted")
	}
	if _, err := s.Dispatch(context.Background(), "", nil); err == nil {
		t.Fatal("empty method accepted")
	}
	_ = automation.ConditionUnknown
}

func TestSSEPublish(t *testing.T) {
	// Exercise the bounded hub directly; HTTP streaming is covered by the same
	// subscription lifecycle and intentionally has no replay buffer.
	h := newEventHub()
	_, events, unsubscribe := h.subscribe()
	defer unsubscribe()
	if err := h.publish(context.Background(), automation.Event{Name: "VPN_CONNECTED"}); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		if event.Name != "VPN_CONNECTED" {
			t.Fatalf("event %q", event.Name)
		}
	case <-time.After(time.Second):
		t.Fatal("event timeout")
	}
}
