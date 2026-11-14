package automation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEngineDispatchAdmissionAndJSON(t *testing.T) {
	var got string
	e := NewEngine(func(ctx context.Context, name string, args json.RawMessage) (any, error) {
		got = name + ":" + string(args)
		return map[string]any{"value": 1}, nil
	})
	ctx := context.Background()
	if err := e.Start(ctx); err != nil { t.Fatal(err) }
	defer e.Stop(context.Background())
	if _, err := e.Dispatch(ctx, "switch-node", json.RawMessage(`{"tag":"n"}`)); !errors.Is(err, ErrAutomationOff) { t.Fatalf("expected intake gate, got %v", err) }
	e.SetSettings(Settings{ReceiveEnabled: true})
	result, err := e.Dispatch(ctx, "com.leadaxe.lxbox.SWITCH_NODE", json.RawMessage(`{"tag":"n"}`))
	if err != nil { t.Fatal(err) }
	if got != `switch-node:{"tag":"n"}` { t.Fatalf("unexpected dispatcher input %q", got) }
	if result == nil { t.Fatal("missing result") }
}

func TestDispatchRejectsUnsupportedActionAndRequiredFields(t *testing.T) {
	e := NewEngine(func(context.Context,string,json.RawMessage)(any,error){return nil,nil}, WithSettings(Settings{ReceiveEnabled:true}))
	if err := e.Start(context.Background()); err != nil { t.Fatal(err) }
	defer e.Stop(context.Background())
	if _, err := e.Dispatch(context.Background(), "not-supported", nil); !errors.Is(err, ErrUnknownAction) { t.Fatalf("got %v", err) }
	if _, err := e.Dispatch(context.Background(), "switch-node", nil); err == nil { t.Fatal("missing required tag accepted") }
	if _, err := e.Dispatch(context.Background(), "urltest-group", json.RawMessage(`{"group":1}`)); err == nil { t.Fatal("wrong group type accepted") }
}

func TestConditionWireAndEvaluation(t *testing.T) {
	c := Condition{Version: 1, Check: "active-node", Equals: "node-a"}
	raw, err := EncodeCondition(c); if err != nil { t.Fatal(err) }
	decoded, err := DecodeCondition(raw); if err != nil { t.Fatal(err) }
	value := "node-a"
	if got := EvaluateCondition(decoded, ConditionState{ActiveNode:&value}); got != ConditionSatisfied { t.Fatalf("got %d",got) }
	if got := EvaluateCondition(decoded, ConditionState{}); got != ConditionUnknown { t.Fatalf("got %d",got) }
	if got := EvaluateCondition(Condition{Check:"active-node",Equals:"node-a"}, ConditionState{ActiveNode:&value}); got != ConditionSatisfied { t.Fatalf("got %d",got) }
	if got := EvaluateCondition(Condition{Check:"unknown"}, ConditionState{}); got != ConditionUnknown { t.Fatalf("got %d",got) }
}

func TestEventGatesThrottleAndMasking(t *testing.T) {
	var mu sync.Mutex
	var events []Event
	var clockMu sync.Mutex
	now := time.Unix(100,0)
	clock := func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return now }
	e := NewEngine(nil, WithClock(clock), WithSettings(Settings{EventGates:EventGates{Lifecycle:true,Subs:true}}), WithEventSink(func(_ context.Context, event Event) error {mu.Lock();defer mu.Unlock();events=append(events,event);return nil}))
	if err:=e.Start(context.Background());err!=nil{t.Fatal(err)}
	defer e.Stop(context.Background())
	if err:=e.EmitVPNConnected(context.Background());err!=nil{t.Fatal(err)}
	if err:=e.EmitNodeChanged(context.Background(),nil,"new","g","user");err!=nil{t.Fatal(err)}
	if err:=e.EmitSubRefreshFailed(context.Background(),"https://provider.example/sub/secret","dial tcp 192.0.2.1:443");err!=nil{t.Fatal(err)}
	if err:=e.EmitSubRefreshFailed(context.Background(),"https://provider.example/sub/secret","second");err!=nil{t.Fatal(err)}
	mu.Lock()
	if len(events)!=2 {mu.Unlock();t.Fatalf("got %d events",len(events))}
	if events[1].Extras["sub_id"]!="https://provider.example/***" {mu.Unlock();t.Fatalf("sub id leak: %#v",events[1].Extras["sub_id"])}
	if events[1].Extras["error"]!="dial tcp 192.0.2.1:443" {mu.Unlock();t.Fatalf("unexpected event error: %#v",events[1].Extras["error"])}
	mu.Unlock()
	clockMu.Lock(); now=now.Add(time.Minute); clockMu.Unlock()
	if err:=e.EmitSubRefreshFailed(context.Background(),"https://provider.example/sub/secret","third");err!=nil{t.Fatal(err)}
	mu.Lock(); defer mu.Unlock()
	if len(events)!=3 {t.Fatalf("throttle did not expire: %d",len(events))}
}

func TestStopCancelsInFlightDispatch(t *testing.T) {
	started := make(chan struct{})
	e := NewEngine(func(ctx context.Context, _ string, _ json.RawMessage)(any,error){close(started);<-ctx.Done();return nil,ctx.Err()}, WithSettings(Settings{ReceiveEnabled:true}))
	ctx,cancel:=context.WithCancel(context.Background()); defer cancel()
	if err:=e.Start(ctx);err!=nil{t.Fatal(err)}
	done:=make(chan error,1)
	go func(){_,err:=e.Dispatch(context.Background(),"start-vpn",nil);done<-err}()
	<-started
	if err:=e.Stop(context.Background());err!=nil{t.Fatal(err)}
	select{case err:=<-done:if err==nil{t.Fatal("dispatch unexpectedly succeeded")};case <-time.After(time.Second):t.Fatal("dispatch not cancelled")}
}

func TestPluginSettingRoundTripAndLimits(t *testing.T) {
	raw,err:=EncodeSetting(Setting{Version:1,Cmd:"com.leadaxe.lxbox.SET_GROUP",Args:map[string]any{"group":"g"}});if err!=nil{t.Fatal(err)}
	s,err:=DecodeSetting(raw);if err!=nil{t.Fatal(err)}
	if s.Cmd!="set-group"||s.Args["group"]!="g"{t.Fatalf("unexpected %#v",s)}
	if _,err:=DecodeSetting([]byte(strings.Repeat("x",LocaleBundleMaxBytes+1)));err==nil{t.Fatal("oversized bundle accepted")}
}
