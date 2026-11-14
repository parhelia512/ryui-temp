package diagnostics

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type fakeMTU struct {
	threshold int
	mtu       int
	sent      []int
}

func (f *fakeMTU) Network(context.Context) (PathMTUNetwork, error) {
	return PathMTUNetwork{Interface: "wlan0", Transport: "wifi", MTU: f.mtu}, nil
}
func (f *fakeMTU) Resolve(context.Context, string) (string, error) { return "192.0.2.1", nil }
func (f *fakeMTU) Probe(_ context.Context, _ string, size, _ int, _ int) (PathMTUProbeReply, error) {
	f.sent = append(f.sent, size)
	if size <= f.threshold {
		return PathMTUProbeReply{Status: PathProbeOK, RTTMS: 7}, nil
	}
	return PathMTUProbeReply{Status: PathProbeTimeout}, nil
}

func TestDispatchRoutesKindsAndDoesNotInventCallbacks(t *testing.T) {
	client := NewClient(Options{Probe: func(_ context.Context, args map[string]any) (map[string]any, error) {
		return map[string]any{"kind": args["kind"]}, nil
	}})
	got, err := client.Dispatch(context.Background(), "diagnostics.run", map[string]any{"kind": "probe"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]any{"kind": "probe"}) {
		t.Fatalf("unexpected callback result: %#v", got)
	}
	if _, err := client.Dispatch(context.Background(), "diagnostics.run", map[string]any{"kind": "connection"}); err == nil {
		t.Fatal("missing connection callback should fail")
	}
	if _, err := NewClient(Options{}).Dispatch(context.Background(), "diagnostics.run", map[string]any{}); err == nil {
		t.Fatal("missing kind should fail")
	}
}

func TestFindPathMTUWithRetryAndBinarySearch(t *testing.T) {
	p := &fakeMTU{threshold: 1340, mtu: 1500}
	result, err := FindPathMTU(context.Background(), p, "8.8.8.8:443", PathMTUCallbacks{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != PathMTUOK || result.PathMTU != 1340 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.Target != "8.8.8.8" || result.WireGuardMTU() != 1280 || result.MasqueMTU() != 1289 {
		t.Fatalf("unexpected derived values: %#v", result)
	}
	if len(p.sent) < 3 {
		t.Fatalf("binary search did not run: %#v", p.sent)
	}
}

func TestFindPathMTUDistinguishesNoNetworkAndCancellation(t *testing.T) {
	noNetwork := &noNetworkMTU{}
	result, err := FindPathMTU(context.Background(), noNetwork, "8.8.8.8", PathMTUCallbacks{})
	if err != nil || result.Status != PathMTUNoNetwork {
		t.Fatalf("unexpected no-network result: %#v, %v", result, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err = FindPathMTU(ctx, &fakeMTU{threshold: 1400, mtu: 1500}, "8.8.8.8", PathMTUCallbacks{})
	if !errors.Is(err, context.Canceled) || result.Status != PathMTUCancelled {
		t.Fatalf("unexpected cancelled result: %#v, %v", result, err)
	}
}

type noNetworkMTU struct{}

func (*noNetworkMTU) Network(context.Context) (PathMTUNetwork, error) {
	return PathMTUNetwork{}, ErrNoNetwork
}
func (*noNetworkMTU) Resolve(context.Context, string) (string, error) { return "", ErrNoNetwork }
func (*noNetworkMTU) Probe(context.Context, string, int, int, int) (PathMTUProbeReply, error) {
	return PathMTUProbeReply{}, ErrNoNetwork
}

func TestChainDeltaAndRedaction(t *testing.T) {
	r := ChainReport{ChainTag: "chain", Layers: []ChainLayer{{Pos: 0, CumulativeMS: 20}, {Pos: 1, CumulativeMS: 55}, {Pos: 2, Error: "timeout"}, {Pos: 3, NotReached: true}}}
	if delta, ok := r.DeltaAt(1); !ok || delta != 35 {
		t.Fatalf("unexpected delta: %d/%v", delta, ok)
	}
	if _, ok := r.DeltaAt(2); ok {
		t.Fatal("failed layer must not have delta")
	}
	redacted := Redact(map[string]any{"token": "secret", "nested": map[string]any{"private_key": "secret"}, "status": 200})
	if redacted["token"] != "<redacted>" || redacted["status"] != 200 {
		t.Fatalf("bad redaction: %#v", redacted)
	}
	nested := redacted["nested"].(map[string]any)
	if nested["private_key"] != "<redacted>" {
		t.Fatalf("nested secret not redacted: %#v", nested)
	}
}
