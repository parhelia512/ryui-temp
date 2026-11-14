package core

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
)

func TestDecodeProbeCandidateOwnConfiguration(t *testing.T) {
	config := `{"dns":{"servers":[{"type":"local","tag":"local"}]},"outbounds":[{"type":"masque","tag":"candidate","server":"162.159.198.1","server_port":443}],"route":{"final":"candidate"}}`
	for _, field := range []string{"config", "raw_config"} {
		for _, asString := range []bool{false, true} {
			var input any = json.RawMessage(config)
			if asString {
				input = config
			}
			raw, err := json.Marshal(map[string]any{field: input, "outbound_tag": "candidate", "timeout_ms": 5000, "link": "https://example.com/generate_204"})
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeProbeCandidate(raw)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.config != config || decoded.outboundTag != "candidate" || decoded.timeoutMS != 5000 {
				t.Fatalf("candidate arguments changed: %#v", decoded)
			}
		}
	}
}

func TestDecodeProbeCandidateRejectsLiveTagAndSharedResources(t *testing.T) {
	for _, raw := range []string{
		`{"outbound_tag":"installed-tag"}`,
		`{"config":{"outbounds":[{"type":"direct","tag":"other"}]},"outbound_tag":"installed-tag"}`,
		`{"config":{"outbounds":[{"type":"direct","tag":"candidate"}],"inbounds":[{"type":"tun"}]},"outbound_tag":"candidate"}`,
		`{"config":{"outbounds":[{"type":"direct","tag":"candidate"}],"experimental":{"cache_file":{"enabled":true}}},"outbound_tag":"candidate"}`,
		`{"config":{"outbounds":[{"type":"direct","tag":"candidate"}],"services":[{"type":"api"}]},"outbound_tag":"candidate"}`,
		`{"config":{"outbounds":[{"type":"direct","tag":"candidate"}],"log":{"output":"shared.log"}},"outbound_tag":"candidate"}`,
		`{"config":{"outbounds":[{"type":"direct","tag":"candidate"}]},"outbound_tag":"candidate","link":"file:///tmp/private"}`,
		`{"config":{"outbounds":[{"type":"direct","tag":"candidate"}]},"outbound_tag":"candidate","timeout_ms":-1}`,
	} {
		if _, err := decodeProbeCandidate(json.RawMessage(raw)); err == nil {
			t.Fatalf("unsafe or incomplete candidate accepted: %s", raw)
		}
	}
}

func TestProbeCandidateCancelledBeforeNativeWork(t *testing.T) {
	controller := &Controller{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := controller.ProbeCandidate(ctx, json.RawMessage(`{}`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled probe = %v", err)
	}
	if _, err := controller.ProbeCandidate(context.Background(), json.RawMessage(`{"outbound_tag":"live"}`)); err == nil || !strings.Contains(err.Error(), "config") {
		t.Fatalf("tag-only probe did not reject live config substitution: %v", err)
	}
}

func TestCandidateProbeMonitorOwnsOnlyItsID(t *testing.T) {
	var stopped uint64
	platform := &candidateProbePlatform{
		ctx: context.Background(),
		platformAdapter: &platformAdapter{call: func(_ context.Context, method string, raw json.RawMessage) (json.RawMessage, error) {
			var args struct {
				ID uint64 `json:"id"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			if args.ID == 0 {
				t.Fatal("probe monitor used unscoped host callback")
			}
			switch method {
			case "network.monitor.start":
				return json.RawMessage(`{"started":true}`), nil
			case "network.monitor.poll":
				return json.RawMessage(`{"interfaceName":"wlan0","interfaceIndex":5}`), nil
			case "network.monitor.stop":
				stopped = args.ID
				return json.RawMessage(`{"stopped":true}`), nil
			}
			return nil, errors.New("unexpected method")
		}},
		monitors: make(map[libbox.InterfaceUpdateListener]candidateMonitor),
	}
	listener := &candidateTestListener{}
	if err := platform.StartDefaultInterfaceMonitor(listener); err != nil {
		t.Fatal(err)
	}
	if listener.index != 5 {
		t.Fatal("candidate default interface was not initialized synchronously")
	}
	if err := platform.CloseDefaultInterfaceMonitor(listener); err != nil {
		t.Fatal(err)
	}
	if stopped == 0 {
		t.Fatal("candidate host monitor was leaked")
	}
}

type candidateTestListener struct{ index int32 }

func (l *candidateTestListener) UpdateDefaultInterface(_ string, index int32, _, _ bool) {
	l.index = index
}
func (*candidateTestListener) UpdateNetworkPath(string) {}
