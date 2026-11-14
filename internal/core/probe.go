package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/experimental/libbox"
)

// ProbeCandidate uses its own libbox service and candidate configuration. The
// temporary CommandServer is deliberately never Start()ed: it has no listener,
// never unlinks command.sock and cannot replace the Controller's live service.
func (c *Controller) ProbeCandidate(ctx context.Context, args json.RawMessage) (value any, returnErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	input, err := decodeProbeCandidate(args)
	if err != nil {
		return nil, err
	}
	if err := libbox.CheckConfig(input.config); err != nil {
		return nil, fmt.Errorf("validate candidate config: %w", err)
	}
	if c.platform == nil {
		return nil, errors.New("candidate probe requires platform networking callbacks")
	}
	timeout := input.timeoutMS
	if timeout == 0 {
		timeout = 30_000
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	platform := &candidateProbePlatform{platformAdapter: &platformAdapter{call: c.platform}, ctx: ctx, monitors: make(map[libbox.InterfaceUpdateListener]candidateMonitor)}
	handler := &candidateProbeHandler{cancel: cancel}
	server, err := libbox.NewCommandServer(handler, platform)
	if err != nil {
		return nil, fmt.Errorf("create candidate service: %w", err)
	}
	stopOnCancel := context.AfterFunc(ctx, func() { _ = server.CloseService() })
	defer stopOnCancel()
	defer func() {
		cancel()
		closeErr := server.CloseService()
		server.Close()
		if closeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close candidate service: %w", closeErr))
		}
	}()

	// Call the embedded daemon service directly. The libbox wrapper's
	// StartOrReloadService writes a global running-config snapshot, which an
	// isolated candidate must never overwrite.
	if err := server.StartedService.StartOrReloadService(ctx, input.config, &daemon.OverrideOptions{}); err != nil {
		return nil, fmt.Errorf("start candidate service: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result, err := server.StartedService.URLTestOutbound(ctx, &daemon.URLTestOutboundRequest{
		OutboundTag: input.outboundTag,
		Link:        input.link,
		Timeout:     uint32(timeout),
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("probe candidate outbound: %w", err)
	}
	if result == nil {
		return nil, errors.New("candidate probe returned no result")
	}
	value = map[string]any{
		"ok":           result.Error == "",
		"delay":        result.Delay,
		"delay_ms":     result.Delay,
		"error":        result.Error,
		"outbound_tag": input.outboundTag,
		"isolated":     true,
	}
	if result.Error != "" {
		return value, errors.New(result.Error)
	}
	return value, nil
}

type probeCandidateInput struct {
	config      string
	outboundTag string
	link        string
	timeoutMS   int64
}

func decodeProbeCandidate(args json.RawMessage) (probeCandidateInput, error) {
	var input struct {
		Config      json.RawMessage `json:"config"`
		RawConfig   json.RawMessage `json:"raw_config"`
		OutboundTag string          `json:"outbound_tag"`
		Link        string          `json:"link"`
		TimeoutMS   int64           `json:"timeout_ms"`
	}
	if err := json.Unmarshal(args, &input); err != nil {
		return probeCandidateInput{}, fmt.Errorf("decode candidate arguments: %w", err)
	}
	raw := input.RawConfig
	if len(raw) == 0 || string(raw) == "null" {
		raw = input.Config
	}
	if len(raw) == 0 || string(raw) == "null" {
		return probeCandidateInput{}, errors.New("config or raw_config is required; a live outbound tag is not a candidate configuration")
	}
	var config string
	if json.Unmarshal(raw, &config) != nil {
		config = string(raw)
	}
	var candidate map[string]json.RawMessage
	if err := json.Unmarshal([]byte(config), &candidate); err != nil || candidate == nil {
		return probeCandidateInput{}, errors.New("candidate config must be a JSON object or a string containing a JSON object")
	}
	if strings.TrimSpace(input.OutboundTag) == "" {
		return probeCandidateInput{}, errors.New("outbound_tag is required")
	}
	if input.TimeoutMS < 0 || input.TimeoutMS > 600_000 {
		return probeCandidateInput{}, errors.New("timeout_ms must be between 0 and 600000")
	}
	if input.Link != "" {
		parsed, err := url.Parse(input.Link)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return probeCandidateInput{}, errors.New("link must be an absolute http or https URL")
		}
	}
	// Headless candidates may contain the DNS/route dependencies their nodes
	// need. Reject listeners and persistent/global settings rather than silently
	// changing what the caller asked to test.
	for _, field := range []string{"inbounds", "services", "network_namespaces"} {
		if raw := candidate[field]; len(raw) != 0 && string(raw) != "null" {
			var items []json.RawMessage
			if json.Unmarshal(raw, &items) != nil || len(items) != 0 {
				return probeCandidateInput{}, fmt.Errorf("candidate config must not contain %s", field)
			}
		}
	}
	for _, field := range []string{"experimental", "ntp"} {
		if raw := candidate[field]; len(raw) != 0 && string(raw) != "null" && string(raw) != "{}" {
			return probeCandidateInput{}, fmt.Errorf("candidate config must not contain %s settings", field)
		}
	}
	if raw := candidate["log"]; len(raw) != 0 && string(raw) != "null" {
		var logOptions struct {
			Output string `json:"output"`
		}
		if err := json.Unmarshal(raw, &logOptions); err != nil || logOptions.Output != "" {
			return probeCandidateInput{}, errors.New("candidate config must not write a log file")
		}
	}
	found := false
	for _, field := range []string{"outbounds", "endpoints"} {
		var nodes []struct {
			Tag  string `json:"tag"`
			Type string `json:"type"`
		}
		if raw := candidate[field]; len(raw) != 0 {
			if err := json.Unmarshal(raw, &nodes); err != nil {
				return probeCandidateInput{}, fmt.Errorf("candidate %s: %w", field, err)
			}
		}
		for _, node := range nodes {
			if node.Tag == input.OutboundTag {
				found = true
			}
		}
	}
	if !found {
		return probeCandidateInput{}, fmt.Errorf("outbound_tag %q is not declared in supplied candidate config", input.OutboundTag)
	}
	return probeCandidateInput{config: config, outboundTag: input.OutboundTag, link: input.Link, timeoutMS: input.TimeoutMS}, nil
}

type candidateProbePlatform struct {
	*platformAdapter
	ctx      context.Context
	mu       sync.Mutex
	monitors map[libbox.InterfaceUpdateListener]candidateMonitor
}

type candidateMonitor struct {
	id     uint64
	cancel context.CancelFunc
	done   chan struct{}
}

var candidateMonitorIDs atomic.Uint64

func (p *candidateProbePlatform) StartDefaultInterfaceMonitor(listener libbox.InterfaceUpdateListener) error {
	id := candidateMonitorIDs.Add(1) | (1 << 52)
	ctx, cancel := context.WithCancel(p.ctx)
	entry := candidateMonitor{id: id, cancel: cancel, done: make(chan struct{})}
	if err := p.invoke(ctx, "network.monitor.start", map[string]any{"id": id}, nil); err != nil {
		cancel()
		return err
	}
	poll := func() error {
		var state struct {
			InterfaceName  string `json:"interfaceName"`
			InterfaceIndex int32  `json:"interfaceIndex"`
			Expensive      bool   `json:"expensive"`
			Constrained    bool   `json:"constrained"`
		}
		if err := p.invoke(ctx, "network.monitor.poll", map[string]any{"id": id}, &state); err != nil {
			return err
		}
		listener.UpdateDefaultInterface(state.InterfaceName, state.InterfaceIndex, state.Expensive, state.Constrained)
		return nil
	}
	// Initialize before Start returns; headless QUIC/WG must not start with an
	// unknown default network while waiting for the first periodic poll.
	if err := poll(); err != nil {
		cancel()
		_ = p.invoke(context.Background(), "network.monitor.stop", map[string]any{"id": id}, nil)
		return err
	}
	p.mu.Lock()
	p.monitors[listener] = entry
	p.mu.Unlock()
	go func() {
		defer close(entry.done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = poll()
			}
		}
	}()
	return nil
}

func (p *candidateProbePlatform) CloseDefaultInterfaceMonitor(listener libbox.InterfaceUpdateListener) error {
	p.mu.Lock()
	entry, exists := p.monitors[listener]
	delete(p.monitors, listener)
	p.mu.Unlock()
	if !exists {
		return nil
	}
	entry.cancel()
	err := p.invoke(context.Background(), "network.monitor.stop", map[string]any{"id": entry.id}, nil)
	<-entry.done
	return err
}

func (*candidateProbePlatform) OpenTun(libbox.TunOptions) (int32, error) {
	return -1, errors.New("candidate probes cannot open a TUN device")
}
func (*candidateProbePlatform) SendNotification(*libbox.Notification) error { return nil }
func (*candidateProbePlatform) CancelNotification(string, int32) error      { return nil }

type candidateProbeHandler struct{ cancel context.CancelFunc }

func (h *candidateProbeHandler) ServiceStop() error { h.cancel(); return nil }
func (*candidateProbeHandler) ServiceReload() error {
	return errors.New("candidate probe cannot reload")
}
func (*candidateProbeHandler) GetSystemProxyStatus() (*libbox.SystemProxyStatus, error) {
	return &libbox.SystemProxyStatus{}, nil
}
func (*candidateProbeHandler) SetSystemProxyEnabled(bool) error {
	return errors.New("candidate probe cannot change system proxy")
}
func (*candidateProbeHandler) TriggerNativeCrash() error {
	return errors.New("candidate probe cannot trigger a crash")
}
func (*candidateProbeHandler) WriteDebugMessage(string) {}
func (*candidateProbeHandler) ConnectSSHAgent() (int32, error) {
	return -1, errors.New("candidate probe cannot connect an SSH agent")
}

var _ libbox.CommandServerHandler = (*candidateProbeHandler)(nil)
var _ libbox.PlatformInterface = (*candidateProbePlatform)(nil)
