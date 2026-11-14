package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const (
	DefaultPathMTUTarget   = "8.8.8.8"
	PathMTUFallbackCeiling = 1500
	PathMTUSmallProbe      = 84
	PathMTUTimeoutMS       = 1000
	MasqueOverhead         = 51
)

var ErrNoNetwork = errors.New("no network")

type PathMTUNetwork struct {
	Interface string `json:"iface"`
	Transport string `json:"transport"`
	MTU       int    `json:"mtu"`
}
type PathMTUProbeStatus string

const (
	PathProbeOK      PathMTUProbeStatus = "ok"
	PathProbeTimeout PathMTUProbeStatus = "timeout"
	PathProbeTooBig  PathMTUProbeStatus = "too_big"
	PathProbeError   PathMTUProbeStatus = "error"
)

type PathMTUProbeReply struct {
	Status PathMTUProbeStatus `json:"status"`
	RTTMS  int                `json:"rtt_ms,omitempty"`
	Error  string             `json:"error,omitempty"`
}
type PathMTUProber interface {
	Network(context.Context) (PathMTUNetwork, error)
	Resolve(context.Context, string) (string, error)
	Probe(context.Context, string, int, int, int) (PathMTUProbeReply, error)
}
type PathMTUProbe struct {
	Size   int                `json:"size"`
	Status PathMTUProbeStatus `json:"status"`
	RTTMS  int                `json:"rtt_ms,omitempty"`
}
type PathMTUStatus string

const (
	PathMTUOK          PathMTUStatus = "ok"
	PathMTUUnreachable PathMTUStatus = "unreachable"
	PathMTUNoNetwork   PathMTUStatus = "no_network"
	PathMTUBelowFloor  PathMTUStatus = "below_floor"
	PathMTUCancelled   PathMTUStatus = "cancelled"
	PathMTUError       PathMTUStatus = "error"
)

type PathMTUResult struct {
	Target     string          `json:"target"`
	IP         string          `json:"ip,omitempty"`
	Network    *PathMTUNetwork `json:"network,omitempty"`
	Status     PathMTUStatus   `json:"status"`
	PathMTU    int             `json:"path_mtu"`
	Probes     []PathMTUProbe  `json:"probes"`
	Error      string          `json:"error,omitempty"`
	VPNRunning bool            `json:"vpn_running,omitempty"`
}

func (r PathMTUResult) Ceiling() int {
	if r.Network != nil && r.Network.MTU > 0 {
		return r.Network.MTU
	}
	return PathMTUFallbackCeiling
}
func (r PathMTUResult) NothingCut() bool { return r.Status == PathMTUOK && r.PathMTU >= r.Ceiling() }
func (r PathMTUResult) IsIPv6() bool     { return strings.Contains(r.IP, ":") }
func (r PathMTUResult) WireGuardMTU() int {
	if r.IsIPv6() {
		return r.PathMTU - 80
	}
	return r.PathMTU - 60
}
func (r PathMTUResult) MasqueMTU() int { return r.PathMTU - MasqueOverhead }
func (r PathMTUResult) ToMap() map[string]any {
	m := map[string]any{"target": r.Target, "ip": r.IP, "iface": "", "transport": "", "iface_mtu": 0, "vpn_running": r.VPNRunning, "path_mtu": r.PathMTU, "status": string(r.Status), "probes": []any{}}
	if r.Network != nil {
		m["iface"] = r.Network.Interface
		m["transport"] = r.Network.Transport
		m["iface_mtu"] = r.Network.MTU
	}
	if r.Error != "" {
		m["error"] = r.Error
	}
	if r.Status == PathMTUOK {
		m["recommend"] = map[string]any{"wireguard": r.WireGuardMTU(), "masque": r.MasqueMTU()}
	}
	probes := make([]any, 0, len(r.Probes))
	for _, p := range r.Probes {
		probes = append(probes, map[string]any{"size": p.Size, "status": string(p.Status), "rtt_ms": p.RTTMS})
	}
	m["probes"] = probes
	return m
}

type PathMTUCallbacks struct {
	OnNetwork func(PathMTUNetwork)
	OnProbe   func(PathMTUProbe)
}

func FindPathMTU(ctx context.Context, p PathMTUProber, target string, cb PathMTUCallbacks) (PathMTUResult, error) {
	target = PathMTUHost(target)
	result := PathMTUResult{Target: target, Status: PathMTUError}
	network, e := p.Network(ctx)
	if e != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if errors.Is(e, ErrNoNetwork) {
			result.Status = PathMTUNoNetwork
		} else {
			result.Status = PathMTUError
		}
		result.Error = e.Error()
		return result, nil
	}
	result.Network = &network
	if cb.OnNetwork != nil {
		cb.OnNetwork(network)
	}
	if e = ctx.Err(); e != nil {
		result.Status = PathMTUCancelled
		return result, e
	}
	ip, e := p.Resolve(ctx, target)
	if e != nil {
		if errors.Is(e, ErrNoNetwork) {
			result.Status = PathMTUNoNetwork
		} else {
			result.Status = PathMTUError
		}
		result.Error = e.Error()
		return result, nil
	}
	result.IP = ip
	floor := 576
	if strings.Contains(ip, ":") {
		floor = 1280
	}
	ceiling := network.MTU
	if ceiling <= 0 {
		ceiling = PathMTUFallbackCeiling
	}
	seq := 0
	attempt := func(size int) (PathMTUProbe, bool) {
		var last PathMTUProbeReply
		for tries := 0; tries < 2; tries++ {
			if e := ctx.Err(); e != nil {
				return PathMTUProbe{}, false
			}
			seq = (seq + 1) & 0xffff
			last, e = p.Probe(ctx, ip, size, PathMTUTimeoutMS, seq)
			if e != nil {
				last = PathMTUProbeReply{Status: PathProbeError, Error: e.Error()}
			}
			if last.Status == PathProbeOK || last.Status == PathProbeTooBig {
				break
			}
		}
		probe := PathMTUProbe{Size: size, Status: last.Status, RTTMS: last.RTTMS}
		result.Probes = append(result.Probes, probe)
		if cb.OnProbe != nil {
			cb.OnProbe(probe)
		}
		return probe, true
	}
	small, ok := attempt(PathMTUSmallProbe)
	if !ok {
		result.Status = PathMTUCancelled
		return result, ctx.Err()
	}
	if small.Status != PathProbeOK {
		result.Status = PathMTUUnreachable
		return result, nil
	}
	low := PathMTUSmallProbe
	top, ok := attempt(ceiling)
	if !ok {
		result.Status = PathMTUCancelled
		result.PathMTU = low
		return result, ctx.Err()
	}
	if top.Status == PathProbeOK {
		result.Status = PathMTUOK
		result.PathMTU = ceiling
		return result, nil
	}
	high := ceiling
	if floor >= ceiling {
		result.Status = PathMTUBelowFloor
		result.PathMTU = low
		return result, nil
	}
	floorProbe, ok := attempt(floor)
	if !ok {
		result.Status = PathMTUCancelled
		result.PathMTU = low
		return result, ctx.Err()
	}
	if floorProbe.Status != PathProbeOK {
		result.Status = PathMTUBelowFloor
		result.PathMTU = low
		return result, nil
	}
	low = floor
	for high-low > 1 {
		if e := ctx.Err(); e != nil {
			result.Status = PathMTUCancelled
			result.PathMTU = low
			return result, e
		}
		mid := (low + high) / 2
		probe, ok := attempt(mid)
		if !ok {
			result.Status = PathMTUCancelled
			result.PathMTU = low
			return result, ctx.Err()
		}
		if probe.Status == PathProbeOK {
			low = mid
		} else {
			high = mid
		}
	}
	result.Status = PathMTUOK
	result.PathMTU = low
	return result, nil
}
func PathMTUHost(input string) string {
	s := strings.TrimSpace(input)
	if strings.HasPrefix(s, "[") {
		if i := strings.IndexByte(s, ']'); i > 0 {
			return s[1:i]
		}
	}
	if i := strings.IndexByte(s, ':'); i > 0 && i == strings.LastIndexByte(s, ':') {
		var port int
		if _, e := fmt.Sscanf(s[i+1:], "%d", &port); e == nil {
			return s[:i]
		}
	}
	return s
}
