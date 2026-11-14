package diagnostics

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
)

type ProbeFunc func(context.Context, map[string]any) (map[string]any, error)
type ConnectionTestFunc func(context.Context, map[string]any) (map[string]any, error)
type SocketDialFunc func(context.Context, string, string) (net.Conn, error)
type ProtectSocketFunc func(uintptr) error
type Options struct {
	URLTest        ProbeFunc
	Probe          ProbeFunc
	ConnectionTest ConnectionTestFunc
	PathMTU        PathMTUProber
	DialContext    SocketDialFunc
	ProtectSocket  ProtectSocketFunc
}
type Client struct{ opts Options }

func (c *Client) probeCallback() ProbeFunc {
	if c.opts.URLTest != nil {
		return c.opts.URLTest
	}
	return c.opts.Probe
}

// NewClient is side-effect free. It never opens sockets or starts a probe.
func NewClient(opts Options) *Client { return &Client{opts: opts} }

// Dispatch is the stable map/JSON boundary for runtime service registration.
func (c *Client) Dispatch(ctx context.Context, method string, args map[string]any) (any, error) {
	if args == nil {
		args = map[string]any{}
	}
	switch strings.ToLower(method) {
	case "diagnostics.checks", "diagnostics.check.list":
		return DiagnosticChecks, nil
	case "diagnostics.url.normalize":
		u, ok := NormalizeCheckURL(stringArg(args, "url", ""))
		if !ok {
			return nil, fmt.Errorf("invalid http(s) URL")
		}
		return map[string]any{"url": u}, nil
	case "diagnostics.report.redact":
		return Redact(args), nil
	case "diagnostics.connection.trace":
		t, e := TraceFromMap(args)
		if e != nil {
			return nil, e
		}
		return map[string]any{"text": TraceToText(t, stringArg(args, "link", ""), stringArg(args, "app", ""), intArg(args, "depth", 0))}, nil
	case "diagnostics.chain.report":
		return ChainReportFromMap(args)
	case "diagnostics.run":
		kind := strings.ToLower(stringArg(args, "kind", ""))
		switch kind {
		case "probe":
			if c.probeCallback() == nil {
				return nil, fmt.Errorf("diagnostics probe callback unavailable")
			}
			return c.probeCallback()(ctx, args)
		case "connection":
			if c.opts.ConnectionTest == nil {
				return nil, fmt.Errorf("diagnostics connection-test callback unavailable")
			}
			return c.opts.ConnectionTest(ctx, args)
		case "path_mtu":
			if c.opts.PathMTU == nil {
				return nil, fmt.Errorf("physical path-MTU prober unavailable")
			}
			v, e := FindPathMTU(ctx, c.opts.PathMTU, stringArg(args, "target", DefaultPathMTUTarget), PathMTUCallbacks{})
			return v.ToMap(), e
		default:
			return nil, fmt.Errorf("diagnostics.run requires kind probe, connection, or path_mtu")
		}
	case "diagnostics.run.probe":
		if c.probeCallback() == nil {
			return nil, fmt.Errorf("diagnostics probe callback unavailable")
		}
		return c.probeCallback()(ctx, args)
	case "diagnostics.run.connection", "diagnostics.connection.run":
		if c.opts.ConnectionTest == nil {
			return nil, fmt.Errorf("diagnostics connection-test callback unavailable")
		}
		return c.opts.ConnectionTest(ctx, args)
	case "diagnostics.run.path_mtu", "diagnostics.path_mtu.run":
		if c.opts.PathMTU == nil {
			return nil, fmt.Errorf("physical path-MTU prober unavailable")
		}
		v, e := FindPathMTU(ctx, c.opts.PathMTU, stringArg(args, "target", DefaultPathMTUTarget), PathMTUCallbacks{})
		return v.ToMap(), e
	default:
		return nil, fmt.Errorf("diagnostics: unknown method %q", method)
	}
}

// DialContext and ProtectSocket only call explicitly injected platform hooks.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if c.opts.DialContext == nil {
		return nil, fmt.Errorf("platform dialer not configured")
	}
	return c.opts.DialContext(ctx, network, address)
}
func (c *Client) ProtectSocket(fd uintptr) error {
	if c.opts.ProtectSocket == nil {
		return fmt.Errorf("platform socket protector not configured")
	}
	return c.opts.ProtectSocket(fd)
}
func NormalizeCheckURL(input string) (string, bool) {
	s := strings.TrimSpace(input)
	if s == "" || strings.ContainsAny(s, " \t\r\n") {
		return "", false
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, e := url.Parse(s)
	if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", false
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), true
}

type DiagnosticCheck struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	URL   string `json:"url"`
}

var DiagnosticChecks = []DiagnosticCheck{{"cf_trace", "Cloudflare trace", "https://1.1.1.1/cdn-cgi/trace"}, {"cf_trace_host", "Cloudflare trace (hostname)", "https://cloudflare.com/cdn-cgi/trace"}, {"ip2location", "IP & location", "https://api.ip2location.io/"}, {"ipinfo", "IP info", "https://ipinfo.io/json"}}

func stringArg(m map[string]any, k, d string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return d
}
func intArg(m map[string]any, k string, d int) int {
	switch v := m[k].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return d
}
func ChainReportFromMap(m map[string]any) (map[string]any, error) {
	r := ChainReport{ChainTag: stringArg(m, "chain_tag", ""), URL: stringArg(m, "url", ""), TimeoutMS: intArg(m, "timeout_ms", 0), Layers: []ChainLayer{}}
	raw, _ := m["layers"].([]any)
	for i, v := range raw {
		x, ok := v.(map[string]any)
		if !ok {
			continue
		}
		l := ChainLayer{Pos: intArg(x, "pos", i), Tag: stringArg(x, "tag", ""), ProbeTag: stringArg(x, "probe_tag", ChainLayerTag(r.ChainTag, i)), CumulativeMS: intArg(x, "cumulative_ms", 0), Error: stringArg(x, "error", ""), NotReached: boolArg(x, "not_reached", false)}
		r.Layers = append(r.Layers, l)
	}
	deltas := make([]any, len(r.Layers))
	for i := range r.Layers {
		if d, ok := r.DeltaAt(i); ok {
			deltas[i] = d
		}
	}
	return map[string]any{"chain_tag": r.ChainTag, "layers": r.Layers, "deltas_ms": deltas, "url": r.URL, "timeout_ms": r.TimeoutMS}, nil
}
func boolArg(m map[string]any, k string, d bool) bool {
	if v, ok := m[k].(bool); ok {
		return v
	}
	return d
}
func clone(m map[string]any) map[string]any {
	o := make(map[string]any, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}
