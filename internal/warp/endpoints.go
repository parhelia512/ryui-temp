package warp

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	mathrand "math/rand"
	"net"
	"strings"
	"sync"
)

type ScanPool struct {
	APIHosts                                    []string
	WGv4, WGv6                                  []string
	WGPorts, WGExtraPorts                       []int
	WGEndpoints                                 []string
	WGRecommended                               string
	WGKeepalive                                 int
	WGSNI, UTLS                                 []string
	MasqueHosts, MasqueH3Extra, MasqueH2Exclude []string
	MasqueRecommended, MasqueRecommendedSNI     string
	MasqueV4                                    []string
	MasqueH3Ports, MasqueH2Ports                []int
	MasqueSNI                                   []string
}
type EndpointPicker struct {
	Pool ScanPool
	rng  *mathrand.Rand
	mu   sync.Mutex
}

func NewEndpointPicker(data []byte, region string, rng *mathrand.Rand) (*EndpointPicker, error) {
	var root map[string]any
	if e := json.Unmarshal(data, &root); e != nil {
		return nil, fmt.Errorf("warp endpoints JSON: %w", e)
	}
	if region != "" {
		root = ApplyRegion(root, region)
	}
	p := parsePool(root)
	if !p.HasData() {
		return nil, fmt.Errorf("warp endpoint pool is empty")
	}
	if rng == nil {
		var b [8]byte
		if _, e := rand.Read(b[:]); e != nil {
			return nil, e
		}
		rng = mathrand.New(mathrand.NewSource(int64(binary.LittleEndian.Uint64(b[:]))))
	}
	return &EndpointPicker{Pool: p, rng: rng}, nil
}
func parsePool(root map[string]any) ScanPool {
	wg, _ := root["wireguard"].(map[string]any)
	mq, _ := root["masque"].(map[string]any)
	api, _ := root["api"].(map[string]any)
	h3, _ := mq["h3"].(map[string]any)
	h2, _ := mq["h2"].(map[string]any)
	p := ScanPool{APIHosts: cleanHosts(strs(api["hosts"])), WGv4: strs(wg["v4_cidr"]), WGv6: strs(wg["v6_cidr"]), WGPorts: ints(wg["ports"]), WGExtraPorts: ints(wg["ports_extra"]), WGEndpoints: strs(wg["endpoints_preset"]), WGRecommended: strVal(wg["recommended_endpoint"]), WGKeepalive: intVal(wg["keepalive"]), WGSNI: strs(wg["sni_pool"]), UTLS: strs(wg["utls_fp_pool"]), MasqueHosts: strs(mq["hosts_preset"]), MasqueRecommended: strVal(mq["recommended_host"]), MasqueV4: strs(h2["v4_cidr"]), MasqueH2Exclude: strs(h2["exclude"]), MasqueH3Ports: ints(h3["ports"]), MasqueH2Ports: ints(h2["ports"]), MasqueSNI: strs(mq["sni_pool"]), MasqueRecommendedSNI: strVal(mq["recommended_sni"])}
	if h2 == nil {
		p.MasqueV4 = strs(mq["v4_cidr"])
		p.MasqueH2Ports = ints(mq["ports_h2"])
	}
	if h3 == nil {
		p.MasqueH3Ports = ints(mq["ports_h3"])
	}
	if v, ok := h3["hosts_extra"]; ok {
		p.MasqueH3Extra = strs(v)
	} else {
		for _, c := range strs(mq["h3_v4_cidr"]) {
			if strings.HasSuffix(c, "/32") {
				h := strings.TrimSuffix(c, "/32")
				if !has(p.MasqueHosts, h) {
					p.MasqueH3Extra = append(p.MasqueH3Extra, h)
				}
			}
		}
	}
	return p
}
func (p ScanPool) HasData() bool {
	return ((len(p.WGv4) > 0 || len(p.WGv6) > 0) && len(p.WGPorts) > 0) || len(p.MasqueV4) > 0 || len(p.MasqueHosts) > 0 || len(p.MasqueH3Extra) > 0
}
func (p ScanPool) MasqueH3Hosts() []string {
	return unique(append(append([]string{}, p.MasqueHosts...), p.MasqueH3Extra...))
}
func (p ScanPool) MasqueHostsFor(network string) []string {
	if network == "h3" {
		return p.MasqueH3Hosts()
	}
	return append([]string{}, p.MasqueHosts...)
}
func (p ScanPool) MasquePortsFor(network string) []int {
	if network == "h2" {
		return p.MasqueH2Ports
	}
	return p.MasqueH3Ports
}
func (p *EndpointPicker) RandomEndpoint(allowV6 bool) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	blocks := p.Pool.WGv4
	if allowV6 && len(p.Pool.WGv6) > 0 && p.rng.Intn(2) == 0 {
		blocks = p.Pool.WGv6
	}
	ports := append(append([]int{}, p.Pool.WGPorts...), p.Pool.WGExtraPorts...)
	if len(blocks) == 0 || len(ports) == 0 {
		return ""
	}
	ip, e := randomIP(blocks[p.rng.Intn(len(blocks))], p.rng)
	if e != nil {
		return ""
	}
	if strings.Contains(ip, ":") {
		ip = "[" + ip + "]"
	}
	return fmt.Sprintf("%s:%d", ip, ports[p.rng.Intn(len(ports))])
}
func (p *EndpointPicker) RandomSNI() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return pick(p.Pool.WGSNI, p.rng)
}
func (p *EndpointPicker) RandomMasqueSNI() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return pick(p.Pool.MasqueSNI, p.rng)
}
func (p *EndpointPicker) RandomMasqueIP(network string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if network == "h3" {
		xs := p.Pool.MasqueH3Hosts()
		return pick(xs, p.rng)
	}
	for i := 0; i < 16 && len(p.Pool.MasqueV4) > 0; i++ {
		ip, e := randomIP(p.Pool.MasqueV4[p.rng.Intn(len(p.Pool.MasqueV4))], p.rng)
		if e == nil && !has(p.Pool.MasqueH2Exclude, ip) {
			return ip
		}
	}
	return ""
}
func (p *EndpointPicker) RandomMasquePort(network string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	xs := p.Pool.MasquePortsFor(network)
	if len(xs) == 0 {
		return 0
	}
	return xs[p.rng.Intn(len(xs))]
}

type Candidate struct {
	IP       string         `json:"ip"`
	Port     int            `json:"port"`
	Protocol string         `json:"protocol"`
	SNI      string         `json:"sni,omitempty"`
	AWG      map[string]any `json:"awg,omitempty"`
}

func (c Candidate) Endpoint() string {
	h := c.IP
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	return fmt.Sprintf("%s:%d", h, c.Port)
}
func (c Candidate) NodeTitle() string {
	switch c.Protocol {
	case "awg":
		mode := strVal(c.AWG["ip"])
		if mode == "" {
			mode = "quic"
		}
		if c.SNI != "" {
			return fmt.Sprintf("🔥⛈️ WARP AWG (%s %s)", mode, c.SNI)
		}
		return fmt.Sprintf("🔥⛈️ WARP AWG (%s)", mode)
	case "masque_h2":
		if c.SNI != "" {
			return "🔥🎭 WARP MASQUE (h2: " + c.SNI + ")"
		}
		return "🔥🎭 WARP MASQUE (h2)"
	default:
		if c.SNI != "" {
			return "🔥🎭 WARP MASQUE (h3: " + c.SNI + ")"
		}
		return "🔥🎭 WARP MASQUE (h3)"
	}
}
func (p *EndpointPicker) GenerateCandidates(n int, allowV6 bool, ratio float64) []Candidate {
	if n < 0 {
		n = 0
	}
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}
	out := make([]Candidate, 0, n)
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := 0; i < n; i++ {
		proto := []string{}
		if (len(p.Pool.WGv4) > 0 || len(p.Pool.WGv6) > 0) && len(p.Pool.WGPorts) > 0 {
			proto = append(proto, "awg")
		}
		if len(p.Pool.MasqueH3Hosts()) > 0 {
			proto = append(proto, "masque_h3")
		}
		if len(p.Pool.MasqueV4) > 0 {
			proto = append(proto, "masque_h2")
		}
		if len(proto) == 0 {
			break
		}
		kind := proto[p.rng.Intn(len(proto))]
		if kind == "awg" {
			blocks := p.Pool.WGv4
			if allowV6 && len(p.Pool.WGv6) > 0 && p.rng.Intn(2) == 0 {
				blocks = p.Pool.WGv6
			}
			ip, e := randomIP(blocks[p.rng.Intn(len(blocks))], p.rng)
			if e != nil {
				continue
			}
			ports := p.Pool.WGPorts
			if len(p.Pool.WGExtraPorts) > 0 && p.rng.Float64() < ratio {
				ports = p.Pool.WGExtraPorts
			}
			mode := []string{"quic", "quic", "quic", "dns", "stun"}[p.rng.Intn(5)]
			sni := pick(p.Pool.WGSNI, p.rng)
			out = append(out, Candidate{IP: ip, Port: ports[p.rng.Intn(len(ports))], Protocol: kind, SNI: sni, AWG: BuildAmneziaAWG(QuicParams{IP: mode, SNI: sni, JC: 4, JMin: 40, JMax: 70})})
			continue
		}
		network := "h3"
		if kind == "masque_h2" {
			network = "h2"
		}
		ip := ""
		if network == "h3" {
			ip = pick(p.Pool.MasqueH3Hosts(), p.rng)
		} else {
			for k := 0; k < 16 && ip == ""; k++ {
				x, e := randomIP(p.Pool.MasqueV4[p.rng.Intn(len(p.Pool.MasqueV4))], p.rng)
				if e == nil && !has(p.Pool.MasqueH2Exclude, x) {
					ip = x
				}
			}
		}
		ports := p.Pool.MasquePortsFor(network)
		port := 443
		if len(ports) > 0 {
			port = ports[p.rng.Intn(len(ports))]
		}
		out = append(out, Candidate{IP: ip, Port: port, Protocol: kind, SNI: pick(p.Pool.MasqueSNI, p.rng)})
	}
	return out
}

func ApplyRegion(root map[string]any, region string) map[string]any {
	base := cloneMap(root)
	loc, _ := root["loc"].(map[string]any)
	delete(base, "loc")
	sec, _ := loc[strings.ToLower(region)].(map[string]any)
	if alias, ok := sec["alias"].(string); ok {
		sec, _ = loc[strings.ToLower(alias)].(map[string]any)
	}
	if sec == nil {
		return base
	}
	return merge(base, sec)
}
func RegionsOfJSON(data []byte) ([]string, error) {
	var root map[string]any
	if e := json.Unmarshal(data, &root); e != nil {
		return nil, e
	}
	loc, _ := root["loc"].(map[string]any)
	out := []string{}
	for k, v := range loc {
		if _, ok := v.(map[string]any); ok {
			out = append(out, strings.ToLower(k))
		}
	}
	return out, nil
}
func merge(a, b map[string]any) map[string]any {
	o := cloneMap(a)
	for k, v := range b {
		if bm, ok := v.(map[string]any); ok {
			if am, ok := o[k].(map[string]any); ok {
				o[k] = merge(am, bm)
				continue
			}
		}
		o[k] = v
	}
	return o
}
func randomIP(cidr string, r *mathrand.Rand) (string, error) {
	_, n, e := net.ParseCIDR(cidr)
	if e != nil {
		return "", e
	}
	ones, bits := n.Mask.Size()
	host := bits - ones
	out := append(net.IP(nil), n.IP...)
	for i := len(out) - 1; host > 0 && i >= 0; i-- {
		take := host
		if take > 8 {
			take = 8
		}
		mask := byte((1 << take) - 1)
		out[i] |= byte(r.Intn(1<<take)) & mask
		host -= take
	}
	return out.String(), nil
}
func strs(v any) []string {
	a, _ := v.([]any)
	o := []string{}
	for _, x := range a {
		if s, ok := x.(string); ok {
			o = append(o, s)
		}
	}
	return o
}
func ints(v any) []int {
	a, _ := v.([]any)
	o := []int{}
	for _, x := range a {
		switch n := x.(type) {
		case float64:
			o = append(o, int(n))
		case int:
			o = append(o, n)
		}
	}
	return o
}
func strVal(v any) string { s, _ := v.(string); return s }
func intVal(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	}
	return 0
}
func cleanHosts(xs []string) []string {
	o := []string{}
	for _, x := range xs {
		x = strings.TrimRight(strings.TrimSpace(x), "/")
		if x != "" {
			o = append(o, x)
		}
	}
	return o
}
func pick(xs []string, r *mathrand.Rand) string {
	if len(xs) == 0 {
		return ""
	}
	return xs[r.Intn(len(xs))]
}
func has(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func unique(xs []string) []string {
	seen := map[string]bool{}
	o := []string{}
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			o = append(o, x)
		}
	}
	return o
}
