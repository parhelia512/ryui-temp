package warp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const DefaultEndpoint = "engage.cloudflareclient.com:2408"
const DefaultMasqueServer = "162.159.198.1"
const DefaultMasquePort = 443

type QuicParams struct {
	SNI  string `json:"sni,omitempty"`
	IP   string `json:"ip,omitempty"`
	IB   string `json:"ib,omitempty"`
	JC   int    `json:"jc,omitempty"`
	JMin int    `json:"jmin,omitempty"`
	JMax int    `json:"jmax,omitempty"`
}

func (p QuicParams) normalized() QuicParams {
	if strings.TrimSpace(p.IP) == "" {
		p.IP = "quic"
	}
	if strings.TrimSpace(p.IB) == "" {
		p.IB = "chrome"
	}
	if p.JC == 0 {
		p.JC = 4
	}
	if p.JMin == 0 {
		p.JMin = 40
	}
	if p.JMax == 0 {
		p.JMax = 70
	}
	return p
}
func BuildAmneziaAWG(p QuicParams) map[string]any {
	p = p.normalized()
	domain := strings.TrimSpace(p.SNI)
	if domain == "" {
		domain = "www.google.com"
	}
	m := map[string]any{"jc": p.JC, "jmin": p.JMin, "jmax": p.JMax, "s1": 0, "s2": 0, "h1": 1, "h2": 2, "h3": 3, "h4": 4, "ip": strings.TrimSpace(p.IP), "id": domain}
	if p.IP == "quic" {
		m["ib"] = p.IB
	}
	return m
}

type WarpAccount struct {
	PrivateKey   string         `json:"priv_key"`
	PeerPublic   string         `json:"peer_pub"`
	ClientV4     string         `json:"client_v4"`
	ClientV6     string         `json:"client_v6"`
	ClientID     string         `json:"client_id"`
	AccountID    string         `json:"account_id"`
	DeviceID     string         `json:"device_id"`
	Token        string         `json:"token"`
	Endpoint     string         `json:"endpoint"`
	CreatedAt    string         `json:"created_at"`
	License      string         `json:"license"`
	LicenseError string         `json:"license_error,omitempty"`
	WarpPlus     bool           `json:"warp_plus"`
	AWG          map[string]any `json:"awg,omitempty"`
}

func (a WarpAccount) Reserved() []byte {
	b, e := base64.StdEncoding.DecodeString(a.ClientID)
	if e != nil || len(b) != 3 {
		return nil
	}
	return b
}

var endpointPattern = regexp.MustCompile(`^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?):([0-9]{1,5})$`)

func IsValidEndpoint(s string) bool {
	m := endpointPattern.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return false
	}
	p, e := strconv.Atoi(m[2])
	return e == nil && p > 0 && p <= 65535
}
func (a WarpAccount) NodeTag() string {
	plus := ""
	if a.WarpPlus {
		plus = "+"
	}
	if a.AWG != nil {
		return "🔥⛈️ WARP" + plus + " (AWG 1.5)"
	}
	return "🔥☁️ WARP" + plus
}
func (a WarpAccount) URI(includeReserved bool, keepalive int) string {
	q := url.Values{}
	q.Set("publickey", a.PeerPublic)
	q.Set("address", joinAddresses(a.ClientV4, a.ClientV6, ","))
	q.Set("allowedips", "0.0.0.0/0,::/0")
	q.Set("mtu", "1280")
	if includeReserved {
		if r := a.Reserved(); len(r) == 3 {
			q.Set("reserved", joinBytes(r))
		}
	}
	if keepalive > 0 {
		q.Set("keepalive", strconv.Itoa(keepalive))
	}
	return "wireguard://" + url.QueryEscape(a.PrivateKey) + "@" + a.Endpoint + "?" + queryString(q) + "#" + url.QueryEscape(a.NodeTag())
}
func (a WarpAccount) Conf(includeReserved bool, keepalive int) string {
	name := "WARP"
	if a.WarpPlus {
		name = "WARP+"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s", name)
	if a.AWG != nil {
		b.WriteString(" (Amnezia 1.5 obfuscation)")
	}
	b.WriteString("\n[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\nAddress = %s\nMTU = 1280\n", a.PrivateKey, joinAddresses(a.ClientV4, a.ClientV6, ", "))
	if a.AWG != nil {
		keys := make([]string, 0, len(a.AWG))
		for k := range a.AWG {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "%s = %v\n", strings.ToUpper(k), a.AWG[k])
		}
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %s\n", a.PeerPublic, a.Endpoint)
	if keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", keepalive)
	}
	if includeReserved {
		if r := a.Reserved(); len(r) == 3 {
			fmt.Fprintf(&b, "Reserved = %s\n", joinBytes(r))
		}
	}
	return b.String()
}
func (a WarpAccount) ToMap() map[string]any {
	m := map[string]any{"priv_key": a.PrivateKey, "peer_pub": a.PeerPublic, "client_v4": a.ClientV4, "client_v6": a.ClientV6, "client_id": a.ClientID, "account_id": a.AccountID, "device_id": a.DeviceID, "token": a.Token, "endpoint": a.Endpoint, "created_at": a.CreatedAt, "license": a.License, "warp_plus": a.WarpPlus}
	if a.LicenseError != "" {
		m["license_error"] = a.LicenseError
	}
	if a.AWG != nil {
		m["awg"] = cloneMap(a.AWG)
	}
	return m
}
func (a WarpAccount) RedactedMap() map[string]any {
	m := a.ToMap()
	m["priv_key"] = "<redacted>"
	m["token"] = "<redacted>"
	if a.License != "" {
		m["license"] = "<redacted>"
	}
	return m
}
func WarpAccountFromMap(m map[string]any) (WarpAccount, error) {
	get := func(k string) string { return stringValue(m[k]) }
	a := WarpAccount{PrivateKey: get("priv_key"), PeerPublic: get("peer_pub"), ClientV4: get("client_v4"), ClientV6: get("client_v6"), ClientID: get("client_id"), AccountID: get("account_id"), DeviceID: get("device_id"), Token: get("token"), Endpoint: get("endpoint"), CreatedAt: get("created_at"), License: get("license"), LicenseError: get("license_error")}
	if a.PrivateKey == "" || a.PeerPublic == "" {
		return WarpAccount{}, fmt.Errorf("warp account: missing private/public key")
	}
	if a.Endpoint == "" {
		a.Endpoint = DefaultEndpoint
	}
	a.WarpPlus, _ = m["warp_plus"].(bool)
	if x, ok := m["awg"].(map[string]any); ok {
		a.AWG = cloneMap(x)
	}
	return a, nil
}

type MasqueAccount struct {
	PrivateKeyDER string `json:"priv_key_der"`
	ServerPubDER  string `json:"server_pub_der"`
	ClientV4      string `json:"client_v4"`
	ClientV6      string `json:"client_v6"`
	Server        string `json:"server"`
	Port          int    `json:"port"`
	DeviceID      string `json:"device_id"`
	Token         string `json:"token"`
	CreatedAt     string `json:"created_at"`
	SNI           string `json:"sni,omitempty"`
	IdleTimeout   string `json:"idle_timeout,omitempty"`
	KeepAlive     string `json:"keep_alive,omitempty"`
}

func (a MasqueAccount) NodeTag() string { return "🔥🎭 WARP (MASQUE)" }
func ensureCIDR(s string) string {
	if s == "" || strings.Contains(s, "/") {
		return s
	}
	if strings.Contains(s, ":") {
		return s + "/128"
	}
	return s + "/32"
}
func (a MasqueAccount) URI(vhttp string) string {
	if vhttp == "" {
		vhttp = "h3"
	}
	q := url.Values{}
	q.Set("publickey", a.ServerPubDER)
	q.Set("address", joinAddresses(ensureCIDR(a.ClientV4), ensureCIDR(a.ClientV6), ","))
	q.Set("profile", "cloudflare")
	q.Set("vhttp", vhttp)
	q.Set("mtu", "1280")
	if a.SNI != "" {
		q.Set("sni", a.SNI)
	}
	if a.IdleTimeout != "" {
		q.Set("idle_timeout", a.IdleTimeout)
	}
	if a.KeepAlive != "" {
		q.Set("keep_alive", a.KeepAlive)
	}
	return "masque://" + url.QueryEscape(a.PrivateKeyDER) + "@" + net.JoinHostPort(a.Server, strconv.Itoa(a.Port)) + "?" + queryString(q) + "#" + url.QueryEscape(a.NodeTag())
}
func (a MasqueAccount) ToMap() map[string]any {
	return map[string]any{"priv_key_der": a.PrivateKeyDER, "server_pub_der": a.ServerPubDER, "client_v4": a.ClientV4, "client_v6": a.ClientV6, "server": a.Server, "port": a.Port, "device_id": a.DeviceID, "token": a.Token, "created_at": a.CreatedAt, "sni": a.SNI, "idle_timeout": a.IdleTimeout, "keep_alive": a.KeepAlive}
}
func (a MasqueAccount) RedactedMap() map[string]any {
	m := a.ToMap()
	m["priv_key_der"] = "<redacted>"
	m["token"] = "<redacted>"
	return m
}
func MasqueAccountFromMap(m map[string]any) (MasqueAccount, error) {
	get := func(k string) string { return stringValue(m[k]) }
	a := MasqueAccount{PrivateKeyDER: get("priv_key_der"), ServerPubDER: get("server_pub_der"), ClientV4: get("client_v4"), ClientV6: get("client_v6"), Server: get("server"), DeviceID: get("device_id"), Token: get("token"), CreatedAt: get("created_at"), SNI: get("sni"), IdleTimeout: get("idle_timeout"), KeepAlive: get("keep_alive")}
	if a.PrivateKeyDER == "" || a.ServerPubDER == "" {
		return MasqueAccount{}, fmt.Errorf("masque account: missing key")
	}
	if a.Server == "" {
		a.Server = DefaultMasqueServer
	}
	a.Port = intValue(m["port"])
	if a.Port == 0 {
		a.Port = DefaultMasquePort
	}
	return a, nil
}
func MarshalMap(v map[string]any) ([]byte, error) { return json.Marshal(v) }
func UnmarshalMap(data []byte) (map[string]any, error) {
	var m map[string]any
	e := json.Unmarshal(data, &m)
	return m, e
}
func queryString(v url.Values) string { return strings.ReplaceAll(v.Encode(), "+", "%20") }
func joinAddresses(a, b, sep string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + sep + b
}
func joinBytes(b []byte) string {
	x := make([]string, len(b))
	for i, v := range b {
		x[i] = strconv.Itoa(int(v))
	}
	return strings.Join(x, ",")
}
func cloneMap(m map[string]any) map[string]any {
	o := make(map[string]any, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}
func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
func intValue(v any) int {
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
