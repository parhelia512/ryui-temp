package warp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestKeyGenerationAndRedaction(t *testing.T) {
	priv, pub, err := GenerateWireGuardKeypair()
	if err != nil { t.Fatal(err) }
	if len(priv) != 44 || len(pub) != 44 { t.Fatalf("unexpected X25519 base64 lengths: %d/%d", len(priv), len(pub)) }
	if b, err := base64.StdEncoding.DecodeString(priv); err != nil || len(b) != 32 { t.Fatalf("private key is not raw 32 bytes: %v", err) }
	keys, err := GenerateMasqueKeys()
	if err != nil { t.Fatal(err) }
	if _, err := base64.StdEncoding.DecodeString(keys.PrivateDER); err != nil { t.Fatal(err) }
	if _, err := base64.StdEncoding.DecodeString(keys.PublicDER); err != nil { t.Fatal(err) }
	a := WarpAccount{PrivateKey: priv, PeerPublic: pub, Token: "token", License: "license", Endpoint: DefaultEndpoint}
	m := a.RedactedMap()
	if m["priv_key"] != "<redacted>" || m["token"] != "<redacted>" || m["license"] != "<redacted>" { t.Fatalf("secrets were not redacted: %#v", m) }
}

func TestEndpointPickerRegionAndCandidates(t *testing.T) {
	asset := []byte(`{"api":{"hosts":["https://api.example"]},"wireguard":{"v4_cidr":["192.0.2.0/30"],"ports":[2408],"sni_pool":["example.com"]},"masque":{"hosts_preset":["192.0.2.2"],"h3":{"ports":[443]},"h2":{"v4_cidr":["198.51.100.0/30"],"ports":[8443]},"sni_pool":["cloudflare.com"]},"loc":{"test":{"wireguard":{"sni_pool":["local.example"]}}}}`)
	p, err := NewEndpointPicker(asset, "test", rand.New(rand.NewSource(1)))
	if err != nil { t.Fatal(err) }
	if got := p.RandomEndpoint(false); !IsValidEndpoint(got) { t.Fatalf("invalid generated endpoint %q", got) }
	if got := p.RandomSNI(); got != "local.example" { t.Fatalf("region overlay not applied: %q", got) }
	candidates := p.GenerateCandidates(24, false, 0)
	if len(candidates) != 24 { t.Fatalf("got %d candidates", len(candidates)) }
	for _, c := range candidates { if c.Endpoint() == "" || c.NodeTitle() == "" { t.Fatalf("incomplete candidate: %#v", c) } }
}

func TestRandomIPStaysWithinIPv4AndIPv6CIDRs(t *testing.T) {
	for _, cidr := range []string{"162.159.192.0/24", "2606:4700:d0::/64", "2001:db8:abcd:1234::/73"} {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil { t.Fatal(err) }
		rng := rand.New(rand.NewSource(7))
		for i := 0; i < 256; i++ {
			address, err := randomIP(cidr, rng)
			if err != nil { t.Fatalf("randomIP(%q): %v", cidr, err) }
			ip := net.ParseIP(address)
			if ip == nil || !network.Contains(ip) {
				t.Fatalf("randomIP(%q) returned out-of-range address %q", cidr, address)
			}
		}
	}
}

func TestParseMasqueEndpointHostPreservesIPLiterals(t *testing.T) {
	cases := map[string]string{
		"162.159.198.1:0":     "162.159.198.1",
		"[2606:4700:d0::1]:0": "2606:4700:d0::1",
		"2606:4700:d0::1:0":   "2606:4700:d0::1",
		"162.159.198.1":       "162.159.198.1",
	}
	for input, want := range cases {
		if got := parseMasqueEndpointHost(input); got != want {
			t.Errorf("parseMasqueEndpointHost(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRegisterUsesExplicitHTTPAndKeepsLicenseError(t *testing.T) {
	var methods []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodPost { w.Header().Set("Content-Type", "application/json"); io.WriteString(w, `{"id":"device","token":"bearer","account":{"id":"account"},"config":{"client_id":"AQID","interface":{"addresses":{"v4":"172.16.0.2","v6":""}},"peers":[{"public_key":"peer","endpoint":{"host":"engage.cloudflareclient.com:2408"}}]}}`); return }
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	client := NewClient(Options{APIHosts: []string{srv.URL}, HTTP: srv.Client()})
	account, err := client.Register(context.Background(), RegisterArgs{Now: "2026-01-01T00:00:00Z", License: "LIC"})
	if err != nil { t.Fatal(err) }
	if account.LicenseError == "" || account.WarpPlus { t.Fatalf("license failure not visible: %#v", account) }
	if len(methods) != 2 || !strings.HasPrefix(methods[1], "PATCH ") { t.Fatalf("unexpected request sequence: %#v", methods) }
	if _, err := json.Marshal(account.ToMap()); err != nil { t.Fatal(err) }
}
