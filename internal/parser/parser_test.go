package parser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"testing/fstest"
)

var testContract = fstest.MapFS{
	"registry/protocols/shadowsocks.json": &fstest.MapFile{Data: []byte(`{"scheme":"ss","kind":"outbound","singbox_type":"shadowsocks","aliases":[],"uri":{"userinfo":{"into":["method","password"],"split":{"sep":":"}},"query":{}},"body":{"fields":{}}}`)},
	"registry/protocols/vless.json": &fstest.MapFile{Data: []byte(`{"scheme":"vless","kind":"outbound","singbox_type":"vless","aliases":[],"uri":{"userinfo":{"into":["uuid"],"split":{"sep":":"}},"query":{"type":{"maps_to":"transport.type"},"path":{"maps_to":"transport.path"},"security":{"maps_to":"tls.enabled"}}},"body":{"fields":{}}}`)},
	"registry/protocols/wireguard.json": &fstest.MapFile{Data: []byte(`{"scheme":"wireguard","kind":"endpoint","singbox_type":"wireguard","aliases":["wg","awg"],"uri":{"userinfo":{"into":["private_key"]},"query":{"publickey":{"maps_to":"peers[].public_key"},"address":{"maps_to":"address"}}},"body":{"fields":{}}}`)},
	"registry/protocols/socks.json": &fstest.MapFile{Data: []byte(`{"scheme":"socks","kind":"outbound","singbox_type":"socks","aliases":["socks5"],"uri":{"userinfo":{"into":["username","password"],"split":{"sep":":"}},"query":{}},"body":{"fields":{}}}`)},
}

func TestParseContractURIGoldens(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "contract", "uri")
	var fixtures []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil { return walkErr }
		if entry.IsDir() || filepath.Ext(path) != ".uri" { return nil }
		fixtures = append(fixtures, path)
		return nil
	})
	if err != nil { t.Fatal(err) }
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(strings.TrimPrefix(fixture, root+string(os.PathSeparator)), func(t *testing.T) {
			body, err := os.ReadFile(fixture); if err != nil { t.Fatal(err) }
			base := strings.TrimSuffix(fixture, ".uri")
			expectedPath := base + ".expected.lxbox.json"
			if _, err := os.Stat(expectedPath); err != nil { expectedPath = base + ".expected.json" }
			expectedBytes, err := os.ReadFile(expectedPath); if err != nil { t.Skip("fixture has no shared expected JSON") }
			var expected struct { Nodes []struct { Entry map[string]any `json:"entry"` } `json:"nodes"` }
			if err := json.Unmarshal(expectedBytes, &expected); err != nil { t.Fatalf("decode expected: %v", err) }
			result := Parse(context.Background(), body, Options{ContractFS: os.DirFS(filepath.Join("..", "..", "assets")), Source: Source{Kind:"corpus", ID:filepath.Base(base)}})
			if len(result.Nodes) != len(expected.Nodes) { t.Fatalf("node count got %d want %d; diagnostics=%+v", len(result.Nodes), len(expected.Nodes), result.Diagnostics) }
			for i, want := range expected.Nodes {
				if got := Emit(result.Nodes[i]); !reflect.DeepEqual(got, want.Entry) { t.Errorf("entry[%d] mismatch\ngot:  %#v\nwant: %#v", i, got, want.Entry) }
			}
		})
	}
}
func TestParseFixtureFileShape(t *testing.T) {
	data, err := os.ReadFile("testdata/ss_subscription.txt")
	if err != nil { t.Fatal(err) }
	result := Parse(context.Background(), data, Options{ContractFS: testContract})
	if len(result.Nodes) != 1 || result.Nodes[0].Protocol != "shadowsocks" { t.Fatalf("unexpected fixture result: %+v", result) }
}

func TestParsePreservesSourceAndEmitsSingBoxEntry(t *testing.T) {
	body := []byte("ss://YWVzLTI1Ni1nY206cGFzcw==@ss.example:443#office\nvless://uuid@example:443?security=tls&type=ws&path=%2Fedge#edge")
	source := Source{Kind: "subscription", ID: "src-7", Name: "primary", URL: "https://sub.example/list"}
	result := Parse(context.Background(), body, Options{ContractFS: testContract, Source: source})
	if !result.Recognized || !result.Complete || len(result.Nodes) != 2 { t.Fatalf("unexpected parse result: %+v", result) }
	if result.Nodes[0].Source != source || result.Source != source { t.Fatalf("source metadata was not preserved: %+v", result.Nodes[0].Source) }
	entry := Emit(result.Nodes[0])
	if entry["type"] != "shadowsocks" || entry["tag"] != "office" || entry["server"] != "ss.example" { t.Fatalf("unexpected emitted Shadowsocks entry: %#v", entry) }
	vless := Emit(result.Nodes[1])
	transport, ok := vless["transport"].(map[string]any)
	if !ok || transport["type"] != "ws" || transport["path"] != "/edge" { t.Fatalf("unexpected emitted VLESS entry: %#v", vless) }
	if result.NodesByKey[result.Nodes[0].Key]["type"] != "shadowsocks" || result.RawByKey[result.Nodes[0].Key]["uri"] != "ss://YWVzLTI1Ni1nY206cGFzcw==@ss.example:443#office" { t.Fatalf("cache maps do not contain emitted and raw entries") }
}

func TestParseWireGuardINIUsesEndpointEntry(t *testing.T) {
	body := []byte("# wg-home\n[Interface]\nPrivateKey = local-key\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = peer-key\nEndpoint = wg.example:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n")
	result := Parse(context.Background(), body, Options{ContractFS: testContract, Source: Source{Kind: "file", ID: "wg1", Name: "wg", URL: "file:///wg.conf"}})
	if len(result.Nodes) != 1 { t.Fatalf("expected one node: %+v", result) }
	node := result.Nodes[0]
	if !node.IsEndpoint() { t.Fatalf("WireGuard must be emitted as an endpoint") }
	entry := node.SingBox()
	peerList, ok := entry["peers"].([]any)
	if entry["type"] != "wireguard" || entry["tag"] != "wg-home" || !ok || len(peerList) != 1 { t.Fatalf("unexpected endpoint entry: %#v", entry) }
	peer, _ := peerList[0].(map[string]any)
	if peer["address"] != "wg.example" || peer["port"] != int64(51820) { t.Fatalf("peer address was not normalized: %#v", peer) }
}

func TestParseBase64SubscriptionAndUnsupportedSchemeDiagnostic(t *testing.T) {
	inner := "ss://YWVzLTI1Ni1nY206cGFzcw==@ss.example:443#one\nunknown://host:1"
	result := Parse(context.Background(), []byte(base64.StdEncoding.EncodeToString([]byte(inner))), Options{ContractFS: testContract, Source: Source{Kind: "subscription", ID: "wrapped"}})
	if len(result.Nodes) != 1 || result.Complete { t.Fatalf("expected partial result with one node: %+v", result) }
	found := false
	for _, d := range result.Diagnostics { if d.Code == "scheme_unsupported" && d.Line == 2 { found = true } }
	if !found { t.Fatalf("unsupported input lacks line diagnostic: %+v", result.Diagnostics) }
}

func TestParseSingBoxAndClashYAMLRetainsUnknownFields(t *testing.T) {
	jsonBody := []byte(`{"outbounds":[{"type":"socks","tag":"local","server":"127.0.0.1","server_port":1080,"custom_extension":{"x":1}}]}`)
	jsonResult := Parse(context.Background(), jsonBody, Options{ContractFS: testContract})
	if len(jsonResult.Nodes) != 1 || jsonResult.Nodes[0].Raw["custom_extension"] == nil { t.Fatalf("raw sing-box fields were not retained: %+v", jsonResult) }
	clash, err := os.ReadFile("testdata/clash.yaml")
	if err != nil { t.Fatal(err) }
	yamlResult := Parse(context.Background(), clash, Options{ContractFS: testContract})
	if len(yamlResult.Nodes) != 1 || yamlResult.Format != "yaml" { t.Fatalf("unexpected Clash YAML result: %+v", yamlResult) }
	if _, ok := yamlResult.Nodes[0].Raw["plugin-extra"]; !ok { t.Fatalf("unknown Clash field was lost: %#v", yamlResult.Nodes[0].Raw) }
	if !json.Valid([]byte(`{"type":"socks","tag":"edge"}`)) { t.Fatal("test JSON sanity") }
}

func TestParsePreservesLargeJSONNumberAndReportsPartialFailure(t *testing.T) {
	body := []byte(`{"outbounds":[{"type":"socks","tag":"large","server":"127.0.0.1","server_port":1080,"unknown_counter":9007199254740993},{"type":"not-in-contract","tag":"bad"}]}`)
	result := Parse(context.Background(), body, Options{ContractFS: testContract})
	if len(result.Nodes) != 1 || result.Complete { t.Fatalf("expected one node and incomplete result: %+v", result) }
	value, ok := result.Nodes[0].Raw["unknown_counter"].(json.Number)
	if !ok || value.String() != "9007199254740993" { t.Fatalf("large JSON number lost precision: %#v", result.Nodes[0].Raw["unknown_counter"]) }
	if result.RawByKey[result.Nodes[0].Key]["unknown_counter"].(json.Number).String() != "9007199254740993" { t.Fatal("raw cache lost exact number") }
	found := false
	for _, diagnostic := range result.Diagnostics { if diagnostic.Code == "protocol_unsupported" { found = true } }
	if !found { t.Fatalf("unsupported outbound lacks diagnostic: %+v", result.Diagnostics) }
}

func TestParseFailsWhenContractFSIsInvalid(t *testing.T) {
	result := Parse(context.Background(), []byte(`{"type":"socks","server":"127.0.0.1"}`), Options{ContractFS: fstest.MapFS{}})
	if result.Complete || len(result.Nodes) != 0 || len(result.Diagnostics) == 0 || result.Diagnostics[0].Code != "contract_load_failed" { t.Fatalf("invalid contract was silently accepted: %+v", result) }
}
