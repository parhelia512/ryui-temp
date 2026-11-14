// Package parser converts subscriptions to cacheable nodes and sing-box entries.
//
// API contract:
//
//	result := parser.Parse(ctx, body, parser.Options{
//	    ContractFS: contractAssets,
//	    Source: parser.Source{Kind: "subscription", ID: id, Name: name, URL: url},
//	})
//
// Result.Nodes is ordered by source position. Each Node.Raw is the source entry
// (or {"uri": originalLink} for links); Node.Canonical is the normalized
// sing-box body map, still without a tag. Node.SingBox() / parser.Emit(node)
// returns a deep-copied sing-box outbound/endpoint entry with type and tag.
// Put ordinary protocols in config.outbounds and WireGuard in config.endpoints.
// Result.NodesByKey indexes emitted sing-box entry maps by stable node key. It
// is ready for a config builder: values contain type/tag and no top-level
// outbounds/endpoints wrapper. Result.RawByKey indexes original Raw maps for
// round-trip/source retention. JSON numeric values are decoded as json.Number
// so unknown large integers remain exact through raw-map caching and emission.
//
// Examples after Emit:
//
//	Shadowsocks link -> {"type":"shadowsocks","tag":"office","server":"ss.example", ...}
//	VLESS link       -> {"type":"vless","tag":"edge","server":"example", ...}
//	WireGuard link   -> {"type":"wireguard","tag":"wg","server":"wg.example", ...}
//
// Unknown contract schemes/protocols, malformed nodes and undecodable inputs
// are returned as diagnostics; an empty node list is not treated as success.
package parser
