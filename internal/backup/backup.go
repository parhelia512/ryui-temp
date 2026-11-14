package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

const (
	Format0x = 1
	Format10 = 2
	AppName = "lxbox"
	KindBackup = "backup"
	WarnUnknownField = "backup_unknown_field"
	WarnTypeMismatch = "backup_field_type_mismatch"
	WarnDirectionExists = "backup_direction_exists"
	WarnChainExists = "backup_chain_exists"
	WarnRulesReplaced = "backup_rules_replaced"
	WarnLocalOnlyDropped = "backup_local_only_dropped"
	WarnUnknownPreset = "backup_unknown_preset"
	WarnVarSkipped = "backup_var_skipped"
	WarnUnknownOutbound = "backup_unknown_outbound"
	WarnFinalDropped = "backup_final_dropped"
	WarnDNSEntrySkipped = "backup_dns_entry_skipped"
	WarnWarpSkipped = "backup_warp_skipped"
	WarnSourceKindUnsupported = "backup_source_kind_unsupported"
)

var ErrUnsupportedVersion = errors.New("portable backup version is newer than supported version 2")
var Categories = []string{"sources", "directions", "rules", "dns", "vars", "route", "warp", "mixins", "native_prefs", "tun_apps", "other"}

var portableVars = set("auto_detect_interface", "dns_cache_capacity", "dns_default_domain_resolver", "dns_final", "dns_optimistic", "dns_resolver_no_stale", "dns_store_cache", "dns_strategy", "ipv6_enabled", "log_level", "resolve_strategy", "tls_fragment", "tls_fragment_fallback_delay", "tls_mixed_case_sni", "tls_record_fragment", "tun_address", "tun_address6", "tun_mtu", "tun_stack", "urltest_interval", "urltest_tolerance", "urltest_url")
var nativeBoolPrefs = set("auto_start", "keep_on_exit", "core_logs_enabled", "core_logs_verbose", "allow_bypass", "auto_redirect", "notification_stop", "notification_restart", "notification_send")
var nativePrefs = set("auto_start", "keep_on_exit", "background_mode", "core_logs_enabled", "core_logs_verbose", "allow_bypass", "auto_redirect", "memory_limit", "notification_stop", "notification_restart", "notification_send", "app_theme_mode")

type Warning struct {
	Code string `json:"code"`
	Detail string `json:"detail"`
	Kind string `json:"kind,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Document retains the exact source bytes and context through preview/apply.
type Document struct {
	Version int `json:"version"`
	Portable bool `json:"portable"`
	Snapshot bool `json:"snapshot"`
	Data map[string]any `json:"data"`
	Raw json.RawMessage `json:"-"`
	Context context.Context `json:"-"`
	Declared map[string]bool `json:"-"`
	Warnings []Warning `json:"warnings,omitempty"`
}

func Decode(ctx context.Context, raw []byte) (*Document, error) {
	if ctx == nil { ctx = context.Background() }
	if err := ctx.Err(); err != nil { return nil, err }
	dec := json.NewDecoder(bytes.NewReader(raw)); dec.UseNumber()
	var root map[string]any
	if err := dec.Decode(&root); err != nil { return nil, fmt.Errorf("backup: decode JSON: %w", err) }
	if root == nil { return nil, errors.New("backup: root must be an object") }
	if err := dec.Decode(new(any)); err != io.EOF { return nil, errors.New("backup: trailing data after JSON object") }
	doc := &Document{Raw: append(json.RawMessage(nil), raw...), Context: ctx, Declared: map[string]bool{}}
	if root["app"] == AppName && root["kind"] == KindBackup {
		if _, ambiguous := root["lx_backup"]; ambiguous { return nil, errors.New("backup: ambiguous snapshot and portable markers") }
		storage, ok := root["storage"].(map[string]any)
		if !ok { return nil, errors.New("backup: snapshot storage must be an object") }
		doc.Snapshot, doc.Data, doc.Declared = true, cloneMap(storage), nil
		return doc, nil
	}
	version, ok := integer(root["lx_backup"])
	if !ok || version < Format0x { return nil, errors.New("backup: unrecognized LX portable backup") }
	if version > Format10 { return nil, ErrUnsupportedVersion }
	doc.Version, doc.Portable = version, true
	for key := range root {
		doc.Declared[key] = true
	}
	if version == Format0x {
		root = normalize0x(root, &doc.Warnings)
	}
	root = sanitizePortable(root, &doc.Warnings)
	doc.Data = portableToStorage(root, &doc.Warnings)
	return doc, nil
}

func ExportPortable(snapshot map[string]any, appVersion string) ([]byte, []Warning, error) {
	warnings := []Warning{}
	root := map[string]any{"lx_backup": Format10, "exported_by": map[string]any{"app": AppName, "version": appVersion, "platform": "android"}, "exported_at": time.Now().UTC().Format(time.RFC3339Nano), "rules": []any{}}
	for _, key := range []string{"sources", "directions", "rules", "dns", "warp", "mixins", "native_prefs"} {
		if value, ok := snapshot[key]; ok && value != nil { root[key] = clone(value) }
	}
	if vars, ok := snapshot["vars"].(map[string]any); ok {
		out := map[string]any{}
		for key, value := range vars {
			if portableVars[key] { out[key] = value } else if key != "auto_rebuild" { warnings = append(warnings, Warning{Code: WarnVarSkipped, Detail: key, Reason: "not_portable"}) }
		}
		if len(out) > 0 { root["vars"] = out }
	}
	if final, ok := snapshot["route_final"].(string); ok && final != "" { root["route"] = map[string]any{"final": final} }
	for _, key := range []string{"node_sort_mode", "node_manual_order", "ping_options", "enabled_groups", "node_budget", "vpn_mode", "storage_version", "current_workspace"} {
		if value, exists := snapshot[key]; exists && !empty(value) { warnings = append(warnings, Warning{Code: WarnLocalOnlyDropped, Detail: key}) }
	}
	root = filterPortable(root, &warnings)
	encoded, err := json.MarshalIndent(root, "", "  ")
	return encoded, warnings, err
}

type MergeResult struct {
	Data map[string]any `json:"data"`
	Added map[string]int `json:"added"`
	Kept map[string]int `json:"kept"`
	Warnings []Warning `json:"warnings,omitempty"`
}

// Merge performs category-level mutation. A missing category does not clear it;
// rules are the only portable category whose declared payload replaces on merge.
func Merge(current, incoming map[string]any, categories []string, replace bool, declared map[string]bool) (MergeResult, error) {
	selected, err := normalizeCategories(categories); if err != nil { return MergeResult{}, err }
	out := cloneMap(current); if out == nil { out = map[string]any{} }
	r := MergeResult{Data: out, Added: map[string]int{}, Kept: map[string]int{}}
	for _, category := range selected {
		if category == "other" {
			if replace {
				clearOther(out)
			}
			mergeOther(out, incoming, replace, &r)
			continue
		}
		key := storageKey(category)
		value, exists := incoming[key]
		if !exists {
			if replace && declared == nil {
				out[key] = emptyCategory(category)
			}
			continue
		}
		if category == "route" {
			if final, ok := value.(string); ok { if replace || out[key] == nil { out[key] = final; r.Added[key]++ } else { r.Kept[key]++ } }
			continue
		}
		if category == "vars" || category == "native_prefs" { mergeMap(out, key, value, replace, &r); continue }
		if category == "dns" || category == "tun_apps" { mergeObject(out, key, value, replace, &r); continue }
		list, ok := value.([]any)
		if !ok { r.Warnings = append(r.Warnings, Warning{Code: WarnTypeMismatch, Detail: key}); continue }
		if category == "rules" && declared != nil && declared["rules"] && !replace {
			old, _ := out[key].([]any)
			if len(old) > 0 { r.Warnings = append(r.Warnings, Warning{Code: WarnRulesReplaced, Detail: fmt.Sprintf("rules: %d", len(old))}) }
			out[key] = clone(list); r.Added[key] = len(list); continue
		}
		if replace { out[key] = clone(list); r.Added[key] += len(list); continue }
		have, _ := out[key].([]any)
		merged, added, kept := mergeRecords(category, have, list)
		out[key], r.Added[key], r.Kept[key] = merged, r.Added[key]+added, r.Kept[key]+kept
	}
	return r, nil
}

func normalizeCategories(categories []string) ([]string, error) {
	if len(categories) == 0 { return append([]string(nil), Categories...), nil }
	allowed, seen := set(Categories...), map[string]bool{}
	out := make([]string, 0, len(categories))
	for _, category := range categories {
		category = strings.TrimSpace(category)
		if !allowed[category] { return nil, fmt.Errorf("backup: unknown category %q", category) }
		if !seen[category] { seen[category] = true; out = append(out, category) }
	}
	return out, nil
}

func normalize0x(root map[string]any, warnings *[]Warning) map[string]any {
	out := cloneMap(root)
	sources := []any{}
	for _, key := range []string{"subscriptions", "servers"} {
		items, _ := out[key].([]any)
		for i, item := range items {
			record, ok := item.(map[string]any)
			if !ok { *warnings = append(*warnings, Warning{Code: WarnTypeMismatch, Detail: fmt.Sprintf("%s[%d]", key, i)}); continue }
			copy := cloneMap(record)
			if key == "subscriptions" {
				copy["kind"] = "subscription"
				if copy["id"] == nil { copy["id"] = stableID("subscription", text(copy["url"])) }
				if interval, exists := copy["update_interval_hours"]; exists { copy["update"] = map[string]any{"interval_hours": interval}; delete(copy, "update_interval_hours") }
			}
			if key == "servers" {
				copy["kind"] = "server"
				if copy["id"] == nil { copy["id"] = stableID("server", canonical(copy)) }
				if uri, ok := copy["uri"].(string); ok { copy["origin"] = map[string]any{"kind":"uri", "raw":uri}; delete(copy,"uri") }
				if body, ok := copy["config_json"].(map[string]any); ok { copy["origin"] = map[string]any{"kind":"json", "raw":string(mustJSON(body))}; delete(copy,"config_json") }
				if folder, ok := copy["folder"].(string); ok && folder != "" { copy["folder_ref"] = folder }
			}
			sources = append(sources, copy)
		}
		delete(out, key)
	}
	if chains, ok := out["chains"].([]any); ok {
		for i, item := range chains {
			if record, ok := item.(map[string]any); ok {
				chain := cloneMap(record); chain["kind"] = "chain"
				if chain["body"] == nil { chain["body"] = map[string]any{"type":"chain"} }
				if hops, ok := chain["hops"].([]any); ok { converted := make([]any,0,len(hops)); for _, hop := range hops { if tag,ok:=hop.(string);ok { converted=append(converted,map[string]any{"tag":tag}) } else { converted=append(converted,hop) } }; chain["hops"] = converted }
				sources = append(sources,chain)
			} else { *warnings = append(*warnings,Warning{Code:WarnTypeMismatch,Detail:fmt.Sprintf("chains[%d]",i)}) }
		}
		delete(out,"chains")
	}
	if len(sources)>0 { out["sources"] = sources }
	if _,ok:=out["directions"];!ok { if value,exists:=out["channels"];exists {out["directions"]=value} };delete(out,"channels");delete(out,"channels_migrated")
	if rules,ok:=out["rules"].([]any);ok {
		for i,item:=range rules { if rule,ok:=item.(map[string]any);ok { if rule["kind"]==nil {rule["kind"]="inline"};if match,ok:=rule["match"].(map[string]any);ok {rule["body"]=normalizeRuleBody(match);delete(rule,"match")};if rule["id"]==nil {rule["id"]=stableID("rule",canonical(rule))};rules[i]=rule } };out["rules"]=rules
	}
	if final,ok:=out["route_final"].(string);ok&&out["route"]==nil {out["route"]=map[string]any{"final":final};delete(out,"route_final")}
	return out
}

func portableToStorage(root map[string]any, warnings *[]Warning) map[string]any {
	out:=map[string]any{}
	if sources,ok:=root["sources"].([]any);ok {
		converted:=[]any{}
		for i,item:=range sources {
			record,ok:=item.(map[string]any);if !ok {*warnings=append(*warnings,Warning{Code:WarnTypeMismatch,Detail:fmt.Sprintf("sources[%d]",i)});continue}
			kind:=text(record["kind"]);if kind!="subscription"&&kind!="server"&&kind!="folder"&&kind!="chain" {*warnings=append(*warnings,Warning{Code:WarnSourceKindUnsupported,Detail:sourceLabel(record),Kind:kind});continue}
			copy:=cloneMap(record);if kind!="chain"&&copy["id"]==nil {copy["id"]=stableID("source",sourceIdentity(copy))}
			if kind == "server" && text(objectValue(copy["origin"])["raw"]) == "" {
				if body, ok := copy["body"].(map[string]any); ok {
					originRaw := string(mustJSON(withTag(body, text(copy["tag"]))))
					copy["origin"] = map[string]any{"kind": "json", "raw": originRaw}
					delete(copy, "body")
				}
			}

			converted=append(converted,copy)
		}
		out["sources"]=converted
	}
	for _,key:=range []string{"directions","rules","warp","mixins"} {if value,ok:=root[key];ok {out[key]=clone(value)}}
	if dns,ok:=root["dns"].(map[string]any);ok {out["dns"]=cloneMap(dns)}
	if vars,ok:=root["vars"].(map[string]any);ok {filtered:=map[string]any{};for key,value:=range vars {if portableVars[key] {filtered[key]=value}else {*warnings=append(*warnings,Warning{Code:WarnVarSkipped,Detail:key,Reason:"not_portable"})}};if len(filtered)>0 {out["vars"]=filtered}}
	if route,ok:=root["route"].(map[string]any);ok {if final,ok:=route["final"].(string);ok&&final!="" {out["route_final"]=final}}
	if prefs,ok:=root["native_prefs"].(map[string]any);ok {filtered:=map[string]any{};for key,value:=range prefs {if !nativePrefs[key] {*warnings=append(*warnings,Warning{Code:WarnUnknownField,Detail:"native_prefs."+key});continue};if nativeBoolPrefs[key] {if _,ok:=value.(bool);!ok {*warnings=append(*warnings,Warning{Code:WarnTypeMismatch,Detail:"native_prefs."+key});continue}} else if _,ok:=value.(string);!ok {*warnings=append(*warnings,Warning{Code:WarnTypeMismatch,Detail:"native_prefs."+key});continue};filtered[key]=value};if len(filtered)>0 {out["native_prefs"]=filtered}}
	return out
}

func filterPortable(root map[string]any, warnings *[]Warning) map[string]any {
	allowed:=set("lx_backup","exported_by","exported_at","sources","directions","rules","dns","vars","route","warp","mixins","native_prefs")
	out:=map[string]any{}
	for key,value:=range root {if !allowed[key] {*warnings=append(*warnings,Warning{Code:WarnUnknownField,Detail:key});continue};out[key]=value}
	if sources,ok:=out["sources"].([]any);ok {filtered:=[]any{};for i,value:=range sources {if record,ok:=value.(map[string]any);ok {filtered=append(filtered,filterObject(record,sourceKeys(text(record["kind"])),fmt.Sprintf("sources[%d]",i),warnings))}};out["sources"]=filtered}
	for _,section:=range []string{"directions","rules","warp","mixins"} {if records,ok:=out[section].([]any);ok {for i,value:=range records {if record,ok:=value.(map[string]any);ok {records[i]=filterObject(record,recordKeys(section),fmt.Sprintf("%s[%d]",section,i),warnings)}}}}
	return out
}

func scanUnknown(root map[string]any, version int) []Warning {
	warnings:=[]Warning{}
	allowed:=set("lx_backup","exported_by","exported_at","sources","subscriptions","servers","directions","chains","rules","dns","vars","route","route_final","warp","mixins","native_prefs","extensions","channels","channels_migrated")
	for key:=range root {if !allowed[key] {warnings=append(warnings,Warning{Code:WarnUnknownField,Detail:key})}}
	for _,section:=range []string{"sources","subscriptions","servers","directions","chains","rules","warp","mixins"} {if records,ok:=root[section].([]any);ok {for i,value:=range records {if record,ok:=value.(map[string]any);ok {keys:=recordKeys(section);if section=="sources" {keys=sourceKeys(text(record["kind"]))};for key:=range record {if !keys[key] {warnings=append(warnings,Warning{Code:WarnUnknownField,Detail:fmt.Sprintf("%s[%d].%s",section,i,key)})}}}}}}
	if version==Format0x {if _,ok:=root["extensions"];ok {warnings=append(warnings,Warning{Code:"backup_extensions_dropped",Detail:"portable backup"})}}
	return warnings
}

func mergeRecords(category string, have,incoming []any) ([]any,int,int) {
	out:=append([]any(nil),have...);keys,prints:=map[string]bool{},map[string]bool{};maxNum:=999
	for _,value:=range have {if record,ok:=value.(map[string]any);ok {if key:=identity(category,record);key!="" {keys[key]=true};prints[fingerprint(category,record)]=true;if category=="rules" {if num,ok:=integer(record["num"]);ok&&num>=1000&&num<=1100&&num>maxNum {maxNum=num}}}}
	added,kept:=0,0
	for _,value:=range incoming {record,ok:=value.(map[string]any);if !ok {continue};key,fp:=identity(category,record),fingerprint(category,record);if (key!=""&&keys[key])||prints[fp] {kept++;continue};copy:=cloneMap(record);if category=="rules" {maxNum++;if maxNum>1100 {maxNum=1100};copy["num"]=maxNum};out=append(out,copy);if key!="" {keys[key]=true};prints[fp]=true;added++}
	return out,added,kept
}
func mergeObject(out map[string]any,key string,value any,replace bool,r *MergeResult) {incoming,ok:=value.(map[string]any);if !ok {r.Warnings=append(r.Warnings,Warning{Code:WarnTypeMismatch,Detail:key});return};if replace||out[key]==nil {out[key]=cloneMap(incoming);r.Added[key]=len(incoming);return};have,ok:=out[key].(map[string]any);if !ok {r.Kept[key]++;return};merged:=cloneMap(have);for field,v:=range incoming {if merged[field]==nil {merged[field]=clone(v);r.Added[key+"."+field]++;continue};if (key=="dns"&&(field=="servers"||field=="rules"))||(key=="tun_apps"&&field=="packages") {h,_:=merged[field].([]any);list,_:=v.([]any);merged[field],r.Added[key+"."+field],r.Kept[key+"."+field]=mergeRecords("dns_"+field,h,list)} else {r.Kept[key+"."+field]++}};out[key]=merged}
func mergeMap(out map[string]any,key string,value any,replace bool,r *MergeResult) {incoming,ok:=value.(map[string]any);if !ok {r.Warnings=append(r.Warnings,Warning{Code:WarnTypeMismatch,Detail:key});return};if replace||out[key]==nil {out[key]=cloneMap(incoming);r.Added[key]=len(incoming);return};have,ok:=out[key].(map[string]any);if !ok {have=map[string]any{}};merged:=cloneMap(have);for field,v:=range incoming {if _,exists:=merged[field];!exists {merged[field]=clone(v);r.Added[key+"."+field]++}else {r.Kept[key+"."+field]++}};out[key]=merged}
func mergeOther(out,incoming map[string]any,replace bool,r *MergeResult) {known:=map[string]bool{};for _,category:=range Categories {known[storageKey(category)]=true};for key,value:=range incoming {if known[key]||key=="storage_version" {continue};if replace||out[key]==nil {out[key]=clone(value);r.Added[key]++}else {r.Kept[key]++}}}

func identity(category string,m map[string]any) string {switch category {case "directions":return pref("tag",m["tag"]);case "sources":if m["kind"]=="chain" {return pref("chain",m["tag"])};return pref("id",m["id"]);case "rules":if m["kind"]=="preset" {return pref("preset",m["ref"])};return pref("id",m["id"]);case "dns_servers":return firstPref("tag",m["tag"],"ref",m["ref"]);case "dns_rules":if m["kind"]=="preset" {return pref("preset",m["ref"])};if m["kind"]=="template" {return pref("template",m["name"])};return pref("id",m["id"]);case "mixins":return "body:"+canonical(map[string]any{"target":m["target"],"op":m["op"],"value":m["value"]})};return pref("id",m["id"])}
func fingerprint(category string,m map[string]any) string {copy:=cloneMap(m);delete(copy,"enabled");if category=="rules" {delete(copy,"id");delete(copy,"num")};if category=="sources" {delete(copy,"id")};return canonical(copy)}

func sourceKeys(kind string) map[string]bool {base:=set("kind","id","name","enabled","tag_policy","detour","replace","detour_policy","tls","warnings","label","sections");switch kind {case "subscription":return add(base,"url","identity","update","disabled","skip","max_nodes","tag","outbounds","import_rules","import_rules_enabled","on_update_action");case "server":return add(base,"tag","origin","body","skip_presets","skip_tailscale_presets","allow_local","allow_lan","allow_gateway","own_routes","disable_taildrop_commands","disable_taildrop_autosave","state_dir_id");case "folder":return add(base,"nodes","ping_url","ping_timeout_ms");case "chain":return add(base,"tag","body","hops")};return base}
func recordKeys(section string) map[string]bool {switch section {case "directions":return set("tag","label","enabled","filter","invert","default","include_direct","include_block","include","interrupt_exist_connections","ping_url","ping_timeout_ms","auto");case "rules":return set("kind","id","name","enabled","num","refs","ref","vars","verbatim","body","dns","resolve","match","outbound");case "warp":return set("type","private_key","peer_public","client_v4","client_v6","client_id","device_id","token","account_id","license","warp_plus","created_at","private_key_der","server_pub_der","server","port","sni","idle_timeout","keep_alive","awg","endpoint");case "mixins":return set("name","enabled","target","op","value")};return map[string]bool{}}
func filterObject(input map[string]any,allowed map[string]bool,path string,warnings *[]Warning) map[string]any {out:=map[string]any{};for key,value:=range input {if !allowed[key] {*warnings=append(*warnings,Warning{Code:WarnUnknownField,Detail:path+"."+key});continue};out[key]=value};return out}
func storageKey(category string) string {if category=="route" {return "route_final"};return category}
func set(keys ...string) map[string]bool {out:=map[string]bool{};for _,key:=range keys {out[key]=true};return out}
func add(m map[string]bool,keys ...string) map[string]bool {out:=map[string]bool{};for key,value:=range m {out[key]=value};for _,key:=range keys {out[key]=true};return out}
func cloneMap(m map[string]any) map[string]any {if m==nil {return nil};return clone(m).(map[string]any)}
func clone(value any) any {data,err:=json.Marshal(value);if err!=nil {return value};dec:=json.NewDecoder(bytes.NewReader(data));dec.UseNumber();var out any;if dec.Decode(&out)!=nil {return value};return out}
func mustJSON(value any) []byte {data,_:=json.Marshal(value);return data}
func canonical(value any) string {return string(mustJSON(canonicalValue(value)))}
func canonicalValue(value any) any {switch v:=value.(type) {case map[string]any:keys:=make([]string,0,len(v));for key:=range v {keys=append(keys,key)};sort.Strings(keys);out:=map[string]any{};for _,key:=range keys {out[key]=canonicalValue(v[key])};return out;case []any:out:=make([]any,len(v));for i,item:=range v {out[i]=canonicalValue(item)};return out};return value}
func stableID(kind,seed string) string {sum:=sha256.Sum256([]byte(kind+":"+seed));hexed:=hex.EncodeToString(sum[:16]);return hexed[:8]+"-"+hexed[8:12]+"-4"+hexed[13:16]+"-a"+hexed[17:20]+"-"+hexed[20:]}
func sourceIdentity(m map[string]any) string {if m["url"]!=nil {return text(m["url"])};return canonical(m)}
func sourceLabel(m map[string]any) string {for _,key:=range []string{"url","name","tag"} {if value:=text(m[key]);value!="" {return value}};return "sources[]"}
func pref(prefix string,value any) string {s,ok:=value.(string);if !ok||s=="" {return ""};return prefix+":"+s}
func firstPref(a string,av any,b string,bv any) string {if key:=pref(a,av);key!="" {return key};return pref(b,bv)}
func text(value any) string {s,_:=value.(string);return s}
func integer(value any) (int,bool) {switch n:=value.(type) {case json.Number:i,err:=n.Int64();return int(i),err==nil;case int:return n,true;case int64:return int(n),true;case float64:return int(n),n==float64(int(n))};return 0,false}
func empty(value any) bool {switch v:=value.(type) {case nil:return true;case string:return v=="";case []any:return len(v)==0;case map[string]any:return len(v)==0};return false}
func objectValue(value any) map[string]any {m,_:=value.(map[string]any);if m==nil {return map[string]any{}};return m}
func withTag(m map[string]any,tag string) map[string]any {out:=cloneMap(m);if tag!="" {out["tag"]=tag};return out}
func normalizeRuleBody(input map[string]any) map[string]any {aliases:=map[string]string{"domains":"domain","domainSuffixes":"domain_suffix","domainKeywords":"domain_keyword","ipCidrs":"ip_cidr","portRanges":"port_range","packages":"package_name","protocols":"protocol","network":"network","ipIsPrivate":"ip_is_private","sourceIpCidrs":"source_ip_cidr","sourceIpIsPrivate":"source_ip_is_private","inbounds":"inbound","outbound":"outbound","target":"outbound"};out:=map[string]any{};for old,key:=range aliases {if value,ok:=input[old];ok {out[key]=value}};for _,key:=range []string{"domain","domain_suffix","domain_keyword","ip_cidr","port","port_range","package_name","protocol","network","inbound","outbound"} {if value,ok:=input[key];ok {out[key]=value}};return out}
