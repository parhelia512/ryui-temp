package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Leadaxe/lxbox/app/internal/automation"
	"github.com/Leadaxe/lxbox/app/internal/ruleset"
)

// debugHTTP adapts the loopback Debug transport's explicit HTTP method/path
// envelopes to runtime-owned data and operations. Unimplemented controller
// surfaces fail as 404; they are never passed to automation or treated as OK.
func (a *Application) debugHTTP(ctx context.Context, method string, args json.RawMessage) (any, error) {
	if ctx == nil { ctx = context.Background() }
	var raw map[string]any
	if err := decode(args, &raw); err != nil { return nil, err }
	if raw == nil { raw = map[string]any{} }
	httpMethod, path, ok := parseDebugMethod(method)
	if !ok { return nil, debugNotFound("debug method: " + method) }
	q := func(key string) string { return debugString(raw[key]) }

	switch {
	case path == "/state" && httpMethod == "GET":
		return a.debugState(ctx)
	case path == "/state/storage" && httpMethod == "GET":
		doc, err := a.store.Snapshot(); if err != nil { return nil, err }
		return scrubDebugStorage(doc), nil
	case path == "/state/config_locked" && httpMethod == "GET":
		doc, err := a.store.Snapshot(); if err != nil { return nil, err }
		vars := objectValue(doc["vars"])
		return map[string]any{"locked": debugBool(vars["config_locked_for_debug"])}, nil
	case path == "/state/subs" && httpMethod == "GET", path == "/subs" && httpMethod == "GET":
		return a.debugSources(debugBool(raw["reveal"]))
	case path == "/state/rules" && httpMethod == "GET", path == "/rules" && httpMethod == "GET":
		doc, err := a.store.Snapshot(); if err != nil { return nil, err }
		if value, ok := doc["rules"]; ok { return value, nil }; return []any{}, nil
	case path == "/state/vpn" && httpMethod == "GET":
		doc, err := a.store.Snapshot(); if err != nil { return nil, err }
		native := objectValue(doc["native_prefs"])
		for _, key := range []string{"auto_start","keep_on_exit","allow_bypass","background_mode","core_logs_enabled","core_logs_verbose"} {
			if value, ok := a.nativePrefValue(ctx,key); ok { native[key] = value }
		}
		return map[string]any{
			"auto_start": native["auto_start"], "keep_on_exit": native["keep_on_exit"],
			"allow_bypass": native["allow_bypass"], "background_mode": native["background_mode"],
			"core_state": a.core.Status(), "current_session_allow_bypass": nil,
			"is_ignoring_battery_optimizations": nil,
		}, nil
	case path == "/config" && httpMethod == "GET":
		return a.readConfig()
	case path == "/config/pretty" && httpMethod == "GET":
		body, err := a.readConfig(); if err != nil { return nil, err }
		var value any; if err = json.Unmarshal(body, &value); err != nil { return nil, err }; return value, nil
	case path == "/config/path" && httpMethod == "GET":
		return map[string]any{"path": a.configPath()}, nil
	case path == "/config/running" && httpMethod == "GET":
		value, err := a.core.Call(ctx, "ccGetRunningConfig", json.RawMessage(`{}`)); if err != nil { return nil, err }; if value == nil || stringValue(value) == "null" { return nil, debugConflict("running config unavailable") }; return value, nil
	case path == "/config" && httpMethod == "PUT":
		configRaw, err := debugRawConfig(raw); if err != nil { return nil, err }
		if _, err = a.saveConfig(ctx, configRaw, true); err != nil { return nil, err }
		status := a.core.Status(); if debugBool(objectValueFrom(status)["running"]) {
			if _, err = a.platformCall(ctx, "vpn.reload", map[string]any{"config": json.RawMessage(configRaw)}); err != nil { return nil, err }
		}
		return map[string]any{"ok": true, "action": "config-put", "bytes": len(configRaw), "tunnel_up_when_saved": debugBool(objectValueFrom(status)["running"])}, nil
	case path == "/device" && httpMethod == "GET":
		memory, memoryErr := a.reportsDispatch(ctx, "memory.get", json.RawMessage(`{}`))
		if memoryErr != nil { return nil, memoryErr }
		device, deviceErr := a.platformCall(ctx, "device.info", map[string]any{})
		if deviceErr != nil { return nil, deviceErr }
		return map[string]any{"device":device,"memory":memory,"uptime_seconds":int64(time.Since(runtimeStartedAt).Seconds())},nil
	case path == "/pool" && httpMethod == "GET":
		tag := q("tag"); if tag == "" { return nil, debugBadRequest("missing query param: tag") }
		return a.core.Call(ctx, "ccGetPool", mustJSON(map[string]any{"tag": tag}))
	case path == "/logs" || path == "/logs/app" || path == "/logs/core":
		if httpMethod != "GET" { return nil, debugBadRequest("logs require GET") }
		if path == "/logs/app" { return nil, debugNotFound("app log reader is not available in Go runtime") }
		if path == "/logs/core" { raw["source"] = "core" }
		raw["client_id"] = "debug-http"
		_, _ = a.core.Call(ctx, "ccGetStatus", mustJSON(map[string]any{"client_id":"debug-http"}))
		return a.core.Call(ctx, "ccGetLogs", mustJSON(raw))
	case path == "/logs/clear" && httpMethod == "POST":
		return nil, debugNotFound("core log clear is not implemented")
	case path == "/backup/export" && httpMethod == "GET":
		request := map[string]any{"format":q("format"),"app_version":q("app_version")}
		return a.backupDispatch(ctx,"backup.export",mustJSON(request))
	case path == "/backup/import" && httpMethod == "POST":
		var body struct { Data string `json:"data"`; Replace *bool `json:"replace"`; Merge bool `json:"merge"`; Categories []string `json:"categories"`; Format string `json:"format"`; AppVersion string `json:"app_version"`; Storage map[string]any `json:"storage"`; VPNSettings map[string]any `json:"vpn_settings"` }
		if err:=decode(args,&body);err!=nil{return nil,err}
		if body.Data=="" && body.Storage!=nil {
			storageDoc:=body.Storage
			if body.VPNSettings!=nil { storageDoc["native_prefs"]=body.VPNSettings }
			wrapped,marshalErr:=json.Marshal(map[string]any{"app":"lxbox","kind":"backup","created_at":time.Now().UTC().Format(time.RFC3339Nano),"storage":storageDoc});if marshalErr!=nil{return nil,marshalErr};body.Data=string(wrapped)
		}
		if body.Data=="" { return nil,debugBadRequest("backup data required") }
		replace := true
		if body.Replace != nil { replace = *body.Replace }
		if body.Merge { replace = false }
		request:=map[string]any{"data":body.Data,"replace":replace,"categories":body.Categories,"format":body.Format,"app_version":body.AppVersion}
		return a.backupDispatch(ctx,"backup.import",mustJSON(request))
	case path == "/settings/config_locked" && httpMethod == "PUT":
		locked, exists := raw["locked"]; if !exists { return nil, debugBadRequest(`field "locked" required`) }
		value, ok := locked.(bool); if !ok { return nil, debugBadRequest(`field "locked" must be boolean`) }
		err := a.updateVar(ctx, "config_locked_for_debug", strconv.FormatBool(value)); if err != nil { return nil, err }
		return map[string]any{"ok":true,"action":"settings-config-locked","locked":value}, nil
	case strings.HasPrefix(path, "/settings/vars/") && (httpMethod == "PUT" || httpMethod == "DELETE"):
		key, err := decodePathComponent(strings.TrimPrefix(path,"/settings/vars/")); if err != nil { return nil, err }
		if key == "debug_token" || key == "debug_enabled" || key == "debug_port" { return nil, debugConflict("debug vars are managed by the host") }
		if httpMethod == "DELETE" { return nil, debugNotFound("generic var deletion is not supported by this runtime") }
		value, ok := raw["value"].(string); if !ok { return nil, debugBadRequest(`field "value" required (string)`) }
		if err = a.updateVar(ctx,key,value); err != nil { return nil, err }
		return map[string]any{"ok":true,"action":"settings-var-put","key":key,"value":value},nil
	case path == "/settings/route_final" && httpMethod == "PUT":
		outbound, ok := raw["outbound"].(string); if !ok { return nil, debugBadRequest(`field "outbound" required`) }
		if err := a.updateTopLevel(ctx,"route_final",outbound); err != nil { return nil,err }; return map[string]any{"ok":true,"action":"settings-route-final","outbound":outbound},nil
	case strings.HasPrefix(path,"/settings/") && (httpMethod=="GET"||httpMethod=="PUT"):
		key:=strings.TrimPrefix(path,"/settings/"); if strings.Contains(key,"/") { return nil, debugNotFound("settings path: "+path) }
		if _, exists := map[string]bool{"route_final":true,"enabled_groups":true,"ping_options":true,"vpn_mode":true,"tun_apps":true,"node_sort":true,"config_locked_for_debug":true}[key]; !exists { return nil, debugNotFound("settings path: /settings/"+key) }
		if httpMethod=="GET" { return a.getSetting(ctx,key) }
		return a.putSetting(ctx,key,raw)
	case path == "/files/srs/list" && httpMethod == "GET":
		return a.listCachedSRS()
	case path == "/files/srs" && httpMethod == "GET":
		id:=q("ruleId"); if id=="" { return nil, debugBadRequest("missing query param: ruleId") }
		client,err:=ruleset.New(a.dataDir); if err!=nil{return nil,err}; body,_,err:=client.ReadOffline(ctx,id); return body,err
	default:
		return nil, debugNotFound("route: "+httpMethod+" "+path)
	}
}

var runtimeStartedAt = time.Now()

func parseDebugMethod(method string) (string,string,bool) {
	if !strings.HasPrefix(method,"http.") { return "","",false }
	parts:=strings.SplitN(strings.TrimPrefix(method,"http.")," ",2); if len(parts)!=2 { return "","",false }
	verb:=strings.ToUpper(strings.TrimSpace(parts[0])); path:=parts[1]
	if !strings.HasPrefix(path,"/") || strings.ContainsAny(path,"?#") { return "","",false }
	switch verb {case "GET","POST","PUT","PATCH","DELETE": default:return "","",false}
	return verb,path,true
}

func debugString(v any) string { s,_:=v.(string); return s }
func (a *Application) nativePrefValue(ctx context.Context,key string)(any,bool){value,err:=a.platformCall(ctx,"nativeprefs.get",map[string]any{"key":key});if err!=nil{return nil,false};object:=objectValueFrom(value);item,ok:=object["value"];if !ok||item==nil{return nil,false};return item,true}
func debugBool(v any) bool { switch x:=v.(type) {case bool:return x;case string:return strings.EqualFold(x,"true")||x=="1"||strings.EqualFold(x,"yes");case json.Number:return x.String()=="1";case float64:return x==1}; return false }
func objectValue(v any) map[string]any { m,_:=v.(map[string]any);if m==nil{return map[string]any{}};return m }
func stringValue(v any) string { if s,ok:=v.(string);ok{return s}; if b,ok:=v.(json.RawMessage);ok{return string(b)};return "" }
func objectValueFrom(value any) map[string]any { if m,ok:=value.(map[string]any);ok{return m};raw,err:=json.Marshal(value);if err!=nil{return map[string]any{}};var out map[string]any;_ = json.Unmarshal(raw,&out);return out }
func debugRawConfig(raw map[string]any)(json.RawMessage,error){
	if value,ok:=raw["config"];ok{
		switch v:=value.(type){case json.RawMessage:if !json.Valid(v){return nil,debugBadRequest("invalid JSON config")};return v,nil;case map[string]any:encoded,err:=json.Marshal(v);return encoded,err;case string:if !json.Valid([]byte(v)){return nil,debugBadRequest("invalid JSON config")};return json.RawMessage(v),nil}
	}
	copy:=make(map[string]any,len(raw));for k,v:=range raw{copy[k]=v};delete(copy,"rebuild");delete(copy,"timeout_ms")
	encoded,err:=json.Marshal(copy);if err!=nil{return nil,err};var object map[string]any;if err=json.Unmarshal(encoded,&object);err!=nil||object==nil{return nil,debugBadRequest("config body must be JSON object")};return encoded,nil
}
func debugNotFound(message string) error { return &automation.Error{Code:"not_found", Message:message} }
func debugBadRequest(message string) error { return &automation.Error{Code:"bad_request", Message:message} }
func debugConflict(message string) error { return &automation.Error{Code:"conflict", Message:message} }
func decodePathComponent(raw string)(string,error){value,err:=url.PathUnescape(raw);if err!=nil||value==""||strings.Contains(value,"/"){return "",debugBadRequest("invalid path component")};return value,nil}

func(a *Application)updateVar(ctx context.Context,key,value string)error{
	a.mutation.Lock();defer a.mutation.Unlock();if err:=ctx.Err();err!=nil{return err}
	err:=a.store.Update(func(doc map[string]any)error{vars:=objectValue(doc["vars"]);vars[key]=value;doc["vars"]=vars;return nil});if err==nil{a.revision++;a.refreshAutomation();a.events.emit("settings.changed",map[string]any{"key":key,"revision":a.revision})};return err
}
func(a *Application)updateTopLevel(ctx context.Context,key string,value any)error{a.mutation.Lock();defer a.mutation.Unlock();if err:=ctx.Err();err!=nil{return err};err:=a.store.Update(func(doc map[string]any)error{doc[key]=value;return nil});if err==nil{a.revision++;a.events.emit("settings.changed",map[string]any{"key":key,"revision":a.revision})};return err}
func(a *Application)getSetting(ctx context.Context,key string)(any,error){
	doc,err:=a.store.Snapshot();if err!=nil{return nil,err}
		if _,ok:=map[string]bool{"route_final":true,"enabled_groups":true,"ping_options":true,"vpn_mode":true,"tun_apps":true,"node_sort":true,"config_locked_for_debug":true}[key];!ok{return nil,debugNotFound("settings path: /settings/"+key)}

	if key=="config_locked_for_debug"{return map[string]any{"locked":debugBool(objectValue(doc["vars"])[key])},nil}
	if strings.HasPrefix(key,"core_logs_"){return nil,debugNotFound("settings path: /settings/"+key)}
	if key=="node_sort" { order:=doc["node_manual_order"];if order==nil{order=[]any{}};return map[string]any{"ok":true,"mode":doc["node_sort_mode"],"order":order},nil }
	if value,ok:=doc[key];ok{return map[string]any{"ok":true,key:value},nil}
	return map[string]any{"ok":true,key:nil},nil
}

func(a *Application)putSetting(ctx context.Context,key string,body map[string]any)(any,error){
	allowed:=map[string]string{"ping_options":"ping_options","enabled_groups":"enabled_groups","vpn_mode":"vpn_mode","tun_apps":"tun_apps","node_sort":"node_sort","core_logs_enabled":"core_logs_enabled","core_logs_verbose":"core_logs_verbose","config_locked":"config_locked_for_debug"}
	storeKey,ok:=allowed[key];if !ok{return nil,debugNotFound("settings path: /settings/"+key)}
	value,exists:=body[storeKey];if !exists{switch storeKey{case "config_locked_for_debug":value=body["locked"];exists=value!=nil;case "core_logs_enabled","core_logs_verbose":value=body["enabled"];exists=value!=nil}}
	if !exists{return nil,debugBadRequest("setting value required")}
	if storeKey=="config_locked_for_debug" { b,ok:=value.(bool);if !ok{return nil,debugBadRequest("locked must be boolean")};value=strconv.FormatBool(b) }
	if strings.HasPrefix(storeKey,"core_logs_"){if _,ok:=value.(bool);!ok{return nil,debugBadRequest("enabled must be boolean")}}
	if storeKey=="enabled_groups"{if _,ok:=value.([]any);!ok{return nil,debugBadRequest("groups must be array")}}
	if storeKey=="ping_options"{if _,ok:=value.(map[string]any);!ok{return nil,debugBadRequest("ping_options must be object")}}
	if storeKey=="vpn_mode"||storeKey=="tun_apps"||storeKey=="node_sort"{if _,ok:=value.(map[string]any);!ok{return nil,debugBadRequest(key+" must be object")}}
	if storeKey=="node_sort" {
		valueMap:=value.(map[string]any); mode,ok:=valueMap["mode"].(string); if !ok { return nil,debugBadRequest(`field "mode" required`) }; orderValue:=valueMap["order"]; order:=[]any{}; if orderValue!=nil { var ok bool; order,ok=orderValue.([]any); if !ok{return nil,debugBadRequest(`field "order" must be string array`)};for _,item:=range order{if _,ok:=item.(string);!ok{return nil,debugBadRequest(`field "order" must be string array`)}} }
		if err:=a.updateTopLevel(ctx,"node_sort_mode",mode);err!=nil{return nil,err};if err:=a.updateTopLevel(ctx,"node_manual_order",order);err!=nil{return nil,err}
		return map[string]any{"ok":true,"action":"settings-node-sort","mode":mode,"order_count":len(order)},nil
	}
		if strings.HasPrefix(storeKey,"core_logs_"){return nil,debugNotFound("settings path: /settings/"+key)}
		if storeKey=="config_locked_for_debug" { if err:=a.updateVar(ctx,storeKey,value.(string));err!=nil{return nil,err} } else if err:=a.updateTopLevel(ctx,storeKey,value);err!=nil{return nil,err}
		return map[string]any{"ok":true,"action":"settings-"+key,key:value},nil

}
func(a *Application)debugState(ctx context.Context)(any,error){
	status:=a.core.Status();body,err:=json.Marshal(status);if err!=nil{return nil,err};var coreStatus map[string]any;if err=json.Unmarshal(body,&coreStatus);err!=nil{return nil,err}
	groupsValue,groupErr:=a.core.Call(ctx,"ccGetGroups",json.RawMessage(`{}`));groups:=[]any{};if groupErr==nil{encoded,_:=json.Marshal(groupsValue);_ = json.Unmarshal(encoded,&groups)}
	out:=map[string]any{"tunnel_up":debugBool(coreStatus["running"]),"core":coreStatus,"groups":groups,"nodes_count":0,"busy":false,"config_length":0,"uptime_seconds":int64(time.Since(runtimeStartedAt).Seconds())}
	if config,readErr:=a.readConfig();readErr==nil{out["config_length"]=len(config)}
	return out,nil
}
func(a *Application)debugSources(reveal bool)(any,error){
	items,err:=a.sourceList();if err!=nil{return nil,err}
	records,ok:=items.([]map[string]any);if !ok{return items,nil}
	out:=make([]map[string]any,0,len(records))
	for _,item:=range records{
		source:=objectValue(item["source"])
		safe:=map[string]any{"id":source["id"],"kind":source["kind"],"name":source["name"],"enabled":source["enabled"]}
		if nodes,ok:=item["nodes"].([]map[string]any);ok{safe["nodes_count"]=len(nodes)} else if nodes,ok:=item["nodes"].([]any);ok{safe["nodes_count"]=len(nodes)}
		if rawURL,ok:=source["url"].(string);ok{if reveal{safe["url"]=rawURL}else{safe["url"]=maskDebugURL(rawURL)}}
		if raw,ok:=source["origin"].(map[string]any);ok{safe["origin_kind"]=raw["kind"];if reveal{safe["raw"]=raw["raw"]}else if text,ok:=raw["raw"].(string);ok{safe["raw_bytes"]=len(text)}}
		if reveal { if text,ok:=item["text"].(string);ok&&text!=""{safe["text"]=text} }
		for _,key:=range []string{"tag_prefix","last_updated","last_update_status","consecutive_fails","update_interval_hours","meta"}{if value,exists:=source[key];exists{safe[key]=value}}
		out=append(out,safe)
	}
	return out,nil
}
func maskDebugURL(raw string)string{if strings.HasPrefix(raw,"file:"){return "file:<local>"};u,err:=url.Parse(raw);if err!=nil||u.Host==""{return "***"};return u.Scheme+"://"+u.Host+"/***"}
func scrubDebugStorage(doc map[string]any)map[string]any{out:=map[string]any{};for k,v:=range doc{if k=="sources"{continue};out[k]=v};vars:=objectValue(out["vars"]);if token,ok:=vars["debug_token"];ok{if debugString(token)!=""{vars["debug_token"]="***"}};out["vars"]=vars;records,err:=sourceRecordsFromDoc(doc);if err==nil{safe:=make([]any,0,len(records));for _,r:=range records{item:=map[string]any{};for k,v:=range r{switch k{case "url":item[k]=maskDebugURL(debugString(v));case "origin":origin:=objectValue(v);next:=map[string]any{"kind":origin["kind"]};if text,ok:=origin["raw"].(string);ok{next["raw_bytes"]=len(text)};item[k]=next;case "nodes":if nodes,ok:=v.([]any);ok{item["nodes_count"]=len(nodes)};default:item[k]=v}};safe=append(safe,item)};out["sources"]=safe};return out}
func sourceRecordsFromDoc(doc map[string]any)([]map[string]any,error){return recordsFromDocument(doc)}
func(a *Application)listCachedSRS()(any,error){
	client,err:=ruleset.New(a.dataDir);if err!=nil{return nil,err}
	dir:=filepath.Join(a.dataDir,"rule_sets")
	entries,err:=os.ReadDir(dir);if errors.Is(err,os.ErrNotExist){return []any{},nil};if err!=nil{return nil,err}
	root,rootErr:=filepath.EvalSymlinks(dir);if rootErr!=nil{return nil,rootErr}
	out:=[]map[string]any{}
	for _,entry:=range entries{
		if entry.IsDir()||!strings.HasSuffix(entry.Name(),".srs"){continue}
		info,e:=entry.Info();if e!=nil{continue}
		id:=strings.TrimSuffix(entry.Name(),".srs")
		path,exists,pathErr:=client.CachedPath(id);if pathErr!=nil||!exists{continue}
		resolved,resolveErr:=filepath.EvalSymlinks(path);if resolveErr!=nil||filepath.Dir(resolved)!=root{continue}
		out=append(out,map[string]any{"rule_id":id,"size":info.Size(),"mtime":info.ModTime().UTC().Format(time.RFC3339Nano)})
	}
	sort.Slice(out,func(i,j int)bool{return debugString(out[i]["rule_id"])<debugString(out[j]["rule_id"])})
	return out,nil
}
