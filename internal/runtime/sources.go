package runtime

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Leadaxe/lxbox/app/assets"
	"github.com/Leadaxe/lxbox/app/internal/parser"
)

const maxSubscriptionBody = 16 << 20

var (
	errSourceNotFound = errors.New("source not found")
	errSourceConflict = errors.New("source or workspace changed while the operation was running; result discarded")
	updatersMu sync.Mutex
	updaters = map[*Application]*sourceUpdater{}
)

type sourceInput struct {
	ID string `json:"id"`
	Name string `json:"name"`
	Text string `json:"text"`
	URL string `json:"url"`
	Source json.RawMessage `json:"source"`
	Auto bool `json:"auto"`
	Force bool `json:"force"`
	Offline bool `json:"offline"`
	Pick bool `json:"pick"`
	IncludeDisabled bool `json:"includeDisabled"`
}

type sourceFetch struct {
	record map[string]any
	generation uint64
	url string
	body []byte
	headers map[string]string
	requestHeaders map[string]string
	previous []byte
	writeCache bool
	cached bool
}

type sourceParsed struct {
	nodes []map[string]any
	details []map[string]any
	diagnostics []any
	recognized bool
	complete bool
	format string
}

func sourceString(m map[string]any, key string) string { v, _ := m[key].(string); return v }
func sourceBool(m map[string]any, key string, fallback bool) bool { v, ok := m[key].(bool); if ok { return v }; return fallback }
func sourceKind(m map[string]any) string { return sourceString(m,"kind") }
func mustJSON(value any) json.RawMessage { b, _ := json.Marshal(value); return b }
func copyObject(value map[string]any) (map[string]any,error) {
	var out map[string]any
	if err := decode(mustJSON(value),&out); err != nil { return nil,err }
	return out,nil
}
func sourceObject(raw []byte) (map[string]any,error) {
	var out map[string]any
	if err := decode(raw,&out); err != nil { return nil,err }
	if out == nil { return nil,errors.New("source must be a JSON object") }
	return out,nil
}
func sourceRecords(a *Application) ([]map[string]any,error) {
	raw,err := a.store.Sources(); if err != nil { return nil,err }
	out := make([]map[string]any,0,len(raw))
	for i,item := range raw { m,e := sourceObject(item); if e != nil { return nil,fmt.Errorf("sources[%d]: %w",i,e) }; out=append(out,m) }
	return out,nil
}
func recordsFromDocument(doc map[string]any) ([]map[string]any,error) {
	value,exists := doc["sources"]; if !exists || value == nil { return []map[string]any{},nil }
	list,ok := value.([]any); if !ok { return nil,errors.New("sources must be an array") }
	out := make([]map[string]any,0,len(list))
	for i,item := range list { m,ok := item.(map[string]any); if !ok || m==nil { return nil,fmt.Errorf("sources[%d] must be an object",i) }; out=append(out,m) }
	return out,nil
}
func sourceArray(records []map[string]any) []any { out:=make([]any,len(records));for i,r:=range records{out[i]=r};return out }
func findSource(records []map[string]any,id string)(int,map[string]any){for i,r:=range records{if sourceString(r,"id")==id{return i,r}};return -1,nil}
func newSourceID() string {var b [16]byte;if _,err:=rand.Read(b[:]);err==nil{b[6]=(b[6]&15)|64;b[8]=(b[8]&63)|128;h:=hex.EncodeToString(b[:]);return h[:8]+"-"+h[8:12]+"-"+h[12:16]+"-"+h[16:20]+"-"+h[20:]};return fmt.Sprintf("source-%d",time.Now().UnixNano())}
func sourceText(record map[string]any) string {
	if sourceKind(record)=="subscription" { return sourceString(record,"url") }
	if origin,ok:=record["origin"].(map[string]any);ok {if text,ok:=origin["raw"].(string);ok{return text}}
	if body,ok:=record["body"].(map[string]any);ok {m,_:=copyObject(body);if tag:=sourceString(record,"tag");tag!=""{m["tag"]=tag};return string(mustJSON(m))}
	return ""
}

// The list is an offline projection. Original records remain available under
// source; derived nodes/text/diagnostics are never persisted back as records.
func (a *Application) sourceList()(any,error){
	a.mutation.Lock()
	records,err:=sourceRecords(a);generation:=a.generation
	bodies:=map[string][]byte{};cacheErrors:=map[string]error{}
	if err==nil{for _,record:=range records{if sourceKind(record)!="subscription"{continue};u:=sourceString(record,"url");if _,ok:=bodies[u];ok{continue};body,_,e:=a.store.ReadCache(u);if e!=nil{cacheErrors[u]=e}else{bodies[u]=body}}}
	a.mutation.Unlock()
	if err!=nil{return nil,err}
	out:=make([]map[string]any,0,len(records))
	for _,record:=range records{
		item,_:=copyObject(record);item["source"]=record;item["text"]=sourceText(record)
		if sourceString(item,"name")==""{item["name"]=sourceString(record,"tag");if item["name"]==""{item["name"]=sourceString(record,"id")}}
		var parsed sourceParsed
		if sourceKind(record)=="subscription"{u:=sourceString(record,"url");err=cacheErrors[u];if err==nil{parsed,err=parseSourceBody(a.ctx,bodies[u],record)}}else{parsed,err=parseRecordBody(a.ctx,record)}
		item["nodes"]=parsed.nodes;item["node_details"]=parsed.details;item["diagnostics"]=parsed.diagnostics
		if err!=nil{item["cache_error"]=err.Error()}
		out=append(out,item)
	}
	a.mutation.Lock();stale:=generation!=a.generation;a.mutation.Unlock()
	if stale{return nil,errSourceConflict};return out,nil
}

// saveSource patches only supplied fields. Nested objects are merged so a
// simple rename cannot erase future fields, identity, policies or disable marks.
func (a *Application) saveSource(raw json.RawMessage)(any,error){
	patch,err:=sourceObject(raw);if err!=nil{return nil,err}
	if wrapped,ok:=patch["source"].(map[string]any);ok{for _,key:=range []string{"id","name","text","enabled"}{if v,exists:=patch[key];exists{wrapped[key]=v}};patch=wrapped}
	id:=strings.TrimSpace(sourceString(patch,"id"));if id==""{id=newSourceID()};patch["id"]=id
	a.mutation.Lock();defer a.mutation.Unlock()
	var committed map[string]any
	err=a.store.Update(func(doc map[string]any)error{
		records,e:=recordsFromDocument(doc);if e!=nil{return e};index,current:=findSource(records,id)
		if current==nil{current=map[string]any{"id":id,"enabled":true}}
		next,_:=copyObject(current);mergeSourcePatch(next,patch)
		if text,exists:=patch["text"];exists{value,ok:=text.(string);if !ok{return errors.New("source text must be a string")};if sourceKind(next)=="subscription"{next["url"]=strings.TrimSpace(value)}else{origin,_:=next["origin"].(map[string]any);if origin==nil{origin=map[string]any{}};origin["raw"]=value;origin["kind"]=sourceDialect(value);next["origin"]=origin}}
		delete(next,"text");delete(next,"source")
		if e=validateSourceRecord(next);e!=nil{return e}
		if index<0{records=append(records,next)}else{records[index]=next};doc["sources"]=sourceArray(records);committed=next;return nil
	})
	if err!=nil{return nil,err};a.revision++;a.events.emit("sources.changed",map[string]any{"reason":"save","id":id,"revision":a.revision});return committed,nil
}
func mergeSourcePatch(dst,patch map[string]any){for k,v:=range patch{if src,ok:=v.(map[string]any);ok{if target,ok:=dst[k].(map[string]any);ok{mergeSourcePatch(target,src);continue}};dst[k]=v}}
func validateSourceRecord(record map[string]any)error{
	kind:=sourceKind(record);if kind==""{return errors.New("source kind is required")}
	if v,ok:=record["enabled"];ok{if _,ok=v.(bool);!ok{return errors.New("enabled must be a boolean")}}
	if v,exists:=record["name"];exists{if _,ok:=v.(string);!ok{return errors.New("name must be a string")}}
	if v,exists:=record["identity"];exists&&v!=nil{if _,ok:=v.(map[string]any);!ok{return errors.New("identity must be an object or null")}}
	if v,exists:=record["on_update_action"];exists{action,ok:=v.(string);if !ok||(action!="none"&&action!="rebuild"&&action!="reload"){return errors.New("on_update_action must be none, rebuild, or reload")}}
	if kind=="subscription"{u:=sourceString(record,"url");if !isHTTPURL(u)&&!isFileURL(u){return errors.New("subscription URL must use http(s), file:, or content:")}}
	if kind=="server"{text:=sourceText(record);if text==""{return errors.New("manual source requires origin.raw or native body")};if len(text)>maxSubscriptionBody{return errors.New("source exceeds 16 MiB limit")}}
	if kind=="subscription"||kind=="server" {if _,exists:=record["nodes"];exists{return errors.New("derived nodes cannot be saved on subscriptions or manual servers; save origin.raw instead")}}
	return nil
}
func (a *Application) deleteSource(raw json.RawMessage)(any,error){
	var p sourceInput;if err:=decode(raw,&p);err!=nil{return nil,err};if p.ID==""{return nil,errors.New("source id is required")}
	a.mutation.Lock();defer a.mutation.Unlock()
	err:=a.store.Update(func(doc map[string]any)error{records,e:=recordsFromDocument(doc);if e!=nil{return e};index,_:=findSource(records,p.ID);if index<0{return errSourceNotFound};records=append(records[:index],records[index+1:]...);doc["sources"]=sourceArray(records);return nil})
	if err!=nil{return nil,err};a.revision++;a.events.emit("sources.changed",map[string]any{"reason":"delete","id":p.ID,"revision":a.revision});return map[string]any{"id":p.ID,"deleted":true},nil
}

// Import parses before committing and retains the exact inline input in
// origin.raw. A remote source is stored only after a usable response is parsed.
func (a *Application) importSource(ctx context.Context,raw json.RawMessage)(any,error){
	ctx,cancel:=a.sourceContext(ctx);defer cancel()
	var p sourceInput;if err:=decode(raw,&p);err!=nil{return nil,err}
	record,objectErr:=sourceObject(raw);if objectErr!=nil{return nil,objectErr}
	for _,key:=range []string{"text","source","auto","force","offline","pick","includeDisabled"}{delete(record,key)}
	if len(p.Source)>0&&string(p.Source)!="null"{wrapped,e:=sourceObject(p.Source);if e!=nil{return nil,e};mergeSourcePatch(wrapped,record);record=wrapped}
	if p.ID!=""{record["id"]=p.ID};id:=sourceString(record,"id");if id==""{id=newSourceID();record["id"]=id}
	if p.Name!=""{record["name"]=p.Name}
	text:=p.Text;if text==""{text=sourceText(record)}
	address:=strings.TrimSpace(p.URL);if address==""{address=sourceString(record,"url")};if address==""&&sourceKind(record)!="server"&&(isHTTPURL(strings.TrimSpace(text))||isFileURL(strings.TrimSpace(text))){address=strings.TrimSpace(text)}
	a.mutation.Lock();generation:=a.generation;records,err:=sourceRecords(a);_,original:=findSource(records,id);if original!=nil{original,_=copyObject(original);merged,_:=copyObject(original);mergeSourcePatch(merged,record);record=merged};a.mutation.Unlock();if err!=nil{return nil,err}
	if _,ok:=record["enabled"];!ok{record["enabled"]=true}
	if text==""{text=sourceText(record)};if address==""{address=sourceString(record,"url")}
	if p.Pick{if a.platform==nil{return nil,errors.New("file picker platform callback is unavailable")};value,e:=a.platformCall(ctx,"file.pick",map[string]any{"mimeTypes":[]string{"text/*","application/json","application/octet-stream"},"maxBytes":maxSubscriptionBody});if e!=nil{return nil,e};switch v:=value.(type){case string:address=v;case map[string]any:address=sourceString(v,"uri");if body,ok:=v["text"].(string);ok{text=body};default:return nil,errors.New("file.pick was cancelled or returned no document")};if address==""&&text==""{return nil,errors.New("file picker was cancelled")}}
	fetch:=sourceFetch{record:original,generation:generation,url:address,headers:map[string]string{}}
	if address!=""{
		record["kind"]="subscription";record["url"]=address;if sourceString(record,"name")==""{record["name"]=address}
		if isFileURL(address)&&text!=""&&!isFileURL(strings.TrimSpace(text)){fetch.body=[]byte(text);fetch.writeCache=true}else{fetch,err=a.fetchRecord(ctx,record,generation,p.Offline)}
		if err!=nil{return nil,err};if isFileURL(address){if _,exists:=record["update"];!exists{record["update"]=map[string]any{"interval_hours":-1}}}
	}else{
		if strings.TrimSpace(text)==""{return nil,errors.New("inline source text is required")};record["kind"]="server";origin,_:=record["origin"].(map[string]any);if origin==nil{origin=map[string]any{}};origin["raw"]=text;origin["kind"]=sourceDialect(text);record["origin"]=origin;fetch.body=[]byte(text)
	}
	if err=validateSourceRecord(record);err!=nil{return nil,err}
	parsed,err:=parseSourceBody(ctx,fetch.body,record);if err!=nil{return nil,err};if len(parsed.details)==0{return nil,fmt.Errorf("no supported nodes: %s",diagnosticsText(parsed.diagnostics))}
	if sourceKind(record)=="server"&&sourceString(record,"tag")==""&&len(parsed.details)>0{if emitted,ok:=parsed.details[0]["canonical"].(map[string]any);ok{record["tag"]=sourceString(emitted,"tag")}}
	a.mutation.Lock();defer a.mutation.Unlock()
	if err=ctx.Err();err!=nil{return nil,err};if generation!=a.generation{return nil,errSourceConflict}
	currentRecords,err:=sourceRecords(a);if err!=nil{return nil,err};_,current:=findSource(currentRecords,id);if !sourceEqual(current,original){return nil,errSourceConflict}
	if fetch.writeCache&&isHTTPURL(address)&&!equalStringMap(a.sourceHeaders(record),fetch.requestHeaders){return nil,fmt.Errorf("%w: HTTP identity settings changed",errSourceConflict)}
	if fetch.writeCache&&isHTTPURL(address){cached,_,e:=a.store.ReadCache(address);if e!=nil&&!errors.Is(e,os.ErrNotExist){return nil,e};if !reflect.DeepEqual(cached,fetch.previous)&&!reflect.DeepEqual(cached,fetch.body){return nil,fmt.Errorf("%w: subscription cache changed",errSourceConflict)}}
	if fetch.writeCache{if err=a.store.WriteCache(address,fetch.body,fetch.headers);err!=nil{a.revision++;return nil,err};a.revision++}
	if sourceKind(record)=="subscription"{setRefreshMetadata(record,fetch,parsed)}
	err=a.store.Update(func(doc map[string]any)error{items,e:=recordsFromDocument(doc);if e!=nil{return e};index,_:=findSource(items,id);if index<0{items=append(items,record)}else{items[index]=record};doc["sources"]=sourceArray(items);return nil})
	if err!=nil{return nil,err};a.revision++;a.events.emit("sources.changed",map[string]any{"reason":"import","id":id,"revision":a.revision})
	return parsedSourceResponse(record,parsed,fetch.cached),nil
}

func (a *Application) sourceContext(ctx context.Context)(context.Context,context.CancelFunc){if ctx==nil{ctx=context.Background()};child,cancel:=context.WithCancel(ctx);if a.ctx==nil{return child,cancel};stop:=context.AfterFunc(a.ctx,cancel);return child,func(){stop();cancel()}}
func sourceEqual(a,b map[string]any)bool{return string(mustJSON(a))==string(mustJSON(b))}
func isHTTPURL(value string)bool{if strings.ContainsAny(value,"\r\n"){return false};u,err:=url.Parse(value);return err==nil&&u.Host!=""&&(strings.EqualFold(u.Scheme,"http")||strings.EqualFold(u.Scheme,"https"))}
func isFileURL(value string)bool{u,err:=url.Parse(value);return err==nil&&(strings.EqualFold(u.Scheme,"file")||strings.EqualFold(u.Scheme,"content"))}
func sourceDialect(text string)string{trim:=strings.TrimSpace(text);if strings.Contains(strings.ToLower(trim),"[interface]"){return "wg_ini"};if strings.HasPrefix(trim,"{")||strings.HasPrefix(trim,"["){var v any;if json.Unmarshal([]byte(trim),&v)==nil{if strings.Contains(trim,`"protocol"`){return "xray"};return "singbox"}};return "uri"}

func (a *Application) refreshSource(ctx context.Context,raw json.RawMessage)(any,error){
	ctx,cancel:=a.sourceContext(ctx);defer cancel();var p sourceInput;if err:=decode(raw,&p);err!=nil{return nil,err};if p.ID==""{return nil,errors.New("source id is required")}
	generation,record,key,already,err:=a.reserveSourceRefresh(p.ID);if err!=nil{return nil,err};if already{return map[string]any{"id":p.ID,"skipped":true,"reason":"already refreshing"},nil};defer a.releaseSourceRefresh(key)
	fetch,err:=a.fetchRecord(ctx,record,generation,p.Offline)
	var parsed sourceParsed;if err==nil{parsed,err=parseSourceBody(ctx,fetch.body,record);if err==nil&&len(parsed.details)==0{err=fmt.Errorf("source produced no supported nodes: %s",diagnosticsText(parsed.diagnostics))}}
	if err!=nil{return a.finishSourceFailure(ctx,record,generation,err)}
	value,err:=a.commitSourceRefresh(ctx,record,fetch,parsed,generation)
	if err==nil&&sourceBool(record,"enabled",true){if response,ok:=value.(map[string]any);ok&&response["changed"]==true{if actionErr:=a.applySourceReaction(ctx,generation,a.updateAction(record));actionErr!=nil{response["reaction_error"]=actionErr.Error()}}}
	return value,err
}
func (a *Application) reserveSourceRefresh(id string)(uint64,map[string]any,string,bool,error){
	a.mutation.Lock();defer a.mutation.Unlock();records,err:=sourceRecords(a);if err!=nil{return 0,nil,"",false,err};_,record:=findSource(records,id);if record==nil{return 0,nil,"",false,errSourceNotFound}
	if sourceKind(record)!="subscription"&&sourceKind(record)!="server"{return 0,nil,"",false,errors.New("only subscriptions and manual servers can be refreshed")}
	address:=sourceString(record,"url");if address==""{address="source:"+id};key:=fmt.Sprintf("%d:%s",a.generation,address)
	if a.fetching==nil{a.fetching=map[string]bool{}};if a.fetching[key]{return a.generation,record,key,true,nil};a.fetching[key]=true;return a.generation,record,key,false,nil
}
func (a *Application) releaseSourceRefresh(key string){a.mutation.Lock();delete(a.fetching,key);a.mutation.Unlock()}
func (a *Application) fetchRecord(ctx context.Context,record map[string]any,generation uint64,offline bool)(sourceFetch,error){
	out:=sourceFetch{record:record,generation:generation,url:sourceString(record,"url"),headers:map[string]string{}}
	if err:=ctx.Err();err!=nil{return out,err}
	if sourceKind(record)=="server"{out.body=[]byte(sourceText(record));out.previous=append([]byte(nil),out.body...);return out,nil}
	a.mutation.Lock();if a.generation!=generation{a.mutation.Unlock();return out,errSourceConflict};cached,headers,cacheErr:=a.store.ReadCache(out.url);out.previous=append([]byte(nil),cached...);out.requestHeaders=a.sourceHeaders(record);a.mutation.Unlock()
	if offline||(isFileURL(out.url)&&cacheErr==nil){if cacheErr!=nil{return out,cacheErr};out.body=cached;out.headers=headers;out.cached=true;return out,nil}
	if isHTTPURL(out.url){body,responseHeaders,err:=fetchSubscriptionHTTP(ctx,out.url,out.requestHeaders);out.body=body;out.headers=responseHeaders;out.writeCache=err==nil;return out,err}
	if isFileURL(out.url){
		if a.platform==nil{return out,errors.New("file.read platform callback is unavailable")}
		value,err:=a.platformCall(ctx,"file.read",map[string]any{"uri":out.url,"maxBytes":maxSubscriptionBody});if err!=nil{return out,err}
		switch v:=value.(type){
		case string:out.body=[]byte(v)
		case map[string]any:
			if v["cancelled"]==true{return out,context.Canceled}
			if text,ok:=v["text"].(string);ok{out.body=[]byte(text)}else if text,ok:=v["body"].(string);ok{out.body=[]byte(text)}else if data,ok:=v["data"].(string);ok{if len(data)>(maxSubscriptionBody+2)/3*4+8{return out,errors.New("file body exceeds 16 MiB limit")};out.body,err=base64.StdEncoding.DecodeString(data);if err!=nil{return out,fmt.Errorf("decode file.read data: %w",err)}}
			if m,ok:=v["headers"].(map[string]any);ok{out.headers=stringMapLoose(m)}
		}
		if len(out.body)==0{return out,errors.New("file.read returned no body")};if len(out.body)>maxSubscriptionBody{return out,errors.New("file body exceeds 16 MiB limit")};out.writeCache=true;return out,nil
	}
	return out,errors.New("unsupported subscription URL")
}

func fetchSubscriptionHTTP(ctx context.Context,address string,headers map[string]string)([]byte,map[string]string,error){
	client:=&http.Client{CheckRedirect:func(req *http.Request,via []*http.Request)error{if len(via)>=10{return errors.New("too many subscription redirects")};if len(via)>0&& !strings.EqualFold(req.URL.Host,via[0].URL.Host){for _,key:=range []string{"Authorization","Cookie","x-hwid","x-device-os","x-ver-os","x-device-model"}{req.Header.Del(key)}};return nil}}
	backoffs:=[]time.Duration{time.Second,3*time.Second};var last error
	for attempt:=0;attempt<3;attempt++{
		if err:=ctx.Err();err!=nil{return nil,nil,err};requestCtx,cancel:=context.WithTimeout(ctx,9*time.Second)
		req,err:=http.NewRequestWithContext(requestCtx,http.MethodGet,address,nil);if err!=nil{cancel();return nil,nil,err};for k,v:=range headers{req.Header.Set(k,v)}
		response,err:=client.Do(req)
		if err==nil{
			h:=map[string]string{};for k,values:=range response.Header{h[strings.ToLower(k)]=strings.Join(values,", ")}
			if response.StatusCode>=200&&response.StatusCode<300{body,readErr:=io.ReadAll(io.LimitReader(response.Body,maxSubscriptionBody+1));response.Body.Close();cancel();if len(body)>maxSubscriptionBody{return nil,h,errors.New("subscription response exceeds 16 MiB limit")};if readErr==nil{return body,h,nil};err=readErr}else{response.Body.Close();err=fmt.Errorf("subscription HTTP %d",response.StatusCode);if response.StatusCode>=400&&response.StatusCode<500{cancel();return nil,h,err}}
		};cancel();last=err;if attempt<2{if err=sleepContext(ctx,backoffs[attempt]);err!=nil{return nil,nil,err}}
	};return nil,nil,last
}
func sleepContext(ctx context.Context,d time.Duration)error{timer:=time.NewTimer(d);defer timer.Stop();select{case<-ctx.Done():return ctx.Err();case<-timer.C:return nil}}

// Called under mutation; per-source Custom identity replaces the entire global
// identity snapshot, including intentionally empty fields.
func (a *Application) sourceHeaders(record map[string]any)map[string]string{
	doc,_:=a.store.Snapshot();out:=map[string]string{}
	for _,key:=range []string{"headers","http_headers"}{if m,ok:=doc[key].(map[string]any);ok{for k,v:=range stringMapLoose(m){out[http.CanonicalHeaderKey(k)]=v}}}
	identity:=map[string]any{}
	for _,key:=range []string{"user_agent","send_hwid","hwid","device_os","ver_os","device_model"}{identity[key]=sourceSetting(doc,"subscription_"+key,nil)}
	if merged,ok:=doc["subscription_identity"].(map[string]any);ok{
		for k,v:=range merged{if k=="user_agent"||k=="send_hwid"||k=="hwid"||k=="device_os"||k=="ver_os"||k=="device_model"{identity[k]=v}}
	}
	if custom,ok:=record["identity"].(map[string]any);ok{identity=custom}
	_,customIdentity:=record["identity"].(map[string]any)
	if customIdentity{for _,key:=range []string{"User-Agent","X-Hwid","X-Device-Os","X-Ver-Os","X-Device-Model"}{delete(out,key)}}
	ua:=sourceString(identity,"user_agent");if ua!=""{out["User-Agent"]=ua}else if out["User-Agent"]==""{out["User-Agent"]="LxBox-android"}
	if rawEnabled:=identity["send_hwid"];rawEnabled!=nil&&!settingBool(rawEnabled,true){for _,key:=range []string{"X-Hwid","X-Device-Os","X-Ver-Os","X-Device-Model"}{delete(out,key)}}
	if settingBool(identity["send_hwid"],true)&&sourceString(identity,"hwid")!=""{out["X-Hwid"]=sourceString(identity,"hwid");for key,field:=range map[string]string{"X-Device-Os":"device_os","X-Ver-Os":"ver_os","X-Device-Model":"device_model"}{if v:=sourceString(identity,field);v!=""{out[key]=v}}}
	for _,key:=range []string{"headers","http_headers"}{if m,ok:=record[key].(map[string]any);ok{for k,v:=range stringMapLoose(m){out[http.CanonicalHeaderKey(k)]=v}}}
	return out
}
func stringMapLoose(m map[string]any)map[string]string{out:=map[string]string{};for k,v:=range m{if s,ok:=v.(string);ok{out[k]=s}};return out}
func sourceSetting(doc map[string]any,key string,fallback any)any{if vars,ok:=doc["vars"].(map[string]any);ok{if v,ok:=vars[key];ok{return v}};if v,ok:=doc[key];ok{return v};return fallback}
func settingBool(value any,fallback bool)bool{switch v:=value.(type){case bool:return v;case string:return v!="false"&&v!="0"};return fallback}

// Cache commits share the same ownership/revision lock as workspace changes
// and configuration snapshots. No network or parser work happens in this lock.
func (a *Application) commitSourceRefresh(ctx context.Context,original map[string]any,fetch sourceFetch,parsed sourceParsed,generation uint64)(any,error){
	a.mutation.Lock();defer a.mutation.Unlock();if err:=ctx.Err();err!=nil{return nil,err};if a.generation!=generation{return nil,errSourceConflict}
	records,err:=sourceRecords(a);if err!=nil{return nil,err};id:=sourceString(original,"id");_,current:=findSource(records,id)
	if !sourceEqual(current,original){return nil,fmt.Errorf("%w: %s",errSourceConflict,id)}
	if isHTTPURL(fetch.url)&&!equalStringMap(a.sourceHeaders(original),fetch.requestHeaders){return nil,fmt.Errorf("%w: HTTP identity settings changed",errSourceConflict)}
	if fetch.url!=""{cached,_,cacheErr:=a.store.ReadCache(fetch.url);if cacheErr!=nil&&!errors.Is(cacheErr,os.ErrNotExist){return nil,cacheErr};if !reflect.DeepEqual(cached,fetch.previous)&&!reflect.DeepEqual(cached,fetch.body){return nil,fmt.Errorf("%w: subscription cache changed",errSourceConflict)}}
	changed:=!reflect.DeepEqual(fetch.previous,fetch.body)
	if fetch.writeCache{if err=a.store.WriteCache(fetch.url,fetch.body,fetch.headers);err!=nil{a.revision++;return nil,err};a.revision++}
	updated,_:=copyObject(current);setRefreshMetadata(updated,fetch,parsed)
	err=a.store.Update(func(doc map[string]any)error{items,e:=recordsFromDocument(doc);if e!=nil{return e};index,_:=findSource(items,id);if index<0{return errSourceNotFound};items[index]=updated;doc["sources"]=sourceArray(items);return nil})
	if err!=nil{return nil,err};a.revision++;a.events.emit("source.updated",map[string]any{"id":id,"revision":a.revision,"changed":changed})
	response:=parsedSourceResponse(updated,parsed,fetch.cached);response["changed"]=changed;return response,nil
}
func (a *Application) finishSourceFailure(ctx context.Context,original map[string]any,generation uint64,cause error)(any,error){
	if err:=ctx.Err();err!=nil{return nil,err};a.mutation.Lock();defer a.mutation.Unlock();if generation!=a.generation{return nil,errSourceConflict}
	id:=sourceString(original,"id")
	err:=a.store.Update(func(doc map[string]any)error{records,e:=recordsFromDocument(doc);if e!=nil{return e};index,current:=findSource(records,id);if !sourceEqual(current,original){return errSourceConflict};current["last_update_attempt"]=time.Now().UTC().Format(time.RFC3339Nano);current["last_update_status"]="failed";n,_:=numberInt(current["consecutive_fails"]);current["consecutive_fails"]=n+1;records[index]=current;doc["sources"]=sourceArray(records);return nil})
	if err!=nil{return nil,errors.Join(cause,err)};a.revision++;a.events.emit("source.failed",map[string]any{"id":id,"error":cause.Error()});return map[string]any{"id":id,"error":cause.Error()},cause
}
func parsedSourceResponse(record map[string]any,parsed sourceParsed,cached bool)map[string]any{return map[string]any{"id":record["id"],"source":record,"nodes":parsed.nodes,"node_details":parsed.details,"diagnostics":parsed.diagnostics,"format":parsed.format,"recognized":parsed.recognized,"complete":parsed.complete,"cached":cached}}
func setRefreshMetadata(record map[string]any,fetch sourceFetch,parsed sourceParsed){if !fetch.cached{now:=time.Now().UTC().Format(time.RFC3339Nano);record["last_updated"]=now;record["last_update_attempt"]=now;record["last_update_status"]="ok";record["consecutive_fails"]=0};record["last_node_count"]=len(parsed.nodes);record["total_node_count"]=len(parsed.details);record["meta"]=subscriptionMeta(record["meta"],fetch.body,fetch.headers)}
func subscriptionMeta(existing any,body []byte,headers map[string]string)map[string]any{
	out:=map[string]any{};if old,ok:=existing.(map[string]any);ok{for k,v:=range old{out[k]=v}}
	merged:=map[string]string{};for _,line:=range strings.Split(string(body),"\n"){line=strings.TrimSpace(line);if line==""{continue};if !strings.HasPrefix(line,"#")&&!strings.HasPrefix(line,"//")&&!strings.HasPrefix(line,";"){break};line=strings.TrimLeft(line,"#/; ");if i:=strings.IndexByte(line,':');i>0{merged[strings.ToLower(strings.TrimSpace(line[:i]))]=strings.TrimSpace(line[i+1:])}}
	for k,v:=range headers{merged[strings.ToLower(k)]=v}
	for header,key:=range map[string]string{"profile-title":"profile_title","profile-web-page-url":"web_page_url","support-url":"support_url","announce":"announce"}{if value,ok:=merged[header];ok{if strings.HasPrefix(value,"base64:"){encoded:=strings.TrimPrefix(value,"base64:");decoded,e:=base64.StdEncoding.DecodeString(encoded);if e!=nil{decoded,e=base64.RawStdEncoding.DecodeString(strings.TrimRight(encoded,"="))};if e!=nil&&header=="announce"{continue};if e==nil{value=string(decoded)}};if header=="announce"{value=strings.ReplaceAll(value,"\r\n","\n");r:=[]rune(value);if len(r)>2000{value=string(r[:2000])}};out[key]=value}}
	if _,ok:=merged["profile-title"];!ok{if _,params,e:=mime.ParseMediaType(merged["content-disposition"]);e==nil&&params["filename"]!=""{name:=params["filename"];for _,ext:=range []string{".txt",".yaml",".yml",".json",".conf"}{if strings.HasSuffix(strings.ToLower(name),ext){name=name[:len(name)-len(ext)];break}};out["profile_title"]=name}}
	if value,ok:=merged["profile-update-interval"];ok{if n,e:=strconv.ParseInt(strings.TrimSpace(value),10,64);e==nil&&n>=0{out["update_interval_hours"]=n}}
	if info,ok:=merged["subscription-userinfo"];ok{for _,pair:=range strings.Split(info,";"){kv:=strings.SplitN(strings.TrimSpace(pair),"=",2);if len(kv)!=2{continue};if n,e:=strconv.ParseInt(strings.TrimSpace(kv[1]),10,64);e==nil{if key:=map[string]string{"upload":"upload_bytes","download":"download_bytes","total":"total_bytes","expire":"expire_timestamp"}[strings.TrimSpace(kv[0])];key!=""{out[key]=n}}}}
	return out
}

func diagnosticsText(values []any)string{for _,v:=range values{if m,ok:=v.(map[string]any);ok{if s,ok:=m["message"].(string);ok{return s}}};return "no nodes"}
func parseSourceBody(ctx context.Context,body []byte,record map[string]any)(sourceParsed,error){
	out:=sourceParsed{nodes:[]map[string]any{},details:[]map[string]any{},diagnostics:[]any{}}
	if ctx==nil{ctx=context.Background()};if err:=ctx.Err();err!=nil{return out,err};if len(body)>maxSubscriptionBody{return out,errors.New("source exceeds 16 MiB limit")}
	result:=parser.Parse(ctx,body,parser.Options{ContractFS:assets.FS,Source:parser.Source{Kind:sourceKind(record),ID:sourceString(record,"id"),Name:sourceString(record,"name"),URL:sourceString(record,"url")},KeepUnknown:true})
	out.recognized=result.Recognized;out.complete=result.Complete;out.format=result.Format
	var failures []error
	appendDiagnostic:=func(d parser.Diagnostic){var value any;_ = decode(mustJSON(d),&value);out.diagnostics=append(out.diagnostics,value);if strings.EqualFold(d.Severity,"error"){failures=append(failures,fmt.Errorf("%s (%s)",d.Message,d.Code))}}
	for _,d:=range result.Diagnostics{appendDiagnostic(d)}
	identities:=map[string]int{}
	for _,node:=range result.Nodes{
		if err:=ctx.Err();err!=nil{return out,err};for _,d:=range node.Diagnostics{appendDiagnostic(d)}
		emitted:=node.SingBox();if len(emitted)==0{failures=append(failures,fmt.Errorf("node %s has no emitted sing-box body",node.Key));continue}
		var detail map[string]any;_ = decode(mustJSON(node),&detail)
		group:=sourceString(emitted,"type");identity:=""
		if group!="selector"&&group!="urltest"{identity=uniqueSourceIdentity(strings.TrimSpace(node.Name),identities)}
		enabled:=sourceNodeEnabled(record,node.Key,identity)
		if group=="selector"||group=="urltest"{enabled=true}
		emitted,enabled,findings:=applySourceImportRules(emitted,enabled,record)
		if defaults,ok:=record["group_defaults"].(map[string]any);ok&&sourceString(emitted,"type")=="selector"{if choice:=sourceString(defaults,sourceString(emitted,"tag"));choice!=""{emitted["default"]=choice}}
		out.diagnostics=append(out.diagnostics,findings...);for _,finding:=range findings{if m,ok:=finding.(map[string]any);ok&&sourceString(m,"severity")=="error"{failures=append(failures,errors.New(sourceString(m,"message")))}}
		detail["identity"]=identity;detail["canonical"]=emitted;detail["enabled"]=enabled;out.details=append(out.details,detail);if enabled{out.nodes=append(out.nodes,emitted)}
	}
	if err:=ctx.Err();err!=nil{return out,err}
	if !out.complete||!out.recognized||len(out.details)==0{failures=append(failures,errors.New("source did not produce a complete set of supported nodes"))}
	return out,errors.Join(failures...)
}
func uniqueSourceIdentity(name string,counts map[string]int)string{if name==""{return ""};if counts[name]==0{counts[name]=1;return name};for{counts[name]++;candidate:=name+"-"+strconv.Itoa(counts[name]);if counts[candidate]==0{counts[candidate]=1;return candidate}}}
func sourceNodeEnabled(record map[string]any,key,tag string)bool{switch disabled:=record["disabled"].(type){case map[string]any:if _,ok:=disabled[tag];ok{return false};if _,ok:=disabled[key];ok{return false};case []any:for _,v:=range disabled{if v==tag||v==key{return false}}};return true}
func parseRecordBody(ctx context.Context,record map[string]any)(sourceParsed,error){
	if sourceKind(record)=="folder"{out:=sourceParsed{nodes:[]map[string]any{},details:[]map[string]any{},diagnostics:[]any{}};members,_:=record["nodes"].([]any);for _,v:=range members{member,ok:=v.(map[string]any);if !ok{continue};parsed,err:=parseRecordBody(ctx,member);out.details=append(out.details,parsed.details...);out.diagnostics=append(out.diagnostics,parsed.diagnostics...);if sourceBool(member,"enabled",true){out.nodes=append(out.nodes,parsed.nodes...)};if err!=nil{out.diagnostics=append(out.diagnostics,map[string]any{"severity":"error","message":err.Error()})}};return out,nil}
	if text:=sourceText(record);text!=""{return parseSourceBody(ctx,[]byte(text),record)};return sourceParsed{},os.ErrNotExist
}

// sourceBodyNodes is the offline node preparation boundary shared with config
// assembly. It returns only SingBox() nodes with import/disable overlays.
func sourceBodyNodes(ctx context.Context,body []byte,record map[string]any)([]map[string]any,[]map[string]any,[]any,error){parsed,err:=parseSourceBody(ctx,body,record);return parsed.nodes,parsed.details,parsed.diagnostics,err}
