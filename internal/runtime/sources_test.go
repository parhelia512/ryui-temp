package runtime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Leadaxe/lxbox/app/internal/storage"
)

// These focused regressions are intentionally not executed by this task.
func sourceTestApp(t *testing.T, records ...map[string]any)*Application{
	t.Helper();store,err:=storage.Open(t.TempDir());if err!=nil{t.Fatal(err)}
	if err=store.Update(func(doc map[string]any)error{doc["sources"]=sourceArray(records);return nil});err!=nil{t.Fatal(err)}
	a:=&Application{store:store,ctx:context.Background(),fetching:map[string]bool{}}
	t.Cleanup(func(){_ = a.Close()});return a
}
func sourceTestSubscription(address string)map[string]any{return map[string]any{"id":"sub","kind":"subscription","name":"original","url":address,"enabled":true,"on_update_action":"none","future":map[string]any{"keep":json.Number("9007199254740993")}}}
const sourceTestBody=`{"type":"socks","tag":"node","server":"example.test","server_port":1080}`

func TestSourceSavePreservesUnknownFields(t *testing.T){
	record:=sourceTestSubscription("https://example.test/sub");record["tag_policy"]=map[string]any{"prefix":"old ","future":"keep"};a:=sourceTestApp(t,record)
	if _,err:=a.saveSource(json.RawMessage(`{"id":"sub","name":"renamed","tag_policy":{"prefix":"new "}}`));err!=nil{t.Fatal(err)}
	items,err:=sourceRecords(a);if err!=nil{t.Fatal(err)};got:=items[0]
	if got["kind"]!="subscription"||got["url"]!=record["url"]||got["name"]!="renamed"{t.Fatalf("lost source fields: %#v",got)}
	policy:=got["tag_policy"].(map[string]any);if policy["future"]!="keep"||policy["prefix"]!="new "{t.Fatalf("lost policy fields: %#v",policy)}
	future:=got["future"].(map[string]any);if future["keep"]!=json.Number("9007199254740993"){t.Fatalf("changed unknown number: %#v",future)}
}
func TestSourceRefreshConflictDoesNotOverwriteCache(t *testing.T){
	a:=sourceTestApp(t,sourceTestSubscription("https://example.test/sub"));originals,_:=sourceRecords(a);original:=originals[0]
	if err:=a.store.WriteCache(original["url"].(string),[]byte("old"),nil);err!=nil{t.Fatal(err)}
	fetch:=sourceFetch{url:original["url"].(string),body:[]byte(sourceTestBody),writeCache:true,requestHeaders:map[string]string{}}
	if _,err:=a.saveSource(json.RawMessage(`{"id":"sub","name":"concurrent edit"}`));err!=nil{t.Fatal(err)}
	if _,err:=a.commitSourceRefresh(context.Background(),original,fetch,sourceParsed{},0);!errors.Is(err,errSourceConflict){t.Fatalf("expected conflict, got %v",err)}
	body,_,err:=a.store.ReadCache(fetch.url);if err!=nil||string(body)!="old"{t.Fatalf("conflict wrote cache: %q %v",body,err)}
	a.mutation.Lock();a.generation++;a.mutation.Unlock()
	if _,err=a.commitSourceRefresh(context.Background(),original,fetch,sourceParsed{},0);!errors.Is(err,errSourceConflict){t.Fatalf("expected workspace barrier, got %v",err)}
}
func TestSourceAllDisabledIsValidAndPartialParseFails(t *testing.T){
	record:=sourceTestSubscription("https://example.test/sub");record["disabled"]=map[string]any{"node":json.Number("1")}
	nodes,details,_,err:=sourceBodyNodes(context.Background(),[]byte(sourceTestBody),record)
	if err!=nil||len(nodes)!=0||len(details)!=1||details[0]["enabled"]!=false{t.Fatalf("disabled parse: nodes=%v details=%v err=%v",nodes,details,err)}
	_,_,_,err=sourceBodyNodes(context.Background(),[]byte("ss://YWVzLTI1Ni1nY206cGFzcw==@a.test:443#ok\nunknown-protocol://x:1"),record)
	if err==nil{t.Fatal("partial unsupported parse was accepted")}
	ctx,cancel:=context.WithCancel(context.Background());cancel();_,_,_,err=sourceBodyNodes(ctx,[]byte(sourceTestBody),record)
	if !errors.Is(err,context.Canceled){t.Fatalf("cancellation lost: %v",err)}
}
func TestSourceRefreshAllDeduplicatesURLAndAppliesRules(t *testing.T){
	var calls atomic.Int32;server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){calls.Add(1);w.Header().Set("profile-title","Test");_,_ = w.Write([]byte(sourceTestBody))}));defer server.Close()
	one:=sourceTestSubscription(server.URL);two:=sourceTestSubscription(server.URL);two["id"]="sub-2";two["disabled"]=map[string]any{"node":1}
	a:=sourceTestApp(t,one,two);response,err:=a.refreshAll(context.Background(),json.RawMessage(`{}`));if err!=nil{t.Fatal(err)}
	if calls.Load()!=1{t.Fatalf("expected one URL fetch, got %d",calls.Load())};if response.(map[string]any)["updated"]!=2{t.Fatalf("expected two records updated: %#v",response)}
	body,_,err:=a.store.ReadCache(server.URL);if err!=nil||string(body)!=sourceTestBody{t.Fatalf("raw cache not retained: %s %v",body,err)}
}
func TestSourceHTTPPermanentAndCancelledDoNotRetry(t *testing.T){
	var calls atomic.Int32;server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){calls.Add(1);w.WriteHeader(http.StatusUnauthorized)}));defer server.Close()
	_,_,err:=fetchSubscriptionHTTP(context.Background(),server.URL,nil);if err==nil||calls.Load()!=1{t.Fatalf("permanent error retried: calls=%d err=%v",calls.Load(),err)}
	ctx,cancel:=context.WithCancel(context.Background());cancel();_,_,err=fetchSubscriptionHTTP(ctx,server.URL,nil);if !errors.Is(err,context.Canceled)||calls.Load()!=1{t.Fatalf("cancelled fetch attempted HTTP: %v",err)}
}
func TestSourceFileReadUsesPlatformAndDecodesBase64(t *testing.T){
	record:=sourceTestSubscription("content://documents/sub");a:=sourceTestApp(t,record);a.platform=func(ctx context.Context,method string,args json.RawMessage)(json.RawMessage,error){if method!="file.read"{t.Fatalf("unexpected platform call: %s",method)};return mustJSON(map[string]any{"data":base64.StdEncoding.EncodeToString([]byte(sourceTestBody))}),nil}
	fetch,err:=a.fetchRecord(context.Background(),record,0,false);if err!=nil||string(fetch.body)!=sourceTestBody||!fetch.writeCache{t.Fatalf("file.read: %#v %v",fetch,err)}
	if _,_,err=a.store.ReadCache(record["url"].(string));!errors.Is(err,os.ErrNotExist){t.Fatalf("read wrote cache before commit: %v",err)}
}
func TestSourceCustomIdentityDoesNotInheritGlobal(t *testing.T){
	a:=sourceTestApp(t);_ = a.store.Update(func(doc map[string]any)error{doc["vars"]=map[string]any{"subscription_user_agent":"global","subscription_send_hwid":"true","subscription_hwid":"global-id","subscription_device_model":"global-model"};return nil})
	headers:=a.sourceHeaders(map[string]any{"identity":map[string]any{"send_hwid":false}})
	if headers["User-Agent"]!="LxBox-android"||headers["X-Hwid"]!=""||headers["X-Device-Model"]!=""{t.Fatalf("custom identity inherited globals: %#v",headers)}
}
func TestSourceImportRetainsExactOrigin(t *testing.T){
	a:=sourceTestApp(t);text:="  "+sourceTestBody+"\n";result,err:=a.importSource(context.Background(),mustJSON(map[string]any{"name":"manual","text":text,"future":map[string]any{"keep":true}}));if err!=nil{t.Fatal(err)}
	record:=result.(map[string]any)["source"].(map[string]any);if record["kind"]!="server"{t.Fatalf("wrong source: %#v",record)};if _,exists:=record["nodes"];exists{t.Fatal("manual record persisted derived nodes")}
	if record["origin"].(map[string]any)["raw"]!=text||!reflect.DeepEqual(record["future"],map[string]any{"keep":true}){t.Fatalf("origin or future field changed: %#v",record)}
}
func TestSourceDueUsesServerIntervalAndRetryGate(t *testing.T){
	now:=time.Now();record:=sourceTestSubscription("https://example.test/sub");record["update"]=map[string]any{"interval_hours":0};record["meta"]=map[string]any{"update_interval_hours":0}
	if sourceDue(record,0,now){t.Fatal("server-disabled auto-update was due")};record["meta"]=map[string]any{"update_interval_hours":1};if !sourceDue(record,0,now){t.Fatal("never fetched source should be due")}
	record["last_update_attempt"]=now.Add(-time.Minute).Format(time.RFC3339Nano);if sourceDue(record,0,now){t.Fatal("minimum retry interval was ignored")}
}
