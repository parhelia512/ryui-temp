package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Leadaxe/lxbox/app/internal/automation"
	"github.com/Leadaxe/lxbox/app/internal/ruleset"
)

func (a *Application) initializeServices()error{
	a.automation=automation.NewEngine(a.automationAction,automation.WithEventSink(func(ctx context.Context,event automation.Event)error{
		a.events.emit("automation.event",event)
		_,err:=a.platformCall(ctx,"automation.emit",event);return err
	}))
	a.refreshAutomation()
	return a.automation.Start(a.ctx)
}

func boolValue(value any)bool{
	switch v:=value.(type){case bool:return v;case string:return strings.EqualFold(v,"true")||v=="1";case json.Number:return v.String()=="1";case float64:return v==1};return false
}

func (a *Application) refreshAutomation(){
	if a.automation==nil{return};doc,err:=a.store.Snapshot();if err!=nil{return};vars,_:=doc["vars"].(map[string]any)
	a.automation.SetSettings(automation.Settings{ReceiveEnabled:boolValue(vars["automation_receive_enabled"]),ExplainerShownV1:boolValue(vars["automation_explainer_shown_v1"]),AppFunctionsEnabled:boolValue(vars["appfunctions_enabled"]),EventGates:automation.EventGates{Lifecycle:boolValue(vars["automation_emit_lifecycle"]),State:boolValue(vars["automation_emit_state"]),Subs:boolValue(vars["automation_emit_subs"]),Health:boolValue(vars["automation_emit_health"])}})
}

func (a *Application) dispatchService(ctx context.Context,method string,args json.RawMessage)(any,error){
	switch method{
	case "automation.get":return a.automation.Settings(),nil
	case "automation.save":
		var p automation.Settings;if err:=decode(args,&p);err!=nil{return nil,err}
		a.mutation.Lock();defer a.mutation.Unlock()
		err:=a.store.Update(func(doc map[string]any)error{vars,_:=doc["vars"].(map[string]any);if vars==nil{vars=map[string]any{};doc["vars"]=vars};vars["automation_receive_enabled"]=p.ReceiveEnabled;vars["automation_explainer_shown_v1"]=p.ExplainerShownV1;vars["appfunctions_enabled"]=p.AppFunctionsEnabled;vars["automation_emit_lifecycle"]=p.Lifecycle;vars["automation_emit_state"]=p.State;vars["automation_emit_subs"]=p.Subs;vars["automation_emit_health"]=p.Health;return nil})
		if err==nil{a.automation.SetSettings(p);a.revision++};return p,err
	case "automation.run","automation.action":
		var p struct{Action string `json:"action"`;Cmd string `json:"cmd"`;Args json.RawMessage `json:"args"`};if err:=decode(args,&p);err!=nil{return nil,err};if p.Action==""{p.Action=p.Cmd};if p.Action==""{return nil,errors.New("automation action is required")};return a.automation.Dispatch(ctx,p.Action,p.Args)
	case "rulesets.download","rulesets.read","rulesets.metadata":
		var p struct{ID string `json:"id"`;URL string `json:"url"`;Conditional bool `json:"conditional"`};if err:=decode(args,&p);err!=nil{return nil,err}
		client,err:=ruleset.New(a.dataDir);if err!=nil{return nil,err}
		switch method{case "rulesets.download":r:=client.Download(ctx,p.ID,p.URL,p.Conditional);if r.Err!=nil{return r,r.Err};a.events.emit("ruleset.updated",map[string]any{"id":p.ID,"path":r.Path});return r,nil
		case "rulesets.read":body,meta,err:=client.ReadOffline(ctx,p.ID);if err!=nil{return nil,err};return map[string]any{"data":body,"meta":meta},nil
		default:return client.ReadMeta(p.ID)}
	default:return a.dispatchExtension(ctx,method,args)
	}
}

func (a *Application) automationAction(ctx context.Context,method string,args json.RawMessage)(any,error){
	var p map[string]any;if len(args)>0{if err:=decode(args,&p);err!=nil{return nil,err}};if p==nil{p=map[string]any{}}
	callCore:=func(name string,value any)(any,error){raw,err:=json.Marshal(value);if err!=nil{return nil,err};return a.core.Call(ctx,name,raw)}
	switch method{
	case "start-vpn":return a.dispatch(ctx,"vpn.start",json.RawMessage(`{}`))
	case "stop-vpn":return a.dispatch(ctx,"vpn.stop",json.RawMessage(`{}`))
	case "toggle-vpn":
		raw,err:=json.Marshal(a.core.Status());if err!=nil{return nil,err};var state struct{Running bool `json:"running"`};if err=json.Unmarshal(raw,&state);err!=nil{return nil,err};if state.Running{return a.dispatch(ctx,"vpn.stop",json.RawMessage(`{}`))};return a.dispatch(ctx,"vpn.start",json.RawMessage(`{}`))
	case "switch-node":return callCore("ccSelectOutbound",p)
	case "set-group":
		group,_:=p["group"].(string);if group==""{return nil,errors.New("group is required")}
		a.mutation.Lock();defer a.mutation.Unlock();err:=a.store.Update(func(doc map[string]any)error{vars,_:=doc["vars"].(map[string]any);if vars==nil{vars=map[string]any{};doc["vars"]=vars};vars["home_direction"]=group;return nil});if err==nil{a.revision++;a.events.emit("group.changed",p)};return p,err
	case "rebuild-config":return a.buildConfig(ctx)
	case "refresh-subs":return a.refreshAll(ctx,args)
	case "reset-network":return callCore("ccResetNetwork",p)
	case "urltest-group":if tag,ok:=p["group"];ok{p["tag"]=tag};return callCore("ccUrlTestGroup",p)
	case "urltest-all":return callCore("ccUrlTestAll",p)
	default:return nil,fmt.Errorf("unknown automation action %q",method)
	}
}
