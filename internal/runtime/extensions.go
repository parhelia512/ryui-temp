package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Leadaxe/lxbox/app/assets"
	"github.com/Leadaxe/lxbox/app/internal/diagnostics"
	"github.com/Leadaxe/lxbox/app/internal/warp"
)

func (a *Application) dispatchExtension(ctx context.Context,method string,raw json.RawMessage)(any,error){
	var args map[string]any;if err:=decode(raw,&args);err!=nil{return nil,err};if args==nil{args=map[string]any{}}
	switch{
	case strings.HasPrefix(method,"warp."):
		endpoints,err:=assets.Read("warp_endpoints.json");if err!=nil{return nil,err}
		client:=warp.NewClient(warp.Options{EndpointJSON:endpoints,ScanProbe:a.warpScanProbe,ScanConcurrency:1})
		value,err:=client.Dispatch(ctx,method,args)
		if err!=nil{return value,err}
		if method=="warp.register"||method=="warp.register.masque"{
			a.mutation.Lock();defer a.mutation.Unlock()
			err=a.store.Update(func(doc map[string]any)error{key:="warp_account";if method=="warp.register.masque"{key="masque_account"};doc[key]=value;return nil})
			if err==nil{a.revision++;a.events.emit("warp.account.changed",map[string]any{"masque":method=="warp.register.masque"})}
		}
		return value,err
	case strings.HasPrefix(method,"diagnostics."):
		if method=="diagnostics.run"{kind,_:=args["kind"].(string);switch kind{case "url","http","dns","tcp":return a.networkDiagnostic(ctx,args)}}
		probe:=func(ctx context.Context,p map[string]any)(map[string]any,error){return a.diagnosticCore(ctx,"ccStartProbe",p)}
		connection:=func(ctx context.Context,p map[string]any)(map[string]any,error){return a.diagnosticCore(ctx,"ccStartConnectionTest",p)}
		client:=diagnostics.NewClient(diagnostics.Options{Probe:probe,ConnectionTest:connection,PathMTU:&platformMTU{app:a}})
		return client.Dispatch(ctx,method,args)
	case method=="transfer.send_backup":
		return a.sendBackup(ctx,raw)
	case strings.HasPrefix(method,"transfer.receive."):
		return a.receiveTransfer(ctx,method,raw)
	case strings.HasPrefix(method,"transfer."):
		name:=strings.TrimPrefix(method,"transfer.")
		if name=="saf.import"||name=="saf.export"{return a.platformCall(ctx,"transfer."+name,args)}
		return a.transferClient().Dispatch(ctx,name,args)
	case strings.HasPrefix(method,"storage."):
		return a.migrationDispatch(ctx,method,raw)
	case strings.HasPrefix(method,"reports.")||method=="memory.get"||method=="pprof.capture"||method=="config.format":
		return a.reportsDispatch(ctx,method,raw)
	case strings.HasPrefix(method,"debug."):
		return a.debugDispatch(ctx,method,args)
	default:return nil,fmt.Errorf("unknown application method %q",method)
	}
}

func (a *Application) diagnosticCore(ctx context.Context,method string,args map[string]any)(map[string]any,error){
	payload,err:=json.Marshal(args);if err!=nil{return nil,err};value,err:=a.core.Call(ctx,method,payload);if err!=nil{return nil,err};encoded,err:=json.Marshal(value);if err!=nil{return nil,err};var result map[string]any;if err=json.Unmarshal(encoded,&result);err!=nil{return nil,err};return result,nil
}

type platformMTU struct{app *Application}
func(p *platformMTU)call(ctx context.Context,method string,args any,out any)error{
	result,err:=p.app.platformCall(ctx,method,args);if err!=nil{return err};raw,err:=json.Marshal(result);if err!=nil{return err};return json.Unmarshal(raw,out)
}
func(p *platformMTU)Network(ctx context.Context)(diagnostics.PathMTUNetwork,error){var r diagnostics.PathMTUNetwork;err:=p.call(ctx,"path_mtu.network",map[string]any{},&r);return r,err}
func(p *platformMTU)Resolve(ctx context.Context,target string)(string,error){var r struct{IP string `json:"ip"`};err:=p.call(ctx,"path_mtu.resolve",map[string]any{"target":target},&r);return r.IP,err}
func(p *platformMTU)Probe(ctx context.Context,ip string,size,timeout,sequence int)(diagnostics.PathMTUProbeReply,error){var r diagnostics.PathMTUProbeReply;err:=p.call(ctx,"path_mtu.probe",map[string]any{"ip":ip,"size":size,"timeoutMs":timeout,"sequence":sequence},&r);return r,err}
