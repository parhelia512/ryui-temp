package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Leadaxe/lxbox/app/assets"
	"github.com/Leadaxe/lxbox/app/internal/parser"
	"github.com/Leadaxe/lxbox/app/internal/warp"
)

func (a *Application) warpScanProbe(ctx context.Context, arguments map[string]any) (map[string]any,error) {
	candidate,_:=arguments["candidate"].(map[string]any)
	if candidate==nil{return nil,errors.New("WARP scan candidate is missing")}
	document,err:=a.store.Snapshot();if err!=nil{return nil,err}
	protocol,_:=candidate["protocol"].(string)
	endpoint,_:=arguments["endpoint"].(string)
	var shareURI string
	if strings.HasPrefix(protocol,"masque_"){
		accountMap,_:=document["masque_account"].(map[string]any)
		account,err:=warp.MasqueAccountFromMap(accountMap);if err!=nil{return nil,fmt.Errorf("MASQUE account is required before scanning: %w",err)}
		account.Server,_=candidate["ip"].(string)
		if port,ok:=numberInt(candidate["port"]);ok{account.Port=int(port)}
		account.SNI,_=candidate["sni"].(string)
		shareURI=account.URI(strings.TrimPrefix(protocol,"masque_"))
	}else{
		accountMap,_:=document["warp_account"].(map[string]any)
		account,err:=warp.WarpAccountFromMap(accountMap);if err!=nil{return nil,fmt.Errorf("WARP account is required before scanning: %w",err)}
		account.Endpoint=endpoint
		if awg,ok:=candidate["awg"].(map[string]any);ok{account.AWG=awg}
		shareURI=account.URI(true,0)
	}
	parsed:=parser.Parse(ctx,[]byte(shareURI),parser.Options{ContractFS:assets.FS,KeepUnknown:true,Source:parser.Source{Kind:"scan",Name:"WARP candidate"}})
	if !parsed.Complete||len(parsed.Nodes)!=1{return nil,fmt.Errorf("candidate configuration could not be parsed: %v",parsed.Diagnostics)}
	node:=parsed.Nodes[0].SingBox();node["tag"]="warp-candidate"
	config:=map[string]any{"log":map[string]any{"level":"error"},"dns":map[string]any{"servers":[]any{map[string]any{"type":"local","tag":"physical-dns"}},"final":"physical-dns"},"route":map[string]any{"final":"warp-candidate","auto_detect_interface":true}}
	if parsed.Nodes[0].IsEndpoint(){config["endpoints"]=[]any{node}}else{config["outbounds"]=[]any{node}}
	if awg,ok:=candidate["awg"].(map[string]any);ok&&protocol=="awg"{for key,value:=range awg{node[key]=value}}
	request,err:=json.Marshal(map[string]any{"raw_config":config,"outbound_tag":"warp-candidate","link":"https://cp.cloudflare.com/generate_204","timeout_ms":10000});if err!=nil{return nil,err}
	value,err:=a.core.ProbeCandidate(ctx,request);if err!=nil{return nil,err}
	encoded,err:=json.Marshal(value);if err!=nil{return nil,err};var result map[string]any;if err=decode(encoded,&result);err!=nil{return nil,err};return result,nil
}
