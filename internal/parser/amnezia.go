package parser

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const maxAmneziaInflated = 4 << 20

func decodeAmneziaProfile(link string) ([]Node, []Diagnostic, bool) {
	link = strings.TrimSpace(link)
	if !strings.HasPrefix(strings.ToLower(link), "vpn://") { return nil,nil,false }
	payload,ok:=decodeBase64Flexible(strings.TrimSpace(link[len("vpn://"):]))
	if !ok { return nil,[]Diagnostic{{Code:"form_unrecognized",Severity:"error",Message:"vpn payload is not valid base64"}},true }
	text,err:=inflateAmnezia(payload)
	if err!=nil { return nil,[]Diagnostic{{Code:"form_unrecognized",Severity:"error",Message:err.Error()}},true }
	var profile map[string]any
	if err:=decodeJSONInto([]byte(text),&profile);err!=nil { return nil,[]Diagnostic{{Code:"form_unrecognized",Severity:"error",Message:"vpn payload is not a JSON profile"}},true }
	containers,ok:=profile["containers"].([]any);if !ok||len(containers)==0{return nil,[]Diagnostic{{Code:"form_unrecognized",Severity:"error",Message:"vpn profile has no containers"}},true}
	var nodes []Node;var diags []Diagnostic
	profileName:=firstString(profile,"description","hostName")
	for _,rawContainer:=range containers{
		container,ok:=rawContainer.(map[string]any);if !ok{continue}
		var ini string;var last map[string]any;kind:=""
		for _,protocol:=range []string{"awg","wireguard"}{proto,ok:=container[protocol].(map[string]any);if !ok{continue};candidate,meta:=extractAmneziaINI(proto);if candidate!=""{ini,last,kind=candidate,meta,protocol;break}}
		if ini==""{continue}
		ini=substituteAmneziaDNS(ini,profile)
		if mtu:=intValue(last["mtu"]);mtu!=nil{ini=amneziaMTU(ini,fmt.Sprint(mtu))}
		node,ok:=parseINI(ini,Source{},nil,"wg_ini",Source{});if !ok{diags=append(diags,Diagnostic{Code:"form_unrecognized",Severity:"warning",Message:"Amnezia container did not produce a usable WireGuard peer",Value:kind});continue}
		containerName:=firstString(container,"container","name")
		if profileName!=""&&containerName!=""{node.Name=profileName+" "+containerName}else if profileName!=""{node.Name=profileName}else if containerName!=""{node.Name=containerName}
		if node.Name==""{node.Name=fmt.Sprintf("wireguard-%s",firstPeerAddress(node.Canonical))}
		node.Key=stableKey(node.Protocol,node.Name,node.Canonical)
		nodes=append(nodes,node)
	}
	if len(nodes)==0{diags=append(diags,Diagnostic{Code:"form_unrecognized",Severity:"error",Message:"vpn profile contains no usable WireGuard/AmneziaWG config"})}
	return nodes,diags,true
}

func extractAmneziaINI(protocol map[string]any)(string,map[string]any){
	lastValue:=protocol["last_config"]
	var last map[string]any
	switch value:=lastValue.(type){case string:if decodeJSONInto([]byte(value),&last)!=nil{return "",nil};case map[string]any:last=value;default:return "",nil}
	ini:=stringValue(last["config"])
	if !isWGIni(ini){return "",nil}
	return ini,last
}

func inflateAmnezia(payload []byte)(string,error){
	if len(payload)>=6 {
		claimed:=binary.BigEndian.Uint32(payload[:4])
		if claimed>maxAmneziaInflated{return "",fmt.Errorf("vpn declared inflated size exceeds %d bytes",maxAmneziaInflated)}
		reader,err:=zlib.NewReader(bytes.NewReader(payload[4:]))
		if err==nil{
			defer reader.Close()
			limited,readErr:=io.ReadAll(io.LimitReader(reader,maxAmneziaInflated+1))
			if readErr==nil&&len(limited)<=maxAmneziaInflated&&(claimed==0||uint32(len(limited))==claimed){return string(limited),nil}
			if readErr==nil&&len(limited)>maxAmneziaInflated{return "",fmt.Errorf("vpn inflated payload exceeds %d bytes",maxAmneziaInflated)}
		}
	}
	if len(payload)>maxAmneziaInflated{return "",fmt.Errorf("vpn payload exceeds %d bytes",maxAmneziaInflated)}
	trimmed:=strings.TrimSpace(string(payload))
	if strings.HasPrefix(trimmed,"{"){var value any;if json.Unmarshal(payload,&value)==nil{return trimmed,nil}}
	return "",fmt.Errorf("vpn payload is neither qCompress nor JSON")
}

func substituteAmneziaDNS(ini string,profile map[string]any)string{
	values:=map[string]string{"$PRIMARY_DNS":strings.TrimSpace(stringValue(profile["dns1"])),"$SECONDARY_DNS":strings.TrimSpace(stringValue(profile["dns2"]))}
	lines:=strings.Split(strings.ReplaceAll(ini,"\r\n","\n"),"\n");out:=make([]string,0,len(lines))
	for _,line:=range lines{trimmed:=strings.TrimSpace(line);if strings.HasPrefix(strings.ToLower(trimmed),"dns")&&strings.Contains(trimmed,"="){left,right,_:=strings.Cut(line,"=");var parts []string;for _,raw:=range strings.Split(right,","){item:=strings.TrimSpace(raw);if strings.HasPrefix(item,"$"){item=values[item]};if item!=""{parts=append(parts,item)}};if len(parts)==0{continue};out=append(out,strings.TrimRight(left," ")+"= "+strings.Join(parts,", "));continue};out=append(out,line)}
	return strings.Join(out,"\n")
}

func amneziaMTU(ini,value string)string{
	if strings.TrimSpace(value)==""{return ini};lines:=strings.Split(strings.ReplaceAll(ini,"\r\n","\n"),"\n");section:="";insert:=-1
	for i,line:=range lines{trimmed:=strings.TrimSpace(line);if strings.HasPrefix(trimmed,"[")&&strings.HasSuffix(trimmed,"]"){section=strings.ToLower(trimmed);if section=="[interface]"{insert=i+1};continue};if section=="[interface]"{if key,_,ok:=strings.Cut(trimmed,"=");ok&&strings.EqualFold(strings.TrimSpace(key),"mtu"){return ini}}}
	if insert<0{return ini};lines=append(lines[:insert],append([]string{"MTU = "+value},lines[insert:]...)...);return strings.Join(lines,"\n")
}
