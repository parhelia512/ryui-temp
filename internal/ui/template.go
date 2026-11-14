package ui

import (
	"context"
	"sort"
	"strings"

	"github.com/egoist/ryui/signal"
	ryui "github.com/egoist/ryui/ui"
)

// Template settings preserve the launcher's declared variable semantics and
// options; edits are staged in signals and committed together to vars.
func(s *session)templateSettings()ryui.Node{
	q:=s.scope();template:=signal.NewFunc[any](nil,nil);doc:=object{};filter:=signal.New("");forms:=[]*objectForm{}
	q.run("settings.get",nil,func(r reply){doc=asObject(r.value);q.run("assets.read",object{"name":"wizard_template.json"},func(r reply){template.Set(r.value)})})
	save:=func(){captured:=[]*capturedForm{};for _,f:=range forms{captured=append(captured,f.capture())};q.work(func(ctx context.Context)(reply,error){
		latest,err:=dispatch(ctx,"settings.get",nil);if err!=nil{return latest,err};vars:=asObject(asObject(latest.value)["vars"])
		for _,f:=range captured{value,err:=f.decode();if err!=nil{return reply{},err};for key,v:=range value{if list,ok:=v.([]any);ok{parts:=[]string{};for _,part:=range list{parts=append(parts,text(part))};vars[key]=strings.Join(parts,"\n")}else{vars[key]=text(v)}}}
		return dispatch(ctx,"settings.save",object{"vars":vars})
	},nil)}
	return page(section("VPN Settings",field("Filter",filter,false),primary("Save",save,q.busy),q.feedback()),ryui.Dynamic(func()ryui.Node{
		value:=template.Get();if value==nil{return ryui.StaticText(tr("Loading…"))};forms=nil;var rows []ryui.Node
		for _,raw:=range listOf(value,"sections"){
			sectionData:=asObject(raw);if text(sectionData["chapter"])=="internal"{continue};query:=strings.ToLower(filter.Get());if query!=""&&!strings.Contains(strings.ToLower(pretty(sectionData)),query){continue}
			fields:=object{};base:=object{};order:=[]any{}
			for _,dv:=range listOf(sectionData,"vars"){
				d:=asObject(dv);key:=text(d["name"]);if key==""{continue};kind:=text(d["type"]);if kind=="text"||kind=="outbound"||kind=="dns_servers"||kind=="interface"{kind="string"};if kind=="bool_spelled"{kind="bool"};if kind=="text_list"{kind="string_array"}
				definition:=object{"type":kind,"required":d["required"],"desc_en":first(d,"title","tooltip"),"default":d["default_value"]};options:=[]any{};for _,ov:=range listOf(d,"options"){if m,ok:=ov.(map[string]any);ok{options=append(options,m["value"])}else{options=append(options,ov)}};if len(options)>0{definition["values"]=options};fields[key]=definition;order=append(order,key)
				v,exists:=asObject(doc["vars"])[key];if !exists{v=d["default_value"]};if kind=="bool"{base[key]=text(v)=="true"||v==true}else if kind=="string_array"{if _,ok:=v.([]any);ok{base[key]=v}else{parts:=[]any{};for _,line:=range strings.Split(text(v),"\n"){if line!=""{parts=append(parts,line)}};base[key]=parts}}else{base[key]=v}
			}
			f,node:=formFields(object{"fields":fields,"order":order},base,func(message string){q.err.Set(message)});forms=append(forms,f);rows=append(rows,section(text(first(sectionData,"name","id")),node))
		}
		return ryui.Column(ryui.Style{Gap:10},rows...)
	}))
}

// DNS uses the same generated form controls, but takes the body fields from
// option/dns.go. A complete config is validated before committing any server.
func(s *session)dnsEditor()ryui.Node{
	q:=s.scope();items:=signal.NewFunc([]any{},nil);nav:=ryui.UseNavigator()
	load:=func(){q.run("config.get",nil,func(r reply){items.Set(listOf(asObject(r.value)["dns"],"servers"))})};load()
	b:=dnsSchemas()
	return page(section("DNS servers",actions(button("Add",func(){s.dnsForm(nav,b,object{},"",load)},q.busy),button("Refresh",load,q.busy)),q.feedback()),ryui.Dynamic(func()ryui.Node{
		var nodes []ryui.Node;for _,value:=range items.Get(){item:=asObject(value);tag:=text(item["tag"]);nodes=append(nodes,section(tag,ryui.StaticText(text(item["type"])),actions(button("Edit",func(){s.dnsForm(nav,b,item,tag,load)},q.busy),button("Delete",func(){confirm("Delete DNS server?",func(){q.run("config.get",nil,func(r reply){config:=asObject(r.value);dns:=asObject(config["dns"]);out:=[]any{};for _,v:=range listOf(dns,"servers"){if text(asObject(v)["tag"])!=tag{out=append(out,v)}};dns["servers"]=out;config["dns"]=dns;q.run("config.save",config,func(reply){load()})})})},q.busy))))};return ryui.Column(ryui.Style{Gap:10},nodes...)
	}))
}

func dnsSchemas()map[string]object{
	result:=map[string]object{};remote:=object{"server":object{"type":"string","required":true},"server_port":object{"type":"uint16","min":float64(1),"max":float64(65535)},"detour":object{"type":"string"},"domain_resolver":object{"type":"string"}}
	for _,kind:=range []string{"udp","tcp","tls","https","quic","h3","local","hosts","fakeip","dhcp","mdns","group"}{fields:=object{};if kind=="udp"||kind=="tcp"||kind=="tls"||kind=="https"||kind=="quic"||kind=="h3"{for k,v:=range remote{fields[k]=v}};if kind=="tls"||kind=="https"||kind=="quic"||kind=="h3"{fields["tls"]=object{"type":"object","fields":object{"enabled":object{"type":"bool"},"server_name":object{"type":"string"},"insecure":object{"type":"bool"},"alpn":object{"type":"string_array"},"certificate_path":object{"type":"string_array"}}}};switch kind{case "https","h3":fields["path"]=object{"type":"string"};fields["method"]=object{"type":"string"};fields["headers"]=object{"type":"object"};case "hosts":fields["path"]=object{"type":"string_array"};fields["predefined"]=object{"type":"object"};case "fakeip":fields["inet4_range"]=object{"type":"string"};fields["inet6_range"]=object{"type":"string"};case "dhcp","mdns":fields["interface"]=object{"type":"string"};case "group":fields["servers"]=object{"type":"string_array","required":true};fields["hosts"]=object{"type":"string_array"};fields["mode"]=object{"type":"string"};fields["error_ttl"]=object{"type":"duration"};fields["win_ttl"]=object{"type":"duration"};case "local":fields["prefer_go"]=object{"type":"bool"};fields["neighbor_domain"]=object{"type":"string_array"}};result[kind]=object{"fields":fields}}
	return result
}

func(s *session)dnsForm(nav *ryui.Navigator,schemas map[string]object,initial object,originalTag string,after func()){
	nav.Push(func()ryui.Node{q:=s.scope();kind:=signal.New(text(initial["type"]));tag:=signal.New(text(initial["tag"]));types:=[]string{};for name:=range schemas{types=append(types,name)};sort.Strings(types);var form *objectForm
		return page(section("DNS server",choice("Type",kind,types,types),field("Tag",tag,false),ryui.Dynamic(func()ryui.Node{base:=initial;if text(initial["type"])!=kind.Get(){base=object{}};var node ryui.Node;form,node=formFields(schemas[kind.Get()],base,func(message string){q.err.Set(message)});return node}),primary("Validate and save",func(){if form==nil{return};captured:=form.capture();serverType,serverTag:=kind.Peek(),tag.Peek();q.work(func(ctx context.Context)(reply,error){server,err:=captured.decode();if err!=nil{return reply{},err};server["type"],server["tag"]=serverType,serverTag;latest,err:=dispatch(ctx,"config.get",nil);if err!=nil{return latest,err};config:=asObject(latest.value);dns:=asObject(config["dns"]);list:=append([]any{},listOf(dns,"servers")...);found:=false;for i,v:=range list{if originalTag!=""&&text(asObject(v)["tag"])==originalTag{list[i]=server;found=true;break}};if !found{list=append(list,server)};dns["servers"]=list;config["dns"]=dns;return dispatch(ctx,"config.save",config)},func(reply){nav.Pop();after()})},q.busy),q.feedback(),jsonView(q.result)))
	},ryui.ScreenOptions{Title:ryui.Val(tr("DNS server"))})
}
