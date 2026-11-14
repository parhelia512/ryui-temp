package ui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/egoist/ryui/signal"
	ryui "github.com/egoist/ryui/ui"
)

// Registry forms use the preserved schema's types, nested objects, references,
// ordering, enum choices, descriptions and numeric limits. Unmentioned fields
// remain in the base object; validation belongs to the real core.
type registryBundle struct { Schemas map[string]object; Definitions map[string]object }
type formEntry struct {
	key string
	schema object
	present *signal.Signal[bool]
	value *signal.Signal[string]
	boolean *signal.Signal[bool]
	child *objectForm
}
type objectForm struct { base object; entries []*formEntry }
type capturedEntry struct { Key string; Schema object; Present bool; Value string; Boolean bool; Child *capturedForm }
type capturedForm struct { Base object; Entries []capturedEntry }

func (f *objectForm) capture() *capturedForm {
	out := &capturedForm{Base: f.base}
	for _, entry := range f.entries {
		e := capturedEntry{Key: entry.key, Schema: entry.schema, Present: entry.present.Peek()}
		if entry.value != nil { e.Value = entry.value.Peek() }
		if entry.boolean != nil { e.Boolean = entry.boolean.Peek() }
		if entry.child != nil { e.Child = entry.child.capture() }
		out.Entries = append(out.Entries, e)
	}
	return out
}

func (f *capturedForm) decode() (object, error) {
	var result object
	if err := json.Unmarshal([]byte(pretty(f.Base)), &result); err != nil { return nil, err }
	if result == nil { result = object{} }
	for _, entry := range f.Entries {
		if !entry.Present { delete(result, entry.Key); continue }
		var value any
		kind := text(entry.Schema["type"])
		switch {
		case entry.Child != nil:
			child, err := entry.Child.decode(); if err != nil { return nil, fmt.Errorf("%s: %w",entry.Key,err) }; value = child
		case kind == "bool": value = entry.Boolean
		case kind == "int" || kind == "uint16":
			n, err := strconv.ParseInt(strings.TrimSpace(entry.Value), 10, 64)
			if err != nil { return nil, fmt.Errorf("%s: %w", entry.Key, err) }
			if min,ok := entry.Schema["min"].(float64); ok && float64(n)<min { return nil,fmt.Errorf("%s: minimum %v",entry.Key,min) }
			if max,ok := entry.Schema["max"].(float64); ok && float64(n)>max { return nil,fmt.Errorf("%s: maximum %v",entry.Key,max) }
			value = n
		case kind == "object" || kind == "array" || kind == "int_array":
			if err := json.Unmarshal([]byte(entry.Value), &value); err != nil { return nil,fmt.Errorf("%s: %w",entry.Key,err) }
		case kind == "string_array" || kind == "listable_string" || kind == "list" || kind == "text_list":
			if strings.HasPrefix(strings.TrimSpace(entry.Value), "[") {
				if err := json.Unmarshal([]byte(entry.Value), &value); err != nil { return nil,fmt.Errorf("%s: %w",entry.Key,err) }
			} else {
				parts := []string{}
				for _, line := range strings.Split(strings.ReplaceAll(entry.Value,"\r\n","\n"),"\n") { if line = strings.TrimSpace(line); line != "" { parts = append(parts,line) } }
				value = parts
			}
		default: value = entry.Value
		}
		if entry.Schema["required"] == true && (value == nil || value == "") { return nil,fmt.Errorf("%s: %s",entry.Key,tr("Required")) }
		result[entry.Key] = value
	}
	return result,nil
}

func loadRegistry(ctx context.Context) (*registryBundle,error) {
	bundle := &registryBundle{Schemas:map[string]object{}, Definitions:map[string]object{}}
	for _, name := range []string{"dialer","tls","multiplex","transports"} {
		r,err := dispatch(ctx,"assets.read",object{"name":"contract/registry/"+name+".json"})
		if err != nil { return nil,err }; bundle.Definitions[name] = asObject(r.value)
	}
	for _, protocol := range []string{"socks","http","shadowsocks","trojan","vless","vmess","hysteria","hysteria2","tuic","anytls","naive","ssh","wireguard","tailscale","openconnect","openvpn-client","masque","trusttunnel","chain"} {
		r,err := dispatch(ctx,"assets.read",object{"name":"contract/registry/protocols/"+protocol+".json"})
		if err != nil { continue }
		entry := asObject(r.value)
		body := asObject(entry["body"])
		if len(asObject(body["fields"])) == 0 { continue }
		bundle.Schemas[protocol] = bundle.resolve(body,0)
	}
	// These are the exact fields of option/group.go; group registry describes
	// the URI dialect rather than a body schema, so it cannot be used as-is.
	common := object{"outbounds":object{"type":"string_array","required":true,"desc_en":"Outbound tags, one per line."},"interrupt_exist_connections":object{"type":"bool"}}
	selector := object{}
	for key,value := range common { selector[key]=value }
	selector["default"] = object{"type":"string"}
	bundle.Schemas["selector"] = object{"fields":selector}
	auto := object{}
	for key,value := range common { auto[key]=value }
	for _,key := range []string{"url","interval","idle_timeout"} { auto[key]=object{"type":"string"} }
	auto["tolerance"] = object{"type":"int","min":float64(0),"max":float64(65535)}
	auto["mode"] = object{"type":"enum","values":[]any{"least_test","round_robin","failover"}}
	auto["balancer"] = object{"type":"object","fields":object{"pool":object{"type":"int","min":float64(1)},"pool_tolerance":object{"type":"int","min":float64(0),"max":float64(65535)},"sticky_hash":object{"type":"string_array"}}}
	bundle.Schemas["urltest"] = object{"fields":auto}
	return bundle,nil
}

func (b *registryBundle) resolve(schema object, depth int) object {
	if depth > 8 { return schema }
	out := object{}
	for key,value := range schema { out[key]=value }
	fields := object{}
	for key,value := range asObject(schema["fields"]) {
		definition := asObject(value)
		if text(definition["type"]) == "ref" {
			ref := text(definition["ref"])
			parts := strings.Split(ref,".")
			doc := b.Definitions[parts[0]]
			sectionName := "body"
			if len(parts)>1 && parts[1]=="common" { sectionName="common" }
			resolved := asObject(doc[sectionName])
			if definition["inline"] == true {
				for nested,nestedValue := range asObject(b.resolve(resolved,depth+1)["fields"]) { fields[nested]=nestedValue }
				continue
			}
			if parts[0]=="dialer" {
				lookup := key; if len(parts)>2 { lookup=parts[2] }
				resolved = asObject(asObject(resolved["fields"])[lookup])
			} else { resolved["type"]="object" }
			merged := object{}
			for name,v := range resolved { merged[name]=v }
			for name,v := range definition { if name!="type" && name!="ref" { merged[name]=v } }
			definition=merged
		}
		fields[key]=b.resolve(definition,depth+1)
	}
	if len(fields)>0 { out["fields"]=fields }
	variants := object{}
	for key,value := range asObject(schema["variants"]) { variants[key]=b.resolve(asObject(value),depth+1) }
	if len(variants)>0 { out["variants"]=variants }
	return out
}

func formFields(schema, base object, onError func(string)) (*objectForm,ryui.Node) {
	form := &objectForm{base:base}
	fields := asObject(schema["fields"])
	keys := []string{}
	seen := map[string]bool{}
	for _,value := range listOf(schema,"order") { key:=text(value); if fields[key]!=nil && !seen[key] { keys=append(keys,key); seen[key]=true } }
	remaining := []string{}
	for key := range fields { if !seen[key] && key!="*" { remaining=append(remaining,key) } }
	sort.Strings(remaining); keys=append(keys,remaining...)
	var nodes []ryui.Node
	for _,key := range keys {
		definition := asObject(fields[key])
		if definition["managed"] == true || text(definition["type"]) == "ref" { continue }
		_,exists := base[key]
		required := definition["required"]==true
		entry := &formEntry{key:key,schema:definition,present:signal.New(exists||required)}
		form.entries=append(form.entries,entry)
		label := key
		if desc:=text(definition["desc_en"]); desc!="" { label += " — "+tr(desc) }
		var input ryui.Node
		kind := text(definition["type"])
		if kind=="bool" {
			value,_ := base[key].(bool); if !exists { value,_=definition["default"].(bool) }
			entry.boolean=signal.New(value)
			input=ryui.Toggle(ryui.ToggleProps{Value:entry.boolean})
		} else if len(asObject(definition["fields"]))>0 {
			input=ryui.Show(entry.present,func()ryui.Node{ child,node:=formFields(definition,asObject(base[key]),onError); entry.child=child; return node })
		} else if len(asObject(definition["variants"]))>0 {
			discriminator:=text(definition["discriminator"]); if discriminator=="" { discriminator="type" }
			typeName:=signal.New(text(asObject(base[key])[discriminator]))
			options:=[]string{}; for name:=range asObject(definition["variants"]) {options=append(options,name)};sort.Strings(options)
			input=ryui.Show(entry.present,func()ryui.Node{return ryui.Column(ryui.Style{Gap:8},choice(discriminator,typeName,options,options),ryui.Dynamic(func()ryui.Node{
				variant:=asObject(asObject(definition["variants"])[typeName.Get()]); childBase:=object{};for k,v:=range asObject(base[key]){childBase[k]=v};childBase[discriminator]=typeName.Get();child,node:=formFields(variant,childBase,onError);entry.child=child;return node
			}))})
		} else {
			value:=text(base[key])
			multi:=kind=="object"||kind=="array"||kind=="string_array"||kind=="listable_string"||kind=="list"||kind=="int_array"||kind=="text_list"
			if exists && multi { value=pretty(base[key]) }
			if !exists && definition["default"]!=nil { value=text(definition["default"]) }
			entry.value=signal.New(value)
			if definition["secret"]==true {input=secret(key,entry.value)} else {input=field(key,entry.value,multi)}
			if options:=listOf(definition,"values");len(options)>0 && len(options)<18 { values:=[]string{};for _,v:=range options{values=append(values,text(v))};input=ryui.Column(ryui.Style{Gap:6},input,choice("Value",entry.value,values,values)) }
		}
		var heading ryui.Node
		if required {heading=ryui.StaticText(label+" *",ryui.Style{Font:ryui.Footnote})} else {heading=ryui.Row(ryui.Style{Gap:8,Align:ryui.AlignCenter},ryui.StaticText(label,ryui.Style{Grow:1,Font:ryui.Footnote}),ryui.Toggle(ryui.ToggleProps{Value:entry.present}))}
		nodes=append(nodes,ryui.Column(ryui.Style{Gap:6,Padding:ryui.All(8)},heading,input))
	}
	return form,ryui.Column(ryui.Style{Gap:8},nodes...)
}

func (s *session) registryEditor(title, sectionKey string) ryui.Node {
	q:=s.scope()
	bundle:=signal.NewFunc[*registryBundle](nil,nil)
	items:=signal.NewFunc([]any{},nil)
	load:=func(){q.work(func(ctx context.Context)(reply,error){r,err:=dispatch(ctx,"config.get",nil);if err!=nil{return r,err};return r,nil},func(r reply){items.Set(listOf(r.value,sectionKey))})}
	q.work(func(ctx context.Context)(reply,error){b,err:=loadRegistry(ctx);return reply{value:b},err},func(r reply){bundle.Set(r.value.(*registryBundle));load()})
	nav:=ryui.UseNavigator()
	return page(section(title,actions(button("Refresh",load,q.busy),button("Add",func(){if b:=bundle.Peek();b!=nil{s.nodeForm(nav,b,sectionKey,object{},"",load)}},q.busy)),q.feedback()),
		ryui.Dynamic(func()ryui.Node{
			b:=bundle.Get();if b==nil{return ryui.StaticText(tr("Loading…"))};var rows []ryui.Node
			for _,value:=range items.Get(){item:=asObject(value);tag:=text(item["tag"]);rows=append(rows,section(nameOf(item),ryui.StaticText(text(item["type"])),button("Edit",func(){s.nodeForm(nav,b,sectionKey,item,tag,load)},q.busy)))}
			return ryui.Column(ryui.Style{Gap:10},rows...)
		}))
}

func(s *session)nodeForm(nav *ryui.Navigator,b *registryBundle,sectionKey string,initial object,originalTag string,after func()){
	nav.Push(func()ryui.Node{
		q:=s.scope();typeName:=signal.New(text(initial["type"]));tag:=signal.New(text(initial["tag"]));options:=[]string{};for name:=range b.Schemas{options=append(options,name)};sort.Strings(options)
		var form *objectForm
		save:=func(){if form==nil{q.err.Set(tr("Select a protocol"));return};captured:=form.capture();nodeType,nodeTag:=typeName.Peek(),tag.Peek();q.work(func(ctx context.Context)(reply,error){
			node,err:=captured.decode();if err!=nil{return reply{},err};if nodeTag==""{return reply{},errors.New(tr("Tag is required"))};node["type"],node["tag"]=nodeType,nodeTag
			latest,err:=dispatch(ctx,"config.get",nil);if err!=nil{return latest,err};config:=asObject(latest.value);list:=append([]any{},listOf(config,sectionKey)...);found:=false
			for i,value:=range list{if text(asObject(value)["tag"])==originalTag&&originalTag!=""{list[i]=node;found=true;break}}
			if !found{for _,value:=range list{if text(asObject(value)["tag"])==nodeTag{return reply{},errors.New(tr("Tag already exists"))}};list=append(list,node)};config[sectionKey]=list;return dispatch(ctx,"config.save",config)
		},func(reply){nav.Pop();after()})}
		return page(section("Node settings",choice("Type",typeName,options,options),field("Tag",tag,false),ryui.Dynamic(func()ryui.Node{
			schema:=b.Schemas[typeName.Get()];if schema==nil{return ryui.StaticText(tr("Select a protocol"))};base:=initial;if text(initial["type"])!=typeName.Get(){base=object{}};var node ryui.Node;form,node=formFields(schema,base,func(message string){q.err.Set(message)});return node
		}),primary("Validate and save",save,q.busy),q.feedback(),jsonView(q.result)))
	},ryui.ScreenOptions{Title:ryui.Val(tr("Node settings"))})
}
