package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const NodeBudgetDefault = 1000
const NodeBudgetUnknownSize = 1 << 30

// NodeBudgetOptions supplies immutable context. NetworkRefresh must contain only
// sources whose HTTP response was successfully fetched AND parsed. Offline reads
// must leave it empty: cache rehydration is not evidence that a node disappeared.
// Parsed input must include disabled nodes, after import rules and before cuts.
// Both emitted sing-box maps and parser detail maps {canonical,name,enabled,...}
// are accepted. Folder details can carry member_index to associate member flags.
// RuleEnable/RuleDisable contain final rule decisions by provider identity, not
// emitted tags; they are persisted only for NetworkRefresh sources.
// PreviousBySource contains the complete previous emitted/detail node set. On a
// network refresh a missing previous body clears a stale core rejection, exactly
// as in refreshSubscriptionVerdicts in the original application.
// IncludeID and UnknownSizeIDs support quota estimation before a target is parsed.
// Protected can be supplied directly, or collected from Document plus records.
type NodeBudgetOptions struct {
	Document map[string]any
	Protected NodeBudgetProtectedTags
	IncludeID string
	UnknownSizeIDs map[string]bool
	Now time.Time
	NetworkRefresh map[string]bool
	PreviousBySource map[string][]map[string]any
	RuleEnable map[string]map[string]bool
	RuleDisable map[string]map[string]bool
}

type NodeBudgetProtectedTags struct {
	FinalTags map[string]bool
	RawBySource map[string]map[string]bool
	DefaultPatterns []string
}

type NodeBudgetSourceProtection struct {
	// Prefix is the record tag_policy.prefix, including its stored separator.
	Prefix string
	FinalTags map[string]bool
	RawTags map[string]bool
	DefaultPatterns []string
}

type NodeBudgetResult struct {
	// NodesBySource is for builders: enabled, retained sing-box entries only.
	NodesBySource map[string][]map[string]any `json:"nodes_by_source"`
	// DetailsBySource retains disabled nodes and warning/identity/cut metadata.
	// Canonical bodies are clean: overlay fields never enter a core config.
	DetailsBySource map[string][]map[string]any `json:"details_by_source"`
	Quotas map[string]int `json:"quotas"`
	TotalBySource map[string]int `json:"total_by_source"`
	KeptBySource map[string]int `json:"kept_by_source"`
	Manual int `json:"manual"`
	// RecordPatches contains only changed fields. The caller must commit these
	// under its existing generation/source/revision barrier; this module never
	// writes a store. Unknown record/warning/disabled fields remain untouched.
	RecordPatches map[string]map[string]any `json:"record_patches"`
	Diagnostics []any `json:"diagnostics"`
}

type budgetNode struct {
	body map[string]any
	detail map[string]any
	name string
	identity string
	legacyHash string
	member int
	enabled bool
	enabledKnown bool
	counted bool
}

// ApplyNodeBudget is the compact, read-only API requested by the runtime. Inputs
// must be FULL parsed source sets, including disabled nodes. No TTL aging or
// rejection clearing occurs here. Use AllocateNodeBudget for details and patches.
func ApplyNodeBudget(records []map[string]any,nodesBySource map[string][]map[string]any,limit int)(map[string][]map[string]any,[]any,error){
	result,err:=AllocateNodeBudget(records,nodesBySource,limit)
	return result.NodesBySource,result.Diagnostics,err
}

// AllocateNodeBudget reproduces node_budget.dart: manual sources take priority
// and are never cut; enabled subscriptions receive equal water-filled shares;
// remainders go in record order. Groups and Tailscale cost zero. Protected nodes
// survive even when they exceed a quota. Limit zero means zero subscription
// budget (manual/protected/exempt nodes still survive); a negative limit is an
// error, not an undocumented unlimited mode. Options is optional, at most one.
func AllocateNodeBudget(records []map[string]any,parsed map[string][]map[string]any,limit int,options ...NodeBudgetOptions)(NodeBudgetResult,error){
	out:=NodeBudgetResult{NodesBySource:map[string][]map[string]any{},DetailsBySource:map[string][]map[string]any{},Quotas:map[string]int{},TotalBySource:map[string]int{},KeptBySource:map[string]int{},RecordPatches:map[string]map[string]any{},Diagnostics:[]any{}}
	if limit<0{return out,errors.New("node budget must not be negative")};if len(options)>1{return out,errors.New("at most one NodeBudgetOptions is supported")}
	opt:=NodeBudgetOptions{};if len(options)==1{opt=options[0]};if opt.Now.IsZero(){opt.Now=time.Now().UTC()}
	protected,findings:=CollectNodeBudgetProtectedTags(opt.Document,records);out.Diagnostics=append(out.Diagnostics,findings...);budgetMergeProtection(&protected,opt.Protected)
	byID:=map[string][]budgetNode{};seen:=map[string]bool{};var failures []error
	for index,record:=range records{
		id:=budgetString(record,"id");kind:=budgetString(record,"kind");if id==""{if kind=="chain"||kind=="auto"||!budgetBool(record,"enabled",true){continue};failures=append(failures,fmt.Errorf("sources[%d] has no id",index));continue};if seen[id]{failures=append(failures,fmt.Errorf("duplicate source id %q",id));continue};seen[id]=true
		nodes,err:=budgetNormalizeNodes(parsed[id]);if err!=nil{failures=append(failures,fmt.Errorf("source %s: %w",id,err));continue}
		if kind=="folder"{nodes,err=budgetFolderMembers(record,nodes);if err!=nil{failures=append(failures,fmt.Errorf("source %s: %w",id,err));continue}}
		byID[id]=nodes
		if budgetBool(record,"enabled",true)&&(kind=="server"||kind=="folder"){
			if _,exists:=parsed[id];!exists{failures=append(failures,fmt.Errorf("manual source %s has no full parsed node set; priority cannot be calculated",id));continue}
			for _,node:=range nodes{if node.enabled&&node.counted{out.Manual++}}
		}
	}
	if len(failures)>0{return out,errors.Join(failures...)}
	ids:=[]string{};sizes:=[]int{}
	for _,record:=range records{
		id:=budgetString(record,"id");if budgetString(record,"kind")!="subscription"||(!budgetBool(record,"enabled",true)&&id!=opt.IncludeID){continue}
		size:=0
		if opt.UnknownSizeIDs[id]{size=NodeBudgetUnknownSize}else if nodes,exists:=parsed[id];exists{_ = nodes;for _,node:=range byID[id]{if node.counted{size++}}}else{size=budgetStoredSize(record);if size>0{out.Diagnostics=append(out.Diagnostics,budgetDiagnostic("budget_size_estimated",id,"subscription parsed nodes are unavailable; stored full size reserves its share"))}}
		ids=append(ids,id);sizes=append(sizes,size)
	}
	alloc:=SplitNodeBudget(limit,out.Manual,sizes);for i,id:=range ids{out.Quotas[id]=alloc[i]}
	for _,record:=range records{
		id:=budgetString(record,"id");if id==""{continue};kind:=budgetString(record,"kind");nodes:=byID[id];out.NodesBySource[id]=[]map[string]any{};out.DetailsBySource[id]=[]map[string]any{};out.TotalBySource[id]=len(nodes)
		if kind!="server"&&kind!="folder"&&kind!="subscription"{continue}
		if _,available:=parsed[id];!available{continue}
		prepared,patch,diagnostics,err:=budgetApplyOverlays(record,nodes,opt);out.Diagnostics=append(out.Diagnostics,diagnostics...);if err!=nil{return out,fmt.Errorf("source %s overlay: %w",id,err)};nodes=prepared
		keep:=make([]bool,len(nodes));for i:=range keep{keep[i]=true}
		if kind=="subscription"{
			if quota,ok:=out.Quotas[id];ok{
				protection:=budgetProtectionForSource(protected,record)
				keep,diagnostics=budgetCut(nodes,quota,protection);out.Diagnostics=append(out.Diagnostics,diagnostics...)
			}else{out.Diagnostics=append(out.Diagnostics,budgetDiagnostic("budget_source_disabled",id,"disabled subscription does not receive or consume a quota"))}
		}
		for i,node:=range nodes{
			if !keep[i]{continue};out.KeptBySource[id]++
			detail:=node.detail;detail["canonical"]=node.body;detail["identity"]=node.identity;detail["enabled"]=node.enabled;detail["counts_in_budget"]=node.counted
			out.DetailsBySource[id]=append(out.DetailsBySource[id],detail)
			if budgetBool(record,"enabled",true)&&node.enabled{out.NodesBySource[id]=append(out.NodesBySource[id],node.body)}
		}
		if kind=="subscription"{if old,ok:=budgetInt(record["total_node_count"]);!ok||old!=len(nodes){patch["total_node_count"]=len(nodes)};if old,ok:=budgetInt(record["last_node_count"]);!ok||old!=out.KeptBySource[id]{patch["last_node_count"]=out.KeptBySource[id]}}
		if len(patch)>0{out.RecordPatches[id]=patch}
	}
	return out,nil
}

// applyNodeBudgetToSources is a read-only Application adapter. records/parsed
// remain caller-owned immutable snapshots; it only reads settings to collect
// references. The caller must compare generation/revision before using results.
// Pass limit >= 0 explicitly, or -1 to resolve top-level node_budget (default
// 1000, minimum 1 as in SettingsStorage). It never persists RecordPatches.
func (a *Application) applyNodeBudgetToSources(ctx context.Context,records []map[string]any,parsed map[string][]map[string]any,limit int)(NodeBudgetResult,error){
	if ctx==nil{ctx=context.Background()};if err:=ctx.Err();err!=nil{return NodeBudgetResult{},err}
	a.mutation.Lock();generation,revision:=a.generation,a.revision;doc,err:=a.store.Snapshot();a.mutation.Unlock();if err!=nil{return NodeBudgetResult{},err}
	if limit<0{limit=NodeBudgetDefault;if n,ok:=budgetInt(doc["node_budget"]);ok{limit=n};if limit<1{limit=1}}
	result,err:=AllocateNodeBudget(records,parsed,limit,NodeBudgetOptions{Document:doc});if err!=nil{return result,err};if err=ctx.Err();err!=nil{return result,err}
	a.mutation.Lock();stale:=generation!=a.generation||revision!=a.revision;a.mutation.Unlock();if stale{return result,errors.New("settings or workspace changed while allocating node budget")};return result,nil
}

// SplitNodeBudget is the original water-filling loop, including ordered odd
// remainders and redistribution from smaller subscriptions.
func SplitNodeBudget(budget,manual int,sizes []int)[]int{
	alloc:=make([]int,len(sizes));remaining:=budget-manual;if remaining<=0{return alloc};active:=[]int{};for i,size:=range sizes{if size>0{active=append(active,i)}}
	for remaining>0&&len(active)>0{
		share:=remaining/len(active);fits:=map[int]bool{}
		for _,i:=range active{if sizes[i]-alloc[i]<=share{fits[i]=true}}
		if len(fits)==0{extra:=remaining-share*len(active);for _,i:=range active{alloc[i]+=share;if extra>0{alloc[i]++;extra--}};break}
		for _,i:=range active{if fits[i]{remaining-=sizes[i]-alloc[i];alloc[i]=sizes[i]}}
		next:=[]int{};for _,i:=range active{if !fits[i]{next=append(next,i)}};active=next
	};return alloc
}

func CountsInNodeBudget(node map[string]any)bool{if body,ok:=node["canonical"].(map[string]any);ok{node=body};switch budgetString(node,"type"){case "selector","urltest","tailscale":return false};return true}
func budgetNormalizeNodes(input []map[string]any)([]budgetNode,error){
	out:=make([]budgetNode,0,len(input));identities:=map[string]int{}
	for i,item:=range input{
		if item==nil{return nil,fmt.Errorf("node %d is null",i)};copy,err:=budgetCloneMap(item);if err!=nil{return nil,err}
		detail:=map[string]any{};body:=copy;name:="";member:=-1;enabled:=true
		if canonical,ok:=copy["canonical"].(map[string]any);ok{body=canonical;detail=copy;name=budgetString(copy,"name");enabled=budgetBool(copy,"enabled",true);if n,ok:=budgetInt(copy["member_index"]);ok{member=n}}
		if budgetString(body,"type")==""{return nil,fmt.Errorf("node %d requires an emitted sing-box type; raw provider maps are not accepted",i)}
		if name==""{name=budgetString(body,"tag")};identity:="";typ:=budgetString(body,"type");if typ!="selector"&&typ!="urltest"{identity=budgetUniqueTag(strings.TrimSpace(name),identities)}
		if recorded:=budgetString(detail,"identity");recorded!=""{identity=recorded}
		hash:=budgetString(detail,"legacy_identity_hash");if hash==""{hash,err=LegacyNodeIdentityHash(body);if err!=nil{return nil,err}}
		_,enabledKnown:=detail["enabled"]
		detail["canonical"]=body;detail["name"]=name
		out=append(out,budgetNode{body:body,detail:detail,name:name,identity:identity,legacyHash:hash,member:member,enabled:enabled,enabledKnown:enabledKnown,counted:CountsInNodeBudget(body)})
	};return out,nil
}
func budgetFolderMembers(record map[string]any,nodes []budgetNode)([]budgetNode,error){
	members:=budgetList(record["nodes"]);seen:=map[int]bool{};hasIndex:=false;for _,n:=range nodes{if n.member>=0{hasIndex=true}}
	if !hasIndex&&len(members)>0&&len(nodes)!=len(members){
		for _,m:=range members{if member,ok:=m.(map[string]any);ok&&!budgetBool(member,"enabled",true){return nil,errors.New("folder has disabled members: supply member_index on complete parsed detail maps to count manual priority exactly")}}
	}
	out:=[]budgetNode{}
	for i,node:=range nodes{
		memberIndex:=node.member;if memberIndex<0&&!hasIndex&&len(nodes)==len(members){memberIndex=i}
		if memberIndex>=0{if memberIndex>=len(members){return nil,fmt.Errorf("member_index %d is outside folder nodes",memberIndex)};if seen[memberIndex]{continue};seen[memberIndex]=true;member,ok:=members[memberIndex].(map[string]any);if !ok{return nil,fmt.Errorf("folder member %d is not an object",memberIndex)};node.enabled=node.enabled&&budgetBool(member,"enabled",true);node.member=memberIndex;node.detail["member_index"]=memberIndex;node.detail["member_record"]=member}
		out=append(out,node)
	};return out,nil
}

// CutNodesToQuota retains protected nodes before filling from provider order.
// Its result preserves original order; total is the uncut count including
// exempt and disabled nodes. A quota is a soft ceiling for protected nodes.
func CutNodesToQuota(nodes []map[string]any,quota int,protected NodeBudgetSourceProtection)([]map[string]any,int,[]any,error){
	if quota<0{return nil,len(nodes),nil,errors.New("quota must not be negative")};normalized,err:=budgetNormalizeNodes(nodes);if err!=nil{return nil,len(nodes),nil,err};keep,findings:=budgetCut(normalized,quota,protected);out:=[]map[string]any{};for i,n:=range normalized{if keep[i]{out=append(out,n.body)}};return out,len(nodes),findings,nil
}
func budgetCut(nodes []budgetNode,quota int,p NodeBudgetSourceProtection)([]bool,[]any){
	keep:=make([]bool,len(nodes));counted:=0;for _,n:=range nodes{if n.counted{counted++}};if counted<=quota{for i:=range keep{keep[i]=true};return keep,nil}
	findings:=[]any{};patterns:=[]*regexp.Regexp{};for _,pattern:=range p.DefaultPatterns{re,err:=regexp.Compile("(?i)"+pattern);if err!=nil{findings=append(findings,budgetDiagnostic("budget_regex_unsupported","",err.Error()));continue};patterns=append(patterns,re)};hits:=make([]bool,len(patterns));kept:=0
	for i,node:=range nodes{if !node.counted{keep[i]=true;continue};shown:=p.Prefix+budgetString(node.body,"tag");hit:=p.RawTags[budgetString(node.body,"tag")]||p.FinalTags[shown];for j,re:=range patterns{if !hits[j]&&re.MatchString(shown){hits[j]=true;hit=true}};if hit{keep[i]=true;kept++}}
	for i:=range nodes{if kept>=quota{break};if !keep[i]{keep[i]=true;kept++}}
	if kept>quota{findings=append(findings,map[string]any{"code":"budget_protected_overage","severity":"info","quota":quota,"kept":kept,"message":"protected nodes exceed subscription quota and were retained"})}
	return keep,findings
}

// CollectNodeBudgetProtectedTags reads only explicit reference locations from
// LxBox records: chain hops, rule outbound, enabled-direction default filters,
// source/member detours. Disabled chains/rules still protect their references,
// matching the original collector. Opaque unrelated JSON is never traversed.
func CollectNodeBudgetProtectedTags(document map[string]any,records []map[string]any)(NodeBudgetProtectedTags,[]any){
	out:=NodeBudgetProtectedTags{FinalTags:map[string]bool{},RawBySource:map[string]map[string]bool{},DefaultPatterns:[]string{}};findings:=[]any{}
	link:=func(value any){budgetProtectLink(&out,value)}
	for _,record:=range records{if budgetString(record,"kind")=="chain"{for _,hop:=range budgetList(record["hops"]){link(hop)}};link(record["detour"]);if policy,ok:=record["detour_policy"].(map[string]any);ok{link(policy["override_detour"])};if budgetString(record,"kind")=="folder"{for _,value:=range budgetList(record["nodes"]){if member,ok:=value.(map[string]any);ok{link(member["detour"])}}}}
	for _,value:=range budgetList(document["chains"]){if chain,ok:=value.(map[string]any);ok{for _,hop:=range budgetList(chain["hops"]){link(hop)}}}
	for _,value:=range budgetList(document["rules"]){if rule,ok:=value.(map[string]any);ok{if tag:=budgetString(rule,"outbound");tag!=""{out.FinalTags[tag]=true};if body,ok:=rule["body"].(map[string]any);ok{if tag:=budgetString(body,"outbound");tag!=""{out.FinalTags[tag]=true}}}}
	for _,value:=range budgetList(document["directions"]){if direction,ok:=value.(map[string]any);ok&&budgetBool(direction,"enabled",true){if pattern:=budgetString(direction,"default_filter");pattern!=""{out.DefaultPatterns=append(out.DefaultPatterns,pattern)}}}
	return out,findings
}
func budgetProtectLink(out *NodeBudgetProtectedTags,value any){switch link:=value.(type){case string:if link!=""{out.FinalTags[link]=true};case map[string]any:tag:=budgetString(link,"tag");if tag==""{return};id:=budgetString(link,"folder_id");if id==""{out.FinalTags[tag]=true}else{if out.RawBySource[id]==nil{out.RawBySource[id]=map[string]bool{}};out.RawBySource[id][tag]=true}}}
func budgetMergeProtection(dst *NodeBudgetProtectedTags,src NodeBudgetProtectedTags){for tag,on:=range src.FinalTags{if on{dst.FinalTags[tag]=true}};for id,tags:=range src.RawBySource{if dst.RawBySource[id]==nil{dst.RawBySource[id]=map[string]bool{}};for tag,on:=range tags{if on{dst.RawBySource[id][tag]=true}}};dst.DefaultPatterns=append(dst.DefaultPatterns,src.DefaultPatterns...)}
func budgetProtectionForSource(all NodeBudgetProtectedTags,record map[string]any)NodeBudgetSourceProtection{
	out:=NodeBudgetSourceProtection{FinalTags:all.FinalTags,DefaultPatterns:all.DefaultPatterns,RawTags:map[string]bool{}}
	if policy,ok:=record["tag_policy"].(map[string]any);ok{out.Prefix=budgetString(policy,"prefix")}
	for tag,on:=range all.RawBySource[budgetString(record,"id")]{out.RawTags[tag]=on};if defaults,ok:=record["group_defaults"].(map[string]any);ok{for _,value:=range defaults{if tag,ok:=value.(string);ok&&tag!=""{out.RawTags[tag]=true}}};return out
}

// DisabledHashTTL is clamp(3*interval, 24h, 30d), including disabled/server-zero
// intervals collapsing to the one-day floor. File/cache rehydration never calls
// GCDisabledHashes merely because time passed.
func DisabledHashTTL(intervalHours int)time.Duration{if intervalHours<=8{return 24*time.Hour};if intervalHours>=240{return 30*24*time.Hour};return time.Duration(intervalHours)*3*time.Hour}
func LegacyNodeIdentityHash(node map[string]any)(string,error){copy,err:=budgetCloneMap(node);if err!=nil{return "",err};delete(copy,"tag");delete(copy,"detour");body,err:=budgetCanonicalJSON(copy);if err!=nil{return "",err};sum:=sha256.Sum256(body);return hex.EncodeToString(sum[:]),nil}
func MigrateLegacyDisabledKeys(current map[string]any,nodes []map[string]any)(map[string]any,[]any,error){
	normalized,err:=budgetNormalizeNodes(nodes);if err!=nil{return nil,nil,err};return budgetMigrateDisabled(current,normalized)
}
func budgetMigrateDisabled(current map[string]any,nodes []budgetNode)(map[string]any,[]any,error){
	out,err:=budgetCloneMap(current);if err!=nil{return nil,nil,err};if out==nil{out=map[string]any{}};hashes:=map[string]string{};for _,n:=range nodes{if n.identity!=""{if _,exists:=hashes[n.legacyHash];!exists{hashes[n.legacyHash]=n.identity}}}
	findings:=[]any{};keys:=[]string{};for key:=range out{if budgetLegacyKey(key){keys=append(keys,key)}};sort.Strings(keys)
	for _,key:=range keys{value:=out[key];delete(out,key);identity:=hashes[key];if identity==""{findings=append(findings,budgetDiagnostic("disabled_legacy_removed","","legacy disable hash no longer matches any node"));continue};if existing,ok:=out[identity];ok{oldTime,oldOK:=budgetTimestamp(existing);newTime,newOK:=budgetTimestamp(value);if oldOK&&newOK&&oldTime.After(newTime){continue}};out[identity]=value}
	return out,findings,nil
}
func GCDisabledHashes(current map[string]any,fresh map[string]bool,intervalHours int,now time.Time)(map[string]any,[]any){
	out:=map[string]any{};findings:=[]any{};ttl:=DisabledHashTTL(intervalHours)
	for key,value:=range current{if fresh[key]{out[key]=now.Unix();continue};last,ok:=budgetTimestamp(value);if !ok{out[key]=value;findings=append(findings,budgetDiagnostic("disabled_timestamp_invalid","","invalid disable timestamp retained without TTL deletion"));continue};if now.Sub(last)<=ttl{out[key]=value}}
	return out,findings
}

// RefreshNodeVerdicts keeps a verdict for the same canonical body, clears only
// core_rejected and its disable mark on a changed/missing old body, and leaves
// manually disabled nodes (no core_rejected entry) disabled.
func RefreshNodeVerdicts(disabled map[string]any,warnings map[string]any,oldBodies,newBodies map[string]string)(map[string]any,map[string]any){
	disabled,_=budgetCloneMap(disabled);warnings,_=budgetCloneMap(warnings);if disabled==nil{disabled=map[string]any{}};if warnings==nil{warnings=map[string]any{}}
	for identity,value:=range warnings{if !budgetHasCoreVerdict(value){continue};nextBody,exists:=newBodies[identity];if !exists{continue};oldBody,hadOld:=oldBodies[identity];if hadOld&&oldBody==nextBody{continue};delete(disabled,identity);rest:=budgetDropCoreVerdict(value);if len(rest)==0{delete(warnings,identity)}else{warnings[identity]=rest}}
	return disabled,warnings
}
func budgetApplyOverlays(record map[string]any,nodes []budgetNode,opt NodeBudgetOptions)([]budgetNode,map[string]any,[]any,error){
	id:=budgetString(record,"id");kind:=budgetString(record,"kind");patch:=map[string]any{};findings:=[]any{}
	if kind!="subscription"{for i:=range nodes{stored:=record["warnings"];if kind=="folder"{if member,ok:=nodes[i].detail["member_record"].(map[string]any);ok{stored=member["warnings"]}};nodes[i].detail["diagnostics"]=budgetStampWarnings(nodes[i].detail["diagnostics"],stored)};return nodes,patch,findings,nil}
	disabled,_:=record["disabled"].(map[string]any);disabled,diagnostics,err:=budgetMigrateDisabled(disabled,nodes);if err!=nil{return nil,patch,findings,err};findings=append(findings,diagnostics...)
	warnings,_:=record["warnings"].(map[string]any);warnings,err=budgetCloneMap(warnings);if err!=nil{return nil,patch,findings,err};if warnings==nil{warnings=map[string]any{}}
	fresh:=map[string]bool{};for _,node:=range nodes{if node.identity!=""{fresh[node.identity]=true}}
	refresh:=opt.NetworkRefresh[id]&&budgetHTTPURL(budgetString(record,"url"))
	if refresh{
		disabled,diagnostics=GCDisabledHashes(disabled,fresh,budgetIntervalHours(record),opt.Now);findings=append(findings,diagnostics...)
		for identity,on:=range opt.RuleEnable[id]{if on{delete(disabled,identity)}};for identity,on:=range opt.RuleDisable[id]{if on{disabled[identity]=opt.Now.Unix()}}
		for identity:=range warnings{if _,off:=disabled[identity];!off&&!fresh[identity]{delete(warnings,identity)}}
		oldNodes,err:=budgetNormalizeNodes(opt.PreviousBySource[id]);if err!=nil{return nil,patch,findings,err};oldBodies,err:=budgetBodies(oldNodes);if err!=nil{return nil,patch,findings,err};newBodies,err:=budgetBodies(nodes);if err!=nil{return nil,patch,findings,err};disabled,warnings=RefreshNodeVerdicts(disabled,warnings,oldBodies,newBodies)
	}
	for identity,on:=range opt.RuleEnable[id]{if on{rest:=budgetDropCoreVerdict(warnings[identity]);if len(rest)==0{delete(warnings,identity)}else{warnings[identity]=rest}}}
	for i:=range nodes{
		identity:=nodes[i].identity;if identity==""{continue};_,off:=disabled[identity]
		enabled:=!off
		// Preserve an explicit rule decision when it differs from the old stored
		// disable mark. Otherwise recompute from migrated/cleared marks.
		_,oldOff:=budgetMap(record["disabled"])[identity]
		if nodes[i].enabledKnown&&!nodes[i].enabled&&!oldOff{enabled=false}
		if nodes[i].enabledKnown&&nodes[i].enabled&&oldOff{enabled=true}
		if opt.RuleEnable[id][identity]{enabled=true};if opt.RuleDisable[id][identity]{enabled=false}
		nodes[i].enabled=enabled;nodes[i].detail["diagnostics"]=budgetStampWarnings(nodes[i].detail["diagnostics"],warnings[identity])
	}
	if !budgetJSONEqual(record["disabled"],disabled)&&len(disabled)>0{patch["disabled"]=disabled}else if len(disabled)==0&&len(budgetMap(record["disabled"]))>0{patch["disabled"]=map[string]any{}}
	if !budgetJSONEqual(record["warnings"],warnings)&&len(warnings)>0{patch["warnings"]=warnings}else if len(warnings)==0&&len(budgetMap(record["warnings"]))>0{patch["warnings"]=map[string]any{}}
	return nodes,patch,findings,nil
}
func budgetBodies(nodes []budgetNode)(map[string]string,error){out:=map[string]string{};for _,node:=range nodes{if node.identity==""{continue};body,err:=budgetCanonicalJSON(node.body);if err!=nil{return nil,err};out[node.identity]=string(body)};return out,nil}
func budgetStampWarnings(computed,stored any)[]any{
	out:=append([]any{},budgetList(computed)...)
	for _,value:=range budgetList(stored){warning,ok:=value.(map[string]any);if !ok||budgetString(warning,"code")==""{continue};code:=budgetString(warning,"code");kept:=[]any{};for _,old:=range out{if m,ok:=old.(map[string]any);ok&&budgetString(m,"code")==code&&(m["path"]==nil||m["path"]==""){continue};kept=append(kept,old)};clone,_:=budgetCloneMap(warning);out=append([]any{clone},kept...)};return out
}
func budgetHasCoreVerdict(value any)bool{for _,v:=range budgetList(value){if w,ok:=v.(map[string]any);ok&&budgetString(w,"code")=="core_rejected"{return true}};return false}
func budgetDropCoreVerdict(value any)[]any{out:=[]any{};for _,v:=range budgetList(value){if w,ok:=v.(map[string]any);ok&&budgetString(w,"code")=="core_rejected"{continue};out=append(out,v)};return out}
func budgetIntervalHours(record map[string]any)int{hours:=24;if update,ok:=record["update"].(map[string]any);ok{if n,ok:=budgetInt(update["interval_hours"]);ok{hours=n}};if hours==0{hours=24;if n,ok:=budgetInt(budgetMap(record["meta"])["update_interval_hours"]);ok{hours=n}};return hours}
func budgetStoredSize(record map[string]any)int{last,_:=budgetInt(record["last_node_count"]);total,_:=budgetInt(record["total_node_count"]);if total<last{total=last};if total<0{return 0};return total}
func budgetLegacyKey(key string)bool{if len(key)!=64{return false};for _,c:=range key{if !(c>='0'&&c<='9'||c>='a'&&c<='f'){return false}};return true}
func budgetTimestamp(value any)(time.Time,bool){if n,ok:=budgetInt64(value);ok{return time.Unix(n,0).UTC(),true};if s,ok:=value.(string);ok{t,err:=time.Parse(time.RFC3339Nano,s);return t,err==nil};return time.Time{},false}
func budgetCanonicalJSON(value any)([]byte,error){var b bytes.Buffer;encoder:=json.NewEncoder(&b);encoder.SetEscapeHTML(false);if err:=encoder.Encode(value);err!=nil{return nil,err};return bytes.TrimSuffix(b.Bytes(),[]byte{'\n'}),nil}
func budgetCloneMap(value map[string]any)(map[string]any,error){if value==nil{return nil,nil};body,err:=json.Marshal(value);if err!=nil{return nil,err};var out map[string]any;decoder:=json.NewDecoder(bytes.NewReader(body));decoder.UseNumber();err=decoder.Decode(&out);return out,err}
func budgetJSONEqual(a,b any)bool{x,e1:=budgetCanonicalJSON(a);y,e2:=budgetCanonicalJSON(b);return e1==nil&&e2==nil&&bytes.Equal(x,y)}
func budgetUniqueTag(name string,counts map[string]int)string{if name==""{return ""};if counts[name]==0{counts[name]=1;return name};for{counts[name]++;candidate:=name+"-"+strconv.Itoa(counts[name]);if counts[candidate]==0{counts[candidate]=1;return candidate}}}
func budgetString(m map[string]any,key string)string{s,_:=m[key].(string);return s}
func budgetBool(m map[string]any,key string,fallback bool)bool{value,ok:=m[key].(bool);if ok{return value};return fallback}
func budgetMap(value any)map[string]any{m,_:=value.(map[string]any);return m}
func budgetList(value any)[]any{switch v:=value.(type){case []any:return v;case []map[string]any:out:=make([]any,len(v));for i,m:=range v{out[i]=m};return out};return nil}
func budgetInt(value any)(int,bool){n,ok:=budgetInt64(value);if !ok||int64(int(n))!=n{return 0,false};return int(n),true}
func budgetInt64(value any)(int64,bool){switch n:=value.(type){case int:return int64(n),true;case int64:return n,true;case float64:return int64(n),n==float64(int64(n));case json.Number:v,err:=n.Int64();return v,err==nil};return 0,false}
func budgetHTTPURL(value string)bool{return strings.HasPrefix(strings.ToLower(value),"http://")||strings.HasPrefix(strings.ToLower(value),"https://")}
func budgetDiagnostic(code,source,message string)map[string]any{return map[string]any{"code":code,"source_id":source,"severity":"warning","message":message}}
