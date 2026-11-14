package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/experimental/libbox"
)

// CallFunc is the JSON-only Android host boundary. Arguments and results are
// copied JSON values; no Java object or Go pointer crosses the JNI boundary.
type CallFunc func(context.Context, string, json.RawMessage) (json.RawMessage, error)

type Status struct {
	State string `json:"state"`
	Running bool `json:"running"`
	Error string `json:"error,omitempty"`
}

type Controller struct {
	platform      CallFunc
	dataDir       string
	server        *libbox.CommandServer
	serverStarted bool
	mu            sync.Mutex
	state         atomic.Value
	lastConfig    string
	closed        bool
	clients       map[string]*asyncClient
	clientMu      sync.Mutex
	streams       map[string]*streamSnapshot
	pingSessions  map[string]*libbox.TailscalePingSession
	inboxSessions map[string]*libbox.TaildropInboxSubscription
	openSessions  map[string]*libbox.OpenConnectStatusSubscription
	probeSessions map[string]*libbox.ConnectionTestSession
}

type asyncClient struct {
	client *libbox.CommandClient
	handler *commandStreamHandler
	close  func() error
}

// New configures libbox once and creates its native command server. dataDir is
// the Android filesDir (the legacy UI data directory is supplied separately to
// runtime.Initialize as applicationInfo.dataDir/app_flutter).
func New(platform CallFunc, dataDir string) (*Controller, error) {
	if platform == nil { return nil, errors.New("core: platform callback is required") }
	if !filepath.IsAbs(dataDir) { return nil, errors.New("core: data directory must be absolute") }
	if err := os.MkdirAll(dataDir, 0700); err != nil { return nil, fmt.Errorf("create data directory: %w", err) }
	tempDir := filepath.Join(dataDir, "tmp")
	if err := os.MkdirAll(tempDir, 0700); err != nil { return nil, fmt.Errorf("create temp directory: %w", err) }
	var setup struct {
		Debug bool `json:"debug"`
		OomKillerEnabled bool `json:"oomKillerEnabled"`
		OomKillerDisabled bool `json:"oomKillerDisabled"`
		OomMemoryLimit int64 `json:"oomMemoryLimit"`
		OomMemoryLimitHeap bool `json:"oomMemoryLimitHeap"`
		PowerReportEnabled bool `json:"powerReportEnabled"`
		AppVersion string `json:"appVersion"`
		AppMarketingVersion string `json:"appMarketingVersion"`
	}
	settings:=json.RawMessage(`{}`)
	rawSetup,callErr:=platform(context.Background(),"core.setup",settings)
	if callErr!=nil{return nil,fmt.Errorf("read core setup: %w",callErr)}
	if err:=json.Unmarshal(rawSetup,&setup);err!=nil{return nil,fmt.Errorf("decode core setup: %w",err)}
	if err := libbox.Setup(&libbox.SetupOptions{
		BasePath: dataDir, WorkingPath: dataDir, TempPath: tempDir,
		LogMaxLines: 3000, CrashReportSource: "lxbox", Debug: setup.Debug,
		OomKillerEnabled: setup.OomKillerEnabled, OomKillerDisabled: setup.OomKillerDisabled,
		OomMemoryLimit: setup.OomMemoryLimit, OomMemoryLimitHeap: setup.OomMemoryLimitHeap,
		PowerReportEnabled: setup.PowerReportEnabled, AppVersion: setup.AppVersion, AppMarketingVersion: setup.AppMarketingVersion,
	}); err != nil { return nil, fmt.Errorf("libbox setup: %w", err) }
	c := &Controller{platform: platform, dataDir: dataDir, clients: map[string]*asyncClient{}, streams: map[string]*streamSnapshot{}, pingSessions: map[string]*libbox.TailscalePingSession{}, inboxSessions: map[string]*libbox.TaildropInboxSubscription{}, openSessions: map[string]*libbox.OpenConnectStatusSubscription{}, probeSessions: map[string]*libbox.ConnectionTestSession{}}
	c.state.Store(Status{State: "stopped"})
	server, err := libbox.NewCommandServer(c, &platformAdapter{call: platform})
	if err != nil { return nil, fmt.Errorf("create libbox command server: %w", err) }
	c.server = server
	return c, nil
}

func (c *Controller) Start(config string) error {
	if config == "" { return errors.New("core: configuration is empty") }
	if err := libbox.CheckConfig(config); err != nil { c.setStatus("error", err); return err }
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed { return os.ErrClosed }
	c.setStatus("starting", nil)
	if !c.serverStarted {
		if err := c.server.Start(); err != nil { c.setStatus("error", err); return err }
		c.serverStarted = true
	}
	if err := c.server.StartOrReloadService(config, &libbox.OverrideOptions{}); err != nil {
		c.setStatus("error", err)
		return err
	}
	c.lastConfig = config
	c.setStatus("running", nil)
	return nil
}

func (c *Controller) Reload(config string) error {
	if config == "" { return errors.New("core: configuration is empty") }
	if err := libbox.CheckConfig(config); err != nil { c.setStatus("error", err); return err }
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed { return os.ErrClosed }
	if !c.serverStarted {
		if err := c.server.Start(); err != nil { c.setStatus("error", err); return err }
		c.serverStarted = true
	}
	if err := c.server.StartOrReloadService(config, &libbox.OverrideOptions{}); err != nil { c.setStatus("error", err); return err }
	c.lastConfig = config
	c.setStatus("running", nil)
	return nil
}

func (c *Controller) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed { return nil }
	if c.server == nil { c.setStatus("stopped", nil); return nil }
	err := c.server.CloseService()
	if err != nil { c.setStatus("error", err) } else { c.setStatus("stopped", nil) }
	return err
}

// Close releases the gRPC listener and the libbox service. Stop deliberately
// keeps the command server alive for a later restart in the same process.
func (c *Controller) Close() error {
	c.mu.Lock()
	if c.closed { c.mu.Unlock(); return nil }
	c.closed = true
	if c.serverStarted { _ = c.server.CloseService() }
	c.mu.Unlock()
	c.closeAsyncClients()
	c.mu.Lock()
	if c.server != nil { c.server.Close() }
	c.setStatus("stopped", nil)
	c.mu.Unlock()
	return nil
}

func (c *Controller) closeAsyncClients() {
	c.clientMu.Lock()
	clients := c.clients
	c.clients = map[string]*asyncClient{}
	c.streams = map[string]*streamSnapshot{}
	pings, inboxes, opens, probes := c.pingSessions, c.inboxSessions, c.openSessions, c.probeSessions
	c.pingSessions = map[string]*libbox.TailscalePingSession{}
	c.inboxSessions = map[string]*libbox.TaildropInboxSubscription{}
	c.openSessions = map[string]*libbox.OpenConnectStatusSubscription{}
	c.probeSessions = map[string]*libbox.ConnectionTestSession{}
	c.clientMu.Unlock()
	for _, session := range pings { _ = session.Close() }
	for _, session := range inboxes { _ = session.Close() }
	for _, session := range opens { _ = session.Close() }
	for _, session := range probes { _ = session.Close() }
	for _, client := range clients { _ = client.close() }
}

func (c *Controller) Status() any {
	value := c.state.Load()
	if value == nil { return Status{State: "stopped"} }
	return value.(Status)
}

func (c *Controller) setStatus(state string, err error) {
	value := Status{State: state, Running: state == "running"}
	if err != nil { value.Error = err.Error() }
	c.state.Store(value)
	payload, _ := json.Marshal(map[string]any{"type":"vpn.status", "data":value})
	_, _ = c.platform(context.Background(), "events.emit", payload)
}

// ServiceStop/ServiceReload are called by libbox's native CommandServer RPCs.
func (c *Controller) ServiceStop() error {
	if err := c.Stop(); err != nil { return err }
	_, err := c.platform(context.Background(), "vpn.stop", json.RawMessage(`{}`))
	return err
}
func (c *Controller) ServiceReload() error {
	c.mu.Lock(); config := c.lastConfig; c.mu.Unlock()
	if config == "" { return errors.New("no configuration has been started") }
	return c.Reload(config)
}
func (c *Controller) GetSystemProxyStatus() (*libbox.SystemProxyStatus, error) {
	return &libbox.SystemProxyStatus{Available:false, Enabled:false}, nil
}
func (c *Controller) SetSystemProxyEnabled(bool) error { return errors.New("system proxy control is unavailable on Android") }
func (c *Controller) TriggerNativeCrash() error { return errors.New("native crash trigger is disabled") }
func (c *Controller) WriteDebugMessage(message string) { c.emit("core.log", map[string]any{"message":message}) }
func (c *Controller) ConnectSSHAgent() (int32, error) { return 0, errors.New("SSH agent is unavailable on Android") }

func (c *Controller) emit(kind string, data any) {
	payload, err := json.Marshal(map[string]any{"type":kind,"data":data}); if err != nil { return }
	_, _ = c.platform(context.Background(), "events.emit", payload)
}

// Call exposes config validation and the cc* API names used by the app. It uses
// libbox's own standalone CommandClient; the client is disconnected on both
// success and failure so its socket/context cannot outlive a request.
func (c *Controller) Call(ctx context.Context, method string, args json.RawMessage) (any, error) {
	if ctx == nil { ctx = context.Background() }
	if err := ctx.Err(); err != nil { return nil, err }
	if len(args) == 0 { args = json.RawMessage(`{}`) }
	if method == "validate" {
		config := string(args);var text string;if json.Unmarshal(args,&text)==nil{config=text};err:=libbox.CheckConfig(config);return map[string]any{"valid":err==nil},err
	}
	var p map[string]json.RawMessage
	if err := json.Unmarshal(args, &p); err != nil { return nil, fmt.Errorf("decode %s arguments: %w", method, err) }
	str := func(k string) string { var v string; _ = json.Unmarshal(p[k], &v); return v }
	boolean := func(k string) bool { var v bool; _ = json.Unmarshal(p[k], &v); return v }
	integer := func(k string) int32 { var v int32; _ = json.Unmarshal(p[k], &v); return v }
	clientID := func() string { if str("client_id") != "" { return str("client_id") }; return str("session_id") }
	sessionID := clientID
	if method == "ccDisposeClient" { return nil, c.disposeClient(clientID()) }
	if method == "ccTaildropDelete" || method == "ccTaildropSave" || method == "ccTaildropSendBytes" || method == "ccTaildropPickAndSend" || method == "ccTaildropCancelReceiving" || method == "ccTaildropMarkRead" { return c.Taildrop(ctx, method, args) }
	if method == "ccProbeCandidate" { return c.ProbeCandidate(ctx, args) }
	c.mu.Lock();closed:=c.closed;c.mu.Unlock();if closed{return nil,os.ErrClosed}
	var err error
	newAsyncClient := func(id string) (*libbox.CommandClient, func() error, error) {
		if id == "" { return nil, nil, errors.New("client_id is required") }
		c.clientMu.Lock()
		if entry := c.clients[id]; entry != nil { c.clientMu.Unlock(); return entry.client, entry.close, nil }
		snapshot := &streamSnapshot{connections: map[string]*libbox.Connection{}}
		handler := &commandStreamHandler{owner:c, scope:id, snapshot:snapshot}
		options := &libbox.CommandClientOptions{StatusInterval:int64(time.Second)}
		for _, command := range []int32{libbox.CommandLog,libbox.CommandStatus,libbox.CommandGroup,libbox.CommandOutbounds,libbox.CommandConnections,libbox.CommandDNS} { options.AddCommand(command) }
		cc := libbox.NewCommandClient(handler,options)
		closeFn := func() error { c.clientMu.Lock(); delete(c.clients,id); delete(c.streams,id); c.clientMu.Unlock(); return cc.Disconnect() }
		c.clients[id] = &asyncClient{client:cc,handler:handler,close:closeFn}; c.streams[id]=snapshot
		c.clientMu.Unlock()
		if err:=cc.Connect();err!=nil{_ = closeFn();return nil,nil,err}
		return cc,closeFn,nil
	}
	asyncMethod := strings.HasPrefix(method,"ccStart") || method=="ccTaildropInboxSnapshot" || method=="ccGetOpenConnectStatus" || method=="ccGetStatus" || method=="ccGetLogs" || method=="ccGetConnections"
	var cc *libbox.CommandClient
	var closeClient func()error
	if asyncMethod { cc,closeClient,err=newAsyncClient(clientID()) } else { cc=libbox.NewStandaloneCommandClient();closeClient=cc.Disconnect }
	if err!=nil{return nil,err}
	if !asyncMethod { stopCancel:=context.AfterFunc(ctx,func(){_ = cc.Disconnect()}); defer stopCancel() }
	defer func(){if !asyncMethod{_ = closeClient()}}()
	switch method {
	case "ccGetGroups": return groupsJSON(cc.GetGroups())
	case "ccGetOutbounds": return outboundsJSON(cc.GetOutbounds())
	case "ccSelectOutbound": return nil, cc.SelectOutbound(str("group"), str("tag"))
	case "ccUrlTestGroup": return nil, cc.URLTest(str("tag"))
	case "ccUrlTestOutbound":
		v, err := cc.URLTestOutbound(str("tag"),str("link"),integer("timeoutMs"));if v==nil{return nil,err};return map[string]any{"delay":v.Delay,"error":v.Error},err
	case "ccGetUrlViaOutbound":
		r, e := cc.GetURLViaOutbound(str("tag"), str("link"), integer("timeoutMs"), integer("maxBytes"), nil)
		if e != nil { return r, e }; if r == nil { return nil, nil }
		return map[string]any{"status":r.Status(),"content":r.Content(),"truncated":r.Truncated(),"contentType":r.ContentType(),"remoteAddr":r.RemoteAddr(),"elapsedMs":r.ElapsedMs()},nil
	case "ccGetRules": return rulesJSON(cc.GetRules())
	case "ccGetDnsGroups": return dnsGroupsJSON(cc.GetDNSGroups())
	case "ccCloseConnection": return nil, cc.CloseConnection(str("id"))
	case "ccCloseConnections": return nil, cc.CloseConnections()
	case "ccGetRunningConfig":
		v, e := cc.GetRunningConfig(); if e != nil { return v, e }; if v == nil { return json.RawMessage("null"), nil }; return json.RawMessage(v.Content()), nil
	case "ccGetPool": return poolJSON(cc.GetPool(str("tag")))
	case "ccSetEndpointEnabled": return endpointToggleJSON(cc.SetEndpointEnabled(str("tag"), boolean("enabled")))
	case "ccGetWireGuardStatus": return wireguardJSON(cc.GetWireGuardStatus(str("tag")))
	case "ccGetTailscaleStatus": return tailscaleJSON(cc.GetTailscaleStatus(str("tag")))
	case "ccTailscaleLogin": return nil, cc.TailscaleLogin(str("tag"), str("auth_key"))
	case "ccTailscaleLogout": return nil, cc.TailscaleLogout(str("tag"))
	case "ccSetTailscaleExitNode": return nil, cc.SetTailscaleExitNode(str("tag"), str("stable_id"))
	case "ccStartTailscalePing": return c.startTailscalePing(cc, closeClient, str("tag"), str("peer_ip"), sessionID())
	case "ccStopTailscalePing": return nil, c.stopTailscalePing(sessionID())
	case "ccTaildropInboxSnapshot": return c.startTaildropInbox(cc, closeClient, str("tag"), sessionID())
	case "ccGetOpenConnectStatus": return c.startOpenConnectStatus(cc, closeClient, sessionID())
	case "ccSubmitOpenConnectForm": return nil, c.submitOpenConnectForm(cc, str("tag"), str("challenge_id"), p["values"])
	case "ccCancelOpenConnectChallenge": return nil, cc.CancelOpenConnectAuthChallenge(str("tag"), str("challenge_id"))
	case "ccStartOpenConnectCallback": return c.platformCall(ctx,"openconnect.callback.start",args)
	case "ccStopOpenConnectCallback": return c.platformCall(ctx,"openconnect.callback.stop",args)
	case "ccStartConnectionTest", "ccStartProbe": return c.startConnectionTest(cc, closeClient, p, sessionID())
	case "ccStopConnectionTest", "ccStopProbe": return nil, c.stopConnectionTest(sessionID())
	case "ccResetNetwork": c.server.ResetNetwork(); return nil, nil
	case "ccUrlTestAll": return c.urlTestAll(ctx, cc)
	case "ccGetStatus": return c.statusSnapshot(clientID())
	case "ccGetLogs": return c.logsSnapshot(clientID())
	case "ccGetConnections": return c.connectionsSnapshot(clientID())
	default: return nil, fmt.Errorf("unknown core call %q", method)
	}
}

func (c *Controller) platformCall(ctx context.Context, method string, args json.RawMessage) (any,error) {
	if c.platform==nil{return nil,errors.New("platform callback is unavailable")}
	data,err:=c.platform(ctx,method,args)
	if err!=nil { var value any; if json.Valid(data){_ = json.Unmarshal(data,&value)}; return value,err }
	if len(data)==0{return nil,nil}
	var value any
	if err=json.Unmarshal(data,&value);err!=nil{return nil,fmt.Errorf("platform %s returned invalid JSON: %w",method,err)}
	return value,nil
}

func endpointToggleJSON(v *libbox.EndpointToggleResult, err error)(any,error){if err!=nil{return v,err};if v==nil{return nil,nil};return map[string]any{"state":v.State},nil}
func wireguardJSON(v *libbox.WireGuardEndpointStatus, err error)(any,error){if err!=nil{return v,err};if v==nil{return nil,nil};"peers":=[]any{};"it":=v.Peers();for it!=nil&&it.HasNext(){"p":=it.Next();if p!=nil{peers=append(peers,map[string]any{"publicKey":p.PublicKey,"endpoint":p.Endpoint,"lastHandshakeUnix":p.LastHandshakeUnix,"rxBytes":p.RxBytes,"txBytes":p.TxBytes,"sessionRxBytes":p.SessionRxBytes,"sessionTxBytes":p.SessionTxBytes})}};return map[string]any{"endpointTag":v.EndpointTag,"endpointState":v.EndpointState,"idleSinceSeconds":v.IdleSinceSeconds,"peers":peers},nil}
func iteratorStrings(it libbox.StringIterator)[]string{"out":=[]string{};for it!=nil&&it.HasNext(){out=append(out,it.Next())};return out}
func tailscaleJSON(v *libbox.TailscaleEndpointStatus, err error)(any,error){if err!=nil{return v,err};if v==nil{return nil,nil};"peerJSON":=func(p *libbox.TailscalePeer)any{if p==nil{return nil};return map[string]any{"stableId":p.StableID,"hostName":p.HostName,"dnsName":p.DNSName,"os":p.OS,"tailscaleIps":iteratorStrings(p.TailscaleIPs()),"sshHostKeys":iteratorStrings(p.SSHHostKeys()),"online":p.Online,"exitNode":p.ExitNode,"exitNodeOption":p.ExitNodeOption,"shareeNode":p.ShareeNode,"expired":p.Expired,"active":p.Active,"canReceiveFiles":p.CanReceiveFiles,"rxBytes":p.RxBytes,"txBytes":p.TxBytes,"keyExpiry":p.KeyExpiry,"lastSeen":p.LastSeen,"path":p.Path,"endpoint":p.Endpoint,"peerRelay":p.PeerRelay,"derpRegionCode":p.DERPRegionCode,"lastHandshake":p.LastHandshake}};"groups":=[]any{};"gi":=v.UserGroups();for gi!=nil&&gi.HasNext(){"g":=gi.Next();if g==nil{continue};"peers":=[]any{};"pi":=g.Peers();for pi!=nil&&pi.HasNext(){peers=append(peers,peerJSON(pi.Next()))};groups=append(groups,map[string]any{"userId":g.UserID,"loginName":g.LoginName,"displayName":g.DisplayName,"profilePicUrl":g.ProfilePicURL,"peers":peers})};return map[string]any{"endpointTag":v.EndpointTag,"backendState":v.BackendState,"stateText":v.StateText,"authUrl":v.AuthURL,"networkName":v.NetworkName,"magicDnsSuffix":v.MagicDNSSuffix,"self":peerJSON(v.Self),"exitNode":peerJSON(v.ExitNode),"keyAuth":v.KeyAuth,"canShareFiles":v.CanShareFiles,"waitingFileCount":v.WaitingFileCount,"receivingFileCount":v.ReceivingFileCount,"unreadFileCount":v.UnreadFileCount,"health":iteratorStrings(v.Health()),"userGroups":groups},nil}
func outboundsJSON(it libbox.OutboundGroupItemIterator, err error) (any,error) {
	if err != nil { return nil,err }; out:=[]any{}
	for it!=nil&&it.HasNext(){ v:=it.Next();if v==nil{continue};out=append(out,itemJSON(v)) }
	return out,nil
}
func itemJSON(v *libbox.OutboundGroupItem) map[string]any { return map[string]any{"tag":v.Tag,"type":v.Type,"urlTestTime":v.URLTestTime,"urlTestDelay":v.URLTestDelay,"endpointState":v.EndpointState,"idleSinceSeconds":v.IdleSinceSeconds} }
func groupsJSON(it libbox.OutboundGroupIterator, err error) (any,error) {
	if err!=nil{return nil,err}; out:=[]map[string]any{}; for it!=nil&&it.HasNext(){g:=it.Next(); if g==nil{continue}; items:=[]any{}; ii:=g.GetItems(); for ii!=nil&&ii.HasNext(){v:=ii.Next();if v!=nil{items=append(items,itemJSON(v))}}; out=append(out,map[string]any{"tag":g.Tag,"type":g.Type,"selectable":g.Selectable,"selected":g.Selected,"isExpand":g.IsExpand,"items":items}) }; return out,nil
}
func rulesJSON(it libbox.RuleIterator, err error) (any,error) { if err!=nil{return nil,err};out:=[]any{};for it!=nil&&it.HasNext(){v:=it.Next();if v!=nil{out=append(out,map[string]any{"type":v.Type,"payload":v.Payload,"action":v.Action,"isDNS":v.IsDNS})}};return out,nil }
func poolJSON(it libbox.PoolSlotIterator, err error) (any,error) { if err!=nil{return nil,err};out:=[]any{};for it!=nil&&it.HasNext(){v:=it.Next();if v!=nil{out=append(out,map[string]any{"slot":v.Slot,"tag":v.Tag,"delay":v.Delay})}};return out,nil }
func dnsGroupsJSON(it libbox.DnsGroupIterator, err error) (any,error) { if err!=nil{return nil,err};out:=[]any{};for it!=nil&&it.HasNext(){g:=it.Next();if g==nil{continue};members:=[]any{};mi:=g.Members();for mi!=nil&&mi.HasNext(){v:=mi.Next();if v!=nil{members=append(members,map[string]any{"tag":v.Tag,"serverType":v.ServerType,"clean":v.Clean,"liveErrors":v.LiveErrors,"lastErrorAgeMs":v.LastErrorAgeMs,"liveWins":v.LiveWins,"current":v.Current,"lastRTTMs":v.LastRTTMs})}};out=append(out,map[string]any{"tag":g.Tag,"mode":g.Mode,"current":g.Current,"members":members})};return out,nil }

// platformAdapter maps libbox's narrow typed interface to the application's
// JSON callback. Async network updates are polled by the host monitor callback,
// keeping Java listener objects out of Go and avoiding JNI global-ref leaks.
type platformAdapter struct {
	call CallFunc
	monitorMu sync.Mutex
	monitors map[uint64]*monitorEntry
}
func (p *platformAdapter) invoke(ctx context.Context, method string, args any, out any) error {
	if ctx==nil {ctx=context.Background()}; raw,err:=json.Marshal(args);if err!=nil{return err};data,err:=p.call(ctx,method,raw);if err!=nil{return err};if out==nil||len(data)==0||string(data)=="null"{return nil};if err=json.Unmarshal(data,out);err!=nil{return fmt.Errorf("platform %s response: %w",method,err)};return nil
}
func (p *platformAdapter) LocalDNSTransport() libbox.LocalDNSTransport { return newPlatformDNS(p.call) }
func (p *platformAdapter) UsePlatformAutoDetectInterfaceControl() bool { return true }
func (p *platformAdapter) AutoDetectInterfaceControl(fd int32) error { return p.invoke(context.Background(),"network.protect",map[string]any{"fd":fd},nil) }
func (p *platformAdapter) OpenTun(o libbox.TunOptions)(int32,error){
	collect:=func(it libbox.RoutePrefixIterator)[]string{r:=[]string{};for it!=nil&&it.HasNext(){v:=it.Next();if v!=nil{r=append(r,v.String())}};return r}
	strings:=func(it libbox.StringIterator)[]string{r:=[]string{};for it!=nil&&it.HasNext(){r=append(r,it.Next())};return r}
	dns,err:=o.GetDNSServerAddress();if err!=nil{return -1,err}
	args:=map[string]any{"inet4Address":collect(o.GetInet4Address()),"inet6Address":collect(o.GetInet6Address()),"dnsServers":strings(dns),"dnsMode":o.GetDNSMode().Value,"mtu":o.GetMTU(),"autoRoute":o.GetAutoRoute(),"strictRoute":o.GetStrictRoute(),"inet4RouteAddress":collect(o.GetInet4RouteAddress()),"inet6RouteAddress":collect(o.GetInet6RouteAddress()),"inet4RouteExcludeAddress":collect(o.GetInet4RouteExcludeAddress()),"inet6RouteExcludeAddress":collect(o.GetInet6RouteExcludeAddress()),"inet4RouteRange":collect(o.GetInet4RouteRange()),"inet6RouteRange":collect(o.GetInet6RouteRange()),"includePackage":strings(o.GetIncludePackage()),"excludePackage":strings(o.GetExcludePackage())}
	if o.IsHTTPProxyEnabled(){bypass:=strings(o.GetHTTPProxyBypassDomain());match:=strings(o.GetHTTPProxyMatchDomain());args["httpProxy"]=map[string]any{"enabled":true,"server":o.GetHTTPProxyServer(),"serverPort":o.GetHTTPProxyServerPort(),"bypassDomain":bypass,"matchDomain":match}}
	var response struct{FD *int32 `json:"fd"`};if err=p.invoke(context.Background(),"vpn.openTun",args,&response);err!=nil{return -1,err};if response.FD==nil||*response.FD<0{return -1,errors.New("platform returned invalid TUN fd")};return *response.FD,nil
}
func (p *platformAdapter) FindConnectionOwner(proto int32,src string,srcPort int32,dst string,dstPort int32)(*libbox.ConnectionOwner,error){var r struct{UserID int32 `json:"userId"`;UserName string `json:"userName"`;ProcessPath string `json:"processPath"`;Packages []string `json:"androidPackageNames"`};err:=p.invoke(context.Background(),"network.connectionOwner",map[string]any{"ipProtocol":proto,"sourceAddress":src,"sourcePort":srcPort,"destinationAddress":dst,"destinationPort":dstPort},&r);if err!=nil{return nil,err};owner:=&libbox.ConnectionOwner{UserId:r.UserID,UserName:r.UserName,ProcessPath:r.ProcessPath};owner.SetAndroidPackageNames(&stringIterator{values:r.Packages});return owner,nil}
func (p *platformAdapter) StartDefaultInterfaceMonitor(l libbox.InterfaceUpdateListener)error{return p.monitorStart(l)}
func (p *platformAdapter) CloseDefaultInterfaceMonitor(l libbox.InterfaceUpdateListener)error{return p.monitorStop(l)}
func (p *platformAdapter) GetInterfaces()(libbox.NetworkInterfaceIterator,error){var r []struct{Index int32 `json:"index"`;MTU int32 `json:"mtu"`;Name string `json:"name"`;Addresses []string `json:"addresses"`;Flags int32 `json:"flags"`;Type int32 `json:"type"`;DNSServer []string `json:"dnsServer"`;Gateway []string `json:"gateway"`;Metered bool `json:"metered"`};if err:=p.invoke(context.Background(),"network.interfaces",map[string]any{},&r);err!=nil{return &interfaceIterator{},err};out:=make([]*libbox.NetworkInterface,0,len(r));for _,v:=range r{out=append(out,&libbox.NetworkInterface{Index:v.Index,MTU:v.MTU,Name:v.Name,Addresses:&stringIterator{values:v.Addresses},Flags:v.Flags,Type:v.Type,DNSServer:&stringIterator{values:v.DNSServer},Gateway:&stringIterator{values:v.Gateway},Metered:v.Metered})};return &interfaceIterator{values:out},nil}
func (p *platformAdapter) UnderNetworkExtension()bool{return false}
func (p *platformAdapter) IncludeAllNetworks()bool{return false}
func (p *platformAdapter) ReadWIFIState()*libbox.WIFIState{var r struct{SSID string `json:"ssid"`;BSSID string `json:"bssid"`};if p.invoke(context.Background(),"network.wifi",map[string]any{},&r)!=nil||r.SSID==""{return nil};return libbox.NewWIFIState(r.SSID,r.BSSID)}
func (p *platformAdapter) ClearDNSCache(){_ = p.invoke(context.Background(),"dns.clear",map[string]any{},nil)}
func (p *platformAdapter) SendNotification(n *libbox.Notification)error{return p.invoke(context.Background(),"notification.send",n,nil)}
func (p *platformAdapter) CancelNotification(id string,t int32)error{return p.invoke(context.Background(),"notification.cancel",map[string]any{"identifier":id,"typeId":t},nil)}
func (p *platformAdapter) StartNeighborMonitor(libbox.NeighborUpdateListener)error{return nil}
func (p *platformAdapter) CloseNeighborMonitor(libbox.NeighborUpdateListener)error{return nil}
func (p *platformAdapter) RegisterMyInterface(name string){_ = p.invoke(context.Background(),"network.registerMyInterface",map[string]any{"name":name},nil)}
func (p *platformAdapter) UsePlatformShell()bool{return false}
func (p *platformAdapter) CheckPlatformShell()error{return errors.New("shell unavailable on Android")}
func (p *platformAdapter) OpenShellSession(*libbox.PlatformUser,string,libbox.StringIterator,string,int32,int32)(libbox.ShellSession,error){return nil,errors.New("shell unavailable on Android")}
func (p *platformAdapter) LookupUser(string)(*libbox.PlatformUser,error){return nil,errors.New("user lookup unavailable on Android")}
func (p *platformAdapter) LookupSFTPServer()(string,error){return "",errors.New("SFTP unavailable on Android")}
func (p *platformAdapter) ReadSystemSSHHostKey()(string,error){return "",errors.New("SSH host keys unavailable on Android")}
func (p *platformAdapter) TailscaleHostname()string{return ""}
func (p *platformAdapter) UsePlatformBridge()bool{return false}
func (p *platformAdapter) CreateBridge(*libbox.BridgeOptions)(libbox.BridgeSession,error){return nil,errors.New("platform bridge unavailable on Android")}

type stringIterator struct { values []string; index int }
func (i *stringIterator) HasNext()bool{return i!=nil&&i.index<len(i.values)}
func (i *stringIterator) Next()string{if !i.HasNext(){return ""};v:=i.values[i.index];i.index++;return v}
func (i *stringIterator) Len()int32{if i==nil{return 0};return int32(len(i.values))}
type interfaceIterator struct{values []*libbox.NetworkInterface;index int}
func(i *interfaceIterator)HasNext()bool{return i!=nil&&i.index<len(i.values)}
func(i *interfaceIterator)Next()*libbox.NetworkInterface{if !i.HasNext(){return &libbox.NetworkInterface{}};v:=i.values[i.index];i.index++;return v}

var monitorIDs atomic.Uint64

type monitorEntry struct { stop chan struct{}; once sync.Once }
func(p *platformAdapter)monitorStart(l libbox.InterfaceUpdateListener)error{
	if l==nil{return nil};id:=monitorIDs.Add(1);entry:=&monitorEntry{stop:make(chan struct{})};p.monitorMu.Lock();if p.monitors==nil{p.monitors=map[uint64]*monitorEntry{}};p.monitors[id]=entry;p.monitorMu.Unlock()
	if err:=p.invoke(context.Background(),"network.monitor.start",map[string]any{"id":id},nil);err!=nil{p.monitorMu.Lock();delete(p.monitors,id);p.monitorMu.Unlock();return err}
	go func(){defer func(){p.monitorMu.Lock();delete(p.monitors,id);p.monitorMu.Unlock()}();ticker:=time.NewTicker(2*time.Second);defer ticker.Stop();var previous string;for{select{case<-entry.stop:return;case<-ticker.C:var state struct{InterfaceName string `json:"interfaceName"`;InterfaceIndex int32 `json:"interfaceIndex"`;Expensive bool `json:"expensive"`;Constrained bool `json:"constrained"`;NetworkPath string `json:"networkPath"`};if p.invoke(context.Background(),"network.monitor.poll",map[string]any{"id":id},&state)==nil{key:=fmt.Sprintf("%s:%d:%t:%t",state.InterfaceName,state.InterfaceIndex,state.Expensive,state.Constrained);if key!=previous{previous=key;l.UpdateDefaultInterface(state.InterfaceName,state.InterfaceIndex,state.Expensive,state.Constrained)};if state.NetworkPath!=""{l.UpdateNetworkPath(state.NetworkPath)}}}}}()
	return nil
}
func(p *platformAdapter)monitorStop(l libbox.InterfaceUpdateListener)error{p.monitorMu.Lock();entries:=p.monitors;p.monitors=map[uint64]*monitorEntry{};for _,entry:=range entries{entry.once.Do(func(){close(entry.stop)})};p.monitorMu.Unlock();return p.invoke(context.Background(),"network.monitor.stop",map[string]any{},nil)}

var _ libbox.PlatformInterface=(*platformAdapter)(nil)
