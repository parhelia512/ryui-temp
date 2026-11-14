package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/Leadaxe/lxbox/app/assets"
	"github.com/Leadaxe/lxbox/app/internal/automation"
	"github.com/Leadaxe/lxbox/app/internal/core"
	"github.com/Leadaxe/lxbox/app/internal/debugapi"
	"github.com/Leadaxe/lxbox/app/internal/storage"
)

var active struct {
	sync.RWMutex
	app *Application
}

type Application struct {
	store *storage.Store
	automation *automation.Engine
	debug *debugapi.Server
	debugMu sync.Mutex
	core *core.Controller
	platform core.CallFunc
	dataDir string
	supportDir string
	ctx context.Context
	cancel context.CancelFunc
	mutation sync.Mutex
	events eventLog
	generation uint64
	revision uint64
	fetching map[string]bool
}

func Initialize(dataDir string, platform core.CallFunc) error {
	if platform == nil { return errors.New("Android platform callback is required") }
	if !filepath.IsAbs(dataDir) { return errors.New("application data directory must be absolute") }
	active.Lock()
	defer active.Unlock()
	if active.app != nil { return nil }
	store, err := storage.Open(dataDir)
	if err != nil { return fmt.Errorf("open application storage: %w",err) }
	supportDir := dataDir
	if raw, callErr := platform(context.Background(),"paths",json.RawMessage(`{}`)); callErr == nil {
		var paths struct { CacheDir string `json:"cacheDir"`; SupportDir string `json:"supportDir"` }
		if json.Unmarshal(raw,&paths) == nil {
			if paths.CacheDir!="" { if err=store.SetCacheDir(paths.CacheDir); err!=nil{return err} }
			if paths.SupportDir!="" { supportDir=paths.SupportDir }
		}
	}
	ctx,cancel := context.WithCancel(context.Background())
	a:=&Application{store:store,platform:platform,dataDir:dataDir,supportDir:supportDir,ctx:ctx,cancel:cancel,fetching:map[string]bool{}}
	corePlatform:=func(ctx context.Context,method string,args json.RawMessage)(json.RawMessage,error){
		if method=="events.emit"{
			var event struct{Type string `json:"type"`;Data json.RawMessage `json:"data"`}
			if err:=decode(args,&event);err!=nil{return nil,err}
			a.events.emit(event.Type,event.Data)
			return json.RawMessage(`null`),nil
		}
		return platform(ctx,method,args)
	}
	controller, err := core.New(corePlatform,supportDir)
	if err != nil { cancel();return fmt.Errorf("initialize Go core: %w",err) }
	a.core=controller
	if _,err=store.RecoverWorkspace();err!=nil{cancel();return fmt.Errorf("recover workspace: %w",err)}
	if err=a.initializeServices();err!=nil{cancel();return err}
	active.app=a
	a.startUpdater()
	a.events.emit("application.ready",map[string]any{"dataDir":dataDir})
	return nil
}

func Dispatch(ctx context.Context, method string, args json.RawMessage) (any,error) {
	if ctx==nil {ctx=context.Background()}
	if err:=ctx.Err();err!=nil{return nil,err}
	active.RLock(); a:=active.app; active.RUnlock()
	if a==nil{return nil,errors.New("application runtime has not been initialized by Android Host")}
	if len(args)==0{args=json.RawMessage(`{}`)}
	if !json.Valid(args){return nil,errors.New("invalid JSON arguments")}
	return a.dispatch(ctx,method,args)
}

func (a *Application) dispatch(ctx context.Context, method string, args json.RawMessage)(any,error){
	switch method {
	case "events.poll":
		var p struct{After uint64 `json:"after"`}; if err:=decode(args,&p);err!=nil{return nil,err};return a.events.poll(p.After),nil
	case "events.emit":
		var p struct{Type string `json:"type"`;Data json.RawMessage `json:"data"`};if err:=decode(args,&p);err!=nil{return nil,err};if p.Type==""{return nil,errors.New("event type is required")};a.events.emit(p.Type,p.Data);return nil,nil
	case "settings.get":return a.store.Snapshot()
	case "settings.save":return a.saveSettings(ctx,args)
	case "sources.list":return a.sourceList()
	case "sources.save":return a.saveSource(args)
	case "sources.delete":return a.deleteSource(args)
	case "sources.import":return a.importSource(ctx,args)
	case "sources.refresh":return a.refreshSource(ctx,args)
	case "sources.refreshAll":return a.refreshAll(ctx,args)
	case "config.get":return a.readConfig()
	case "config.save":return a.saveConfig(ctx,args,true)
	case "config.build":return a.buildConfig(ctx)
	case "config.validate":
		config,err:=a.configArgument(args);if err!=nil{return nil,err};return a.core.Call(ctx,"validate",config)
	case "vpn.status":return a.core.Status(),nil
	case "vpn.start","vpn.reload":
		config,err:=a.readConfig();if err!=nil{return nil,err};return a.platformCall(ctx,method,map[string]any{"config":config})
	case "vpn.stop":return a.platformCall(ctx,method,map[string]any{})
	case "service.start","service.reload":
		config,err:=a.configArgument(args);if err!=nil{return nil,err}
		if method=="service.start"{err=a.core.Start(string(config))}else{err=a.core.Reload(string(config))}
		if err!=nil{a.events.emit("vpn.error",map[string]any{"message":err.Error()});return nil,err};a.events.emit("vpn.status",a.core.Status());a.onVPNState(true);return a.core.Status(),nil
	case "service.stop":
		err:=a.core.Stop();a.events.emit("vpn.status",a.core.Status());a.onVPNState(false);return a.core.Status(),err
	case "core.call":
		var p struct{Method string `json:"method"`;Args json.RawMessage `json:"args"`};if err:=decode(args,&p);err!=nil{return nil,err};if p.Method==""{return nil,errors.New("core method is required")};if len(p.Args)==0{p.Args=json.RawMessage(`{}`)};return a.core.Call(ctx,p.Method,p.Args)
	case "workspaces.list":return a.listWorkspaces()
	case "workspaces.save","workspaces.load","workspaces.delete","workspaces.rename":return a.workspace(ctx,method,args)
	case "backup.export","backup.import","backup.preview","backup.list":return a.backupDispatch(ctx,method,args)
	case "assets.read":
		var p struct{Name string `json:"name"`};if err:=decode(args,&p);err!=nil{return nil,err};body,err:=assets.Read(p.Name);if err!=nil{return nil,err};var value any;if json.Unmarshal(body,&value)==nil{return value,nil};return string(body),nil
	case "platform.call":
		var p struct{Method string `json:"method"`;Args json.RawMessage `json:"args"`};if err:=decode(args,&p);err!=nil{return nil,err};if p.Method==""{return nil,errors.New("platform method is required")};return a.platformCall(ctx,p.Method,p.Args)
	default:return a.dispatchService(ctx,method,args)
	}
}

func (a *Application) platformCall(ctx context.Context, method string,value any)(any,error){
	raw,err:=json.Marshal(value);if err!=nil{return nil,err};result,err:=a.platform(ctx,method,raw);if err!=nil{return nil,err};if len(result)==0{return nil,nil};var out any;if err=json.Unmarshal(result,&out);err!=nil{return nil,fmt.Errorf("platform %s returned invalid JSON: %w",method,err)};return out,nil
}

func decode(raw []byte,value any)error{
	d:=json.NewDecoder(bytes.NewReader(raw));d.UseNumber();if err:=d.Decode(value);err!=nil{return err};if d.Decode(new(any))!=io.EOF{return errors.New("unexpected data after JSON value")};return nil
}

func (a *Application) configPath()string{return filepath.Join(a.supportDir,"singbox_config.json")}
func (a *Application) readConfig()(json.RawMessage,error){
	body,err:=os.ReadFile(a.configPath());if errors.Is(err,os.ErrNotExist){return nil,errors.New("no saved configuration; build or import a configuration first")};if err!=nil{return nil,err};if !json.Valid(body){return nil,errors.New("saved configuration is not valid JSON")};return body,nil
}

func (a *Application) configArgument(args json.RawMessage)(json.RawMessage,error){
	var wrapped map[string]json.RawMessage;if err:=json.Unmarshal(args,&wrapped);err!=nil{return nil,err}
	if len(wrapped)==0{return a.readConfig()}
	if value,ok:=wrapped["config"];ok{var text string;if json.Unmarshal(value,&text)==nil{value=json.RawMessage(text)};if !json.Valid(value){return nil,errors.New("configuration is not valid JSON")};return value,nil}
	return args,nil
}

func (a *Application) saveConfig(ctx context.Context, raw json.RawMessage,validate bool)(any,error){
	config,err:=a.configArgument(raw);if err!=nil{return nil,err}
	var object map[string]any;if err=decode(config,&object);err!=nil{return nil,err};if object==nil{return nil,errors.New("configuration must be an object")}
	if validate{if _,err=a.core.Call(ctx,"validate",config);err!=nil{return nil,err}}
	if err=ctx.Err();err!=nil{return nil,err}
	pretty,err:=json.MarshalIndent(object,"","  ");if err!=nil{return nil,err}
	if err=atomicWrite(a.configPath(),pretty);err!=nil{return nil,err};a.events.emit("config.changed",map[string]any{"bytes":len(pretty)});return object,nil
}

func atomicWrite(path string,body []byte)error{
	if err:=os.MkdirAll(filepath.Dir(path),0700);err!=nil{return err};f,err:=os.CreateTemp(filepath.Dir(path),".lxbox-write-*");if err!=nil{return err};name:=f.Name();defer os.Remove(name)
	if err=f.Chmod(0600);err!=nil{f.Close();return err};if _,err=f.Write(body);err!=nil{f.Close();return err};if err=f.Sync();err!=nil{f.Close();return err};if err=f.Close();err!=nil{return err};return os.Rename(name,path)
}
