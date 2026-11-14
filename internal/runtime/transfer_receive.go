package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"

	"github.com/Leadaxe/lxbox/app/internal/transfer"
)

var receivers = struct{sync.Mutex; items map[*Application]*transfer.Receiver}{items:map[*Application]*transfer.Receiver{}}

func transferIPv4(address string)string{
	host,_,_:=strings.Cut(address,"/");ip:=net.ParseIP(host)
	if ip==nil||ip.To4()==nil||ip.IsLoopback()||ip.IsUnspecified(){return ""}
	return ip.String()
}

func (a *Application) receiveTransfer(ctx context.Context, method string, raw json.RawMessage) (any,error) {
	switch method {
	case "transfer.receive.stop":
		receivers.Lock(); receiver:=receivers.items[a];delete(receivers.items,a);receivers.Unlock()
		if receiver!=nil{receiver.Close()};return map[string]any{"stopped":true},nil
	case "transfer.receive.start":
		var request struct{Name string `json:"name"`;Addresses []string `json:"addresses"`}
		if err:=decode(raw,&request);err!=nil{return nil,err}
		if request.Name==""{request.Name="LxBox"}
		if len(request.Addresses)==0{
			var interfaces []struct{Addresses []string `json:"addresses"`}
			if err:=a.platformJSON(ctx,"network.interfaces",map[string]any{},&interfaces);err!=nil{return nil,err}
			for _,entry:=range interfaces{for _,address:=range entry.Addresses{if host:=transferIPv4(address);host!=""{request.Addresses=append(request.Addresses,host)}}}
		}
		if len(request.Addresses)==0{return nil,errors.New("no physical IPv4 LAN address is available")}
		receivers.Lock();defer receivers.Unlock()
		if previous:=receivers.items[a];previous!=nil{previous.Close();delete(receivers.items,a)}
		receiver,err:=transfer.NewReceiver(a.ctx,transfer.ReceiverOptions{Parse:func(ctx context.Context,data string)(any,error){return a.backupDispatch(ctx,"backup.preview",mustJSON(map[string]any{"data":data}))}})
		if err!=nil{return nil,err}
		code,err:=receiver.CodeFor(request.Addresses,request.Name);if err!=nil{receiver.Close();return nil,err}
		text,err:=code.Encode();if err!=nil{receiver.Close();return nil,err}
		receivers.items[a]=receiver
		go func(){result,ok:=<-receiver.Done();if !ok{return};a.events.emit("transfer.received",map[string]any{"status":string(result.Kind),"data":result.Raw,"preview":result.Parsed});receivers.Lock();if receivers.items[a]==receiver{delete(receivers.items,a)};receivers.Unlock()}()
		return map[string]any{"code":text,"port":receiver.Port(),"addresses":request.Addresses},nil
	default:return nil,errors.New("unknown transfer receiver operation")
	}
}
