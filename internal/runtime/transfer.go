package runtime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/Leadaxe/lxbox/app/internal/transfer"
)

func(a *Application)sendBackup(ctx context.Context,raw json.RawMessage)(any,error){
	var request struct{Code string `json:"code"`;Data string `json:"data"`}
	if err:=decode(raw,&request);err!=nil{return nil,err}
	code,err:=transfer.ParseCode(request.Code);if err!=nil{return nil,err}
	if request.Data==""{value,err:=a.backupDispatch(ctx,"backup.export",json.RawMessage(`{}`));if err!=nil{return nil,err};encoded,err:=json.Marshal(value);if err!=nil{return nil,err};var out struct{Data string `json:"data"`};if err=json.Unmarshal(encoded,&out);err!=nil{return nil,err};request.Data=out.Data}
	if request.Data==""{return nil,fmt.Errorf("backup is empty")}
	envelope,err:=transfer.Seal([]byte(request.Data),code.Key);if err!=nil{return nil,err}
	result:=a.transferClient().Sender().Send(ctx,*code,envelope)
	if result.Status!=transfer.Sent{return result,fmt.Errorf("transfer failed: %s %s",result.Status,result.Detail)}
	return result,nil
}

func(a *Application)transferClient()*transfer.Client{
	sender:=transfer.NewSenderWithNativePost(func(ctx context.Context,endpoint transfer.Endpoint,body []byte)(transfer.LANOutcome,error){
		var reply struct{Outcome string `json:"outcome"`;Status int `json:"status"`;Body string `json:"body"`;Detail string `json:"detail"`}
		err:=a.platformJSON(ctx,"lan.post",map[string]any{"host":endpoint.Host,"port":endpoint.Port,"path":transfer.Path,"body":base64.StdEncoding.EncodeToString(body),"connectTimeoutMs":5000,"readTimeoutMs":60000},&reply)
		if err!=nil{return transfer.LANOutcome{},err}
		result:=transfer.LANOutcome{Status:reply.Status,Body:reply.Body,Detail:reply.Detail}
		switch reply.Outcome{case "response":result.Kind=transfer.LANResponse;case "refused":result.Kind=transfer.LANRefused;case "unreachable":result.Kind=transfer.LANUnreachable;case "no_network":result.Kind=transfer.LANNoNetwork;default:return transfer.LANOutcome{},fmt.Errorf("Android LAN callback returned unknown outcome %q",reply.Outcome)}
		return result,nil
	})
	return transfer.New(transfer.WithSender(sender))
}
