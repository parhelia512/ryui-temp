package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/sagernet/sing-box/experimental/libbox"
)

type platformDNS struct {
	call CallFunc
	raw  bool
}

func newPlatformDNS(call CallFunc) *platformDNS {
	d := &platformDNS{call: call}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if raw, err := call(ctx, "dns.capabilities", json.RawMessage(`{}`)); err == nil {
		var value struct {
			Raw bool `json:"raw"`
		}
		if json.Unmarshal(raw, &value) == nil {
			d.raw = value.Raw
		}
	}
	return d
}
func (d *platformDNS) Raw() bool { return d.raw }
func (d *platformDNS) Lookup(exchange *libbox.ExchangeContext, network, domain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	exchange.OnCancel(cancelFunc{cancel})
	args, _ := json.Marshal(map[string]any{"network": network, "domain": domain})
	raw, err := d.call(ctx, "dns.lookup", args)
	if err != nil {
		return err
	}
	var response struct {
		Addresses []string `json:"addresses"`
		RCode     int32    `json:"rcode"`
		Errno     int32    `json:"errno"`
	}
	if err = json.Unmarshal(raw, &response); err != nil {
		return err
	}
	if response.Errno != 0 {
		exchange.ErrnoCode(response.Errno)
		return nil
	}
	if response.RCode != 0 {
		exchange.ErrorCode(response.RCode)
		return nil
	}
	exchange.Success(strings.Join(response.Addresses, "\n"))
	return nil
}
func (d *platformDNS) Exchange(exchange *libbox.ExchangeContext, message []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	exchange.OnCancel(cancelFunc{cancel})
	args, _ := json.Marshal(map[string]any{"message": base64.StdEncoding.EncodeToString(message)})
	raw, err := d.call(ctx, "dns.exchange", args)
	if err != nil {
		return err
	}
	var response struct {
		Message string `json:"message"`
		RCode   int32  `json:"rcode"`
		Errno   int32  `json:"errno"`
	}
	if err = json.Unmarshal(raw, &response); err != nil {
		return err
	}
	if response.Errno != 0 {
		exchange.ErrnoCode(response.Errno)
		return nil
	}
	if response.RCode != 0 {
		exchange.ErrorCode(response.RCode)
		return nil
	}
	if response.Message == "" {
		return errors.New("Android DNS returned an empty response")
	}
	responseBytes, err := base64.StdEncoding.DecodeString(response.Message)
	if err != nil {
		return err
	}
	exchange.RawSuccess(responseBytes)
	return nil
}

type cancelFunc struct{ cancel context.CancelFunc }

func (f cancelFunc) Invoke() error { f.cancel(); return nil }
