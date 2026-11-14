package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/Leadaxe/lxbox/app/internal/debugapi"
)

func (a *Application) debugDispatch(ctx context.Context, method string, args map[string]any) (any, error) {
	a.debugMu.Lock()
	defer a.debugMu.Unlock()
	switch method {
	case "debug.status":
		if a.debug == nil {
			return map[string]any{"running": false}, nil
		}
		return map[string]any{"running": a.debug.Running(), "address": a.debug.Addr()}, nil
	case "debug.start":
		if a.debug != nil && a.debug.Running() {
			return map[string]any{"running": true, "address": a.debug.Addr()}, nil
		}
		doc, err := a.store.Snapshot()
		if err != nil {
			return nil, err
		}
		vars, _ := doc["vars"].(map[string]any)
		token, _ := vars["debug_token"].(string)
		if token == "" {
			body := make([]byte, 32)
			if _, err = rand.Read(body); err != nil {
				return nil, err
			}
			token = hex.EncodeToString(body)
			if err = a.store.Update(func(doc map[string]any) error {
				v, _ := doc["vars"].(map[string]any)
				if v == nil {
					v = map[string]any{}
					doc["vars"] = v
				}
				v["debug_token"] = token
				return nil
			}); err != nil {
				return nil, err
			}
		}
		config := debugapi.DefaultConfig(token)
		if value, ok := vars["debug_port"]; ok {
			if port, parseErr := strconv.Atoi(toText(value)); parseErr == nil && port > 0 && port <= 65535 {
				config.Port = port
			}
		}
		a.debug = debugapi.NewServer(config, func(ctx context.Context, name string, args json.RawMessage) (any, error) {
			if strings.HasPrefix(name, "http.") {
				return a.debugHTTP(ctx, name, args)
			}
			return a.automation.DispatchDebug(ctx, name, args)
		})
		if err = a.debug.Start(a.ctx); err != nil {
			return nil, err
		}
		return map[string]any{"running": true, "address": a.debug.Addr()}, nil
	case "debug.stop":
		if a.debug == nil {
			return map[string]any{"running": false}, nil
		}
		stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		err := a.debug.Stop(stopCtx)
		return map[string]any{"running": false}, err
	default:
		return nil, errors.New("unknown debug API operation")
	}
}

func toText(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}
