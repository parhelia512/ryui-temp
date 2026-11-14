//go:build android

package mobile

/*
#cgo CFLAGS: -I${SRCDIR}
#include <stdint.h>
#include <stdlib.h>
#include "jni_bridge.h"
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"unsafe"

	"github.com/Leadaxe/lxbox/app/internal/core"
	"github.com/Leadaxe/lxbox/app/internal/runtime"
)

//export NativeBootstrap
func NativeBootstrap(dataDir *C.char) *C.char {
	if dataDir == nil {
		return errorJSON(errors.New("dataDir is required"))
	}
	documents := filepath.Join(C.GoString(dataDir), "app_flutter")
	appCall := core.CallFunc(platformCall)
	if err := runtime.Initialize(documents, appCall); err != nil {
		return errorJSON(err)
	}
	return envelope(nil, nil)
}

//export NativeAppCall
func NativeAppCall(method *C.char, args *C.char) *C.char {
	if method == nil {
		return errorJSON(errors.New("method is required"))
	}
	raw := json.RawMessage(`{}`)
	if args != nil && C.GoString(args) != "" {
		raw = json.RawMessage(C.GoString(args))
	}
	value, err := runtime.Dispatch(context.Background(), C.GoString(method), raw)
	return envelope(value, err)
}

func platformCall(ctx context.Context, method string, args json.RawMessage) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cMethod := C.CString(method)
	cArgs := C.CString(string(args))
	defer C.free(unsafe.Pointer(cMethod))
	defer C.free(unsafe.Pointer(cArgs))
	var cError *C.char
	result := C.lxbox_call(cMethod, cArgs, &cError)
	if cError != nil {
		defer C.lxbox_release(cError)
		return nil, errors.New(C.GoString(cError))
	}
	if result == nil {
		return nil, errors.New("platform callback returned no JSON")
	}
	defer C.lxbox_release(result)
	responseJSON := json.RawMessage(C.GoString(result))
	if !json.Valid(responseJSON) {
		return nil, errors.New("platform callback returned invalid JSON")
	}
	var response struct {
		OK    bool            `json:"ok"`
		Data  json.RawMessage `json:"data"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(responseJSON, &response); err == nil {
		if response.Error != nil {
			return append(json.RawMessage(nil), response.Data...), errors.New(response.Error.Message)
		}
		if response.OK {
			return append(json.RawMessage(nil), response.Data...), nil
		}
	}
	return responseJSON, nil
}

func envelope(value any, err error) *C.char {
	body := map[string]any{"ok": err == nil, "data": value}
	if err != nil {
		body["error"] = map[string]any{"message": err.Error()}
	}
	raw, marshalErr := json.Marshal(body)
	if marshalErr != nil {
		raw = []byte(`{"ok":false,"data":null,"error":{"message":"marshal response"}}`)
	}
	return C.CString(string(raw))
}

func errorJSON(err error) *C.char { return envelope(nil, err) }

//export NativeFree
func NativeFree(value *C.char) {
	if value != nil {
		C.free(unsafe.Pointer(value))
	}
}
