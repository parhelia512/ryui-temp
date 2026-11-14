package runtime

import (
	"context"
	"encoding/json"
	"time"
)

func Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	active.Lock()
	application := active.app
	active.app = nil
	active.Unlock()
	if application == nil {
		return nil
	}
	application.cancel()
	_ = application.Close()
	_, _ = application.receiveTransfer(ctx, "transfer.receive.stop", json.RawMessage(`{}`))
	application.debugMu.Lock()
	if application.debug != nil {
		stopContext, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = application.debug.Stop(stopContext)
		cancel()
	}
	application.debugMu.Unlock()
	if application.automation != nil {
		_ = application.automation.Stop(ctx)
	}
	return application.core.Close()
}
