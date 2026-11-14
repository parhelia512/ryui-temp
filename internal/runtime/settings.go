package runtime

import (
	"context"
	"encoding/json"
	"errors"
)

func (a *Application) saveSettings(ctx context.Context, args json.RawMessage) (any, error) {
	var patch map[string]any
	if err := decode(args, &patch); err != nil { return nil, err }
	if patch == nil { return nil, errors.New("settings must be an object") }
	if err := lockConfigBuild(ctx, &a.mutation); err != nil { return nil, err }
	err := a.store.Update(func(document map[string]any) error {
		mergeSourcePatch(document, patch)
		return nil
	})
	if err != nil { a.mutation.Unlock(); return nil, err }
	a.revision++
	a.refreshAutomation()
	document, err := a.store.Snapshot()
	a.mutation.Unlock()
	if err != nil { return nil, err }
	a.events.emit("settings.changed", map[string]any{})
	if err := a.applyNativeSettings(ctx, document); err != nil {
		return document, errors.New("settings were saved, but Android preferences could not be applied: " + err.Error())
	}
	return document, nil
}
