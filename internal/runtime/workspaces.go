package runtime

import (
	"context"
	"encoding/json"
	"errors"
)

func (a *Application) listWorkspaces() (any, error) {
	manifest, err := a.store.ListWorkspaces()
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	var value struct {
		Current string           `json:"current"`
		Slots   []map[string]any `json:"slots"`
	}
	if err = json.Unmarshal(body, &value); err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(value.Slots))
	for _, slot := range value.Slots {
		name, _ := slot["name"].(string)
		slot["id"] = name
		slot["current"] = name == value.Current
		out = append(out, slot)
	}
	if len(out) == 0 {
		out = append(out, map[string]any{"id": value.Current, "name": value.Current, "current": true})
	}
	return out, nil
}

func (a *Application) workspace(ctx context.Context, method string, args json.RawMessage) (any, error) {
	var p struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		NewName string `json:"newName"`
	}
	if err := decode(args, &p); err != nil {
		return nil, err
	}
	if p.Name == "" {
		p.Name = p.ID
	}
	if p.Name == "" {
		return nil, errors.New("workspace name is required")
	}
	a.mutation.Lock()
	defer a.mutation.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var err error
	switch method {
	case "workspaces.save":
		err = a.store.SaveWorkspace(p.Name)
	case "workspaces.load":
		if _, err = a.platformCall(ctx, "vpn.stop", map[string]any{}); err != nil {
			return nil, err
		}
		if err = a.core.Stop(); err != nil {
			return nil, err
		}
		_, err = a.store.LoadWorkspace(p.Name)
		if err == nil {
			a.generation++
			a.events.emit("workspace.changed", map[string]any{"name": p.Name, "generation": a.generation})
		}
	case "workspaces.delete":
		err = a.store.DeleteWorkspace(p.Name)
	case "workspaces.rename":
		if p.NewName == "" {
			return nil, errors.New("new workspace name is required")
		}
		err = a.store.RenameWorkspace(p.Name, p.NewName)
	default:
		return nil, errors.New("unknown workspace method")
	}
	if err != nil {
		return nil, err
	}
	return a.listWorkspaces()
}
