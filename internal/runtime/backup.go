package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Leadaxe/lxbox/app/internal/backup"
	"github.com/Leadaxe/lxbox/app/internal/storage"
)

type backupRequest struct {
	Data       string   `json:"data"`
	Replace    bool     `json:"replace"`
	Categories []string `json:"categories"`
	Format     string   `json:"format"`
	AppVersion string   `json:"app_version"`
}

// backupDispatch owns the complete backup lifecycle without widening storage's
// frozen API. Preview is read-only; import reparses against the latest snapshot.
func (a *Application) backupDispatch(ctx context.Context, method string, args json.RawMessage) (any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var request backupRequest
	if len(args) != 0 {
		if err := decode(args, &request); err != nil {
			return nil, fmt.Errorf("%s arguments: %w", method, err)
		}
	}
	switch method {
	case "backup.list":
		doc, err := a.store.Snapshot()
		if err != nil {
			return nil, err
		}
		return backupCategoryList(doc), nil
	case "backup.export":
		doc, err := a.store.Snapshot()
		if err != nil {
			return nil, err
		}
		seed := map[string]any{}
		if version, exists := doc["storage_version"]; exists {
			seed["storage_version"] = version
		}
		selection, err := backup.Merge(seed, doc, request.Categories, true, nil)
		if err != nil {
			return nil, err
		}
		doc = selection.Data
		if request.Format == "portable" || request.Format == "lx_backup" {
			body, warnings, err := backup.ExportPortable(doc, request.AppVersion)
			if err != nil {
				return nil, err
			}
			return map[string]any{"data": string(body), "format": "lx_backup", "version": backup.Format10, "warnings": warnings}, nil
		}
		body, err := json.MarshalIndent(map[string]any{"app": backup.AppName, "kind": backup.KindBackup, "created_at": time.Now().UTC().Format(time.RFC3339Nano), "storage": doc}, "", "  ")
		if err != nil {
			return nil, err
		}
		return map[string]any{"data": string(body), "format": "snapshot", "warnings": []backup.Warning{}}, nil
	case "backup.preview":
		if request.Data == "" {
			return nil, errors.New("backup.preview requires data")
		}
		parsed, err := backup.Decode(ctx, []byte(request.Data))
		if err != nil {
			return nil, err
		}
		current, err := a.store.Snapshot()
		if err != nil {
			return nil, err
		}
		merged, err := backup.Merge(current, parsed.Data, request.Categories, request.Replace, parsed.Declared)
		if err != nil {
			return nil, err
		}
		warnings := append(append([]backup.Warning(nil), parsed.Warnings...), merged.Warnings...)
		return map[string]any{
			"format": backupFormat(parsed), "version": parsed.Version, "snapshot": parsed.Snapshot,
			"categories": backupCategoryCounts(parsed.Data), "counts": backupCategoryCounts(parsed.Data), "added": merged.Added, "kept": merged.Kept,
			"warnings": warnings, "requires_confirmation": true,
			"source_bytes": len(parsed.Raw),
		}, nil
	case "backup.import":
		if request.Data == "" {
			return nil, errors.New("backup.import requires data")
		}
		parsed, err := backup.Decode(ctx, []byte(request.Data))
		if err != nil {
			return nil, err
		}
		return a.importBackupDocument(ctx, request, parsed)
	default:
		return nil, fmt.Errorf("unknown backup method %q", method)
	}
}

func (a *Application) importBackupDocument(ctx context.Context, request backupRequest, parsed *backup.Document) (any, error) {
	a.mutation.Lock()
	generation, revision, storeGeneration := a.generation, a.revision, a.store.Generation()
	incoming := parsed.Data
	var migration storage.MigrationReport
	var err error
	if parsed.Snapshot {
		incoming, migration, err = storage.MigrateDocumentWithOptions(incoming, a.migrationOptions(ctx))
	}
	a.mutation.Unlock()
	if err != nil {
		return nil, err
	}
	if migration.ReadOnly {
		return map[string]any{"applied": false, "read_only": true, "migration": migration, "warnings": parsed.Warnings}, storage.ErrReadOnly
	}
	// Validate category selection before stopping the Android VPN service.
	if _, err := backup.Merge(map[string]any{}, incoming, request.Categories, request.Replace, parsed.Declared); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil { return nil, err }
	if a.platform != nil {
		if _, err := a.platformCall(ctx, "vpn.stop", map[string]any{}); err != nil {
			return nil, err
		}
	}
	if a.core != nil {
		if err := a.core.Stop(); err != nil { return nil, err }
	}
	a.mutation.Lock()
	if err := ctx.Err(); err != nil { a.mutation.Unlock(); return nil, err }
	if a.generation != generation || a.revision != revision {
		a.mutation.Unlock()
		return nil, errors.New("settings or workspace changed while stopping VPN; preview and retry import")
	}
	var merged backup.MergeResult
	err = a.store.UpdateIfGeneration(storeGeneration, func(doc map[string]any) error {
		if err := ctx.Err(); err != nil { return err }
		var mergeErr error
		merged, mergeErr = backup.Merge(doc, incoming, request.Categories, request.Replace, parsed.Declared)
		if mergeErr != nil { return mergeErr }
		for key := range doc { delete(doc, key) }
		for key, value := range merged.Data { doc[key] = value }
		return nil
	})
	if err != nil { a.mutation.Unlock(); return nil, err }
	a.generation++
	a.revision++
	committedRevision, committedGeneration := a.revision, a.generation
	a.refreshAutomation()
	a.events.emit("settings.changed", map[string]any{"reason":"backup.import", "revision":committedRevision, "generation":committedGeneration})
	committed, snapshotErr := a.store.Snapshot()
	a.mutation.Unlock()
	warnings := append(append([]backup.Warning(nil), parsed.Warnings...), merged.Warnings...)
	response := map[string]any{
		"format": backupFormat(parsed), "version": parsed.Version, "applied": true,
		"replace": request.Replace, "categories": backupCategoryCounts(incoming),
		"counts": backupCategoryCounts(incoming), "added": merged.Added, "kept": merged.Kept,
		"warnings": warnings, "migration": migration, "revision": committedRevision, "generation": committedGeneration,
	}
	if snapshotErr != nil { return response, snapshotErr }
	if backupCategorySelected(request.Categories, "native_prefs") || backupCategorySelected(request.Categories, "vars") {
		if err := a.applyNativeSettings(ctx, committed); err != nil {
			response["native_settings_error"] = err.Error()
			return response, err
		}
	}
	return response, nil
}

func backupCategorySelected(categories []string, category string) bool {
	if len(categories) == 0 { return true }
	for _, selected := range categories { if selected == category { return true } }
	return false
}

func backupFormat(doc *backup.Document) string {
	if doc.Snapshot {
		return "snapshot"
	}
	return "lx_backup"
}

func backupCategoryCounts(doc map[string]any) map[string]int {
	counts := map[string]int{}
	for _, category := range backup.Categories {
		key := category
		if category == "route" {
			key = "route_final"
		}
		value, exists := doc[key]
		if !exists || value == nil {
			counts[category] = 0
			continue
		}
		switch item := value.(type) {
		case []any:
			counts[category] = len(item)
		case map[string]any:
			if category == "dns" {
				counts[category] = countList(item["servers"]) + countList(item["rules"])
			} else if category == "tun_apps" {
				counts[category] = countList(item["packages"])
			} else {
				counts[category] = len(item)
			}
		default:
			counts[category] = 1
		}
	}
	return counts
}

func backupCategoryList(doc map[string]any) map[string]any {
	counts := backupCategoryCounts(doc)
	items := make([]map[string]any, 0, len(backup.Categories))
	for _, category := range backup.Categories {
		items = append(items, map[string]any{"id": category, "count": counts[category], "selected": true})
	}
	return map[string]any{"categories": items, "counts": counts}
}

func countList(value any) int {
	list, _ := value.([]any)
	return len(list)
}
