// Package storage provides the Go app's filesystem persistence boundary.
//
// Host data-directory contract:
//
//  1. The host resolves the legacy Flutter documents directory as
//     applicationInfo.dataDir + "/app_flutter" and calls Open with that path.
//  2. The host resolves the native support cache as filesDir + "/sub_cache" and
//     calls SetCacheDir immediately after Open.
//  3. Runtime calls RecoverWorkspace before consuming Snapshot, then uses
//     Generation and UpdateIfGeneration for asynchronous refreshes.
//
// Open does not infer Android paths and does not depend on RyUI, Android, or
// Flutter. Settings are stored as app_flutter/lxbox_settings.json. Workspace
// state uses app_flutter/workspaces.json and app_flutter/workspaces/<name>/.
// The workspace slot contains lxbox_settings.json, rule_sets/, and sub_cache/.
// Core-generated singbox_config.json, cache.db, logs, native SharedPreferences,
// and tailscale state are deliberately outside this package's slot and backup
// scope.
//
// JSON preservation:
//
// Snapshot and Update use map[string]any. Update clones and validates the full
// document before an atomic temp-file write, so keys not owned by the caller
// survive. Sources returns json.RawMessage records in array order. Workspace
// manifest and its slot/pending entries preserve unknown JSON fields in Extra.
//
// Compatibility:
//
// The reader accepts the current storage_version form and keeps unknown future
// versions read-only. A legacy 2.23.2 document is also loaded read-only until
// MigrateLegacy is called with the external NodeLink/template facts needed to
// prove conversion. A complete conversion normalizes sources/rules/dns,
// removes the recognized legacy collections, and writes storage_version: 1;
// an incomplete conversion returns the original document and never writes it.
// The original legacy bytes are retained once in lxbox_settings.json.v0.bak.
// MigrationReport names every missing semantic input. This package does not
// claim full Dart model, Flutter template, or Android native-preference parity.
package storage
