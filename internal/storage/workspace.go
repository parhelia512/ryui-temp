package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WorkspaceSlot is a saved workspace entry. Extra retains slot fields written
// by newer clients.
type WorkspaceSlot struct {
	Name    string
	SavedAt time.Time
	Extra   map[string]json.RawMessage
}

// WorkspacePending is the journal for an interrupted load operation.
type WorkspacePending struct {
	Op     string
	Target string
	Extra  map[string]json.RawMessage
}

// WorkspaceManifest is the on-disk workspaces.json contract. The JSON field
// names intentionally match the Dart implementation.
type WorkspaceManifest struct {
	Version int
	Current string
	Slots   []WorkspaceSlot
	Pending *WorkspacePending
	Extra   map[string]json.RawMessage
}

func initialManifest() WorkspaceManifest {
	return WorkspaceManifest{Version: WorkspaceManifestVersion, Current: DefaultWorkspaceName}
}

func (m WorkspaceManifest) HasSlot(name string) bool {
	for _, slot := range m.Slots {
		if slot.Name == name {
			return true
		}
	}
	return false
}

func (m WorkspaceManifest) Names() map[string]bool {
	names := map[string]bool{m.Current: true}
	for _, slot := range m.Slots {
		if slot.Name != "" && requireExistingWorkspaceName(slot.Name) == nil {
			names[slot.Name] = true
		}
	}
	return names
}

func (m WorkspaceManifest) MarshalJSON() ([]byte, error) {
	out := cloneRawMap(m.Extra)
	if out == nil {
		out = map[string]json.RawMessage{}
	}
	version, err := json.Marshal(m.Version)
	if err != nil {
		return nil, err
	}
	current, err := json.Marshal(m.Current)
	if err != nil {
		return nil, err
	}
	slots, err := json.Marshal(m.Slots)
	if err != nil {
		return nil, err
	}
	out["version"] = version
	out["current"] = current
	out["slots"] = slots
	if m.Pending == nil {
		out["pending"] = []byte("null")
	} else if pending, err := json.Marshal(m.Pending); err != nil {
		return nil, err
	} else {
		out["pending"] = pending
	}
	return json.Marshal(out)
}

func (m *WorkspaceManifest) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var version int
	if value, ok := raw["version"]; ok && json.Unmarshal(value, &version) == nil {
		m.Version = version
	} else {
		m.Version = WorkspaceManifestVersion
	}
	if value, ok := raw["current"]; ok {
		_ = json.Unmarshal(value, &m.Current)
	}
	if m.Current == "" {
		m.Current = DefaultWorkspaceName
	}
	if value, ok := raw["slots"]; ok {
		_ = json.Unmarshal(value, &m.Slots)
	}
	if value, ok := raw["pending"]; ok && string(value) != "null" {
		var pending WorkspacePending
		if err := json.Unmarshal(value, &pending); err == nil {
			m.Pending = &pending
		}
	}
	m.Extra = unknownRaw(raw, "version", "current", "slots", "pending")
	return nil
}

func (slot WorkspaceSlot) MarshalJSON() ([]byte, error) {
	out := cloneRawMap(slot.Extra)
	if out == nil {
		out = map[string]json.RawMessage{}
	}
	name, err := json.Marshal(slot.Name)
	if err != nil {
		return nil, err
	}
	savedAt, err := json.Marshal(slot.SavedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	out["name"] = name
	out["saved_at"] = savedAt
	return json.Marshal(out)
}

func (slot *WorkspaceSlot) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	_ = json.Unmarshal(raw["name"], &slot.Name)
	var saved string
	if json.Unmarshal(raw["saved_at"], &saved) == nil {
		slot.SavedAt, _ = time.Parse(time.RFC3339Nano, saved)
	}
	if slot.SavedAt.IsZero() {
		slot.SavedAt = time.Unix(0, 0).UTC()
	}
	slot.Extra = unknownRaw(raw, "name", "saved_at")
	return nil
}

func (pending WorkspacePending) MarshalJSON() ([]byte, error) {
	out := cloneRawMap(pending.Extra)
	if out == nil {
		out = map[string]json.RawMessage{}
	}
	op, err := json.Marshal(pending.Op)
	if err != nil {
		return nil, err
	}
	target, err := json.Marshal(pending.Target)
	if err != nil {
		return nil, err
	}
	out["op"] = op
	out["target"] = target
	return json.Marshal(out)
}

func (pending *WorkspacePending) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	_ = json.Unmarshal(raw["op"], &pending.Op)
	_ = json.Unmarshal(raw["target"], &pending.Target)
	pending.Extra = unknownRaw(raw, "op", "target")
	return nil
}

// ListWorkspaces reads the manifest. Missing manifests use the Dart-compatible
// initial state and do not create a file.
func (s *Store) ListWorkspaces() (WorkspaceManifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readManifestLocked()
}

// SaveWorkspace copies the current scene into name and marks name current.
// The saved slot consists of settings, rule_sets, and subscription sub_cache.
func (s *Store) SaveWorkspace(rawName string) error {
	name, err := requireWorkspaceName(rawName)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	manifest, err := s.readManifestLocked()
	if err != nil {
		return err
	}
	if err := s.copySceneToSlotLocked(name); err != nil {
		return err
	}
	manifest = manifest.withSlotSaved(name, time.Now().UTC())
	manifest.Current = name
	manifest.Pending = nil
	return s.writeManifestLocked(manifest)
}

// LoadWorkspace switches the scene to name. It returns false when name is
// already current. A pending journal makes a killed mid-copy operation
// replayable through RecoverWorkspace.
func (s *Store) LoadWorkspace(rawName string) (bool, error) {
	name := strings.TrimSpace(rawName)
	if err := requireExistingWorkspaceName(name); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	manifest, err := s.readManifestLocked()
	if err != nil {
		return false, err
	}
	if name == manifest.Current {
		return false, nil
	}
	if manifest.Pending != nil {
		return false, errors.New("storage: recover the pending workspace operation first")
	}
	if !manifest.HasSlot(name) || !s.slotExistsLocked(name) {
		return false, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err := s.copySceneToSlotLocked(manifest.Current); err != nil {
		return false, err
	}
	manifest = manifest.withSlotSaved(manifest.Current, time.Now().UTC())
	manifest.Pending = &WorkspacePending{Op: "load", Target: name}
	if err := s.writeManifestLocked(manifest); err != nil {
		return false, err
	}
	if err := s.performLoadLocked(manifest); err != nil {
		return false, err
	}
	if err := s.reloadDocumentLocked(); err != nil {
		return false, err
	}
	manifest.Current = name
	manifest.Pending = nil
	if err := s.writeManifestLocked(manifest); err != nil {
		return false, err
	}
	s.generation++
	return true, nil
}

// RecoverWorkspace replays an interrupted load journal. It should run before
// runtime starts consuming settings. It returns true when it completed a load.
func (s *Store) RecoverWorkspace() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	manifest, err := s.readManifestLocked()
	if err != nil {
		return false, err
	}
	if manifest.Pending == nil {
		return false, nil
	}
	if manifest.Pending.Op != "load" || !s.slotExistsLocked(manifest.Pending.Target) {
		manifest.Pending = nil
		return false, s.writeManifestLocked(manifest)
	}
	if err := s.performLoadLocked(manifest); err != nil {
		return false, err
	}
	if err := s.reloadDocumentLocked(); err != nil {
		return false, err
	}
	manifest.Current = manifest.Pending.Target
	manifest.Pending = nil
	if err := s.writeManifestLocked(manifest); err != nil {
		return false, err
	}
	s.generation++
	return true, nil
}

// RenameWorkspace renames an inactive or current saved slot, preserving its
// directory contents and manifest metadata.
func (s *Store) RenameWorkspace(rawOld, rawNew string) error {
	oldName := strings.TrimSpace(rawOld)
	newName, err := requireWorkspaceName(rawNew)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	manifest, err := s.readManifestLocked()
	if err != nil {
		return err
	}
	if oldName == newName {
		return nil
	}
	if !manifest.HasSlot(oldName) || !s.slotExistsLocked(oldName) {
		return fmt.Errorf("%w: %s", ErrNotFound, oldName)
	}
	if manifest.HasSlot(newName) || s.slotExistsLocked(newName) {
		return fmt.Errorf("%w: %s", ErrExists, newName)
	}
	if err := os.Rename(s.slotDir(oldName), s.slotDir(newName)); err != nil {
		return err
	}
	for i := range manifest.Slots {
		if manifest.Slots[i].Name == oldName {
			manifest.Slots[i].Name = newName
		}
	}
	if manifest.Current == oldName {
		manifest.Current = newName
	}
	return s.writeManifestLocked(manifest)
}

// DeleteWorkspace removes an inactive saved slot. Current cannot be deleted,
// matching the Dart WorkspaceStore contract.
func (s *Store) DeleteWorkspace(rawName string) error {
	name := strings.TrimSpace(rawName)
	if err := requireExistingWorkspaceName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	manifest, err := s.readManifestLocked()
	if err != nil {
		return err
	}
	if name == manifest.Current {
		return fmt.Errorf("%w: %s", ErrCurrentWorkspace, name)
	}
	if !manifest.HasSlot(name) {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err := os.RemoveAll(s.slotDir(name)); err != nil {
		return err
	}
	manifest.removeSlot(name)
	return s.writeManifestLocked(manifest)
}

// WorkspaceSizeBytes reports the on-disk size of a saved slot.
func (s *Store) WorkspaceSizeBytes(rawName string) (int64, error) {
	name := strings.TrimSpace(rawName)
	if err := requireExistingWorkspaceName(name); err != nil {
		return 0, err
	}
	var total int64
	err := filepath.WalkDir(s.slotDir(name), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("storage: symlinks are not valid workspace entries")
		}
		if !entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			total += info.Size()
		}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	return total, err
}

func (s *Store) readManifestLocked() (WorkspaceManifest, error) {
	data, err := os.ReadFile(filepath.Join(s.dataDir, WorkspaceFileName))
	if errors.Is(err, os.ErrNotExist) {
		return initialManifest(), nil
	}
	if err != nil {
		return WorkspaceManifest{}, err
	}
	var manifest WorkspaceManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return WorkspaceManifest{}, fmt.Errorf("storage: decode workspace manifest: %w", err)
	}
	if manifest.Current == "" || requireExistingWorkspaceName(manifest.Current) != nil {
		return WorkspaceManifest{}, fmt.Errorf("storage: invalid current workspace name %q", manifest.Current)
	}
	for _, slot := range manifest.Slots {
		if requireExistingWorkspaceName(slot.Name) != nil {
			return WorkspaceManifest{}, fmt.Errorf("storage: invalid workspace slot name %q", slot.Name)
		}
	}
	if manifest.Pending != nil && requireExistingWorkspaceName(manifest.Pending.Target) != nil {
		return WorkspaceManifest{}, fmt.Errorf("storage: invalid pending workspace target %q", manifest.Pending.Target)
	}
	if manifest.Version == 0 {
		manifest.Version = WorkspaceManifestVersion
	}
	return manifest, nil
}

func (s *Store) writeManifestLocked(manifest WorkspaceManifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("storage: encode workspace manifest: %w", err)
	}
	return s.writeAtomicLocked(filepath.Join(s.dataDir, WorkspaceFileName), data, 0o600)
}

func (s *Store) performLoadLocked(manifest WorkspaceManifest) error {
	if manifest.Pending == nil {
		return errors.New("storage: workspace load has no pending target")
	}
	target := manifest.Pending.Target
	if err := s.keepLegacyWorkspaceCopyLocked(target); err != nil {
		return err
	}
	return s.copySlotToSceneLocked(target)
}

func (s *Store) keepLegacyWorkspaceCopyLocked(name string) error {
	settings := filepath.Join(s.slotDir(name), SettingsFileName)
	data, err := os.ReadFile(settings)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	doc, err := model.DecodeObject(data)
	if err != nil {
		return nil
	}
	if _, versioned := doc["storage_version"]; versioned {
		return nil
	}
	backup := settings + ".v0.bak"
	if _, err := os.Stat(backup); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeFileAtomic(backup, data, 0o600)
}

func (s *Store) reloadDocumentLocked() error {
	data, err := os.ReadFile(filepath.Join(s.dataDir, SettingsFileName))
	if err != nil {
		return err
	}
	doc, err := model.DecodeObject(data)
	if err != nil {
		return err
	}
	migrated, report, err := MigrateDocumentWithOptions(doc, MigrationOptions{})
	if err != nil {
		return err
	}
	if report.ReadOnly {
		s.readOnly = true
		s.migration = cloneMigrationReport(report)
		return ErrReadOnly
	}
	s.doc = migrated
	s.readOnly = false
	s.migration = cloneMigrationReport(report)
	if report.Migrated {
		if err := s.writeDocumentLocked(migrated); err != nil { return err }
	}
	return nil
}

func (s *Store) slotDir(name string) string {
	return filepath.Join(s.dataDir, WorkspaceDirName, name)
}

func (s *Store) slotExistsLocked(name string) bool {
	info, err := os.Stat(s.slotDir(name))
	return err == nil && info.IsDir()
}

func (s *Store) copySceneToSlotLocked(name string) error {
	slot := s.slotDir(name)
	if err := os.MkdirAll(filepath.Dir(slot), 0o700); err != nil {
		return err
	}
	if err := replaceDirectory(slot, func(temp string) error {
		if err := copyFileIfPresent(filepath.Join(s.dataDir, SettingsFileName), filepath.Join(temp, SettingsFileName)); err != nil {
			return err
		}
		if err := copyDirectoryIfPresent(filepath.Join(s.dataDir, RuleSetsDirName), filepath.Join(temp, RuleSetsDirName)); err != nil {
			return err
		}
		return copyDirectoryIfPresent(s.cacheDir, filepath.Join(temp, "sub_cache"))
	}); err != nil {
		return fmt.Errorf("storage: save workspace %q: %w", name, err)
	}
	return nil
}

func (s *Store) copySlotToSceneLocked(name string) error {
	slot := s.slotDir(name)
	if err := copyFileIfPresent(filepath.Join(slot, SettingsFileName), filepath.Join(s.dataDir, SettingsFileName)); err != nil {
		return err
	}
	if err := replaceDirectory(filepath.Join(s.dataDir, RuleSetsDirName), func(temp string) error {
		return copyDirectoryIfPresent(filepath.Join(slot, RuleSetsDirName), temp)
	}); err != nil {
		return err
	}
	if err := replaceDirectory(s.cacheDir, func(temp string) error {
		return copyDirectoryIfPresent(filepath.Join(slot, "sub_cache"), temp)
	}); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(s.dataDir, SettingsFileName+".bak"))
	return nil
}

func (m WorkspaceManifest) withSlotSaved(name string, at time.Time) WorkspaceManifest {
	next := make([]WorkspaceSlot, 0, len(m.Slots)+1)
	for _, slot := range m.Slots {
		if slot.Name != name {
			next = append(next, slot)
		}
	}
	next = append(next, WorkspaceSlot{Name: name, SavedAt: at})
	m.Slots = next
	return m
}

func (m *WorkspaceManifest) removeSlot(name string) {
	next := m.Slots[:0]
	for _, slot := range m.Slots {
		if slot.Name != name {
			next = append(next, slot)
		}
	}
	m.Slots = next
}

func requireWorkspaceName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" || name == "." || name == ".." || strings.HasPrefix(name, ".") || len([]rune(name)) > 64 {
		return "", fmt.Errorf("%w: %q", ErrInvalidWorkspaceName, raw)
	}
	for _, char := range name {
		if char < 0x20 || char == 0x7f || char == '/' || char == '\\' {
			return "", fmt.Errorf("%w: %q", ErrInvalidWorkspaceName, raw)
		}
	}
	return name, nil
}

func requireExistingWorkspaceName(name string) error {
	if name == "" || name == "." || name == ".." || strings.HasPrefix(name, ".") || len([]rune(name)) > 64 {
		return fmt.Errorf("%w: %q", ErrInvalidWorkspaceName, name)
	}
	for _, char := range name {
		if char < 0x20 || char == 0x7f || char == '/' || char == '\\' {
			return fmt.Errorf("%w: %q", ErrInvalidWorkspaceName, name)
		}
	}
	return nil
}

func replaceDirectory(destination string, build func(string) error) error {
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	temp, err := os.MkdirTemp(parent, ".workspace-tmp-")
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(temp)
		}
	}()
	if err := build(temp); err != nil {
		return err
	}
	backup := destination + ".swap-bak"
	if _, err := os.Stat(backup); err == nil {
		if _, destinationErr := os.Stat(destination); errors.Is(destinationErr, os.ErrNotExist) {
			if err := os.Rename(backup, destination); err != nil {
				return err
			}
		} else if err := os.RemoveAll(backup); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Stat(destination); err == nil {
		if err := os.Rename(destination, backup); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(temp, destination); err != nil {
		if _, backupErr := os.Stat(backup); backupErr == nil {
			_ = os.Rename(backup, destination)
		}
		return err
	}
	keep = true
	if err := os.RemoveAll(backup); err != nil {
		return err
	}
	return nil
}

func copyFileIfPresent(source, destination string) error {
	data, err := os.ReadFile(source)
	if errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(destination)
		return nil
	}
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	fileInfo, err := os.Stat(source)
	if err != nil {
		return err
	}
	return writeFileAtomic(destination, data, fileInfo.Mode().Perm())
}

func copyDirectoryIfPresent(source, destination string) error {
	info, err := os.Stat(source)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("storage: %s is not a directory", source)
	}
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("storage: symlink in workspace tree: %s", path)
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		mode := os.FileMode(0o600)
		if fileInfo, err := entry.Info(); err == nil {
			mode = fileInfo.Mode().Perm()
		}
		return writeFileAtomic(target, data, mode)
	})
}

func writeFileAtomic(destination string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(destination), ".copy-tmp-")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	keep := false
	defer func() {
		_ = temp.Close()
		if !keep {
			_ = os.Remove(tempName)
		}
	}()
	if err := temp.Chmod(mode); err != nil {
		return err
	}
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	_ = os.Remove(destination)
	if err := os.Rename(tempName, destination); err != nil {
		return err
	}
	keep = true
	return nil
}

func cloneRawMap(input map[string]json.RawMessage) map[string]json.RawMessage {
	if input == nil {
		return nil
	}
	out := make(map[string]json.RawMessage, len(input))
	for key, value := range input {
		out[key] = append(json.RawMessage(nil), value...)
	}
	return out
}

func unknownRaw(input map[string]json.RawMessage, known ...string) map[string]json.RawMessage {
	knownSet := make(map[string]bool, len(known))
	for _, key := range known {
		knownSet[key] = true
	}
	out := map[string]json.RawMessage{}
	for key, value := range input {
		if !knownSet[key] {
			out[key] = append(json.RawMessage(nil), value...)
		}
	}
	return out
}

var _ = time.Time{}
