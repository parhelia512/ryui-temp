package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Leadaxe/lxbox/app/internal/model"
)

const (
	SettingsFileName         = "lxbox_settings.json"
	WorkspaceFileName        = "workspaces.json"
	WorkspaceDirName         = "workspaces"
	RuleSetsDirName          = "rule_sets"
	SettingsVersion          = 1
	WorkspaceManifestVersion = 1
	DefaultWorkspaceName     = "Default"
)

var (
	ErrNotFound             = errors.New("storage: not found")
	ErrExists               = errors.New("storage: already exists")
	ErrCurrentWorkspace     = errors.New("storage: cannot delete current workspace")
	ErrInvalidWorkspaceName = errors.New("storage: invalid workspace name")
	ErrReadOnly             = errors.New("storage: storage is read-only until migration succeeds")
)

type Store struct {
	mu                  sync.Mutex
	dataDir             string
	cacheDir            string
	doc                 map[string]any
	readOnly            bool
	migration           MigrationReport
	generation          uint64
	tmpSeq              uint64
	recoveredFromBackup bool
	loaded              bool
}

type MigrationReport struct {
	Migrated     bool     `json:"migrated"`
	ReadOnly     bool     `json:"read_only"`
	FoundVersion *int     `json:"found_version,omitempty"`
	Info         []string `json:"info,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

type MigrationStatus struct {
	ReadOnly bool
	Report   MigrationReport
}

// Open uses the legacy Flutter documents directory supplied by the host. The
// host should call SetCacheDir with filesDir/sub_cache immediately afterwards.
func Open(dataDir string) (*Store, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("storage: data directory is empty")
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("storage: resolve data directory: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("storage: create data directory: %w", err)
	}
	s := &Store{dataDir: abs, cacheDir: filepath.Join(abs, "sub_cache")}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) DataDir() string { return s.dataDir }

func (s *Store) SetCacheDir(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("storage: cache directory is empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("storage: resolve cache directory: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return fmt.Errorf("storage: create cache directory: %w", err)
	}
	s.cacheDir = abs
	return nil
}

func (s *Store) CacheDir() string   { s.mu.Lock(); defer s.mu.Unlock(); return s.cacheDir }
func (s *Store) Generation() uint64 { s.mu.Lock(); defer s.mu.Unlock(); return s.generation }

func (s *Store) MigrationStatus() MigrationStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return MigrationStatus{ReadOnly: s.readOnly, Report: cloneMigrationReport(s.migration)}
}

// MigrateLegacy persists only a complete, externally-validated migration.
func (s *Store) MigrateLegacy(options MigrationOptions) (MigrationReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := cloneDocument(s.doc)
	if err != nil {
		return MigrationReport{}, err
	}
	migrated, report, err := MigrateDocumentWithOptions(current, options)
	if err != nil {
		return report, err
	}
	if report.ReadOnly {
		s.readOnly = true
		s.migration = cloneMigrationReport(report)
		return report, ErrReadOnly
	}
	if !report.Migrated {
		s.migration = cloneMigrationReport(report)
		return report, nil
	}
	if err := s.writeDocumentLocked(migrated); err != nil {
		return report, err
	}
	s.doc = migrated
	s.readOnly = false
	s.migration = cloneMigrationReport(report)
	return report, nil
}

func cloneMigrationReport(report MigrationReport) MigrationReport {
	out := report
	out.Info = append([]string(nil), report.Info...)
	out.Warnings = append([]string(nil), report.Warnings...)
	if report.FoundVersion != nil {
		value := *report.FoundVersion
		out.FoundVersion = &value
	}
	return out
}

func (s *Store) Snapshot() (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneDocument(s.doc)
}

func (s *Store) UpdateIfGeneration(generation uint64, fn func(map[string]any) error) error {
	if fn == nil {
		return errors.New("storage: update callback is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.generation != generation {
		return fmt.Errorf("storage: stale generation %d (current %d)", generation, s.generation)
	}
	return s.updateLocked(fn)
}

func (s *Store) Update(fn func(map[string]any) error) error {
	if fn == nil {
		return errors.New("storage: update callback is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updateLocked(fn)
}

func (s *Store) updateLocked(fn func(map[string]any) error) error {
	if s.readOnly {
		return ErrReadOnly
	}
	next, err := cloneDocument(s.doc)
	if err != nil {
		return err
	}
	if err := fn(next); err != nil {
		return err
	}
	encoded, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("storage: updated document is not JSON encodable: %w", err)
	}
	normalized, err := model.DecodeObject(encoded)
	if err != nil {
		return fmt.Errorf("storage: updated document is not an object: %w", err)
	}
	if err := s.writeDocumentLocked(normalized); err != nil {
		return err
	}
	s.doc = normalized
	return nil
}

func (s *Store) Sources() ([]json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return rawSources(s.doc)
}

func (s *Store) ReadCache(url string) ([]byte, map[string]string, error) {
	if url == "" {
		return nil, nil, errors.New("storage: cache URL is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := cacheKey(url)
	body, err := os.ReadFile(filepath.Join(s.cacheDir, key))
	if err != nil {
		return nil, nil, err
	}
	headers := map[string]string{}
	headerData, err := os.ReadFile(filepath.Join(s.cacheDir, key+".headers"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	if len(headerData) > 0 {
		if err := json.Unmarshal(headerData, &headers); err != nil {
			return nil, nil, fmt.Errorf("storage: decode cached headers: %w", err)
		}
	}
	return body, headers, nil
}

func (s *Store) WriteCache(url string, body []byte, headers map[string]string) error {
	if url == "" {
		return errors.New("storage: cache URL is empty")
	}
	headerData, err := json.Marshal(headers)
	if err != nil {
		return fmt.Errorf("storage: encode cache headers: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.cacheDir, 0o700); err != nil {
		return err
	}
	key := cacheKey(url)
	if err := s.writeAtomicLocked(filepath.Join(s.cacheDir, key), body, 0o600); err != nil {
		return err
	}
	return s.writeAtomicLocked(filepath.Join(s.cacheDir, key+".headers"), headerData, 0o600)
}

func (s *Store) RemoveCache(url string) error {
	if url == "" {
		return errors.New("storage: cache URL is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := cacheKey(url)
	for _, suffix := range []string{"", ".headers"} {
		err := os.Remove(filepath.Join(s.cacheDir, key+suffix))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (s *Store) ExportBackup() ([]byte, error) {
	doc, err := s.Snapshot()
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(map[string]any{"app": "lxbox", "kind": "backup", "created_at": time.Now().UTC().Format(time.RFC3339Nano), "storage": doc}, "", "  ")
}

type BackupReport struct {
	Replaced    bool            `json:"replaced"`
	AddedKeys   int             `json:"added_keys"`
	Migration   MigrationReport `json:"migration"`
	Warnings    []string        `json:"warnings,omitempty"`
	VPNSettings map[string]any  `json:"vpn_settings,omitempty"`
}

func (s *Store) ImportBackup(raw []byte, replace bool) (BackupReport, error) {
	return s.ImportBackupWithOptions(raw, replace, MigrationOptions{})
}

func (s *Store) ImportBackupWithOptions(raw []byte, replace bool, options MigrationOptions) (BackupReport, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var envelope map[string]any
	if err := decoder.Decode(&envelope); err != nil {
		return BackupReport{}, fmt.Errorf("storage: decode backup: %w", err)
	}
	if envelope["app"] != "lxbox" || envelope["kind"] != "backup" {
		return BackupReport{}, errors.New("storage: invalid LxBox backup markers")
	}
	incoming, ok := envelope["storage"].(map[string]any)
	if !ok {
		return BackupReport{}, errors.New("storage: backup storage must be an object")
	}
	migrated, migration, err := MigrateDocumentWithOptions(incoming, options)
	if err != nil {
		return BackupReport{}, err
	}
	if migration.ReadOnly {
		return BackupReport{Migration: migration, Warnings: migration.Warnings, VPNSettings: objectValue(envelope["vpn_settings"])}, ErrReadOnly
	}
	added := 0
	if err := s.Update(func(current map[string]any) error {
		if replace {
			for key := range current {
				delete(current, key)
			}
			for key, value := range migrated {
				current[key] = value
			}
			added = len(migrated)
			return nil
		}
		for key, value := range migrated {
			if _, exists := current[key]; !exists {
				current[key] = value
				added++
			}
		}
		return nil
	}); err != nil {
		return BackupReport{}, err
	}
	return BackupReport{Replaced: replace, AddedKeys: added, Migration: migration, Warnings: []string{"category-level Dart merge and native VPN preference application remain host responsibilities"}, VPNSettings: objectValue(envelope["vpn_settings"])}, nil
}

func MigrateDocument(input map[string]any) (map[string]any, MigrationReport, error) {
	return migrateDocument(input)
}

func (s *Store) load() error {
	main := filepath.Join(s.dataDir, SettingsFileName)
	data, err := os.ReadFile(main)
	if errors.Is(err, os.ErrNotExist) {
		s.doc = map[string]any{"storage_version": SettingsVersion}
		s.loaded = true
		return nil
	}
	if err != nil {
		return fmt.Errorf("storage: read settings: %w", err)
	}
	doc, parseErr := model.DecodeObject(data)
	if parseErr != nil {
		backup, backupErr := os.ReadFile(main + ".bak")
		if backupErr != nil {
			return fmt.Errorf("storage: settings are corrupt (%v), backup unavailable: %w", parseErr, backupErr)
		}
		doc, backupErr = model.DecodeObject(backup)
		if backupErr != nil {
			return fmt.Errorf("storage: settings and backup are corrupt: %w", backupErr)
		}
		_, report, migrationErr := MigrateDocumentWithOptions(doc, MigrationOptions{})
		if migrationErr != nil {
			return migrationErr
		}
		report.ReadOnly = true
		report.Warnings = append(report.Warnings, "main settings file is corrupt; valid .bak loaded read-only; explicit recovery is required before writes")
		s.doc, s.readOnly, s.recoveredFromBackup, s.migration, s.loaded = doc, true, true, cloneMigrationReport(report), true
		return nil
	}
	_, report, err := MigrateDocumentWithOptions(doc, MigrationOptions{})
	if err != nil {
		return err
	}
	if _, hasVersion := integerValue(doc["storage_version"]); !hasVersion {
		report.ReadOnly = true
		report.Warnings = append(report.Warnings, "legacy settings are loaded read-only until explicit migration succeeds")
	}
	if _, hasVersion := integerValue(doc["storage_version"]); !hasVersion {

		legacyCopy := main + ".v0.bak"
		if _, statErr := os.Stat(legacyCopy); errors.Is(statErr, os.ErrNotExist) {
			if err := s.writeAtomicLocked(legacyCopy, data, 0o600); err != nil {
				return err
			}
		} else if statErr != nil {
			return statErr
		}
	}
	s.doc, s.readOnly, s.migration, s.loaded = doc, report.ReadOnly, cloneMigrationReport(report), true
	return nil
}

func (s *Store) RecoverCorruptSettings() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	backup, err := os.ReadFile(filepath.Join(s.dataDir, SettingsFileName+".bak"))
	if err != nil {
		return err
	}
	doc, err := model.DecodeObject(backup)
	if err != nil {
		return fmt.Errorf("storage: backup is corrupt: %w", err)
	}
	if err := s.writeAtomicLocked(filepath.Join(s.dataDir, SettingsFileName), backup, 0o600); err != nil {
		return err
	}
	_, report, err := MigrateDocumentWithOptions(doc, MigrationOptions{})
	if err != nil {
		return err
	}
	s.doc, s.readOnly, s.recoveredFromBackup, s.migration = doc, report.ReadOnly, false, cloneMigrationReport(report)
	return nil
}

func (s *Store) writeDocumentLocked(doc map[string]any) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("storage: encode settings: %w", err)
	}
	path := filepath.Join(s.dataDir, SettingsFileName)
	if _, statErr := os.Stat(path); statErr == nil && !s.recoveredFromBackup {
		old, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if err := s.writeAtomicLocked(path+".bak", old, 0o600); err != nil {
			return err
		}
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	if err := s.writeAtomicLocked(path, data, 0o600); err != nil {
		return err
	}
	s.recoveredFromBackup = false
	return nil
}

func (s *Store) writeAtomicLocked(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	s.tmpSeq++
	tmp := fmt.Sprintf("%s.%d.%d.tmp", path, os.Getpid(), s.tmpSeq)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := io.Copy(f, bytes.NewReader(data)); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func cloneDocument(doc map[string]any) (map[string]any, error) {
	if doc == nil {
		return map[string]any{"storage_version": SettingsVersion}, nil
	}
	cloned, err := model.CloneJSON(doc)
	if err != nil {
		return nil, fmt.Errorf("storage: clone document: %w", err)
	}
	return cloned, nil
}

func rawSources(doc map[string]any) ([]json.RawMessage, error) {
	records, err := model.ParseSources(doc)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	out := make([]json.RawMessage, len(records))
	for i, record := range records {
		out[i] = append(json.RawMessage(nil), record.Raw...)
	}
	return out, nil
}

func cacheKey(url string) string {
	sum := sha256.Sum256([]byte(url))
	return hex.EncodeToString(sum[:])
}
func objectValue(value any) map[string]any { object, _ := value.(map[string]any); return object }
