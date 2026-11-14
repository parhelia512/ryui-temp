package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	goruntime "runtime"
	"runtime/metrics"
	"runtime/pprof"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	singjson "github.com/sagernet/sing/common/json"
)

const (
	reportCrashCurrent = "CrashReport-lxbox.log"
	reportCrashArchive = "crash_reports"
	reportOOMArchive   = "oom_reports"
	reportTraceName    = "go.log"
	reportMetadataName = "metadata.json"

	maxReportFileBytes = 32 << 20
	maxReportMetaBytes = 1 << 20
	maxPprofBytes      = 32 << 20
	maxPprofDuration   = 30 * time.Second
)

var (
	pprofCaptureGate   = make(chan struct{}, 1)
	shareBearerRE      = regexp.MustCompile(`(?i)(bearer\s+)[a-z0-9._~+/-]+=*`)
	shareURLAuthRE     = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/@\s:]+:[^/@\s]+@`)
	shareQuerySecretRE = regexp.MustCompile(`(?i)([?&](?:access[_-]?token|api[_-]?key|auth|key|password|secret|token)=)[^&#\s]+`)
)

// ReportsDispatch is the exported entry point for the main app method switch.
func (a *Application) ReportsDispatch(ctx context.Context, method string, args json.RawMessage) (any, error) {
	return a.reportsDispatch(ctx, method, args)
}

// ReportsMethods returns the app-level report methods for the public dispatcher.
func ReportsMethods() []string {
	return []string{
		"reports.list", "reports.read", "reports.share", "reports.delete",
		"memory.get", "pprof.capture", "config.format",
	}
}

// reportsDispatch implements diagnostics and report operations without allowing
// callers to supply filesystem paths. Share returns a scrubbed payload for the
// UI to present; this method never transmits report data to another service.
func (a *Application) reportsDispatch(ctx context.Context, method string, args json.RawMessage) (any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	var p struct {
		ID         string          `json:"id"`
		Kind       string          `json:"kind"`
		Name       string          `json:"name"`
		File       string          `json:"file"`
		Profile    string          `json:"profile"`
		DurationMS int             `json:"duration_ms"`
		Duration   int             `json:"duration"`
		Config     json.RawMessage `json:"config"`
	}
	if err := decode(args, &p); err != nil {
		return nil, fmt.Errorf("decode %s arguments: %w", method, err)
	}
	switch method {
	case "reports.list":
		return a.listReports(ctx)
	case "reports.read":
		id := reportArgumentID(p.ID, p.Kind, p.Name)
		return a.readReport(ctx, id, p.File)
	case "reports.share":
		id := reportArgumentID(p.ID, p.Kind, p.Name)
		return a.shareReport(ctx, id)
	case "reports.delete":
		id := reportArgumentID(p.ID, p.Kind, p.Name)
		return a.deleteReport(ctx, id)
	case "memory.get":
		return a.memoryReport(ctx)
	case "pprof.capture":
		profile := p.Profile
		if profile == "" {
			profile = p.Kind
		}
		return capturePprof(ctx, profile, p.DurationMS, p.Duration)
	case "config.format":
		return formatRuntimeConfig(ctx, p.Config)
	default:
		return nil, fmt.Errorf("unknown reports operation %q", method)
	}
}

func reportArgumentID(id, kind, name string) string {
	if kind == "crash" || kind == "oom" {
		if id == "current" && kind == "crash" {
			return "crash:current"
		}
		if id != "" {
			if strings.HasPrefix(id, "crash:") || strings.HasPrefix(id, "oom:") {
				return id
			}
			return kind + ":" + id
		}
		if name == reportCrashCurrent && kind == "crash" {
			return "crash:current"
		}
		if name != "" {
			return kind + ":" + name
		}
	}
	return id
}

type reportRecord struct {
	ID       string
	Kind     string
	Name     string
	Path     string
	Dir      string
	Current  bool
	MTime    time.Time
	Size     int64
	Files    []string
	Metadata map[string]any
}

func (a *Application) reportRoot() (string, error) {
	root := a.supportDir
	if root == "" {
		root = a.dataDir
	}
	if root == "" || !filepath.IsAbs(root) {
		return "", errors.New("report storage directory is unavailable")
	}
	return filepath.Clean(root), nil
}

func (a *Application) listReports(ctx context.Context) ([]map[string]any, error) {
	root, err := a.reportRoot()
	if err != nil {
		return nil, err
	}
	records := make([]reportRecord, 0)
	currentPath := filepath.Join(root, reportCrashCurrent)
	if info, statErr := regularFileInfo(currentPath); statErr == nil && info.Size() > 0 {
		records = append(records, reportRecord{
			ID: "crash:current", Kind: "crash", Name: reportCrashCurrent,
			Path: currentPath, Current: true, MTime: info.ModTime(), Size: info.Size(),
			Files: []string{reportCrashCurrent},
		})
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect current crash report: %w", statErr)
	}
	for _, archive := range []struct{ kind, dir string }{
		{kind: "crash", dir: reportCrashArchive},
		{kind: "oom", dir: reportOOMArchive},
	} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		archivePath := filepath.Join(root, archive.dir)
		if info, statErr := os.Lstat(archivePath); statErr == nil && !info.IsDir() {
			return nil, fmt.Errorf("%s report archive path is not a directory", archive.kind)
		} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return nil, fmt.Errorf("inspect %s report archive: %w", archive.kind, statErr)
		}
		entries, readErr := os.ReadDir(archivePath)
		if errors.Is(readErr, os.ErrNotExist) {
			continue
		}
		if readErr != nil {
			return nil, fmt.Errorf("read %s reports: %w", archive.kind, readErr)
		}
		for _, entry := range entries {
			if !safeReportComponent(entry.Name()) || !entry.IsDir() {
				continue
			}
			dir := filepath.Join(archivePath, entry.Name())
			if err := reportPathWithin(root, dir, true); err != nil {
				continue
			}
			files, size, newest, scanErr := reportDirectorySummary(dir)
			if scanErr != nil {
				continue
			}
			meta := map[string]any(nil)
			if raw, readMetaErr := readBoundedFile(filepath.Join(dir, reportMetadataName), maxReportMetaBytes); readMetaErr == nil {
				_ = json.Unmarshal(raw, &meta)
			}
			if archive.kind == "oom" && meta == nil {
				continue
			}
			if archive.kind == "crash" {
				if _, hasTrace := containsName(files, reportTraceName); !hasTrace {
					continue
				}
			}
			if newest.IsZero() {
				if info, infoErr := entry.Info(); infoErr == nil {
					newest = info.ModTime()
				}
			}
			records = append(records, reportRecord{
				ID: archive.kind + ":" + entry.Name(), Kind: archive.kind,
				Name: entry.Name(), Path: dir, Dir: dir, MTime: newest,
				Size: size, Files: files, Metadata: meta,
			})
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].MTime.Equal(records[j].MTime) {
			return records[i].ID < records[j].ID
		}
		return records[i].MTime.After(records[j].MTime)
	})
	out := make([]map[string]any, 0, len(records))
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		item := map[string]any{
			"id": record.ID, "kind": record.Kind, "name": record.Name,
			"size": record.Size, "mtime": record.MTime.UTC().Format(time.RFC3339Nano),
			"files": record.Files,
		}
		if record.Current {
			item["current"] = true
		}
		if record.Metadata != nil {
			item["metadata"] = scrubReportValue(record.Metadata)
		}
		out = append(out, item)
	}
	return out, nil
}

func (a *Application) readReport(ctx context.Context, id, file string) (any, error) {
	if id == "" {
		return nil, errors.New("report kind and name (or id) are required")
	}
	path, displayName, err := a.resolveReportFile(ctx, id, file)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	body, err := readBoundedFile(path, maxReportFileBytes)
	if err != nil {
		return nil, fmt.Errorf("read report %q: %w", id, err)
	}
	encoding, data := "utf8", string(body)
	if !utf8.Valid(body) {
		encoding, data = "base64", base64.StdEncoding.EncodeToString(body)
	}
	return map[string]any{
		"id": id, "file": displayName, "size": len(body),
		"encoding": encoding, "data": data,
	}, nil
}

func (a *Application) shareReport(ctx context.Context, id string) (any, error) {
	if id == "" {
		return nil, errors.New("report kind and name (or id) are required")
	}
	record, err := a.findReport(ctx, id)
	if err != nil {
		return nil, err
	}
	file := reportTraceName
	if record.Current {
		file = reportCrashCurrent
	} else if record.Kind == "oom" {
		file = reportMetadataName
	}
	path, displayName, err := a.resolveReportFile(ctx, id, file)
	if err != nil {
		return nil, err
	}
	body, err := readBoundedFile(path, maxReportFileBytes)
	if err != nil {
		return nil, fmt.Errorf("read report %q: %w", id, err)
	}
	if !utf8.Valid(body) {
		return nil, errors.New("selected report file is binary and cannot be shared as text")
	}
	if strings.EqualFold(displayName, reportMetadataName) {
		var meta map[string]any
		if err := json.Unmarshal(body, &meta); err != nil {
			return nil, fmt.Errorf("decode report metadata: %w", err)
		}
		safe, err := json.MarshalIndent(scrubReportValue(meta), "", "  ")
		if err != nil {
			return nil, err
		}
		body = safe
	}
	return map[string]any{
		"id": id, "name": record.Name + "-" + displayName,
		"data": scrubReportText(string(body)), "mime": reportMIME(displayName),
		"redacted": true,
	}, nil
}

func reportMIME(name string) string {
	if strings.HasSuffix(strings.ToLower(name), ".json") {
		return "application/json"
	}
	return "text/plain"
}

func (a *Application) deleteReport(ctx context.Context, id string) (any, error) {
	if id == "" {
		return nil, errors.New("report kind and name (or id) are required")
	}
	record, err := a.findReport(ctx, id)
	if err != nil {
		return nil, err
	}
	if record.Current {
		return nil, errors.New("the current crash report cannot be deleted")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := a.reportRoot()
	if err != nil {
		return nil, err
	}
	if err := reportPathWithin(root, record.Dir, true); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(record.Dir); err != nil {
		return nil, fmt.Errorf("delete report %q: %w", id, err)
	}
	a.events.emit("reports.changed", map[string]any{"id": id, "action": "delete"})
	return map[string]any{"id": id, "deleted": true}, nil
}

func (a *Application) findReport(ctx context.Context, id string) (reportRecord, error) {
	if !safeReportID(id) {
		return reportRecord{}, errors.New("report id must be crash:<name> or oom:<name>")
	}
	items, err := a.listReports(ctx)
	if err != nil {
		return reportRecord{}, err
	}
	for _, item := range items {
		if item["id"] != id {
			continue
		}
		kind, _ := item["kind"].(string)
		name, _ := item["name"].(string)
		current, _ := item["current"].(bool)
		root, err := a.reportRoot()
		if err != nil {
			return reportRecord{}, err
		}
		path := filepath.Join(root, reportCrashArchive, name)
		dir := path
		if current {
			path = filepath.Join(root, reportCrashCurrent)
			dir = ""
		} else if kind == "oom" {
			path = filepath.Join(root, reportOOMArchive, name)
			dir = path
		}
		if dir != "" {
			if err := reportPathWithin(root, dir, true); err != nil {
				return reportRecord{}, err
			}
		}
		mtime, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(item["mtime"]))
		size, _ := item["size"].(int64)
		if size == 0 {
			if n, ok := item["size"].(int); ok {
				size = int64(n)
			}
		}
		files, _ := item["files"].([]string)
		meta, _ := item["metadata"].(map[string]any)
		return reportRecord{ID: id, Kind: kind, Name: name, Path: path, Dir: dir, Current: current, MTime: mtime, Size: size, Files: files, Metadata: meta}, nil
	}
	return reportRecord{}, fmt.Errorf("report %q does not exist", id)
}

func (a *Application) resolveReportFile(ctx context.Context, id, file string) (string, string, error) {
	record, err := a.findReport(ctx, id)
	if err != nil {
		return "", "", err
	}
	if record.Current {
		if file != "" && file != reportCrashCurrent {
			return "", "", errors.New("current crash report only contains its stderr log")
		}
		root, err := a.reportRoot()
		if err != nil {
			return "", "", err
		}
		return checkedReportFile(record.Path, root, reportCrashCurrent)
	}
	if file == "" {
		if record.Kind == "oom" {
			file = reportMetadataName
		} else {
			file = reportTraceName
		}
	}
	if !safeReportComponent(file) {
		return "", "", errors.New("report file must be a safe basename")
	}
	root, err := a.reportRoot()
	if err != nil {
		return "", "", err
	}
	return checkedReportFile(filepath.Join(record.Dir, file), root, filepath.Join(filepath.Base(record.Dir), file))
}

func checkedReportFile(path string, root string, relative string) (string, string, error) {
	if err := reportPathWithin(root, path, false); err != nil {
		return "", "", err
	}
	info, err := regularFileInfo(path)
	if err != nil {
		return "", "", fmt.Errorf("report file does not exist: %w", err)
	}
	if info.Size() > maxReportFileBytes {
		return "", "", fmt.Errorf("report file exceeds %d bytes", maxReportFileBytes)
	}
	return path, filepath.Base(relative), nil
}

func reportPathWithin(root, path string, allowDirectory bool) error {
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("report storage directory does not exist")
		}
		return err
	}
	pathReal, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(rootReal, pathReal)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return errors.New("report path is outside the application report directory")
	}
	info, err := os.Stat(pathReal)
	if err != nil {
		return err
	}
	if allowDirectory && !info.IsDir() {
		return errors.New("report path is not a directory")
	}
	return nil
}

func safeReportID(id string) bool {
	parts := strings.Split(id, ":")
	if len(parts) != 2 || (parts[0] != "crash" && parts[0] != "oom") {
		return false
	}
	if parts[0] == "crash" && parts[1] == "current" {
		return true
	}
	return safeReportComponent(parts[1])
}

func safeReportComponent(name string) bool {
	return name != "" && name != "." && name != ".." &&
		!strings.HasPrefix(name, ".") && !strings.Contains(name, "..") &&
		!strings.ContainsAny(name, `/\\:`) && filepath.Base(name) == name
}

func regularFileInfo(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("report path is not a regular file")
	}
	return info, nil
}

func containsName(names []string, want string) (int, bool) {
	for i, name := range names {
		if name == want {
			return i, true
		}
	}
	return -1, false
}

func reportDirectorySummary(dir string) ([]string, int64, time.Time, error) {
	entries, err := os.ReadDir(dir)

	if err != nil {
		return nil, 0, time.Time{}, err
	}
	files := make([]string, 0, len(entries))
	var total int64
	var newest time.Time
	for _, entry := range entries {
		if !safeReportComponent(entry.Name()) || entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, statErr := regularFileInfo(path)
		if statErr != nil {
			continue
		}
		files = append(files, entry.Name())
		total += info.Size()
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	sort.Strings(files)
	return files, total, newest, nil
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	info, err := regularFileInfo(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return body, nil
}

func scrubReportValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, child := range v {
			if sensitiveReportKey(key) {
				out[key] = "[redacted]"
			} else {
				out[key] = scrubReportValue(child)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			out[i] = scrubReportValue(child)
		}
		return out
	case string:
		return scrubReportText(v)
	default:
		return value
	}
}

func sensitiveReportKey(key string) bool {
	lower := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key))
	for _, marker := range []string{"password", "passwd", "token", "secret", "apikey", "authorization", "credential", "privatekey", "processpath", "filepath", "platformmetadata", "configcontent"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func scrubReportText(text string) string {
	text = shareBearerRE.ReplaceAllString(text, `${1}[redacted]`)
	text = shareURLAuthRE.ReplaceAllString(text, `${1}[redacted]@`)
	text = shareQuerySecretRE.ReplaceAllString(text, `${1}[redacted]`)
	return text
}

func formatRuntimeConfig(ctx context.Context, raw json.RawMessage) (any, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, errors.New("config.format requires a config string or object")
	}
	var source string
	if err := json.Unmarshal(trimmed, &source); err != nil {
		if trimmed[0] != '{' && trimmed[0] != '[' {
			return nil, errors.New("config.format config must be a string or object")
		}
		source = string(trimmed)
	}
	if strings.TrimSpace(source) == "" {
		return nil, errors.New("config.format config is empty")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Use sing-box's context-aware extended JSON parser (the same parser used by
	// libbox.parseConfig), and decode into a map so future/unknown keys survive.
	var value map[string]any
	value, err := singjson.UnmarshalExtendedContext[map[string]any](ctx, []byte(source))
	if err != nil {
		return nil, fmt.Errorf("parse sing-box configuration: %w", err)
	}
	if value == nil {
		return nil, errors.New("sing-box configuration must be a JSON object")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	formatted, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("format sing-box configuration: %w", err)
	}
	return string(formatted), nil
}

func (a *Application) memoryReport(ctx context.Context) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	descriptors := metrics.All()
	samples := make([]metrics.Sample, len(descriptors))
	for i := range descriptors {
		samples[i].Name = descriptors[i].Name
	}
	metrics.Read(samples)
	values := make(map[string]any, len(samples)+1)
	for _, sample := range samples {
		switch sample.Value.Kind() {
		case metrics.KindUint64:
			values[sample.Name] = sample.Value.Uint64()
		case metrics.KindFloat64:
			values[sample.Name] = sample.Value.Float64()
		}
	}
	values["/sched/goroutines:goroutines"] = uint64(goruntime.NumGoroutine())
	android, androidErr := a.platformCall(ctx, "getMemoryInfo", map[string]any{})
	androidResult := map[string]any{"available": androidErr == nil, "data": android}
	if androidErr != nil {
		androidResult["error"] = androidErr.Error()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return map[string]any{"runtime": values, "android": androidResult}, nil
}

type limitedProfileBuffer struct {
	bytes.Buffer
	limit int
}

func (w *limitedProfileBuffer) Write(p []byte) (int, error) {
	remaining := w.limit - w.Len()
	if remaining <= 0 {
		return 0, errors.New("pprof output exceeds size limit")
	}
	if len(p) > remaining {
		_, _ = w.Buffer.Write(p[:remaining])
		return remaining, errors.New("pprof output exceeds size limit")
	}
	return w.Buffer.Write(p)
}

func capturePprof(ctx context.Context, profile string, durationMS, durationSeconds int) (any, error) {
	allowed := map[string]bool{
		"goroutine": true, "profile": true, "heap": true, "allocs": true,
		"block": true, "mutex": true, "threadcreate": true,
	}
	if !allowed[profile] {
		return nil, fmt.Errorf("unknown pprof profile %q", profile)
	}
	duration := 10 * time.Second
	if durationMS > 0 {
		duration = time.Duration(durationMS) * time.Millisecond
	} else if durationSeconds > 0 {
		duration = time.Duration(durationSeconds) * time.Second
	} else if profile != "profile" {
		duration = 5 * time.Second
	}
	if duration < 100*time.Millisecond || duration > maxPprofDuration {
		return nil, fmt.Errorf("pprof duration must be between 100ms and %s", maxPprofDuration)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case pprofCaptureGate <- struct{}{}:
		defer func() { <-pprofCaptureGate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	buffer := &limitedProfileBuffer{limit: maxPprofBytes}
	started := time.Now()
	if profile == "profile" {
		if err := pprof.StartCPUProfile(buffer); err != nil {
			return nil, fmt.Errorf("start CPU profile: %w", err)
		}
		timer := time.NewTimer(duration)
		select {
		case <-ctx.Done():
			timer.Stop()
			pprof.StopCPUProfile()
			return nil, ctx.Err()
		case <-timer.C:
			pprof.StopCPUProfile()
		}
	} else {
		lookupName := profile
		if lookupName == "goroutine" {
			lookupName = "goroutine"
		}
		lookup := pprof.Lookup(lookupName)
		if lookup == nil {
			return nil, fmt.Errorf("runtime pprof profile %q is unavailable", profile)
		}
		done := make(chan error, 1)
		go func() { done <- lookup.WriteTo(buffer, 2) }()
		timer := time.NewTimer(duration)
		select {
		case err := <-done:
			timer.Stop()
			if err != nil {
				return nil, fmt.Errorf("write pprof profile %q: %w", profile, err)
			}
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
			return nil, fmt.Errorf("pprof profile %q exceeded %s", profile, duration)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if buffer.Len() > maxPprofBytes {
		return nil, errors.New("pprof output exceeds size limit")
	}
	return map[string]any{
		"profile": profile, "duration_ms": time.Since(started).Milliseconds(),
		"content_type": "application/octet-stream", "data": base64.StdEncoding.EncodeToString(buffer.Bytes()),
	}, nil
}
