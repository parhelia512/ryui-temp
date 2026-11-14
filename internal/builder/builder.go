package builder

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// DiagnosticLevel classifies a build diagnostic.
type DiagnosticLevel string

const (
	LevelInfo    DiagnosticLevel = "info"
	LevelWarning DiagnosticLevel = "warning"
	LevelError   DiagnosticLevel = "error"
)

// Diagnostic is a machine-readable finding. Fatal findings make Complete false.
type Diagnostic struct {
	Level   DiagnosticLevel `json:"level"`
	Code    string          `json:"code"`
	Path    string          `json:"path,omitempty"`
	Message string          `json:"message"`
	Value   json.RawMessage `json:"value,omitempty"`
	Fatal   bool            `json:"fatal,omitempty"`
}

// SourceInput is an ordered source record plus already-parsed cached nodes.
// URL metadata is never fetched by the builder.
type SourceInput struct {
	ID           string           `json:"id,omitempty"`
	Kind         string           `json:"kind,omitempty"`
	Name         string           `json:"name,omitempty"`
	Enabled      *bool            `json:"enabled,omitempty"`
	TagPrefix    string           `json:"tag_prefix,omitempty"`
	DetourPolicy map[string]any   `json:"detour_policy,omitempty"`
	Detour       any              `json:"detour,omitempty"`
	Replace      map[string]any   `json:"replace,omitempty"`
	Nodes        []map[string]any `json:"nodes,omitempty"`
	Members      []MemberInput    `json:"members,omitempty"`
	Raw          map[string]any   `json:"raw,omitempty"`
}

// MemberInput is one cached folder member.
type MemberInput struct {
	Enabled *bool          `json:"enabled,omitempty"`
	Node    map[string]any `json:"node,omitempty"`
	Raw     any            `json:"raw,omitempty"`
	Detour  any            `json:"detour,omitempty"`
	Flags   map[string]any `json:"flags,omitempty"`
}

// CacheInput carries only local node and ruleset cache data.
type CacheInput struct {
	Nodes    map[string]json.RawMessage `json:"nodes,omitempty"`
	RuleSets map[string]json.RawMessage `json:"rule_sets,omitempty"`
	Files    map[string][]byte          `json:"files,omitempty"`
}

// Input is JSON-shaped to avoid app parser/model dependencies.
type Input struct {
	Settings     map[string]any  `json:"settings,omitempty"`
	Template     map[string]any  `json:"template,omitempty"`
	Sources      []SourceInput   `json:"sources,omitempty"`
	Cache        CacheInput      `json:"cache,omitempty"`
	ValidateCore bool            `json:"validate_core,omitempty"`
	CoreContext  context.Context `json:"-"`
}

// Result carries config even on failure so the caller can surface diagnostics.
type Result struct {
	Config      []byte            `json:"config"`
	Diagnostics []Diagnostic      `json:"diagnostics,omitempty"`
	Generated   map[string]string `json:"generated,omitempty"`
	EmittedTags []string          `json:"emitted_tags,omitempty"`
	Pure        bool              `json:"pure"`
	Complete    bool              `json:"complete"`
}

// BuildError identifies fatal build diagnostics.
type BuildError struct{ Diagnostics []Diagnostic }

func (e *BuildError) Error() string {
	if len(e.Diagnostics) == 0 {
		return "configuration build failed"
	}
	return fmt.Sprintf("configuration build failed: %s (%s)", e.Diagnostics[0].Message, e.Diagnostics[0].Code)
}

// Build assembles config offline without initializing sing-box runtime services.
func Build(ctx context.Context, in Input) (Result, error) { return build(ctx, in) }

// BuildJSON decodes numbers losslessly and rejects trailing JSON values.
func BuildJSON(ctx context.Context, raw []byte) (Result, error) {
	var in Input
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&in); err != nil {
		return Result{Pure: true}, fmt.Errorf("decode builder input: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Result{Pure: true}, fmt.Errorf("decode builder input: trailing JSON value")
		}
		return Result{Pure: true}, fmt.Errorf("decode builder input: %w", err)
	}
	return Build(ctx, in)
}

var ErrUnsupported = errors.New("unsupported configuration semantics")
var ErrInvalidInput = errors.New("invalid builder input")
