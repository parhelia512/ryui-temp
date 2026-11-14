// Package contract loads the shared parser contract without importing application
// packages. The contract is intentionally represented as maps so new registry
// fields remain available to callers before this package learns their schema.
package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

type Registry struct {
	Version   string
	Protocols map[string]*Protocol
	Schemes   map[string]*Protocol
	Sources   map[string]map[string]any
}

type Protocol struct {
	Name        string
	Scheme      string
	Kind        string
	SingboxType string
	Aliases     []string
	Sources     []string
	Raw         map[string]any
	URI         URIContract
	Body        BodyContract
}

type URIContract struct {
	Userinfo map[string]any
	Query    map[string]Param
	Fragment string
}

type BodyContract struct {
	Fields map[string]Field
}

type Param struct {
	Raw      map[string]any
	MapsTo   []string
	Aliases  []string
	Type     string
	Values   []string
	Default  any
	Required bool
}

type Field struct {
	Raw      map[string]any
	MapsTo   []string
	Type     string
	Values   []string
	Aliases  []string
	Required bool
}

func Load(fsys fs.FS) (*Registry, error) {
	if fsys == nil {
		return nil, fmt.Errorf("contract: nil filesystem")
	}
	r := &Registry{Protocols: map[string]*Protocol{}, Schemes: map[string]*Protocol{}, Sources: map[string]map[string]any{}}
	if b, err := fs.ReadFile(fsys, "VERSION"); err == nil {
		r.Version = strings.TrimSpace(string(b))
	}
	files, err := fs.Glob(fsys, "registry/protocols/*.json")
	if err != nil {
		return nil, fmt.Errorf("contract: list protocols: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("contract: registry/protocols is empty")
	}
	sort.Strings(files)
	for _, name := range files {
		m, err := readMap(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("contract: %s: %w", name, err)
		}
		base := path.Base(name)
		base = strings.TrimSuffix(base, path.Ext(base))
		if overlay, ok := readOverlay(fsys, "contract_draft/uri/"+base+".json"); ok {
			mergeMap(m, overlay)
		}
		p := protocolFromMap(base, m)
		if p.SingboxType == "" || p.Scheme == "" {
			continue
		}
		r.Protocols[p.SingboxType] = p
		r.Schemes[strings.ToLower(p.Scheme)] = p
		for _, alias := range p.Aliases {
			r.Schemes[strings.ToLower(alias)] = p
		}
	}
	for _, name := range []string{"registry/source_kinds.json", "registry/allowlists.json", "registry/warnings.json"} {
		if m, err := readMap(fsys, name); err == nil {
			r.Sources[path.Base(name)] = m
		}
	}
	return r, nil
}

func readOverlay(fsys fs.FS, name string) (map[string]any, bool) {
	m, err := readMap(fsys, name)
	return m, err == nil
}

func readMap(fsys fs.FS, name string) (map[string]any, error) {
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	if err := decoder.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

func protocolFromMap(name string, m map[string]any) *Protocol {
	p := &Protocol{Name: name, Raw: m, URI: URIContract{Query: map[string]Param{}}, Body: BodyContract{Fields: map[string]Field{}}}
	p.Scheme, _ = m["scheme"].(string)
	p.Kind, _ = m["kind"].(string)
	p.SingboxType, _ = m["singbox_type"].(string)
	p.Aliases = stringsFrom(m["aliases"])
	p.Sources = stringsFrom(m["sources"])
	if uri, ok := m["uri"].(map[string]any); ok {
		p.URI.Fragment, _ = uri["fragment"].(string)
		p.URI.Userinfo, _ = uri["userinfo"].(map[string]any)
		if q, ok := uri["query"].(map[string]any); ok {
			for key, value := range q {
				if raw, ok := value.(map[string]any); ok {
					p.URI.Query[key] = paramFromMap(raw)
				}
			}
		}
	}
	if body, ok := m["body"].(map[string]any); ok {
		if fields, ok := body["fields"].(map[string]any); ok {
			for key, value := range fields {
				if raw, ok := value.(map[string]any); ok {
					p.Body.Fields[key] = fieldFromMap(raw)
				}
			}
		}
	}
	return p
}

func paramFromMap(m map[string]any) Param {
	p := Param{Raw: m, MapsTo: mapsTo(m["maps_to"]), Aliases: stringsFrom(m["aliases"]), Type: stringValue(m["type"]), Values: stringsFrom(m["values"]), Default: m["default"]}
	if required, ok := m["required"].(bool); ok {
		p.Required = required
	}
	return p
}

func fieldFromMap(m map[string]any) Field {
	f := Field{Raw: m, MapsTo: mapsTo(m["maps_to"]), Aliases: stringsFrom(m["aliases"]), Type: stringValue(m["type"]), Values: stringsFrom(m["values"])}
	if required, ok := m["required"].(bool); ok {
		f.Required = required
	}
	return f
}

func mapsTo(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		return stringsFrom(x)
	default:
		return nil
	}
}

func stringsFrom(v any) []string {
	var out []string
	if list, ok := v.([]any); ok {
		for _, item := range list {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func stringValue(v any) string {
	s, _ := v.(string)
	return s
}

func mergeMap(dst, src map[string]any) {
	for key, value := range src {
		sm, sok := value.(map[string]any)
		dm, dok := dst[key].(map[string]any)
		if sok && dok {
			mergeMap(dm, sm)
			continue
		}
		dst[key] = value
	}
}
