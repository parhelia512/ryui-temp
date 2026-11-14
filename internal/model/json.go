// Package model contains lossless JSON-facing application models.
//
// The app storage format evolves independently from the Go runtime. Models in
// this package therefore retain each record's original JSON instead of
// decoding it into a closed struct that could discard fields added by a newer
// LxBox release.
package model

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Document is the user settings document stored in lxbox_settings.json.
// Values are decoded into ordinary encoding/json values so runtime callers can
// use map[string]any while updates preserve every key not explicitly changed.
type Document map[string]any

// SourceRecord is a lossless source entry from the ordered sources array.
// Raw is a standalone JSON object and is copied by ParseSources.
type SourceRecord struct {
	Raw json.RawMessage
}

// Decode returns a mutable map for callers that need selected known fields.
// Unknown fields remain in the returned map and can be marshalled unchanged.
func (r SourceRecord) Decode() (map[string]any, error) {
	var record map[string]any
	if err := json.Unmarshal(r.Raw, &record); err != nil {
		return nil, err
	}
	if record == nil {
		return nil, fmt.Errorf("source record must be a JSON object")
	}
	return record, nil
}

// CloneJSON deep-copies values supported by encoding/json. It avoids sharing
// mutable nested maps and slices between snapshots and committed state.
func CloneJSON[T any](value T) (T, error) {
	var zero T
	data, err := json.Marshal(value)
	if err != nil {
		return zero, fmt.Errorf("encode JSON value: %w", err)
	}
	var cloned T
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&cloned); err != nil {
		return zero, fmt.Errorf("decode cloned JSON value: %w", err)
	}
	return cloned, nil
}

// DecodeObject decodes a JSON object while preserving integral numbers as
// json.Number. A non-object or malformed input is rejected.
func DecodeObject(data []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, fmt.Errorf("JSON document must be an object")
	}
	return object, nil
}

// ParseSources extracts raw source records without normalizing or dropping
// fields. Non-object records are returned as an error with their array index.
func ParseSources(document map[string]any) ([]SourceRecord, error) {
	raw, ok := document["sources"]
	if !ok || raw == nil {
		return nil, nil
	}
	sources, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("sources must be an array")
	}
	out := make([]SourceRecord, 0, len(sources))
	for index, source := range sources {
		encoded, err := json.Marshal(source)
		if err != nil {
			return nil, fmt.Errorf("encode sources[%d]: %w", index, err)
		}
		if len(encoded) == 0 || encoded[0] != '{' {
			return nil, fmt.Errorf("sources[%d] must be an object", index)
		}
		out = append(out, SourceRecord{Raw: append(json.RawMessage(nil), encoded...)})
	}
	return out, nil
}
