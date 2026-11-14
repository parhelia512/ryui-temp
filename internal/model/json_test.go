package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeObjectPreservesIntegersAndUnknownSourceFields(t *testing.T) {
	doc, err := DecodeObject([]byte(`{"unknown":9007199254740993,"sources":[{"kind":"server","new_field":{"x":1}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if number, ok := doc["unknown"].(json.Number); !ok || number.String() != "9007199254740993" {
		t.Fatalf("integer was not preserved exactly: %#v", doc["unknown"])
	}
	sources, err := ParseSources(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 || !strings.Contains(string(sources[0].Raw), "new_field") {
		t.Fatalf("source field was lost: %#v", sources)
	}
}

func TestParseSourcesRejectsNonObjectRecord(t *testing.T) {
	_, err := ParseSources(map[string]any{"sources": []any{42}})
	if err == nil || !strings.Contains(err.Error(), "sources[0]") {
		t.Fatalf("error = %v, want indexed source validation", err)
	}
}
