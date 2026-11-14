package builder

import (
	"fmt"
	"strings"
)

func typedDefault(value any, kind string) any {
	if value == nil { return defaultForType(kind) }
	switch kind {
	case "bool":
		if text, ok := value.(string); ok { return text == "true" }
	case "int":
		if text, ok := value.(string); ok { parsed, err := parseInteger(text); if err == nil { return parsed } }
	case "text_list":
		return stringsToAny(stringsOf(value))
	}
	return value
}
func defaultForType(kind string) any { switch kind { case "bool": return false; case "int": return 0; case "text_list": return []any{}; default: return "" } }
func parseInteger(value string) (int, error) {
	var n int
	_, err := fmt.Sscanf(strings.TrimSpace(value), "%d", &n)
	return n, err
}
