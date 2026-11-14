package builder

func cloneMap(source map[string]any) map[string]any {
	if source == nil {
		return nil
	}
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = clone(value)
	}
	return result
}

func clone(value any) any {
	switch raw := value.(type) {
	case map[string]any:
		return cloneMap(raw)
	case []any:
		result := make([]any, len(raw))
		for index, item := range raw {
			result[index] = clone(item)
		}
		return result
	case []byte:
		return append([]byte(nil), raw...)
	default:
		return raw
	}
}
