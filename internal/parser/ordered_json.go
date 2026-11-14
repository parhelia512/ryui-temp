package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type orderedObject struct {
	values map[string]any
	keys   []string
}

func decodeOrderedMap(data []byte) (map[string]any, map[string][]string, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	orders := map[string][]string{}
	value, err := decodeOrderedValue(decoder, "", orders)
	if err != nil {
		return nil, nil, err
	}
	root, ok := value.(orderedObject)
	if !ok {
		return nil, nil, fmt.Errorf("contract JSON root is not an object")
	}
	return root.values, orders, nil
}

func decodeOrderedValue(decoder *json.Decoder, path string, orders map[string][]string) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := orderedObject{values: map[string]any{}, keys: []string{}}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("object key is not a string")
			}
			value, err := decodeOrderedValue(decoder, joinJSONPath(path, key), orders)
			if err != nil {
				return nil, err
			}
			object.keys = append(object.keys, key)
			object.values[key] = unwrapOrdered(value)
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		orders[path] = append([]string(nil), object.keys...)
		return object, nil
	case '[':
		array := []any{}
		for index := 0; decoder.More(); index++ {
			value, err := decodeOrderedValue(decoder, joinJSONPath(path, fmt.Sprint(index)), orders)
			if err != nil {
				return nil, err
			}
			array = append(array, unwrapOrdered(value))
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return array, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

func unwrapOrdered(value any) any {
	switch current := value.(type) {
	case orderedObject:
		return current.values
	case []any:
		out := make([]any, len(current))
		for index, item := range current {
			out[index] = unwrapOrdered(item)
		}
		return out
	default:
		return current
	}
}
func joinJSONPath(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}
