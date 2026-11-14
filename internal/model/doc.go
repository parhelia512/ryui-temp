// Package model defines the JSON-facing application state used by the Go app.
//
// Models deliberately use open JSON objects. LxBox storage has a contract with
// a longer-lived Dart client and can contain fields newer than this runtime.
// Closed structs are therefore not used for persisted records unless an API
// explicitly documents a field. Callers should update a cloned document and
// leave keys they do not own untouched.
package model
