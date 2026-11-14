package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"
)

func TestTaildropBase64Size(t *testing.T) {
	for _, raw := range []string{"", "a", "ab", "abc", "hello", "\x00\xff"} {
		encoded := base64.StdEncoding.EncodeToString([]byte(raw))
		size, err := taildropBase64Size(encoded)
		if err != nil || size != int64(len(raw)) {
			t.Fatalf("size(%q) = %d, %v", encoded, size, err)
		}
	}
	for _, encoded := range []string{"!bad", "Zg", "Zg=", "Zh==", "Zg==\n"} {
		if _, err := taildropBase64Size(encoded); err == nil {
			t.Fatalf("invalid base64 %q accepted", encoded)
		}
	}
}

func TestTaildropCopyChunksBoundedAndErrors(t *testing.T) {
	payload := bytes.Repeat([]byte("0123456789"), 100000)
	var received bytes.Buffer
	buf := make([]byte, taildropIOChunkSize)
	calls := 0
	if err := taildropCopyChunks(context.Background(), bytes.NewReader(payload), buf, func(chunk []byte) error {
		calls++
		if len(chunk) > taildropIOChunkSize {
			t.Fatalf("oversized chunk: %d", len(chunk))
		}
		_, err := received.Write(chunk)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if calls <= 1 || !bytes.Equal(payload, received.Bytes()) {
		t.Fatal("chunked copy changed content or buffered entire payload")
	}
	failure := errors.New("provider write failed")
	if err := taildropCopyChunks(context.Background(), bytes.NewReader(payload), buf, func([]byte) error { return failure }); !errors.Is(err, failure) {
		t.Fatalf("write failure was lost: %v", err)
	}
	if err := taildropCopyChunks(context.Background(), emptyTaildropReader{}, buf, func([]byte) error { return nil }); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("empty reads should fail: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := taildropCopyChunks(ctx, bytes.NewReader(payload), buf, func([]byte) error { t.Fatal("write after cancellation"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled copy = %v", err)
	}
}

type emptyTaildropReader struct{}

func (emptyTaildropReader) Read([]byte) (int, error) { return 0, nil }

func TestTaildropPlatformReaderOwnershipAndEOF(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	reads, closes := 0, 0
	controller := &Controller{platform: func(callCtx context.Context, method string, raw json.RawMessage) (json.RawMessage, error) {
		mu.Lock()
		defer mu.Unlock()
		switch method {
		case "file.openRead":
			return json.RawMessage(`{"handle":"owned-handle","size":3,"name":"hello.txt"}`), nil
		case "file.readChunk":
			if callCtx != ctx {
				t.Fatal("reader did not use caller context")
			}
			var args struct {
				Handle   string `json:"handle"`
				MaxBytes int    `json:"maxBytes"`
			}
			if err := json.Unmarshal(raw, &args); err != nil || args.Handle != "owned-handle" || args.MaxBytes > taildropIOChunkSize {
				t.Fatalf("bad read arguments %s: %v", raw, err)
			}
			reads++
			return json.RawMessage(`{"data":"YWJj","eof":true}`), nil
		case "file.close":
			closes++
			return json.RawMessage(`{"closed":true}`), nil
		}
		t.Fatalf("unexpected method %s", method)
		return nil, errors.New("unexpected callback")
	}}
	source, err := controller.openTaildropURISource(ctx, "content://document", "fallback")
	if err != nil || source.name != "hello.txt" || source.size != 3 {
		t.Fatalf("source metadata = %#v, %v", source, err)
	}
	buf := make([]byte, 8)
	n, err := source.reader.Read(buf)
	if err != nil || string(buf[:n]) != "abc" {
		t.Fatalf("first read = %q, %v", buf[:n], err)
	}
	if _, err := source.reader.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("final chunk EOF was lost: %v", err)
	}
	if err := source.reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := source.reader.Close(); err != nil {
		t.Fatal(err)
	}
	if reads != 1 || closes != 1 {
		t.Fatalf("reads=%d closes=%d, want one of each", reads, closes)
	}
}

func TestTaildropPlatformReaderRejectsOversizeAndNoProgress(t *testing.T) {
	for _, response := range []string{`{"data":"YWJjZA==","eof":false}`, `{"data":"","eof":false}`, `null`} {
		controller := &Controller{platform: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
			return json.RawMessage(response), nil
		}}
		reader := &taildropPlatformReader{controller: controller, ctx: context.Background(), handle: "handle"}
		if _, err := reader.Read(make([]byte, 3)); err == nil {
			t.Fatalf("malformed provider response accepted: %s", response)
		}
	}
}

func TestTaildropFinishRequiresAllFiles(t *testing.T) {
	result := &taildropSendResult{done: make(chan struct{}), completed: make(map[int32]int64)}
	handler := &taildropSendHandler{result: result, files: []taildropSource{{size: 5}}}
	handler.OnFinish("")
	if result.err == "" {
		t.Fatal("premature stream EOF reported success")
	}

	result = &taildropSendResult{done: make(chan struct{}), completed: make(map[int32]int64)}
	handler = &taildropSendHandler{result: result, files: []taildropSource{{size: 5}}}
	handler.OnFileCompleted(0, 5)
	handler.OnFinish("")
	if result.err != "" {
		t.Fatal(result.err)
	}
}

func TestTaildropValidationDoesNotFakeSuccess(t *testing.T) {
	controller := &Controller{}
	for _, test := range []struct{ method, args string }{
		{"ccTaildropSendBytes", `{}`},
		{"ccTaildropSendBytes", `{"tag":"ts","peer_id":"peer","bytes":"bad!"}`},
		{"ccTaildropPickAndSend", `{"tag":"ts"}`},
		{"ccTaildropSave", `{"tag":"ts"}`},
	} {
		if _, err := controller.Taildrop(context.Background(), test.method, json.RawMessage(test.args)); err == nil {
			t.Fatalf("%s accepted malformed arguments", test.method)
		}
	}
}
