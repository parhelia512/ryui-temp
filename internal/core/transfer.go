package core

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
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/experimental/libbox"
)

const taildropIOChunkSize = 64 * 1024

type taildropSource struct {
	name   string
	size   int64
	reader io.ReadCloser
}

func closeTaildropSources(sources []taildropSource) {
	for _, source := range sources {
		if source.reader != nil {
			_ = source.reader.Close()
		}
	}
}

func (c *Controller) Taildrop(ctx context.Context, method string, args json.RawMessage) (any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	// Each invocation owns its context, standalone libbox client and host
	// handles. Cancelling this call cannot disconnect another transfer.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	var values map[string]json.RawMessage
	if err := json.Unmarshal(args, &values); err != nil {
		return nil, fmt.Errorf("decode %s arguments: %w", method, err)
	}
	tag, name := taildropString(values, "tag"), taildropString(values, "name")
	switch method {
	case "ccTaildropDelete":
		if tag == "" || name == "" {
			return nil, errors.New("tag and name are required")
		}
		client := libbox.NewStandaloneCommandClient()
		stopCancel := context.AfterFunc(ctx, func() { _ = client.Disconnect() })
		defer stopCancel()
		defer client.Disconnect()
		return nil, client.DeleteTaildropFile(tag, name)
	case "ccTaildropMarkRead":
		if tag == "" {
			return nil, errors.New("tag is required")
		}
		client := libbox.NewStandaloneCommandClient()
		stopCancel := context.AfterFunc(ctx, func() { _ = client.Disconnect() })
		defer stopCancel()
		defer client.Disconnect()
		return nil, client.MarkTaildropInboxRead(tag)
	case "ccTaildropCancelReceiving":
		senderID := taildropString(values, "sender_id")
		if tag == "" || name == "" || senderID == "" {
			return nil, errors.New("tag, sender_id and name are required")
		}
		client := libbox.NewStandaloneCommandClient()
		stopCancel := context.AfterFunc(ctx, func() { _ = client.Disconnect() })
		defer stopCancel()
		defer client.Disconnect()
		return nil, client.CancelTaildropReceiving(tag, senderID, name)
	case "ccTaildropSendBytes":
		return c.taildropSend(ctx, values)
	case "ccTaildropPickAndSend":
		return c.pickAndSend(ctx, values)
	case "ccTaildropSave":
		return c.saveTaildrop(ctx, values)
	default:
		return nil, fmt.Errorf("unsupported Taildrop method %q", method)
	}
}

func (c *Controller) taildropSend(ctx context.Context, args map[string]json.RawMessage) (any, error) {
	tag, peerID := taildropString(args, "tag"), taildropString(args, "peer_id")
	if tag == "" || peerID == "" {
		return nil, errors.New("tag and peer_id are required")
	}
	var sources []taildropSource
	switch {
	case args["uri"] != nil:
		source, err := c.openTaildropURISource(ctx, taildropString(args, "uri"), taildropString(args, "name"))
		if err != nil {
			return nil, err
		}
		sources = []taildropSource{source}
	case args["bytes"] != nil:
		var encoded string
		if err := json.Unmarshal(args["bytes"], &encoded); err != nil {
			return nil, errors.New("bytes must be a base64 string")
		}
		decodedSize, err := taildropBase64Size(encoded)
		if err != nil {
			return nil, err
		}
		name := taildropString(args, "name")
		if name == "" {
			name = taildropNoteName()
		}
		sources = []taildropSource{{name: taildropSafeName(name), size: decodedSize, reader: io.NopCloser(base64.NewDecoder(base64.StdEncoding, strings.NewReader(encoded)))}}
	case args["text"] != nil:
		text := taildropString(args, "text")
		name := taildropString(args, "name")
		if name == "" {
			name = taildropNoteName()
		}
		content := []byte(text)
		sources = []taildropSource{{name: taildropSafeName(name), size: int64(len(content)), reader: io.NopCloser(bytes.NewReader(content))}}
	default:
		return nil, errors.New("one of uri, bytes or text is required")
	}
	return c.sendTaildropSources(ctx, args, sources)
}

func (c *Controller) pickAndSend(ctx context.Context, args map[string]json.RawMessage) (any, error) {
	if taildropString(args, "tag") == "" || taildropString(args, "peer_id") == "" {
		return nil, errors.New("tag and peer_id are required")
	}
	picked, err := c.platformCall(ctx, "file.pick", json.RawMessage(`{"mimeTypes":["*/*"],"allowMultiple":true,"metadataOnly":true}`))
	if err != nil {
		return nil, fmt.Errorf("pick Taildrop files: %w", err)
	}
	sources, cancelled, err := c.taildropPickedSources(ctx, picked)
	if err != nil {
		closeTaildropSources(sources)
		return nil, err
	}
	if cancelled || len(sources) == 0 {
		return map[string]any{"status": "cancelled"}, nil
	}
	return c.sendTaildropSources(ctx, args, sources)
}

func (c *Controller) taildropPickedSources(ctx context.Context, value any) ([]taildropSource, bool, error) {
	var documents []any
	switch result := value.(type) {
	case map[string]any:
		if result["cancelled"] == true {
			return nil, true, nil
		}
		if list, ok := result["documents"].([]any); ok {
			documents = list
		} else if list, ok := result["files"].([]any); ok {
			documents = list
		} else {
			documents = []any{result}
		}
	case []any:
		documents = result
	default:
		return nil, false, errors.New("file picker returned an unsupported response")
	}
	var sources []taildropSource
	for _, value := range documents {
		doc, ok := value.(map[string]any)
		if !ok {
			return sources, false, errors.New("file picker returned a malformed document")
		}
		uri, _ := doc["uri"].(string)
		name, _ := doc["name"].(string)
		if uri == "" {
			return sources, false, errors.New("file picker must return document URIs for streaming")
		}
		source, err := c.openTaildropURISource(ctx, uri, name)
		if err != nil {
			return sources, false, err
		}
		sources = append(sources, source)
	}
	return sources, false, nil
}

func (c *Controller) openTaildropURISource(ctx context.Context, uri, fallbackName string) (taildropSource, error) {
	if uri == "" {
		return taildropSource{}, errors.New("uri is required")
	}
	var response struct {
		Handle string `json:"handle"`
		Size   *int64 `json:"size"`
		Name   string `json:"name"`
	}
	if err := c.taildropPlatformCall(ctx, "file.openRead", map[string]any{"uri": uri}, &response); err != nil {
		return taildropSource{}, fmt.Errorf("open document: %w", err)
	}
	if response.Handle == "" {
		return taildropSource{}, errors.New("file.openRead returned no handle")
	}
	if err := ctx.Err(); err != nil {
		_ = c.taildropPlatformCall(context.Background(), "file.close", map[string]any{"handle": response.Handle}, nil)
		return taildropSource{}, err
	}
	name := response.Name
	if name == "" {
		name = fallbackName
	}
	if name == "" {
		name = "file"
	}
	size := int64(-1)
	if response.Size != nil {
		size = *response.Size
	}
	return taildropSource{
		name:   taildropSafeName(name),
		size:   size,
		reader: &taildropPlatformReader{controller: c, ctx: ctx, handle: response.Handle},
	}, nil
}

type taildropPlatformReader struct {
	controller *Controller
	ctx        context.Context
	handle     string
	once       sync.Once
	closed     error
	eof        bool
}

func (r *taildropPlatformReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.eof {
		return 0, io.EOF
	}
	maxBytes := min(len(p), taildropIOChunkSize)
	var response struct {
		Data string `json:"data"`
		EOF  bool   `json:"eof"`
	}
	if err := r.controller.taildropPlatformCall(r.ctx, "file.readChunk", map[string]any{"handle": r.handle, "maxBytes": maxBytes}, &response); err != nil {
		return 0, fmt.Errorf("read document chunk: %w", err)
	}
	if len(response.Data) > base64.StdEncoding.EncodedLen(maxBytes) {
		return 0, errors.New("file.readChunk exceeded requested maxBytes")
	}
	chunk, err := base64.StdEncoding.DecodeString(response.Data)
	if err != nil {
		return 0, fmt.Errorf("decode document chunk: %w", err)
	}
	if len(chunk) > maxBytes {
		return 0, errors.New("file.readChunk exceeded requested maxBytes")
	}
	if len(chunk) == 0 && !response.EOF {
		return 0, io.ErrNoProgress
	}
	r.eof = response.EOF
	if len(chunk) == 0 {
		return 0, io.EOF
	}
	return copy(p, chunk), nil
}

func (r *taildropPlatformReader) Close() error {
	r.once.Do(func() {
		r.closed = r.controller.taildropPlatformCall(context.Background(), "file.close", map[string]any{"handle": r.handle}, nil)
	})
	return r.closed
}

func (c *Controller) sendTaildropSources(ctx context.Context, args map[string]json.RawMessage, sources []taildropSource) (any, error) {
	if len(sources) == 0 {
		return nil, errors.New("no Taildrop files selected")
	}
	defer closeTaildropSources(sources)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	wait := taildropInt64(args, "wait_ms", 60_000)
	if wait <= 0 {
		wait = 60_000
	}
	if wait > 30*60*1000 {
		return nil, errors.New("wait_ms must not exceed 1800000")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(wait)*time.Millisecond)
	defer cancel()
	client := libbox.NewStandaloneCommandClient()
	stopCancel := context.AfterFunc(ctx, func() { _ = client.Disconnect() })
	defer stopCancel()
	defer client.Disconnect()
	result := &taildropSendResult{done: make(chan struct{}), completed: make(map[int32]int64)}
	opts := libbox.NewTaildropSendOptions()
	opts.EndpointTag = taildropString(args, "tag")
	opts.PeerStableID = taildropString(args, "peer_id")
	for _, source := range sources {
		opts.AddFile(source.name, source.size)
		if platformReader, ok := source.reader.(*taildropPlatformReader); ok {
			platformReader.ctx = ctx
		}
	}
	closeOnCancel := context.AfterFunc(ctx, func() { closeTaildropSources(sources) })
	defer closeOnCancel()
	session, err := client.SendTaildropFiles(opts, &taildropSendHandler{result: result, files: sources})
	if err != nil {
		return nil, err
	}
	defer session.Close()
	buf := make([]byte, min(int(libbox.TaildropChunkSize), taildropIOChunkSize))
	for _, source := range sources {
		if err := taildropCopyChunks(ctx, source.reader, buf, session.WriteChunk); err != nil {
			return nil, fmt.Errorf("send %q: %w", source.name, err)
		}
		if err := source.reader.Close(); err != nil {
			return nil, fmt.Errorf("close source %q: %w", source.name, err)
		}
		if err := session.FinishFile(); err != nil {
			return nil, fmt.Errorf("finish %q: %w", source.name, err)
		}
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-result.done:
		result.mu.Lock()
		message := result.err
		result.mu.Unlock()
		if message != "" {
			return map[string]any{"status": "error", "error": message}, errors.New(message)
		}
	}
	names := make([]string, len(sources))
	for i := range sources {
		names[i] = sources[i].name
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return map[string]any{"status": "sent", "name": names[0], "names": names}, nil
}

type taildropSendResult struct {
	mu       sync.Mutex
	done     chan struct{}
	err      string
	finished  bool
	completed map[int32]int64
}

func (r *taildropSendResult) finish(message string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finished {
		return
	}
	r.finished = true
	r.err = message
	close(r.done)
}

type taildropSendHandler struct {
	result *taildropSendResult
	files  []taildropSource
}

func (*taildropSendHandler) OnProgress(int32, int64) {}
func (h *taildropSendHandler) OnFileCompleted(index int32, sentBytes int64) {
	h.result.mu.Lock()
	h.result.completed[index] = sentBytes
	h.result.mu.Unlock()
}
func (h *taildropSendHandler) OnFinish(message string) {
	if message == "" {
		h.result.mu.Lock()
		for i, source := range h.files {
			sent, completed := h.result.completed[int32(i)]
			if !completed || (source.size >= 0 && sent != source.size) {
				message = "Taildrop stream ended without completing every file"
				break
			}
		}
		h.result.mu.Unlock()
	}
	h.result.finish(message)
}

func (c *Controller) saveTaildrop(ctx context.Context, args map[string]json.RawMessage) (any, error) {
	tag, name := taildropString(args, "tag"), taildropString(args, "name")
	if tag == "" || name == "" {
		return nil, errors.New("tag and name are required")
	}
	tempDir := filepath.Join(c.dataDir, "tmp")
	if err := os.MkdirAll(tempDir, 0700); err != nil {
		return nil, fmt.Errorf("create Taildrop temp directory: %w", err)
	}
	tempFile, err := os.CreateTemp(tempDir, "taildrop-save-*")
	if err != nil {
		return nil, fmt.Errorf("create Taildrop temp file: %w", err)
	}
	tempPath := tempFile.Name()
	if err := tempFile.Close(); err != nil {
		_ = os.Remove(tempPath)
		return nil, fmt.Errorf("prepare Taildrop temp file: %w", err)
	}
	_ = os.Remove(tempPath)
	defer os.Remove(tempPath)

	client := libbox.NewStandaloneCommandClient()
	stopCancel := context.AfterFunc(ctx, func() { _ = client.Disconnect() })
	defer stopCancel()
	defer client.Disconnect()
	downloadDone := make(chan string, 1)
	session, err := client.DownloadTaildropFile(tag, name, tempPath, &taildropDownloadHandler{done: downloadDone})
	if err != nil {
		return nil, err
	}
	defer session.Close()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case message := <-downloadDone:
		if message != "" {
			return map[string]any{"status": "error", "error": message}, errors.New(message)
		}
	}
	if err := session.Close(); err != nil {
		return nil, fmt.Errorf("close Taildrop download: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	input, err := os.Open(tempPath)
	if err != nil {
		return nil, fmt.Errorf("open downloaded Taildrop file: %w", err)
	}
	defer input.Close()
	var destination struct {
		Handle string `json:"handle"`
		URI    string `json:"uri"`
		Name   string `json:"name"`
	}
	if err := c.taildropPlatformCall(ctx, "file.create", map[string]any{"suggestedName": name, "mime": "application/octet-stream"}, &destination); err != nil {
		return nil, fmt.Errorf("create SAF destination: %w", err)
	}
	closeDestination := func(commit bool) error {
		return c.taildropPlatformCall(context.Background(), "file.close", map[string]any{"handle": destination.Handle, "commit": commit}, nil)
	}
	if destination.Handle == "" || destination.URI == "" {
		if destination.Handle != "" {
			_ = closeDestination(false)
		}
		return nil, errors.New("file.create returned no handle or URI")
	}
	committed := false
	var closeOnce sync.Once
	var closeErr error
	closeHandle := func(commit bool) error {
		closeOnce.Do(func() { closeErr = closeDestination(commit) })
		return closeErr
	}
	abortOnCancel := context.AfterFunc(ctx, func() { _ = closeHandle(false) })
	defer abortOnCancel()
	defer func() {
		if !committed {
			_ = closeHandle(false)
		}
	}()
	buf := make([]byte, taildropIOChunkSize)
	if err := taildropCopyChunks(ctx, input, buf, func(chunk []byte) error {
		var response struct{ Written *int `json:"written"` }
		err := c.taildropPlatformCall(ctx, "file.writeChunk", map[string]any{"handle": destination.Handle, "data": base64.StdEncoding.EncodeToString(chunk)}, &response)
		if err == nil && (response.Written == nil || *response.Written != len(chunk)) {
			err = io.ErrShortWrite
		}
		return err
	}); err != nil {
		return nil, fmt.Errorf("copy Taildrop file to SAF: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := closeHandle(true); err != nil {
		return nil, fmt.Errorf("finalize SAF destination: %w", err)
	}
	committed = true
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// A standalone download closes its connection from the receive goroutine.
	// Use a separate client for deletion so that cleanup cannot race a redial.
	deleteClient := libbox.NewStandaloneCommandClient()
	defer deleteClient.Disconnect()
	stopDelete := context.AfterFunc(ctx, func() { _ = deleteClient.Disconnect() })
	defer stopDelete()
	if err := deleteClient.DeleteTaildropFile(tag, name); err != nil {
		return map[string]any{"status": "saved", "uri": destination.URI, "name": destination.Name}, fmt.Errorf("file saved but could not remove Taildrop inbox copy: %w", err)
	}
	return map[string]any{"status": "saved", "uri": destination.URI, "name": destination.Name}, nil
}

type taildropDownloadHandler struct{ done chan<- string }

func (*taildropDownloadHandler) OnProgress(int64, int64) {}
func (h *taildropDownloadHandler) OnFinish(message string) { h.done <- message }

func (c *Controller) taildropPlatformCall(ctx context.Context, method string, args any, out any) error {
	if c.platform == nil {
		return errors.New("platform callback is unavailable")
	}
	payload, err := json.Marshal(args)
	if err != nil {
		return err
	}
	response, err := c.platform(ctx, method, payload)
	if err != nil {
		return err
	}
	if out == nil || len(response) == 0 || string(response) == "null" {
		return nil
	}
	if err := json.Unmarshal(response, out); err != nil {
		return fmt.Errorf("platform %s response: %w", method, err)
	}
	return nil
}

// taildropCopyChunks owns no handles; the caller must close source and sink.
// It never buffers beyond buf and never reports read/write/cancellation errors
// as a completed file.
func taildropCopyChunks(ctx context.Context, source io.Reader, buf []byte, write func([]byte) error) error {
	if len(buf) == 0 {
		return errors.New("Taildrop chunk buffer is empty")
	}
	emptyReads := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := source.Read(buf)
		if n > 0 {
			emptyReads = 0
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := write(buf[:n]); err != nil {
				return err
			}
		} else if readErr == nil {
			emptyReads++
			if emptyReads >= 100 {
				return io.ErrNoProgress
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func taildropString(args map[string]json.RawMessage, key string) string {
	var value string
	_ = json.Unmarshal(args[key], &value)
	return value
}

func taildropInt64(args map[string]json.RawMessage, key string, fallback int64) int64 {
	var value int64
	if len(args[key]) == 0 || json.Unmarshal(args[key], &value) != nil {
		return fallback
	}
	return value
}

func taildropBase64Size(encoded string) (int64, error) {
	// Validate without ever allocating a decoded file-sized byte slice. The
	// decoder and io.Copy's buffer are bounded even for a large JSON payload.
	if strings.ContainsAny(encoded, "\r\n") {
		return 0, errors.New("bytes must be a single padded base64 string")
	}
	size, err := io.Copy(io.Discard, base64.NewDecoder(base64.StdEncoding.Strict(), strings.NewReader(encoded)))
	if err != nil {
		return 0, fmt.Errorf("decode bytes: %w", err)
	}
	return size, nil
}

func taildropNoteName() string { return "note-" + time.Now().Format("2006-01-02-1504") + ".txt" }

func taildropSafeName(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	if name == "." || name == string(filepath.Separator) || name == "" {
		return "file"
	}
	return name
}

var _ libbox.TaildropSendHandler = (*taildropSendHandler)(nil)
var _ libbox.TaildropDownloadHandler = (*taildropDownloadHandler)(nil)
