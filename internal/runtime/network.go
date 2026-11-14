package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (a *Application) networkDiagnostic(ctx context.Context, args map[string]any) (any, error) {
	kind, _ := args["kind"].(string)
	host, _ := args["host"].(string)
	if host == "" {
		host, _ = args["target"].(string)
	}
	budget := 10 * time.Second
	if n, e := strconv.Atoi(toText(args["timeoutMs"])); e == nil && n > 0 && n <= 120000 {
		budget = time.Duration(n) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	began := time.Now()
	switch kind {
	case "dns":
		if host == "" {
			return nil, errors.New("DNS hostname is required")
		}
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		ips := make([]string, 0, len(addresses))
		for _, address := range addresses {
			ips = append(ips, address.String())
		}
		return map[string]any{"kind": kind, "host": host, "addresses": ips, "elapsed_ms": time.Since(began).Milliseconds(), "network": "application"}, nil
	case "tcp":
		if host == "" {
			return nil, errors.New("TCP host is required")
		}
		if _, _, err := net.SplitHostPort(host); err != nil {
			port := toText(args["port"])
			if port == "" {
				port = "443"
			}
			host = net.JoinHostPort(host, port)
		}
		connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", host)
		if err != nil {
			return nil, err
		}
		defer connection.Close()
		return map[string]any{"kind": kind, "host": host, "remote": connection.RemoteAddr().String(), "local": connection.LocalAddr().String(), "elapsed_ms": time.Since(began).Milliseconds(), "network": "application"}, nil
	case "url", "http":
		target, _ := args["url"].(string)
		if target == "" {
			target = host
		}
		if !strings.Contains(target, "://") {
			target = "https://" + target
		}
		parsed, err := url.Parse(target)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
			return nil, errors.New("HTTP(S) URL is required")
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("User-Agent", "LxBox-Go/2.25.21")
		transport := http.DefaultTransport.(*http.Transport).Clone()
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: budget}
		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil {
			return nil, err
		}
		return map[string]any{"kind": kind, "status": response.StatusCode, "body": string(body), "content_type": response.Header.Get("Content-Type"), "elapsed_ms": time.Since(began).Milliseconds(), "network": "application"}, nil
	default:
		return nil, fmt.Errorf("unknown network diagnostic %q", kind)
	}
}

func (a *Application) platformJSON(ctx context.Context, method string, args any, out any) error {
	value, err := a.platformCall(ctx, method, args)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return decode(raw, out)
}
