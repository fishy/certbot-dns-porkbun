package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

const (
	success      = "SUCCESS"
	recordType   = "TXT"
	domainPrefix = "_acme-challenge"
)

var client http.Client

// flags
var (
	level slog.Level

	domain = flag.String(
		"domain",
		"",
		"The domain requested",
	)

	validation = flag.String(
		"validation",
		"",
		"The ACME validation, leave empty to delete all records matching domain (cleanup mode), exactly one of validation, cleanup-id, and cleanup-all must be set",
	)
	cleanupID = flag.String(
		"cleanup-id",
		"",
		"The subdomain id to cleanup, exactly one of validation, cleanup-id, and cleanup-all must be set",
	)
	cleanupAll = flag.Bool(
		"cleanup-all",
		false,
		"Cleanup all subdomains, exactly one of validation, cleanup-id, and cleanup-all must be set",
	)

	endpoint = flag.String(
		"endpoint",
		"https://api-ipv4.porkbun.com/api/json/v3",
		"Porkbun API endpoint",
	)
	apiKey = flag.String(
		"apikey",
		"",
		"Porkbun API key (example: pk1_deadbeef)",
	)
	secKey = flag.String(
		"secretapikey",
		"",
		"Porkbun secret API key (example: sk1_deadbeef)",
	)
	ttl = flag.Duration(
		"ttl",
		1*time.Minute, // NOTE: this is the current minimal TTL allowed by Porkbun
		"The TTL for the record",
	)
	timeout = flag.Duration(
		"timeout",
		5*time.Second,
		"Timeout for each http requests",
	)
)

type request struct {
	// Required for all requests
	APIKey string `json:"apikey"`
	SecKey string `json:"secretapikey"`

	Subdomain string `json:"name,omitempty"`
	Type      string `json:"type,omitempty"`
	Content   string `json:"content,omitempty"`
	TTL       string `json:"ttl,omitempty"`
}

func main() {
	flag.TextVar(&level, "log-level", &level, "minimal log level to keep")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:     &level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if req, ok := a.Value.Any().(request); ok {
				req.SecKey = "*REDACTED*"

				var sb strings.Builder
				if err := json.NewEncoder(&sb).Encode(req); err == nil {
					a.Value = slog.StringValue(sb.String())
				}
			}
			return a
		},
	})))

	ctx := context.Background()

	var exclusiveCount int
	if *validation != "" {
		exclusiveCount++
	}
	if *cleanupID != "" {
		exclusiveCount++
	}
	if *cleanupAll {
		exclusiveCount++
	}
	if exclusiveCount != 1 {
		fatal(
			ctx,
			"Exactly one of validation, cleanup-id, and cleanup-all must be set",
			"validation", *validation,
			"cleanup-id", *cleanupID,
			"cleanup-all", *cleanupAll,
		)
	}

	topDomain, err := publicsuffix.EffectiveTLDPlusOne(*domain)
	if err != nil {
		fatal(ctx, "Failed to split domain", "err", err, "domain", *domain)
	}
	subDomain, _ := strings.CutSuffix(*domain, topDomain)
	if subDomain == "" {
		subDomain = domainPrefix
	} else {
		subDomain = strings.TrimSuffix(subDomain, ".")
		subDomain = domainPrefix + "." + subDomain
	}

	content := getIP(ctx)
	slog.DebugContext(ctx, "auth successful", "ip", content)
	if *validation != "" {
		slog.DebugContext(ctx, "input", "validation", *validation)
		create(ctx, topDomain, subDomain, *validation)
		return
	}
	if *cleanupID != "" {
		deleteID(ctx, topDomain, *cleanupID)
		return
	}
	if *cleanupAll {
		cleanup(ctx, topDomain, subDomain)
		return
	}
}

var bufPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

func getBuf() *bytes.Buffer {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

func returnBuf(buf **bytes.Buffer) {
	bufPool.Put(*buf)
	*buf = nil
}

func fatal(ctx context.Context, msg string, args ...any) {
	slog.ErrorContext(ctx, msg, args...)
	os.Exit(-1)
}

func decodeBody(resp *http.Response, data any) (string, error) {
	buf := getBuf()
	defer returnBuf(&buf)
	reader := io.TeeReader(resp.Body, buf)
	defer func() {
		io.Copy(io.Discard, reader)
		resp.Body.Close()
	}()

	err := json.NewDecoder(reader).Decode(data)
	return buf.String(), err
}

func getIP(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	buf := getBuf()
	defer returnBuf(&buf)

	req := request{
		APIKey: *apiKey,
		SecKey: *secKey,
	}
	if err := json.NewEncoder(buf).Encode(req); err != nil {
		fatal(
			ctx,
			"Failed to json encode request",
			"err", err,
			"request", req,
		)
		return ""
	}

	url := *endpoint + "/ping"
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, url, buf)
	if err != nil {
		fatal(
			ctx,
			"Failed to generate http request",
			"err", err,
			"url", url,
			"request", req,
		)
		return ""
	}

	resp, err := client.Do(r)
	if err != nil {
		fatal(
			ctx,
			"http request failed",
			"err", err,
			"url", url,
			"request", req,
		)
		return ""
	}
	var data struct {
		Status string `json:"status"`
		IP     string `json:"yourIp"`
	}
	body, err := decodeBody(resp, &data)
	if err != nil {
		fatal(
			ctx,
			"Failed to decode response body",
			"err", err,
			"url", url,
			"code", resp.StatusCode,
			"body", body,
		)
		return ""
	}
	slog.DebugContext(ctx, "auth", "url", url, "response", body, "decoded", data)
	if data.Status != success {
		fatal(
			ctx,
			"Ping failed",
			"url", url,
			"code", resp.StatusCode,
			"status", data.Status,
			"body", body,
		)
		return ""
	}
	return data.IP
}

func getIDs(ctx context.Context, domain, subDomain string) []string {
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	buf := getBuf()
	defer returnBuf(&buf)

	req := request{
		APIKey: *apiKey,
		SecKey: *secKey,
	}
	if err := json.NewEncoder(buf).Encode(req); err != nil {
		fatal(
			ctx,
			"Failed to json encode request for getIDs",
			"err", err,
			"request", req,
		)
		return nil
	}

	url := fmt.Sprintf("%s/dns/retrieveByNameType/%s/%s/%s", *endpoint, domain, recordType, subDomain)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, url, buf)
	if err != nil {
		fatal(
			ctx,
			"Failed to generate http request for getIDs",
			"err", err,
			"url", url,
			"request", req,
		)
		return nil
	}

	resp, err := client.Do(r)
	if err != nil {
		fatal(
			ctx,
			"http request failed for getIDs",
			"err", err,
			"url", url,
			"request", req,
		)
		return nil
	}
	var data struct {
		Status string `json:"status"`

		Records []struct {
			ID      string `json:"id"`
			Content string `json:"content"`
		} `json:"records"`
	}
	body, err := decodeBody(resp, &data)
	if err != nil {
		fatal(
			ctx,
			"Failed to decode response body for getIDs",
			"err", err,
			"url", url,
			"code", resp.StatusCode,
			"body", body,
		)
		return nil
	}
	if data.Status != success {
		fatal(
			ctx,
			"getIDs failed",
			"url", url,
			"code", resp.StatusCode,
			"status", data.Status,
			"body", body,
		)
	}
	ids := make([]string, len(data.Records))
	for i, record := range data.Records {
		ids[i] = record.ID
	}
	slog.DebugContext(ctx, "got IDs", "ids", ids, "url", url, "response", body, "decoded", data)
	return ids
}

func deleteID(ctx context.Context, domain, id string) {
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	buf := getBuf()
	defer returnBuf(&buf)

	req := request{
		APIKey: *apiKey,
		SecKey: *secKey,
	}
	if err := json.NewEncoder(buf).Encode(req); err != nil {
		fatal(
			ctx,
			"Failed to json encode request for deleteID",
			"err", err,
			"request", req,
		)
		return
	}

	url := fmt.Sprintf("%s/dns/delete/%s/%s", *endpoint, domain, id)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, url, buf)
	if err != nil {
		fatal(
			ctx,
			"Failed to generate http request for deleteID",
			"err", err,
			"url", url,
			"request", req,
		)
		return
	}

	resp, err := client.Do(r)
	if err != nil {
		fatal(
			ctx,
			"http request failed for deleteID",
			"err", err,
			"url", url,
			"request", req,
		)
		return
	}
	var data struct {
		Status string `json:"status"`
	}
	body, err := decodeBody(resp, &data)
	if err != nil {
		fatal(
			ctx,
			"Failed to decode response body for deleteID",
			"err", err,
			"url", url,
			"code", resp.StatusCode,
			"body", body,
		)
		return
	}
	if data.Status != success {
		fatal(
			ctx,
			"Cleanup failed",
			"url", url,
			"code", resp.StatusCode,
			"status", data.Status,
			"body", body,
		)
	}
	slog.DebugContext(ctx, "deleted record", "url", url, "response", body, "decoded", data)
}

func cleanup(ctx context.Context, domain, subDomain string) {
	ids := getIDs(ctx, domain, subDomain)
	for _, id := range ids {
		deleteID(ctx, domain, id)
	}
	slog.InfoContext(ctx, "deleted records", "ids", ids, "n", len(ids))
}

func create(ctx context.Context, domain, subDomain, validation string) {
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	buf := getBuf()
	defer returnBuf(&buf)

	req := request{
		APIKey: *apiKey,
		SecKey: *secKey,

		Subdomain: subDomain,
		Type:      recordType,
		Content:   validation,
		TTL:       strconv.FormatInt(int64(ttl.Seconds()), 10),
	}

	if err := json.NewEncoder(buf).Encode(req); err != nil {
		fatal(
			ctx,
			"Failed to json encode request for create",
			"err", err,
			"request", req,
		)
		return
	}

	url := fmt.Sprintf("%s/dns/create/%s", *endpoint, domain)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, url, buf)
	if err != nil {
		fatal(
			ctx,
			"Failed to generate http request for create",
			"err", err,
			"url", url,
			"body", buf.String(),
		)
		return
	}

	resp, err := client.Do(r)
	if err != nil {
		fatal(
			ctx,
			"http request failed for create",
			"err", err,
			"url", url,
			"body", buf.String(),
		)
		return
	}
	var data struct {
		Status string `json:"status"`
		ID     int    `json:"id"`
	}
	body, err := decodeBody(resp, &data)
	if err != nil {
		fatal(
			ctx,
			"Failed to decode response body for create",
			"err", err,
			"url", url,
			"code", resp.StatusCode,
			"body", body,
		)
		return
	}
	if data.Status != success {
		fatal(
			ctx,
			"Create failed",
			"url", url,
			"code", resp.StatusCode,
			"status", data.Status,
			"body", body,
		)
		return
	}
	slog.DebugContext(ctx, "created record", "url", url, "response", body, "decoded", data)
	fmt.Println(data.ID)
}
