package internal

import (
	"Bucket-Diver-Azure/models"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var textExtensions = map[string]bool{
	".txt": true, ".log": true, ".json": true, ".yaml": true, ".yml": true,
	".env": true, ".cfg": true, ".conf": true, ".config": true, ".ini": true,
	".toml": true, ".xml": true, ".csv": true, ".tsv": true,
	".go": true, ".py": true, ".js": true, ".ts": true, ".rb": true,
	".java": true, ".php": true, ".sh": true, ".bash": true, ".zsh": true,
	".tf": true, ".tfvars": true, ".hcl": true,
	".properties": true, ".pem": true, ".key": true, ".crt": true,
	".md": true, ".html": true, ".htm": true, ".sql": true, ".gz": true,
	".zip": true,
}

var textMIMEPrefixes = []string{
	"text/",
	"application/json",
	"application/xml",
	"application/x-yaml",
	"application/javascript",
}

const maxArchiveDepth = 3

const maxZipBufferSize = 50 * 1024 * 1024

type rateLimiter struct {
	ticker *time.Ticker
}

func newRateLimiter(requestsPerSec int) *rateLimiter {
	return &rateLimiter{
		ticker: time.NewTicker(time.Second / time.Duration(requestsPerSec)),
	}
}

func (rl *rateLimiter) Wait(ctx context.Context) error {
	select {
	case <-rl.ticker.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (rl *rateLimiter) Stop() {
	rl.ticker.Stop()
}

func isScannable(ext, contentType string) bool {
	if textExtensions[ext] {
		return true
	}
	if ext == "" {
		for _, prefix := range textMIMEPrefixes {
			if strings.HasPrefix(contentType, prefix) {
				return true
			}
		}
	}
	return false
}

type PoolConfig struct {
	Workers          int
	MaxFileSizeBytes int64
	RateLimit        int
	ScanMetadata     bool
}

type Metrics struct {
	Scanned uint64
	Skipped uint64
	Errors  uint64
}

func StartPool(cfg PoolConfig, az *AzureClient, tasks <-chan models.ScanTask, findings chan<- models.Finding, ctx context.Context) (*sync.WaitGroup, *Metrics) {
	var wg sync.WaitGroup
	rl := newRateLimiter(cfg.RateLimit)
	seen := NewSeenSecrets()
	m := &Metrics{}

	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range tasks {
				processTask(ctx, az, seen, findings, task, cfg, rl, m)
			}
		}()
	}

	go func() {
		wg.Wait()
		rl.Stop()
	}()

	return &wg, m
}

func processTask(ctx context.Context, az *AzureClient, seen *SeenSecrets, findings chan<- models.Finding, task models.ScanTask, cfg PoolConfig, rl *rateLimiter, m *Metrics) {
	key := task.Key
	bucket := task.Bucket
	ext := strings.ToLower(filepath.Ext(key))

	if ext != "" && !isScannable(ext, "") {
		atomic.AddUint64(&m.Skipped, 1)
		return
	}

	if err := rl.Wait(ctx); err != nil {
		return
	}

	stream, size, contentType, err := az.GetFileStream(ctx, bucket, key)
	if err != nil {
		slog.Error("failed to download blob", "bucket", bucket, "key", key, "error", err)
		atomic.AddUint64(&m.Errors, 1)
		return
	}
	defer stream.Close()

	if size != -1 && size > cfg.MaxFileSizeBytes {
		atomic.AddUint64(&m.Skipped, 1)
		return
	}

	reader := bufio.NewReader(stream)

	isGeneric := contentType == "" ||
		contentType == "application/octet-stream" ||
		contentType == "binary/octet-stream"

	if ext == "" || isGeneric {
		peekBytes, _ := reader.Peek(512)
		sniffedType := http.DetectContentType(peekBytes)
		if !isScannable(ext, sniffedType) {
			atomic.AddUint64(&m.Skipped, 1)
			return
		}
	} else if !isScannable(ext, contentType) {
		atomic.AddUint64(&m.Skipped, 1)
		return
	}

	ProcessObject(ctx, az, seen, findings, bucket, key, ext, reader, size, cfg, 0)
	atomic.AddUint64(&m.Scanned, 1)
}

func ProcessObject(
	ctx context.Context,
	az *AzureClient,
	seen *SeenSecrets,
	findings chan<- models.Finding,
	bucket, key, ext string,
	r io.Reader,
	size int64,
	cfg PoolConfig,
	depth int,
) {
	if depth > maxArchiveDepth {
		slog.Warn("max archive depth reached, skipping", "bucket", bucket, "key", key, "depth", depth)
		return
	}

	if cfg.ScanMetadata && depth == 0 && !strings.Contains(key, "::") {
		meta, err := az.GetObjectMetadata(ctx, bucket, key)
		if err == nil && len(meta) > 0 {
			ScanMetadata(bucket, key, meta, seen, findings)
		}
	}

	keyLower := strings.ToLower(key)

	if strings.HasSuffix(keyLower, ".gz") {
		gz, err := gzip.NewReader(r)
		if err != nil {
			slog.Error("failed to open gzip", "bucket", bucket, "key", key, "error", err)
			return
		}
		defer gz.Close()

		innerKey := key[:len(key)-3]
		ProcessObject(ctx, az, seen, findings, bucket, innerKey, filepath.Ext(innerKey), gz, -1, cfg, depth+1)
		return
	}

	if strings.HasSuffix(keyLower, ".zip") {
		buf, err := io.ReadAll(io.LimitReader(r, maxZipBufferSize))
		if err != nil {
			slog.Error("failed to read zip", "bucket", bucket, "key", key, "error", err)
			return
		}

		zipR, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
		if err != nil {
			slog.Error("failed to parse zip", "bucket", bucket, "key", key, "error", err)
			return
		}

		for _, zf := range zipR.File {
			if cfg.MaxFileSizeBytes != -1 && int64(zf.UncompressedSize64) > cfg.MaxFileSizeBytes {
				continue
			}
			rc, err := zf.Open()
			if err != nil {
				slog.Warn("failed to open zip entry", "bucket", bucket, "key", key, "entry", zf.Name, "error", err)
				continue
			}
			ProcessObject(ctx, az, seen, findings, bucket, key+"::"+zf.Name, filepath.Ext(zf.Name), rc, int64(zf.UncompressedSize64), cfg, depth+1)
			rc.Close()
		}
		return
	}

	if cfg.MaxFileSizeBytes != -1 && size > cfg.MaxFileSizeBytes {
		return
	}

	ScanStream(ctx, bucket, key, ext, r, seen, findings)
}
