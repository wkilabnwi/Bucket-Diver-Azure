package main

import (
	"Bucket-Diver-Azure/internal"
	"Bucket-Diver-Azure/models"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

func main() {
	accountName := flag.String("a", "", "Azure Storage Account name (required)")
	containerList := flag.String("c", "", "Comma-separated container names; omit to scan ALL containers")
	prefix := flag.String("prefix", "", "Only scan blobs whose name starts with this prefix")
	threads := flag.Int("t", 10, "Concurrent worker goroutines")
	rateLimit := flag.Int("rate", 100, "Max blob download requests per second")
	maxSize := flag.Int("max-size", 10, "Skip blobs larger than this many MB")
	scanMeta := flag.Bool("meta", false, "Also scan blob metadata and tags (doubles API calls)")
	outputFile := flag.String("o", "", "Write JSON findings to this file (default: stdout only)")
	quiet := flag.Bool("q", false, "Suppress human-readable progress output")
	verbose := flag.Bool("v", false, "Enable debug-level structured logging")
	flag.Parse()

	if *accountName == "" {
		fmt.Fprintln(os.Stderr, "error: -a (account name) is required")
		flag.Usage()
		os.Exit(1)
	}

	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		slog.Error("failed to obtain Azure credential", "error", err)
		os.Exit(1)
	}

	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", *accountName)
	client, err := azblob.NewClient(serviceURL, cred, nil)
	if err != nil {
		slog.Error("failed to create Azure Blob client", "error", err)
		os.Exit(1)
	}

	azProvider := internal.NewAzureClient(*accountName, client)

	var containers []string
	if *containerList != "" {
		containers = splitTrim(*containerList, ",")
	} else {
		slog.Info("no containers specified — discovering all containers")
		containers, err = listAllContainers(ctx, client)
		if err != nil {
			slog.Error("container discovery failed", "error", err)
			os.Exit(1)
		}
		slog.Info("discovered containers", "count", len(containers))
	}
	if len(containers) == 0 {
		slog.Error("no containers to scan")
		os.Exit(1)
	}

	writers := []json.Encoder{}
	stdoutEnc := json.NewEncoder(os.Stdout)
	writers = append(writers, *stdoutEnc)

	var fileOut *os.File
	if *outputFile != "" {
		fileOut, err = os.Create(*outputFile)
		if err != nil {
			slog.Error("failed to create output file", "path", *outputFile, "error", err)
			os.Exit(1)
		}
		defer fileOut.Close()
	}

	fileTasks := make(chan models.ScanTask, 1000)
	findings := make(chan models.Finding, 200)
	maxSizeBytes := int64(*maxSize) * 1024 * 1024

	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)

		outEnc := json.NewEncoder(os.Stdout)
		var fileEnc *json.Encoder
		if fileOut != nil {
			fileEnc = json.NewEncoder(fileOut)
		}

		for found := range findings {
			if !*quiet {
				severity := found.Severity
				fmt.Fprintf(os.Stderr, "[%s] %s  %s/%s  (line %d)\n",
					severity, found.Category, found.Bucket, found.File, found.Line)
			}
			if err := outEnc.Encode(found); err != nil {
				slog.Error("failed to encode finding to stdout", "error", err)
			}
			if fileEnc != nil {
				if err := fileEnc.Encode(found); err != nil {
					slog.Error("failed to encode finding to file", "error", err)
				}
			}
		}
		_ = writers
	}()

	poolCfg := internal.PoolConfig{
		Workers:          *threads,
		MaxFileSizeBytes: maxSizeBytes,
		RateLimit:        *rateLimit,
		ScanMetadata:     *scanMeta,
	}
	wg, metrics := internal.StartPool(poolCfg, azProvider, fileTasks, findings, ctx)

	var indexWg sync.WaitGroup
	for _, c := range containers {
		indexWg.Add(1)
		go func(container string) {
			defer indexWg.Done()
			paginateContainer(ctx, client, container, *prefix, fileTasks)
		}(c)
	}

	go func() {
		indexWg.Wait()
		close(fileTasks)
	}()

	wg.Wait()
	close(findings)
	<-outputDone

	if !*quiet {
		fmt.Fprintf(os.Stderr, "\n[*] Scan complete — scanned: %d  skipped: %d  errors: %d\n",
			metrics.Scanned, metrics.Skipped, metrics.Errors)
		if *outputFile != "" {
			fmt.Fprintf(os.Stderr, "[*] Findings written to %s\n", *outputFile)
		}
	}
}

func paginateContainer(ctx context.Context, client *azblob.Client, container, prefix string, tasks chan<- models.ScanTask) {
	pager := client.NewListBlobsFlatPager(container, &azblob.ListBlobsFlatOptions{
		Prefix: &prefix,
	})

	for pager.More() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		page, err := pager.NextPage(ctx)
		if err != nil {
			slog.Error("failed to list blobs", "container", container, "error", err)
			return
		}

		for _, blob := range page.Segment.BlobItems {
			select {
			case tasks <- models.ScanTask{Bucket: container, Key: *blob.Name}:
			case <-ctx.Done():
				return
			}
		}
	}
}

func listAllContainers(ctx context.Context, client *azblob.Client) ([]string, error) {
	var containers []string
	pager := client.NewListContainersPager(nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, c := range page.ContainerItems {
			if c.Name != nil {
				containers = append(containers, *c.Name)
			}
		}
	}
	return containers, nil
}

func splitTrim(s, sep string) []string {
	raw := strings.Split(s, sep)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if t := strings.TrimSpace(v); t != "" {
			out = append(out, t)
		}
	}
	return out
}
