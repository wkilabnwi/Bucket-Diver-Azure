package internal

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

const (
	maxRetriesAz       = 3
	retryBaseWaitAz    = 500 * time.Millisecond
	blobRequestTimeout = 2 * time.Minute
)

type readCloserWithCancel struct {
	io.ReadCloser
	cancel context.CancelFunc
}

type AzureClient struct {
	accountName string
	Client      *azblob.Client
}

func NewAzureClient(accountName string, client *azblob.Client) *AzureClient {
	return &AzureClient{accountName: accountName, Client: client}
}

func (a *AzureClient) GetFileStream(ctx context.Context, container, blobName string) (io.ReadCloser, int64, string, error) {
	var lastErr error

	for attempt := 0; attempt < maxRetriesAz; attempt++ {
		requestCtx, cancel := context.WithTimeout(ctx, blobRequestTimeout)
		if attempt > 0 {
			wait := retryBaseWaitAz * time.Duration(attempt)
			slog.Warn("retrying blob download",
				"attempt", attempt,
				"max", maxRetriesAz-1,
				"container", container,
				"blob", blobName,
				"wait", wait,
			)
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				cancel()
				return nil, 0, "", ctx.Err()
			}
		}

		resp, err := a.Client.DownloadStream(requestCtx, container, blobName, nil)
		if err != nil {
			cancel()
			lastErr = err
			if isNonRetryableAz(err) {
				return nil, 0, "", err
			}
			continue
		}

		wrappedBody := &readCloserWithCancel{
			ReadCloser: resp.Body,
			cancel:     cancel,
		}

		contentType := ""
		if resp.ContentType != nil {
			contentType = *resp.ContentType
		}

		size := int64(-1)
		if resp.ContentLength != nil {
			size = *resp.ContentLength
		}

		return wrappedBody, size, contentType, nil
	}

	return nil, 0, "", lastErr
}

func isNonRetryableAz(err error) bool {
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.StatusCode {
		case 400, 401, 403, 404, 409, 410:
			return true
		}
	}
	return false
}

func (a *AzureClient) GetObjectMetadata(ctx context.Context, container, blobName string) (map[string]string, error) {
	combined := make(map[string]string)

	blobClient := a.Client.ServiceClient().NewContainerClient(container).NewBlobClient(blobName)

	props, err := blobClient.GetProperties(ctx, nil)
	if err != nil {
		slog.Warn("failed to get blob properties",
			"container", container,
			"blob", blobName,
			"error", err,
		)
	} else {
		for k, v := range props.Metadata {
			if v != nil {
				combined[k] = *v
			}
		}
	}

	tags, err := blobClient.GetTags(ctx, nil)
	if err != nil {
		slog.Warn("failed to get blob tags",
			"container", container,
			"blob", blobName,
			"error", err,
		)
	} else {
		for _, t := range tags.BlobTagSet {
			if t.Key != nil && t.Value != nil {
				combined[*t.Key] = *t.Value
			}
		}
	}

	return combined, nil
}

func (r *readCloserWithCancel) Close() error {
	r.cancel()
	return r.ReadCloser.Close()
}
