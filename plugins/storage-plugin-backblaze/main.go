package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Backblaze/blazer/b2"
	"github.com/freew/secure-backup/pkg/plugins"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type BackblazeProvider struct {
	client *b2.Client
	bucket *b2.Bucket
}

func (b *BackblazeProvider) Init(config map[string]string) error {
	accountID := config["account_id"]
	applicationKey := config["application_key"]
	bucketName := config["bucket"]

	if accountID == "" || applicationKey == "" || bucketName == "" {
		return fmt.Errorf("account_id, application_key, and bucket are required for backblaze plugin")
	}

	ctx := context.Background()
	client, err := b2.NewClient(ctx, accountID, applicationKey)
	if err != nil {
		return fmt.Errorf("failed to create B2 client: %w", err)
	}

	bucket, err := client.Bucket(ctx, bucketName)
	if err != nil {
		return fmt.Errorf("failed to find B2 bucket: %w", err)
	}

	b.client = client
	b.bucket = bucket
	return nil
}

func (b *BackblazeProvider) UploadFile(localPath, remotePath string) error {
	ctx := context.Background()
	var lastErr error

	// Retry loop
	for i := 0; i < 3; i++ {
		err := b.doUpload(ctx, localPath, remotePath)
		if err == nil {
			return nil
		}
		lastErr = err
		log.Printf("Upload failed, retrying (%d/3)... err: %v", i+1, err)
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("failed to upload after 3 retries: %w", lastErr)
}

func (b *BackblazeProvider) doUpload(ctx context.Context, localPath, remotePath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	obj := b.bucket.Object(remotePath)
	w := obj.NewWriter(ctx)
	if _, err := io.Copy(w, f); err != nil {
		w.Close()
		return fmt.Errorf("failed to upload data: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close writer: %w", err)
	}
	return nil
}

func (b *BackblazeProvider) DownloadFile(remotePath, localPath string) error {
	ctx := context.Background()
	var lastErr error

	// Retry loop
	for i := 0; i < 3; i++ {
		err := b.doDownload(ctx, remotePath, localPath)
		if err == nil {
			return nil
		}
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return err
		}
		lastErr = err
		log.Printf("Download failed, retrying (%d/3)... err: %v", i+1, err)
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("failed to download after 3 retries: %w", lastErr)
}

func (b *BackblazeProvider) doDownload(ctx context.Context, remotePath, localPath string) error {
	obj := b.bucket.Object(remotePath)
	r := obj.NewReader(ctx)
	defer r.Close()

	f, err := os.OpenFile(localPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, r); err != nil {
		// Blazer's reader construction doesn't return an error, so map common "missing" conditions here.
		// If it looks missing, return a gRPC NotFound so the host can distinguish it from network errors.
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "not found") || strings.Contains(lower, "nosuchfile") || strings.Contains(lower, "no such file") || strings.Contains(lower, "404") || strings.Contains(lower, "not exist") {
			return status.Error(codes.NotFound, "object not found")
		}
		return fmt.Errorf("failed to download data: %w", err)
	}

	return nil
}

func (b *BackblazeProvider) ListFiles(prefix string) ([]string, error) {
	ctx := context.Background()
	var files []string
	iter := b.bucket.List(ctx, b2.ListPrefix(prefix))
	for iter.Next() {
		files = append(files, iter.Object().Name())
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to list files: %w", err)
	}
	return files, nil
}

func (b *BackblazeProvider) DeleteFile(remotePath string) error {
	ctx := context.Background()
	obj := b.bucket.Object(remotePath)
	if err := obj.Delete(ctx); err != nil {
		return fmt.Errorf("failed to delete %s: %w", remotePath, err)
	}
	return nil
}

func main() {
	b2Provider := &BackblazeProvider{}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: plugins.HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"provider": &plugins.ProviderGRPCPlugin{Impl: b2Provider},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
