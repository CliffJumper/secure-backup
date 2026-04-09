package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/CliffJumper/secure-backup/pkg/plugins"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type S3Provider struct {
	client *s3.Client
	bucket string
}

func (s *S3Provider) Init(cfg map[string]string) error {
	accessKey := cfg["access_key_id"]
	secretKey := cfg["secret_access_key"]
	bucketName := cfg["bucket"]
	region := cfg["region"]

	if bucketName == "" {
		return fmt.Errorf("bucket target is strictly required for the aws-s3 plugin")
	}

	opts := []func(*config.LoadOptions) error{}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}

	// Securely pass mapped keys avoiding direct ENV checks if we were provided them via credential plugins
	if accessKey != "" && secretKey != "" {
		opts = append(opts, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")))
	}

	awsCfg, err := config.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return fmt.Errorf("failed to load initial AWS configuration: %w", err)
	}

	s.client = s3.NewFromConfig(awsCfg)
	s.bucket = bucketName
	return nil
}

func (s *S3Provider) UploadFile(localPath, remotePath string) error {
	ctx := context.Background()
	var lastErr error

	for i := 0; i < 3; i++ {
		err := s.doUpload(ctx, localPath, remotePath)
		if err == nil {
			return nil
		}
		lastErr = err
		log.Printf("Upload failed, retrying (%d/3)... err: %v", i+1, err)
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("failed to upload after 3 retries: %w", lastErr)
}

func (s *S3Provider) doUpload(ctx context.Context, localPath, remotePath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open file for streaming: %w", err)
	}
	defer f.Close()

	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(remotePath),
		Body:   f,
	})
	return err
}

func (s *S3Provider) DownloadFile(remotePath, localPath string) error {
	ctx := context.Background()
	var lastErr error

	for i := 0; i < 3; i++ {
		err := s.doDownload(ctx, remotePath, localPath)
		if err == nil {
			return nil
		}
		lastErr = err
		log.Printf("Download failed, retrying (%d/3)... err: %v", i+1, err)
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("failed to download after 3 retries: %w", lastErr)
}

func (s *S3Provider) doDownload(ctx context.Context, remotePath, localPath string) error {
	resp, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(remotePath),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			// Common S3 codes for missing objects: NoSuchKey / NotFound.
			if apiErr.ErrorCode() == "NoSuchKey" || apiErr.ErrorCode() == "NotFound" {
				return status.Error(codes.NotFound, "object not found")
			}
		}
		return err
	}
	defer resp.Body.Close()

	f, err := os.OpenFile(localPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create local file replica: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("failed writing downloaded data to replica: %w", err)
	}
	return nil
}

func (s *S3Provider) ListFiles(prefix string) ([]string, error) {
	ctx := context.Background()
	var files []string

	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed paginating S3 objects list: %w", err)
		}
		for _, obj := range page.Contents {
			files = append(files, *obj.Key)
		}
	}
	return files, nil
}

func (s *S3Provider) DeleteFile(remotePath string) error {
	ctx := context.Background()
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(remotePath),
	})
	if err != nil {
		return fmt.Errorf("failed deleting remote key %s: %w", remotePath, err)
	}
	return nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: plugins.HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"provider": &plugins.ProviderGRPCPlugin{
				Impl: &S3Provider{},
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
