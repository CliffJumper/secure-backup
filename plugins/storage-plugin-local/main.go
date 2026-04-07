package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/freew/secure-backup/pkg/plugins"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type LocalProvider struct {
	baseDir string
}

func (l *LocalProvider) Init(config map[string]string) error {
	dir := config["local_dir"]
	if dir == "" {
		return fmt.Errorf("local_dir is required for local plugin")
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("invalid local_dir %q: %v", dir, err)
	}

	// Ensure the base directory exists
	if err := os.MkdirAll(absDir, 0755); err != nil {
		return fmt.Errorf("failed to create local_dir %q: %v", absDir, err)
	}

	l.baseDir = absDir
	return nil
}

func (l *LocalProvider) getAbsPath(remotePath string) (string, error) {
	// Prevents path traversal out of baseDir
	cleaned := filepath.Clean(remotePath)
	if filepath.IsAbs(cleaned) {
		cleaned = cleaned[1:]
	}
	joined := filepath.Join(l.baseDir, cleaned)
	abs, err := filepath.Abs(joined)
	if err != nil {
		return "", fmt.Errorf("failed to resolve path %q: %w", remotePath, err)
	}
	if !strings.HasPrefix(abs, l.baseDir+string(filepath.Separator)) && abs != l.baseDir {
		return "", fmt.Errorf("path %q resolves to %q which is outside base directory", remotePath, abs)
	}
	return abs, nil
}

func (l *LocalProvider) UploadFile(localPath, remotePath string) error {
	destPath, err := l.getAbsPath(remotePath)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create directories for %s: %w", destPath, err)
	}

	src, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer src.Close()

	dst, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("failed to copy data: %w", err)
	}

	return nil
}

func (l *LocalProvider) DownloadFile(remotePath, localPath string) error {
	srcPath, err := l.getAbsPath(remotePath)
	if err != nil {
		return err
	}

	src, err := os.Open(srcPath)
	if err != nil {
		if os.IsNotExist(err) {
			return status.Error(codes.NotFound, "object not found")
		}
		return fmt.Errorf("failed to open source directory/file: %w", err)
	}
	defer src.Close()

	dst, err := os.OpenFile(localPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("failed to download data: %w", err)
	}

	return nil
}

func (l *LocalProvider) ListFiles(prefix string) ([]string, error) {
	var files []string
	
	err := filepath.Walk(l.baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		
		relPath, err := filepath.Rel(l.baseDir, path)
		if err != nil {
			return err
		}
		
		// To match B2 semantics, paths might need to be forward slash separated
		relPath = filepath.ToSlash(relPath)
		
		if strings.HasPrefix(relPath, prefix) {
			files = append(files, relPath)
		}
		return nil
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to walk local directory: %w", err)
	}
	
	return files, nil
}

func (l *LocalProvider) DeleteFile(remotePath string) error {
	targetPath, err := l.getAbsPath(remotePath)
	if err != nil {
		return err
	}
	
	if err := os.Remove(targetPath); err != nil {
		if os.IsNotExist(err) {
			return nil // Idempotent delete
		}
		return fmt.Errorf("failed to delete file: %w", err)
	}
	return nil
}

func main() {
	localProvider := &LocalProvider{}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: plugins.HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"provider": &plugins.ProviderGRPCPlugin{Impl: localProvider},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
