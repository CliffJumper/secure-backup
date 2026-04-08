package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/freew/secure-backup/pkg/encrypt"
	"github.com/freew/secure-backup/pkg/plugins"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type FileMeta struct {
	Size    int64  `json:"size"`
	ModTime int64  `json:"mod_time"`
	Mode    uint32 `json:"mode"`
	ChunkID string `json:"chunk_id"`
}

type Manifest struct {
	Files  map[string]FileMeta `json:"files"`
	Chunks []string            `json:"chunks"`
}

const RemoteManifestName = "manifest.enc"

func NewManifest() *Manifest {
	return &Manifest{
		Files:  make(map[string]FileMeta),
		Chunks: make([]string, 0),
	}
}

// DownloadAndDecrypt fetches the manifest from the provider and parses it.
// If it does not exist, it returns a new empty manifest.
func DownloadAndDecrypt(provider plugins.Provider, password []byte) (*Manifest, error) {
	tempFile, err := os.CreateTemp("", "manifest-*.enc")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tempPath := tempFile.Name()
	tempFile.Close()
	defer os.Remove(tempPath)

	err = provider.DownloadFile(RemoteManifestName, tempPath)
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return NewManifest(), nil
		}
		
		// Fallback for wrapped errors or string matching for missing files
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "not found") || strings.Contains(lower, "nosuchfile") || strings.Contains(lower, "no such file") || strings.Contains(lower, "404") || strings.Contains(lower, "not exist") {
			return NewManifest(), nil
		}
		
		return nil, fmt.Errorf("failed to download manifest: %w", err)
	}

	data, err := os.ReadFile(tempPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read downloaded manifest: %w", err)
	}

	plaintext, err := encrypt.DecryptData(data, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt manifest: %w", err)
	}
	defer encrypt.ZeroBytes(plaintext)

	var m Manifest
	if err := json.Unmarshal(plaintext, &m); err != nil {
		return nil, fmt.Errorf("failed to parse manifest json: %w", err)
	}

	if m.Files == nil {
		m.Files = make(map[string]FileMeta)
	}
	return &m, nil
}

// EncryptAndUpload encrypts the manifest struct and uploads it.
func EncryptAndUpload(provider plugins.Provider, password []byte, m *Manifest) error {
	plaintext, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	ciphertext, err := encrypt.EncryptData(plaintext, password)
	encrypt.ZeroBytes(plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt manifest: %w", err)
	}
	defer encrypt.ZeroBytes(ciphertext)

	tempFile, err := os.CreateTemp("", "manifest-out-*.enc")
	if err != nil {
		return fmt.Errorf("failed to create temp output file: %w", err)
	}
	tempPath := tempFile.Name()
	
	if err := os.WriteFile(tempPath, ciphertext, 0600); err != nil {
		tempFile.Close()
		return fmt.Errorf("failed to write encrypted manifest to temp: %w", err)
	}
	tempFile.Close()
	defer os.Remove(tempPath)

	err = provider.UploadFile(tempPath, filepath.ToSlash(RemoteManifestName))
	if err != nil {
		return fmt.Errorf("failed to upload manifest: %w", err)
	}

	return nil
}
