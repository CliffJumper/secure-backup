package archive

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/dsnet/compress/bzip2"
	"github.com/freew/secure-backup/pkg/manifest"
	"github.com/google/uuid"
)

const defaultChunkLimit = 100 * 1024 * 1024 // 100MB

func cleanRelativeTarPath(p string) (string, error) {
	// Tar headers are defined with forward slashes regardless of platform.
	// Normalize to an OS path for cleaning, then convert back.
	if strings.TrimSpace(p) == "" {
		return "", fmt.Errorf("empty path")
	}

	pp := filepath.FromSlash(p)
	pp = filepath.Clean(pp)

	// Reject absolute and volume paths.
	if filepath.IsAbs(pp) {
		return "", fmt.Errorf("absolute paths are not allowed: %q", p)
	}
	if v := filepath.VolumeName(pp); v != "" {
		return "", fmt.Errorf("volume paths are not allowed: %q", p)
	}

	// Reject traversal.
	if pp == ".." || strings.HasPrefix(pp, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path traversal is not allowed: %q", p)
	}

	if pp == "." {
		return "", fmt.Errorf("invalid path: %q", p)
	}

	return filepath.ToSlash(pp), nil
}

func safeJoinWithinBase(baseDir, rel string) (string, error) {
	relClean, err := cleanRelativeTarPath(rel)
	if err != nil {
		return "", err
	}

	joined := filepath.Join(baseDir, filepath.FromSlash(relClean))
	abs, err := filepath.Abs(joined)
	if err != nil {
		return "", fmt.Errorf("failed to resolve path %q: %w", rel, err)
	}

	baseAbs, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve base dir: %w", err)
	}

	// Verify containment using Rel as prefix-checking is susceptible to collisions
	// e.g., /tmp/restore vs /tmp/restore-secret
	relToRoot, err := filepath.Rel(baseAbs, abs)
	if err != nil {
		return "", fmt.Errorf("failed to compute relative path: %w", err)
	}

	if strings.HasPrefix(relToRoot, ".."+string(filepath.Separator)) || relToRoot == ".." {
		return "", fmt.Errorf("path %q resolves outside restore directory", rel)
	}

	return abs, nil
}

func ensureNoSymlinkParents(baseAbs, targetAbs string) error {
	rel, err := filepath.Rel(baseAbs, targetAbs)
	if err != nil {
		return fmt.Errorf("failed to compute relative path: %w", err)
	}

	// Walk each parent directory segment and reject symlinks.
	cur := baseAbs
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)

		fi, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				// Parent doesn't exist yet; future mkdir will create it.
				return nil
			}
			return fmt.Errorf("failed to lstat %q: %w", cur, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write through symlinked path component %q", cur)
		}
	}
	return nil
}

type Archiver struct {
	chunkDir    string
	chunkLimit  int64
	currentUUID string
	currentSize int64

	f   *os.File
	bzw *bzip2.Writer
	tw  *tar.Writer

	Chunks []string
	Files  map[string]manifest.FileMeta
}

// NewArchiver creates an archiver that drops temporary chunks in a random tmp dir.
func NewArchiver() (*Archiver, error) {
	dir, err := os.MkdirTemp("", "backup-chunks-*")
	if err != nil {
		return nil, err
	}
	return &Archiver{
		chunkDir:   dir,
		chunkLimit: defaultChunkLimit,
		Chunks:     make([]string, 0),
		Files:      make(map[string]manifest.FileMeta),
	}, nil
}

func (a *Archiver) rollChunk() error {
	if a.tw != nil {
		if err := a.tw.Close(); err != nil {
			return err
		}
		if err := a.bzw.Close(); err != nil {
			return err
		}
		if err := a.f.Close(); err != nil {
			return err
		}
	}

	uid := uuid.New().String()
	chunkPath := filepath.Join(a.chunkDir, uid+".tar.bz2")
	f, err := os.Create(chunkPath)
	if err != nil {
		return err
	}

	bzw, err := bzip2.NewWriter(f, &bzip2.WriterConfig{Level: bzip2.DefaultCompression})
	if err != nil {
		f.Close()
		return err
	}

	tw := tar.NewWriter(bzw)

	a.currentUUID = uid
	a.currentSize = 0
	a.f = f
	a.bzw = bzw
	a.tw = tw

	a.Chunks = append(a.Chunks, uid)
	return nil
}

// Add walks a target path and adds files to chunks.
func (a *Archiver) Add(target string) error {
	return filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		name := filepath.ToSlash(path)

		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			return err
		}
		header.Name = name

		if info.Mode().IsRegular() {
			if a.tw == nil || a.currentSize >= a.chunkLimit {
				if err := a.rollChunk(); err != nil {
					return err
				}
			}

			if err := a.tw.WriteHeader(header); err != nil {
				return err
			}

			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()

			written, err := io.Copy(a.tw, f)
			if err != nil {
				return err
			}
			a.currentSize += written

			// Track in manifest Files
			a.Files[name] = manifest.FileMeta{
				Size:    info.Size(),
				ModTime: info.ModTime().Unix(),
				Mode:    uint32(info.Mode()),
				ChunkID: a.currentUUID,
			}
		} else if info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			if a.tw == nil {
				if err := a.rollChunk(); err != nil {
					return err
				}
			}

			// Add symlink support if needed, `tar.FileInfoHeader` handles it
			if info.Mode()&os.ModeSymlink != 0 {
				link, err := os.Readlink(path)
				if err == nil {
					header.Linkname = link
				}
			}

			if err := a.tw.WriteHeader(header); err != nil {
				return err
			}

			// Track in manifest Files
			a.Files[name] = manifest.FileMeta{
				Size:    0,
				ModTime: info.ModTime().Unix(),
				Mode:    uint32(info.Mode()),
				ChunkID: a.currentUUID,
			}
		}

		return nil
	})
}

// AddFile adds a single file (by path and its FileInfo) to the archive.
// Unlike Add, it does not walk directories recursively.
func (a *Archiver) AddFile(path string, info os.FileInfo) error {
	name := filepath.ToSlash(path)

	header, err := tar.FileInfoHeader(info, info.Name())
	if err != nil {
		return err
	}
	header.Name = name

	if info.Mode().IsRegular() {
		if a.tw == nil || a.currentSize >= a.chunkLimit {
			if err := a.rollChunk(); err != nil {
				return err
			}
		}

		if err := a.tw.WriteHeader(header); err != nil {
			return err
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		written, err := io.Copy(a.tw, f)
		if err != nil {
			return err
		}
		a.currentSize += written

		a.Files[name] = manifest.FileMeta{
			Size:    info.Size(),
			ModTime: info.ModTime().Unix(),
			Mode:    uint32(info.Mode()),
			ChunkID: a.currentUUID,
		}
	} else if info.Mode()&os.ModeSymlink != 0 {
		if a.tw == nil {
			if err := a.rollChunk(); err != nil {
				return err
			}
		}

		link, err := os.Readlink(path)
		if err == nil {
			header.Linkname = link
		}

		if err := a.tw.WriteHeader(header); err != nil {
			return err
		}

		a.Files[name] = manifest.FileMeta{
			Size:    0,
			ModTime: info.ModTime().Unix(),
			Mode:    uint32(info.Mode()),
			ChunkID: a.currentUUID,
		}
	}

	return nil
}

// Finalize gracefully closes the last chunk. Returns chunk temp dir path.
func (a *Archiver) Finalize() (string, error) {
	if a.tw != nil {
		if err := a.tw.Close(); err != nil {
			return "", err
		}
		if err := a.bzw.Close(); err != nil {
			return "", err
		}
		if err := a.f.Close(); err != nil {
			return "", err
		}
		a.tw = nil
	}
	return a.chunkDir, nil
}

// Extract unpacks specific files from a bzip2 tar chunk to a destination directory.
func Extract(chunkData []byte, filesToExtract map[string]bool, destDir string, stripPrefix string) error {
	bzw, err := bzip2.NewReader(bytes.NewReader(chunkData), nil)
	if err != nil {
		return err
	}
	defer bzw.Close()

	tr := tar.NewReader(bzw)
	destAbs, err := filepath.Abs(destDir)
	if err != nil {
		return fmt.Errorf("failed to resolve destination dir: %w", err)
	}

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Check if we need to extract this file
		if len(filesToExtract) > 0 && !filesToExtract[header.Name] {
			continue
		}

		name := header.Name
		if stripPrefix != "" {
			// Normalize both the file path and the strip prefix to be purely relative 
			// and identically cleaned so we never fail due to leading/trailing slash mismatches.
			sn := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(name)), "/")
			ss := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(stripPrefix)), "/")

			// Avoid generating phantom directories if the directory metadata itself matches the strip target
			if sn == ss || strings.HasSuffix(sn, "/"+ss) {
				if header.Typeflag == tar.TypeDir {
					continue
				}
			}

			ssDir := ss
			if ssDir != "" && !strings.HasSuffix(ssDir, "/") {
				ssDir += "/"
			}

			if strings.HasPrefix(sn, ssDir) {
				name = sn[len(ssDir):]
			} else if strings.HasPrefix(sn, ss) {
				name = sn[len(ss):]
			}

			name = strings.TrimPrefix(name, "/")

			if name == "" && header.Typeflag != tar.TypeDir {
				continue // skip file if they stripped the entire name to avoid OS create errors
			}
		}

		relName, err := cleanRelativeTarPath(name)
		if err != nil {
			return fmt.Errorf("invalid tar entry name %q: %w", header.Name, err)
		}

		target, err := safeJoinWithinBase(destAbs, relName)
		if err != nil {
			return fmt.Errorf("unsafe tar path %q: %w", header.Name, err)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			// Ensure none of the existing parents are symlinks.
			if err := ensureNoSymlinkParents(destAbs, filepath.Dir(target)); err != nil {
				return err
			}
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			parent := filepath.Dir(target)
			if err := ensureNoSymlinkParents(destAbs, parent); err != nil {
				return err
			}
			if err := os.MkdirAll(parent, 0755); err != nil {
				return err
			}
			// Refuse to overwrite an existing symlink.
			if fi, err := os.Lstat(target); err == nil && (fi.Mode()&os.ModeSymlink != 0) {
				return fmt.Errorf("refusing to overwrite symlink %q", target)
			}
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
			// Apply only permission bits; avoid restoring setuid/setgid/sticky from archives.
			_ = os.Chmod(target, os.FileMode(header.Mode)&0o777)
		case tar.TypeSymlink:
			// Allow only relative symlinks that, when resolved from their directory,
			// still point within the restore directory. This blocks the common tar-symlink attacks.
			if strings.TrimSpace(header.Linkname) == "" {
				return fmt.Errorf("invalid symlink %q with empty linkname", header.Name)
			}
			if filepath.IsAbs(header.Linkname) || filepath.VolumeName(header.Linkname) != "" {
				return fmt.Errorf("refusing absolute symlink %q -> %q", header.Name, header.Linkname)
			}
			if _, err := cleanRelativeTarPath(header.Linkname); err != nil {
				return fmt.Errorf("refusing unsafe symlink %q -> %q: %w", header.Name, header.Linkname, err)
			}

			parent := filepath.Dir(target)
			if err := ensureNoSymlinkParents(destAbs, parent); err != nil {
				return err
			}
			if err := os.MkdirAll(parent, 0755); err != nil {
				return err
			}
			// Validate resolved destination remains within base.
			resolved, err := filepath.Abs(filepath.Join(parent, header.Linkname))
			if err != nil {
				return fmt.Errorf("failed resolving symlink target %q: %w", header.Linkname, err)
			}
			if !strings.HasPrefix(resolved, destAbs+string(filepath.Separator)) {
				return fmt.Errorf("refusing symlink that points outside restore directory: %q -> %q", header.Name, header.Linkname)
			}

			_ = os.Remove(target) // ignore error
			if err := os.Symlink(header.Linkname, target); err != nil {
				return err
			}
		case tar.TypeLink:
			// Hardlinks can be abused similarly to escape directories; skip for safety.
			continue
		}
	}
	return nil
}
