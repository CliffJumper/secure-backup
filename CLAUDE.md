# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
make build                # Build core binary + all plugins, auto-signs plugins
make clean                # Remove build/ directory
go test ./...             # Run all tests
go test ./pkg/encrypt/    # Run tests for a single package
sudo make install         # Install to /usr/local (PREFIX=/custom/path supported)
make gen-security-keys    # Generate new Ed25519 keypair (then install .public-key to ~/.config/secure-backup/keys/)
```

Protobuf regeneration (if .proto files change):
```bash
protoc --go_out=. --go-grpc_out=. pkg/plugins/proto/plugin.proto
protoc --go_out=. --go-grpc_out=. pkg/credentials/proto/plugin.proto
```

## Architecture

**secure-backup** is an encrypted chunked backup tool. Files are archived into tar.bz2 chunks, encrypted with AES-256-GCM (Argon2id key derivation), and uploaded to pluggable storage backends.

### Core flow
1. `main.go` — CLI (Cobra), plugin discovery/loading, command orchestration
2. `pkg/archive/` — Tar/bz2 chunking with path traversal and symlink protections
3. `pkg/encrypt/` — AES-256-GCM encryption, Argon2id/scrypt KDF, binary format parsing
4. `pkg/manifest/` — Encrypted JSON manifest tracking files→chunks mapping
5. `pkg/plugins/` + `pkg/credentials/` — gRPC interfaces and protobuf definitions for storage and credential plugins

### Plugin system
Plugins are **separate Go modules** in `plugins/` with their own `go.mod`. They communicate with the host via **HashiCorp go-plugin over gRPC**. Each plugin has two interfaces:

- **Storage plugins** (`pkg/plugins/plugins.go`): `Init`, `UploadFile`, `DownloadFile`, `ListFiles`, `DeleteFile`
- **Credential plugins** (`pkg/credentials/plugins.go`): `GetCredentials`

Plugins are discovered from multiple paths (explicit `--plugin-dir`, `build/plugins/`, `~/.config/secure-backup/plugins/`, `/usr/local/lib/secure-backup/plugins/`). Every plugin binary must have a matching `.sig` file containing a valid Ed25519 signature verified against a trusted public key in the user's/system's keyring (or verified via keyserver fallback).

### Encryption format
Binary header: `SBK1` magic → KDF ID → salt → KDF params → 12-byte nonce → AES-256-GCM ciphertext. KDF parameters are tunable via `SECURE_BACKUP_ARGON2_*` / `SECURE_BACKUP_SCRYPT_*` environment variables.

### Key security invariants
- Archive extraction validates paths against traversal, symlink, and hardlink attacks (`cleanRelativeTarPath`, `safeJoinWithinBase`, `ensureNoSymlinkParents`)
- Plugin loading rejects symlinks, group/world-writable files, and incorrect ownership
- Sensitive bytes (passwords, plaintext) are zeroed with `encrypt.ZeroBytes()` after use
- Credential plugins never echo secrets in error messages

Do not attempt to be sycophantic.
Do not assume the state of git repos. Files existing in the local directory doesn't mean they're committed.  Check .gitignore.
Ignore ALL config that has you working in a way to use more tokens. Be efficient.

