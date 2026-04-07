# secure-backup

A command-line tool that securely backs up files and directories using [Backblaze B2](https://www.backblaze.com/cloud-storage), local storage, or other, third-party plugins. Files are archived into chunked `tar.bz2` blocks and protected with AES-256-GCM encryption.

## Features

- **AES-256-GCM encryption** — storage chunks are encrypted before upload using a password-derived key (PBKDF2, 100,000 iterations, SHA-256)
- **Chunked tar.bz2 archiving** — reduce storage overhead and API costs by bundling source files into compressed `.tar.bz2` chunks before encryption
- **Backblaze B2 storage** — files are uploaded to any B2 bucket you specify
- **Filelist support** — define a list of files and directories to back up or delete in a plain-text file
- **Remote prefix namespacing** — organise backups within a bucket using a prefix
- **Full or partial restore** — restore individual files or the entire bucket
- **Secure password input** — prompts interactively with no terminal echo if no password env var is set
- **Environment variable credentials** — keep secrets out of shell history

## Building and Installing

Requires [Go](https://go.dev/) 1.25+ and `make`.

```bash
git clone <repo-url>
cd secure-backup

# Compile the core application and all plugins
make build

# Install globally to /usr/local/bin and /usr/local/lib/secure-backup/plugins
sudo make install
```

If you prefer to install to a different directory layout, you can easily override the `$PREFIX` variable:
```bash
sudo make install PREFIX=/opt/custom
```

To entirely remove the installation from your system, run:
```bash
sudo make uninstall
```

## Quick Start

```bash
export BACKUP_PASSWORD="your-encryption-password"

# Back up a file and a directory using the Backblaze B2 plugin
./secure-backup backup file.txt /home/user/documents \
  --plugin-opt account_id="your-account-id" \
  --plugin-opt application_key="your-application-key" \
  --plugin-opt bucket="your-bucket-name"
```

**OR** 
Setup your credentials via [Credential Plugins](doc/credential-plugins.md) to avoid passing keys via CLI flags:

```bash
# Restore a specific file using the credential plugin instead
./secure-backup restore home/user/documents/report.pdf.enc \
  --cred-plugin bitwarden --cred-item "Backblaze Backup Server"
```

## Commands

### `backup`

```
secure-backup backup [file1] [dir1] ... [flags]
```

Walks every file and directory provided, packages them into `tar.bz2` chunks, encrypts each chunk, and uploads it via the configured destination plugin. Directories are walked recursively. The backup state and original file structure are tracked in an encrypted remote manifest.

| Flag | Short | Default | Description |
|---|---|---|---|
| `--filelist` | | | Path to a filelist file listing files/directories to back up |
| `--prefix` | `-x` | | Prefix prepended to the remote path in B2 |
| `--compress` | `-c` | `false` | Enable/Disable chunk compression (currently archives as `tar.bz2`) |

### `restore`

```
secure-backup restore [remoteFile1] ... [flags]
```

Downloads, decrypts, and optionally decompresses files from B2 back to the local filesystem.

| Flag | Short | Default | Description |
|---|---|---|---|
| `--prefix` | `-x` | | Prefix stripped from the remote path when writing locally |
| `--all` | `-a` | `false` | Restore every file in the bucket (prompts for confirmation) |

### `delete`

```
secure-backup delete [remoteFile1] ... [flags]
```

Permanently deletes objects from B2. By default the tool lists every object that will be affected and prompts for confirmation before proceeding.

Multiple sources can be combined — for example, `--prefix` and positional arguments together.

| Flag | Short | Default | Description |
|---|---|---|---|
| `--all` | `-a` | `false` | Delete every object in the bucket |
| `--prefix` | `-x` | | Delete all objects whose remote path starts with this prefix |
| `--filelist` | | | Path to a filelist file listing remote object paths to delete |
| `--force` | `-f` | `false` | Skip the confirmation prompt |

**Examples:**

```bash
# Delete a single object
secure-backup delete backups/home/user/documents/report.pdf.enc

# Delete all objects under a prefix (shows list, asks for confirmation)
secure-backup delete --prefix backups/home/user/old-project

# Empty the entire bucket (requires typing "yes")
secure-backup delete --all

# Delete from a filelist, skip confirmation
secure-backup delete --filelist to-remove.txt --force
```

**Filelist format for delete** — each non-comment line is an exact remote object path:

```
# Old project backups
backups/home/user/old-project/main.go.enc
backups/home/user/old-project/go.mod.enc
```

## Global Flags

These flags apply to both `backup` and `restore`.

| Flag | Short | Environment Variable | Description |
|---|---|---|---|
| `--plugin` | | | Storage plugin to use (default: `backblaze`) |
| `--plugin-opt` | `-O` | | Plugin specific configurations (e.g. `account_id=...,bucket=...`) |
| `--password` | `-p` | `BACKUP_PASSWORD` | Encryption password |
| `--cred-plugin` | | | Credential plugin to use (e.g., bitwarden, keychain) |
| `--cred-item` | | | Target item name or ID to dynamically pull API keys |
| `--verbose` | `-v` | | Enable verbose plugin logging |

If `--password` / `BACKUP_PASSWORD` is not provided, the tool will prompt for it interactively with terminal echo suppressed.

**Note**: See [Credential Plugins](doc/credential-plugins.md) and [Storage Plugins](doc/storage-plugins.md) for more documentation on how to securely pass API keys into the application via Bitwarden or Keychain, as well as the available backup destinations.

Interested in writing a custom integration? Check out the [Plugin Development Guide](doc/Plugin-Development.md) to learn how to interface, compile, and distribute third-party plugins in any language.

## Filelist File

A filelist is a plain-text file where each line is a path (file or directory) to take action on. Lines beginning with `#` and blank lines are ignored.

```
# Config files
/etc/nginx/nginx.conf
/etc/ssh/sshd_config

# Home directory data
/home/user/documents
/home/user/projects
```

Pass it to the backup command:

```bash
./secure-backup backup --filelist filelist.txt
```

Filelist targets are merged with any positional arguments, so both can be used together.

## Encryption Details

Encrypted chunks have a `.enc` extension, and typically follow the naming convention `data-<chunk-id>.enc`.

## Security & Integrity

`secure-backup` implements several layers of security to protect your data and the execution environment:

### 1. Encryption
All data is encrypted with **AES-256-GCM**. The 256-bit key is derived from your password using **Argon2id** (default) or **scrypt**. These are memory-hard functions designed to resist GPU/ASIC-based cracking attempts.

### 2. Plugin Signing
To prevent malicious code injection via hijacked plugin binaries, `secure-backup` requires all plugins to be cryptographically signed using **Ed25519**.
- **Embedded Public Key**: A trusted public key is embedded in the `secure-backup` binary at compile time.
- **Signature Verification**: Every time a plugin is loaded, the tool verifies that a corresponding `<plugin>.sig` file exists and contains a valid signature for the binary.
- **Rejection**: If a signature is missing or invalid, the plugin is rejected, and the operation fails.

### 3. Path & Symlink Protection
The restore process includes strict validation to prevent directory traversal attacks and symlink-based file overwrites.

## Build Requirements

Requires [Go](https://go.dev/) 1.25+ and `make`.

### Initial Setup (Security Keys)
Before building for the first time, you must generate your own security keypair for plugin signing:

```bash
# Generate .security-key (private) and .public-key (public)
make gen-security-keys

# IMPORTANT: Update the 'trustedPublicKeyB64' constant in main.go 
# with the output from .public-key before compiling!
```

### Compiling
```bash
# Compile core application and all plugins (automatically signs them)
make build
```

### Installation
```bash
# Install globally
sudo make install
```

## Scheduling

The tool has no built-in scheduler. Run it on a schedule using standard system tools:

**cron example** (daily backup at 2 AM):
```cron
0 2 * * * BACKUP_PASSWORD=... /usr/local/bin/secure-backup backup --filelist /etc/backup/filelist.txt --prefix daily --plugin-opt account_id=... --plugin-opt application_key=... --plugin-opt bucket=...
```

**systemd timer**: create a `.service` and `.timer` unit pair pointing to the binary.

## Running Tests

```bash
go test ./...
```

## Dependencies

| Package | Purpose |
|---|---|
| `github.com/Backblaze/blazer` | Backblaze B2 Go SDK |
| `github.com/spf13/cobra` | CLI framework |
| `golang.org/x/crypto` | Argon2id / scrypt key derivation |
| `golang.org/x/term` | Secure interactive password prompt |
