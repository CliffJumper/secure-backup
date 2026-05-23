# Plugin Signing and Validation

To prevent malicious code execution and plugin binary hijacking, `secure-backup` implements a robust security and validation layer. Any plugin (storage or credential) must pass strict path, permission, ownership, and cryptographic signature checks before the core application executes it.

This guide explains the validation process, how trusted public keys are managed, and how to sign custom plugins.

---

## 1. Directory and Permission Validation

Before verifying cryptographic signatures, `secure-backup` verifies the physical binary path and file system metadata of the plugin candidate. If any check fails, the plugin is skipped.

* **No Symbolic Links**:
  * Every parent directory component in the plugin's path must **not** be a symbolic link.
  * The plugin binary itself must **not** be a symbolic link.
  * *Reasoning: This prevents path traversal or symlink swap attacks that redirect execution to an untrusted location.*
* **Directory Permission Enforcement**:
  * None of the parent directories of the plugin binary can be group-writable or world-writable (using a mask of `0o022`).
  * *Reasoning: If a parent directory is writable by others, an attacker could rename the plugin directory or inject files.*
* **Binary Permission Enforcement**:
  * The plugin binary itself must **not** be group-writable or world-writable.
* **Ownership Verification**:
  * On Unix-like systems (macOS, Linux), the plugin binary must be owned by either the **current user** running `secure-backup` or the **root** user (`uid 0`).
  * *Reasoning: Ensures only administrators or the executing user can modify the executable code.*

---

## 2. Cryptographic Signature Verification

If the file system permissions are safe, `secure-backup` validates the cryptographic integrity of the plugin binary using **Ed25519** signatures.

### How it works
1. For a given plugin binary (e.g., `/usr/local/lib/secure-backup/plugins/storage-plugin-s3`), `secure-backup` looks for a companion signature file named with a `.sig` extension: `/usr/local/lib/secure-backup/plugins/storage-plugin-s3.sig`.
2. If the `.sig` file is missing, the plugin is rejected immediately.
3. The contents of the `.sig` file are treated as a raw Ed25519 signature.
4. `secure-backup` gathers all **Trusted Public Keys** (see Keyring Sources below) and attempts to verify the signature of the binary.
5. If verification succeeds against any of the trusted public keys, the plugin is approved and loaded.

---

## 3. Keyring Sources (Where Trusted Keys are Loaded)

Instead of relying on a single hardcoded key, `secure-backup` dynamically loads trusted public keys from several system and environment keyrings:

### A. Local Keyrings
* **Environment Variable**: `SECURE_BACKUP_KEYRING` (points to a directory containing base64-encoded or raw 32-byte public keys).
* **User-specific Directory**: `~/.config/secure-backup/keys/`
* **System-wide Directory**: `/etc/secure-backup/keys/`

Any files in these directories (excluding hidden files) are read and checked. They can either contain a base64-encoded public key or raw 32-byte public key bytes.

### B. SSH Agent
* If the `SSH_AUTH_SOCK` environment variable is present, `secure-backup` connects to the running SSH Agent, queries all active identities, and imports any keys of type `ssh-ed25519` as trusted signing keys.

### C. Local SSH Directory
* `~/.ssh/authorized_keys`: The tool parses this file and registers all `ssh-ed25519` keys as trusted.
* `~/.ssh/*.pub`: Any public key file ending in `.pub` in the user's `.ssh` directory is scanned for `ssh-ed25519` keys.

### D. GnuPG (GPG)
* If the `gpg` CLI tool is available, the tool runs `gpg --list-public-keys --with-colons` to extract public key fingerprints.
* For each fingerprint, it runs `gpg --export-ssh-key <fingerprint>` and loads any compatible `ssh-ed25519` keys.

### E. macOS Keychain
* On macOS, the tool queries the system Keychain for a generic password item with service name `secure-backup-plugin-key` by running:
  ```bash
  security find-generic-password -s secure-backup-plugin-key -g
  ```
  The password value of this item is expected to be a base64-encoded Ed25519 public key.

### F. Linux Secret Service
* On Linux, the tool queries the DBus Secret Service for a secret with the service label `secure-backup-plugin-key` by running:
  ```bash
  secret-tool lookup service secure-backup-plugin-key
  ```
  The value returned must be a base64-encoded Ed25519 public key.

---

## 4. Keyserver Verification Fallback

If the signature cannot be validated by any key loaded from the keyring sources, `secure-backup` checks for a fallback keyserver authorization:

1. The tool looks for a companion public key file next to the plugin (e.g., `storage-plugin-s3.pub`).
2. If found, it reads the base64-encoded public key and verifies that it signed the binary (via `<plugin>.sig`).
3. If the signature is cryptographically valid, the tool computes a fingerprint by hashing the public key: `hex(sha256(publicKey))`.
4. It then queries the keyserver URL (derived from the `SECURE_BACKUP_KEYSERVER` environment variable, defaulting to `https://keys.secure-backup.org`) at:
   ```
   GET <keyserver-url>/<hex-fingerprint>
   ```
5. If the keyserver returns an HTTP `200 OK` status and the response body contains the exact same base64-encoded public key, the key is trusted, and the plugin validation succeeds.
6. If the keyserver does not verify the key, loading fails with a warning:
   `WARNING: Plugin <path> verified by key <key>, but key is NOT trusted by keyserver: <error>`

---

## 5. Key Generation and Plugin Signing Guide

### Generating a Keypair
To generate an Ed25519 keypair for your own plugins, run:
```bash
make gen-security-keys
```
This runs the security tool helper, generating:
* `.security-key`: Contains the base64-encoded private key (keep this secret, do not commit).
* `.public-key`: Contains the base64-encoded public key.

To register this public key as trusted on your system, copy `.public-key` (or place its base64 string in a file) to the local keyring directory:
```bash
mkdir -p ~/.config/secure-backup/keys/
cp .public-key ~/.config/secure-backup/keys/developer-key.pub
```

### Signing a Plugin Binary
#### Automatic Signing
If you build plugins using the root `Makefile` via `make build`, it automatically looks for a `.security-key` file in the project root. If found, it automatically signs all compiled plugins in `build/plugins/`.

#### Manual Signing
If you compile a plugin manually, you can sign it using the security tool utility:
```bash
go run scripts/security-tool/main.go -sign build/plugins/storage-plugin-mycustom -key path/to/private-key-file
```
This will output `build/plugins/storage-plugin-mycustom.sig`. Distribute both the binary and the `.sig` file together.
