# Plugin Development Guide

`secure-backup` abstracts both its backend storage destinations and credential resolution mechanisms using HashiCorp's robust [go-plugin](https://github.com/hashicorp/go-plugin) framework. The core application runs these plugins seamlessly as independent, fully isolated gRPC sub-processes.

This means you can write and distribute third-party plugins in **any** language conforming to the protobuf specifications, though writing them natively in Go by pulling in our shared `pkg/` interfaces is by far the simplest path.

## Plugin Domains
1. **[Storage Plugins](storage-plugins.md)**: Implement the destination layer determining exactly where and how archived chunks get stored (e.g. S3, WebDAV, local disk).
2. **[Credential Plugins](credential-plugins.md)**: Implement dynamic, secure fetching of API Keys/Secrets into the runner environment (e.g. 1Password, MacOS Keychain, AWS Secrets Manager).

---

## 1. Writing Your Code (Go Example)

You will be writing an independent deployable Go binary using a `main` execution package.

### Storage Plugin Example
If you are writing a custom backend storage target, you must fully implement the `Provider` interface found in `github.com/freew/secure-backup/pkg/plugins`.

```go
package main

import (
	"github.com/hashicorp/go-plugin"
	"github.com/freew/secure-backup/pkg/plugins"
)

type MyCustomStorage struct{}

func (s *MyCustomStorage) Init(config map[string]string) error {
    // Basic flags like `--bucket` and `--account-id` are passed here implicitly
    
    // You can also access ANY arbitrary `--plugin-opt` passed by the user!
    // e.g. If the user ran: `--plugin-opt region=eu-west-1`
    region := config["region"] 
    _ = region
    
    return nil
}
func (s *MyCustomStorage) UploadFile(localPath, remotePath string) error { return nil }
func (s *MyCustomStorage) DownloadFile(remotePath, localPath string) error { return nil }
func (s *MyCustomStorage) DeleteFile(remotePath string) error { return nil }

func main() {
    // Serve the plugin over gRPC using the core Handshake configuration
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: plugins.HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"provider": &plugins.ProviderGRPCPlugin{
				Impl: &MyCustomStorage{},
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
```

### Credential Plugin Example
If you are writing a custom credential resolver, construct it utilizing the `Provider` from `github.com/freew/secure-backup/pkg/credentials`.

```go
package main

import (
	"github.com/hashicorp/go-plugin"
	"github.com/freew/secure-backup/pkg/credentials"
)

type MyVault struct{}

func (k *MyVault) GetCredentials(target string) (map[string]string, error) {
    // Resolve external tokens and return standardized mappings
	return map[string]string{
		"keyID": "fetched-account-id",
		"applicationKey": "fetched-application-key",
	}, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: credentials.HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"provider": &credentials.ProviderGRPCPlugin{
				Impl: &MyVault{},
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
```

---

## 2. Naming the Output Binary

The tool heavily relies on **convention over configuration** for discovering sub-processes automatically without a central registry. When compiling your binary, it **must** be arbitrarily prefixed:

- **Storage**: `storage-plugin-[name]` (e.g., `storage-plugin-s3`)
- **Credentials**: `credential-plugin-[name]` (e.g., `credential-plugin-1password`)

```bash
go build -o storage-plugin-s3 main.go
```

---

## 3. Installing Your Plugin

Because `secure-backup` universally resolves plugins using a dynamic fallback hierarchy, you do not need to modify any code or inject references within the core application repository! You simply copy your built executable into one of the recognized discovery directories:

1. **System-Wide** (Recommended for officially packaged deployments): `/usr/local/lib/secure-backup/plugins/` *(or `$PREFIX/lib/...`)*
2. **User-Specific**: `~/.config/secure-backup/plugins/` (Linux) or `~/Library/Application Support/secure-backup/plugins/` (macOS)
3. **Isolated/Portable**: `./plugins/` situated next to the executing `secure-backup` binary, or relative to your current working directory.

```bash
# System-wide Deployment Example:
sudo cp storage-plugin-s3 /usr/local/lib/secure-backup/plugins/
sudo chmod +x /usr/local/lib/secure-backup/plugins/storage-plugin-s3
```

---

## 4. Usage

After placing your plugin in the filesystem, merely supply your unique suffix to the standard toolchain:

```bash
# Uses the custom S3 storage backend!
secure-backup backup ... --plugin s3

# Optionally, pass parameters directly and exclusively into your plugin's Init config map!
secure-backup backup ... --plugin s3 --plugin-opt enable_accelerator=true --plugin-opt region=eu-west-1
```

---

## 5. Security & Signing

For security reasons, `secure-backup` will **refuse** to execute any plugin that is not cryptographically signed by a trusted key.

### How it works:
1. When `secure-backup` searches for a plugin (e.g., `storage-plugin-s3`), it also looks for a companion file named `storage-plugin-s3.sig`.
2. This `.sig` file must contain an **Ed25519 signature** of the binary, generated using the private key corresponding to the public key embedded in the `secure-backup` core binary.

### Signing your plugin:
If you are developing a new plugin, you must sign the binary before `secure-backup` will accept it:

```bash
# Using the built-in security tool and your private key
go run scripts/security-tool/main.go -sign storage-plugin-my-custom -key <YOUR_PRIVATE_KEY_B64>
```

If you are using the provided `Makefile`, all plugins in the `plugins/` directory are automatically signed during the `make build` process if a `.security-key` file is present in the project root.
