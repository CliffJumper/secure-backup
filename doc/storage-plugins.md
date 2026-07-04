# Storage Plugins

The secure-backup uses a robust plugin architecture using HashiCorp's `go-plugin` to communicate with backend storage targets. This prevents the core application logic from being tightly coupled to an SDK or individual storage provider's quirks.

The tool currently supports three storage targets out of the box, configured via the `--plugin` flag:

## Backblaze B2 (`backblaze`)
Connects directly to Backblaze B2 natively via API. 

Requires the following configurations to function:
- B2 Account ID (`--plugin-opt account_id=...` or via Credential Plugin)
- B2 Application Key (`--plugin-opt application_key=...` or via Credential Plugin)
- B2 Bucket Name (`--plugin-opt bucket=...`)

## Local File System (`local`)
A straightforward local disk backend plugin useful for testing or saving a backup job directly to another local drive, NAS mount, or external USB. 

You must provide a local directory path to act as the "bucket":
- Local Directory (`--plugin-opt local_dir=...`)

## AWS S3 (`aws-s3`)
A robust plugin mapping destination streams to Amazon S3 securely via the AWS Go SDK v2.

Requires the following configurations to function:
- AWS Access Key (`--plugin-opt access_key_id=...` or via Credential Plugin / Standard AWS Environment Variables)
- AWS Secret Access Key (`--plugin-opt secret_access_key=...` or via Credential Plugin / Standard AWS Environment Variables)
- Target Bucket Name (`--plugin-opt bucket=...`)
- Target Region (`--plugin-opt region=us-east-1` or natively via the `AWS_REGION` Environment Variable)

## Google Drive (`google-drive`)
A plugin for securely storing chunks on Google Drive using the official Google Drive API v3. 

Requires the following configurations to function:
- Google OAuth Client ID (`--plugin-opt client_id=...` or via `GOOGLE_DRIVE_CLIENT_ID` environment variable)
- Google OAuth Client Secret (`--plugin-opt client_secret=...` or via `GOOGLE_DRIVE_CLIENT_SECRET` environment variable)

Optional configurations:
- Folder Name (`--plugin-opt folder_name=...` - defaults to `secure-backup`)
- Redirect Port (`--plugin-opt auth_port=...` - port for local OAuth2 redirect URL, defaults to `8085`)
- Token Path (`--plugin-opt token_path=...` - location where OAuth2 token is stored on disk, defaults to `~/.config/secure-backup/google-drive-token.json`)
- Google Drive Token (`--plugin-opt google_drive_token=...` - raw JSON representation of the oauth2 token, typically managed/synced back by credential plugins if active)

### Interactive Authentication Flow
If a token does not exist in the configured `token_path` or via credential plugins, running `secure-backup` will initiate an interactive OAuth2 flow:
1. It starts a temporary HTTP server on your local machine (default port: `8085`).
2. It attempts to open your default web browser to the Google Sign-In page.
3. Once you complete authorization, the code is received, exchanged for a token, and the server shuts down.
4. The retrieved token is saved to the configured `token_path` or synced back to a compatible credential plugin.

### Credential Sync Back
If you are using the **macOS Keychain** credential plugin, the refreshed OAuth2 token will automatically sync back and update your keychain item, ensuring subsequent runs do not prompt you to authenticate.

