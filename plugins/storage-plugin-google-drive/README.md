# Google Drive Storage Plugin

Provides backup destination support for Google Drive using the official Google Drive API v3.

## Options
Because `secure-backup` abstracts plugins, you must configure this plugin dynamically through the core interface using the `--plugin-opt` flag.

- `client_id` (required, or via `GOOGLE_DRIVE_CLIENT_ID` environment variable): Your Google OAuth2 Client ID.
- `client_secret` (required, or via `GOOGLE_DRIVE_CLIENT_SECRET` environment variable): Your Google OAuth2 Client Secret.
- `folder_name` (optional): Target Google Drive folder. Defaults to `secure-backup`.
- `auth_port` (optional): Port used to launch a temporary local HTTP server for interactive authentication. Defaults to `8085`.
- `token_path` (optional): Path where the retrieved token is cached. Defaults to `~/.config/secure-backup/google-drive-token.json`.
- `google_drive_token` (optional): JSON representation of the OAuth2 token. Typically automatically loaded/managed by credential plugins.

### Example
```bash
secure-backup backup /path/to/data \
  --plugin google-drive \
  --plugin-opt client_id="your-client-id" \
  --plugin-opt client_secret="your-client-secret"
```

### Authentication Flow
If a token does not exist at `token_path` or inside a credential plugin, the plugin will start a temporary HTTP server (on port `8085`) and launch your default browser to authorize access to your Google Drive account. After authorization is completed, the token is saved back to `token_path` (or synced back to compatible credential plugins like macOS Keychain).
