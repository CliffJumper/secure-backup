# Credential Plugins

The secure-backup uses a plugin architecture for securely fetching configuration or secret material, avoiding the need to expose them locally in environment variables or within your shell's history.

Credentials like your `Account ID` and `Application Key` for Backblaze B2 are typically pulled using these plugins. 

When you specify `--cred-plugin <plugin>`, the tool will load the binary located at `./plugins/credential-plugin-<plugin>` and dispatch a request to it with the target item specified via `--cred-item`.

## Bitwarden (`bitwarden`)

The Bitwarden plugin relies on the official [Bitwarden CLI (`bw`)](https://bitwarden.com/help/cli/) tool. The vault must be unlocked and your environment must have a valid `BW_SESSION` exported. 

The credential item (e.g. `cli-tool-backup`) should contain the credentials represented as JSON in either the "Notes" field or a Custom Field named "Additional options". 

Example payload:
```json
{
  "keyID": "005a1...",
  "applicationKey": "K005aTn..."
}
```

Usage:
```bash
./secure-backup backup --cred-plugin bitwarden --cred-item "cli-tool-backup"
```

## MacOS Keychain (`keychain`)

The MacOS Keychain plugin natively uses the `security` CLI built into MacOS to securely retrieve your configuration. It searches for a Generic Password item (`-s`) matching your `--cred-item` value. The value of this keychain generic password **must** be a JSON string, identical to what the Bitwarden plugin expects.

Example payload stored in the Keychain password field:
```json
{
  "keyID": "005a...",
  "applicationKey": "K005..."
}
```

Usage:
```bash
./secure-backup backup --cred-plugin keychain --cred-item "cli-tool-backup"
```
