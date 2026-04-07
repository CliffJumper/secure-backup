# Keychain Credential Plugin (macOS)

Retrieves target secrets locally and natively from your macOS Keychain via the built-in `security` binary tools.

## Usage
Supply the name of your generic password item safely configured in your Keychain app:
```bash
secure-backup backup ... --cred-plugin keychain --cred-item "My-App-Secrets"
```

## Payload Structure
When generating your generic password inside the macOS Keychain, place a raw `.json` formatted string into the **Password** field. `secure-backup` strictly enforces transparent payloads, which means your Keychain data gets blindly forwarded directly to the backend storage plugins!

### Example (For Backblaze Plugin):
```json
{
  "account_id": "YOUR_B2_ACCOUNT_ID",
  "application_key": "YOUR_B2_APPLICATION_KEY",
  "bucket": "YOUR_B2_BUCKET"
}
```
