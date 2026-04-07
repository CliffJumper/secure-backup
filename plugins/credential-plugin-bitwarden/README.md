# Bitwarden Credential Plugin

Dynamically retrieves requested secrets natively from a Bitwarden vault by spinning up the `bw` CLI in an isolated subprocess.

## Usage
Simply supply the name or ID of the exact Item you want to decrypt:
```bash
secure-backup backup ... --cred-plugin bitwarden --cred-item "My-App-Secrets"
```
*(Requires the `BW_SESSION` environment variable to be exported, or an unlocked vault CLI in your active shell!)*

## Payload Structure
`secure-backup` core natively forwards anything yielded by a credential plugin directly into the underlying storage plugin's option map. As such, your Bitwarden item payload **MUST exactly correspond to the required plugins!** 

To fulfill this, insert a raw JSON string containing key-value mappings anywhere into your item's `Notes` or into a Custom Variable Field.

### Example (For AWS S3 Plugin):
```json
{
  "access_key_id": "AKIAXXXXXXXXXXXXXXXX",
  "secret_access_key": "some-secret",
  "bucket": "my-s3-bucket",
  "region": "us-east-1"
}
```
