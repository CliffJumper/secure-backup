# Backblaze Storage Plugin

Provides backup destination support for Backblaze B2 using the native API.

## Options
Because `secure-backup` abstracts plugins, you must configure this plugin dynamically through the core interface using the `--plugin-opt` flag.

- `account_id` (required): Your Backblaze Account ID.
- `application_key` (required): Your Backblaze Application Key.
- `bucket` (required): Target B2 Bucket Name.

### Example
```bash
secure-backup backup ... --plugin backblaze --plugin-opt account_id=XYZ --plugin-opt application_key=XYZ --plugin-opt bucket=my-bucket
```
Alternatively, credential plugins automatically map `account_id` and `application_key`!
