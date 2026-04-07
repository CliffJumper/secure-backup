# Storage Plugins

The secure-backup uses a robust plugin architecture using HashiCorp's `go-plugin` to communicate with backend storage targets. This prevents the core application logic from being tightly coupled to an SDK or individual storage provider's quirks.

The tool currently supports three storage targets out of the box, configured via the `--plugin` flag:

## Backblaze B2 (`backblaze`)
This is the default plugin. It connects directly to Backblaze B2 natively via API. 

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
