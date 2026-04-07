# AWS S3 Storage Plugin

Provides backup destination support directly to Amazon S3 leveraging the official AWS SDK v2.

## Options
Configure this plugin directly utilizing the generic `--plugin-opt` flags or standard AWS SDK environment mechanisms.

- `bucket` (required): Target S3 Bucket Name.
- `access_key_id` (optional): AWS Access Key ID. *(Native `AWS_ACCESS_KEY_ID` environment variables act as a seamless fallback).*
- `secret_access_key` (optional): AWS Secret Access Key. *(Native `AWS_SECRET_ACCESS_KEY` environment variables act as a seamless fallback).*
- `region` (optional): AWS Region. *(Native `AWS_REGION` environment variables act as a seamless fallback).*

### Example
```bash
secure-backup backup ... --plugin aws-s3 --plugin-opt bucket=my-aws-bucket --plugin-opt region=us-east-1 
```
