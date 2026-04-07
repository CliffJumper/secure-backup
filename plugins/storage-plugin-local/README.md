# Local Storage Plugin

A simple local disk fallback backend. This mimics "cloud" functionality safely on your local file system, perfect for testing, mounts, or external hard drives!

## Options
- `local_dir` (required): The absolute or relative path to a local directory functioning as your destination "bucket".

### Example
```bash
secure-backup backup ... --plugin local --plugin-opt local_dir=/Volumes/ExternalUSB/Backups
```
