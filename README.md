# 🤿 Bucket Diver — Azure Edition

> The new version of Bucket Diver, now built for Azure.

Bucket Diver Azure is a fast, concurrent CLI tool that scans Azure Blob Storage containers for accidentally exposed secrets — API keys, credentials, tokens, private keys, connection strings, and high-entropy values that shouldn't be there.

---

## Features

- **Aho-Corasick pre-filtering** — multi-pattern string matching as a fast gate before regex evaluation
- **Shannon entropy analysis** — detects secrets that don't match known patterns but look statistically anomalous
- **Archive recursion** — scans `.gz` and `.zip` files recursively, with zip-bomb protection
- **Metadata & tag scanning** — optionally scans blob metadata and tags in addition to file content
- **Bloom filter deduplication** — probabilistic dedup across the entire scan session (~1M items, 0.1% FP rate)
- **Extension-aware entropy thresholds** — reduces false positives by tuning entropy cutoffs per file type
- **Content-type sniffing** — falls back to `http.DetectContentType` for blobs with no extension or generic MIME types

---

## Detection Coverage

| Category | Severity | Example Pattern |
|---|---|---|
| `AWS_ACCESS_KEY` | CRITICAL | `AKIA...` |
| `AWS_SECRET_KEY` | CRITICAL | `secret = "..."` |
| `AZURE_KEY` | CRITICAL | `AccountKey=...` |
| `GCP_SERVICE_KEY` | CRITICAL | `"private_key": "-----BEGIN..."` |
| `PRIVATE_KEY` | CRITICAL | `-----BEGIN RSA PRIVATE KEY-----` |
| `DB_URL` | HIGH | `postgres://user:pass@host/db` |
| `STRIPE_KEY` | HIGH | `sk_live_...` |
| `GITHUB_TOKEN` | HIGH | `ghp_...` / `gho_...` |
| `SLACK_WEBHOOK` | MEDIUM | `hooks.slack.com/services/...` |
| `SLACK_TOKEN` | MEDIUM | `xoxb-...` |
| `JWT_SECRET` | MEDIUM | `eyJ...eyJ...` |
| `GOOGLE_KEY` | MEDIUM | `AIza...` |
| `SENDGRID_KEY` | MEDIUM | `SG....` |
| `TWILIO_KEY` | MEDIUM | `SK[a-f0-9]{32}` |
| `NPM_TOKEN` | MEDIUM | `npm_...` |
| `PYPI_TOKEN` | MEDIUM | `pypi-AgEI...` |
| `TERRAFORM_CLOUD_TOKEN` | MEDIUM | `atlasv1....` |
| `DATADOG_API_KEY` | LOW | `dd_api_key = "..."` |
| `HIGH_ENTROPY_CANDIDATE` | LOW | High-entropy string in file content |
| `HIGH_ENTROPY_METADATA` | LOW | High-entropy value in blob metadata |

---

## Authentication

Uses `DefaultAzureCredential`, which tries credential sources in this order:

1. Environment variables (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`)
2. Workload identity
3. Managed identity
4. Azure CLI (`az login`)

No extra configuration needed if you're already logged in with the Azure CLI.

---

## Installation

```bash
git clone https://github.com/yourhandle/bucket-diver-azure
cd bucket-diver-azure
go mod tidy
go build -o bucket-diver-azure .
```

Requires Go 1.21+.

---

## Usage

```
bucket-diver-azure -a <storage-account> [options]
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-a` | *(required)* | Azure Storage Account name |
| `-c` | *(all)* | Comma-separated container names to scan |
| `--prefix` | *(none)* | Only scan blobs whose name starts with this prefix |
| `-t` | `10` | Number of concurrent worker goroutines |
| `--rate` | `100` | Max blob download requests per second |
| `--max-size` | `10` | Skip blobs larger than this many MB |
| `--meta` | `false` | Also scan blob metadata and tags |
| `-o` | *(stdout)* | Write JSON findings to a file |
| `-q` | `false` | Suppress human-readable progress output |
| `-v` | `false` | Enable debug-level structured logging |

### Examples

Scan all containers in a storage account:
```bash
bucket-diver-azure -a mystorageaccount
```

Scan specific containers with metadata scanning enabled:
```bash
bucket-diver-azure -a mystorageaccount -c backups,uploads --meta
```

Scan with a blob prefix, 20 workers, and save output to a file:
```bash
bucket-diver-azure -a mystorageaccount --prefix prod/ -t 20 -o findings.json
```

---

## Output

Findings are written as newline-delimited JSON to stdout (and optionally to a file with `-o`). Human-readable progress is printed to stderr.

```json
{
  "bucket": "my-container",
  "file": "configs/app.env",
  "line": 14,
  "secret": "AKIAIOSFODNN7EXAMPLE",
  "category": "AWS_ACCESS_KEY",
  "severity": "CRITICAL",
  "timestamp": "2025-04-01T10:32:00Z"
}
```

A summary is printed at the end:
```
[*] Scan complete — scanned: 4821  skipped: 312  errors: 2
```

---

## Architecture

```
main.go          — CLI flags, Azure client setup, orchestration
internal/
  azure.go       — Azure Blob SDK wrapper (download, metadata, retry logic)
  engine.go      — Scanning core (Aho-Corasick, regex, entropy, dedup)
  pool.go        — Worker pool, rate limiter, archive handling
models/
  finding.go     — Finding and ScanTask types, severity mapping
```

The pipeline is fully channel-driven:

```
paginateContainer() → fileTasks chan → worker pool → findings chan → output goroutine
```

---

## Disclaimer

This tool is intended for use on storage accounts you own or have explicit written permission to scan. Do not use it against accounts you don't control.

---

## License

MIT License — Copyright (c) 2026 Louai SAHLI

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.