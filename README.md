# GCP Auditor
A lightweight GCP security scanner for running security checks on your Google Cloud projects.

**Features:**
- 30+ security checks across IAM, Storage, Compute, Networking, and Databases
- ISO 27001, SOC 2, and CIS GCP Benchmark mappings
- Copy-paste remediation commands for each finding
- HTML, JSON, SARIF, and Markdown report formats
- Configuration file support with suppressions

## Quick Start

```bash
pip install -e .
gcp-auditor scan --project my-project-id
```

For a demo without GCP credentials:
```bash
gcp-auditor demo
```

## Who is this for

- Teams needing quick GCP security visibility without buying expensive tools
- DevOps/SRE engineers doing pre-deployment security checks
- Anyone generating compliance reports for audits

## What it checks

30+ checks across IAM, Cloud Storage, Compute Engine, VPC Firewall, Cloud SQL, Cloud KMS, Cloud Logging, BigQuery, and GKE.

**By severity:** 5 Critical, 10 High, 12 Medium, 5+ Low.

Every check answers one question: *would an attacker exploit this?* If not, the check doesn't exist.

<details>
<summary>Full check list</summary>

### Security

| ID | Severity | Description |
|----|----------|-------------|
| `gcp-iam-001` | High | Service account with no key rotation |
| `gcp-iam-002` | Medium | Service account key older than 90 days |
| `gcp-iam-003` | Critical | Overly permissive IAM policy (roles/editor on project) |
| `gcp-storage-001` | Critical | Cloud Storage bucket publicly accessible |
| `gcp-storage-002` | High | Cloud Storage bucket without uniform access |
| `gcp-storage-003` | Medium | Cloud Storage bucket without versioning |
| `gcp-storage-004` | Medium | Cloud Storage bucket without lifecycle policy |
| `gcp-compute-001` | High | Compute instance with public IP |
| `gcp-compute-002` | Medium | Compute instance without OS Login |
| `gcp-compute-003` | Medium | Compute instance serial port enabled |
| `gcp-compute-004` | Low | Compute instance IP forwarding enabled |
| `gcp-firewall-001` | Critical | Firewall rule allows 0.0.0.0/0 on sensitive ports |
| `gcp-firewall-002` | High | Firewall rule allows 0.0.0.0/0 on SSH (port 22) |
| `gcp-firewall-003` | High | Firewall rule allows 0.0.0.0/0 on RDP (port 3389) |
| `gcp-sql-001` | Critical | Cloud SQL instance has public IP |
| `gcp-sql-002` | High | Cloud SQL instance without SSL enforcement |
| `gcp-sql-003` | Medium | Cloud SQL instance without automated backups |
| `gcp-kms-001` | Medium | KMS key without rotation |
| `gcp-kms-002` | High | KMS key with overly permissive IAM |
| `gcp-logging-001` | High | Logging sink not configured |
| `gcp-logging-002` | Medium | Log retention period too short |
| `gcp-bigquery-001` | Medium | BigQuery dataset is public |
| `gcp-gke-001` | Critical | GKE cluster has public control plane |
| `gcp-gke-002` | High | GKE cluster legacy ABAC enabled |
| `gcp-gke-003` | Medium | GKE cluster without workload identity |

### Cost

| ID | Severity | Description |
|----|----------|-------------|
| `gcp-storage-005` | Low | Cloud Storage bucket without lifecycle rules |
| `gcp-compute-005` | Low | Unattached persistent disk |

### Reliability

| ID | Severity | Description |
|----|----------|-------------|
| `gcp-storage-003` | Low | Cloud Storage bucket without versioning |
| `gcp-sql-003` | Medium | Cloud SQL without automated backups |
| `gcp-sql-004` | Low | Cloud SQL auto minor version upgrade disabled |

</details>

## Every finding includes a fix

This is what makes gcp-auditor different from most scanners. Run with `-R` to see remediation for each finding:

```
$ gcp-auditor scan --project my-project -R

  CRITICAL  Cloud Storage bucket publicly accessible
  Resource:   gs://public-data-bucket
  Compliance: ISO 27001 A.8.3, SOC 2 CC6.1, CIS GCP 5.1
  Effort:     LOW
  CLI:        gcloud storage buckets update gs://public-data-bucket --public-access-prevention=enforced
  Terraform:  resource "google_storage_bucket" "bucket" { ... }
  Docs:       https://cloud.google.com/storage/docs/public-access-prevention

  CRITICAL  Firewall rule allows 0.0.0.0/0 on port 22
  Resource:   default-allow-ssh
  Compliance: ISO 27001 A.13.1, SOC 2 CC6.6, CIS GCP 3.6
  Effort:     LOW
  CLI:        gcloud compute firewall-rules update default-allow-ssh --source-ranges=10.0.0.0/8
  Terraform:  resource "google_compute_firewall" "ssh" { ... }
```

Or export all fixes as a bash script:

```bash
gcp-auditor scan --project my-project --export-fixes fixes.sh
```

The script is commented and uses `set -e` — review it, uncomment what you want to apply, and run.

## Reports

Generate reports in multiple formats:

```bash
# HTML report
gcp-auditor scan --project my-project --format html --output report.html

# JSON
gcp-auditor scan --project my-project --format json --output report.json

# SARIF (for GitHub Code Scanning)
gcp-auditor scan --project my-project --format sarif --output results.sarif

# Markdown
gcp-auditor scan --project my-project --format markdown --output report.md
```

## Installation

From source:
```bash
git clone https://github.com/abdullahkamil/gcp-auditor.git
cd gcp-auditor
pip install -e ".[dev]"
```

## Usage

```bash
# Basic scan
gcp-auditor scan --project my-project

# Show remediation details
gcp-auditor scan --project my-project -R

# Specific regions
gcp-auditor scan --project my-project --regions us-central1,europe-west1

# Export fixes as bash script
gcp-auditor scan --project my-project --export-fixes fixes.sh

# List available checks
gcp-auditor list-checks

# Filter by severity
gcp-auditor scan --project my-project --min-severity high
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings (after suppressions and severity filter) |
| 1 | Findings detected |
| 2 | Scan error (bad credentials, invalid config) |

### Configuration file

Create `.gcp-auditor.yml` in your project root:

```yaml
provider: gcp
project: my-project-id
regions:
  - us-central1
  - europe-west1
min_severity: medium
exclude_checks:
  - gcp-storage-005
suppressions:
  - check_id: gcp-firewall-001
    resource_id: my-allowed-rule
    reason: "Intentionally open for load balancer"
    accepted_by: "admin@example.com"
    expires: "2026-12-31"
```

Auto-detected from the current directory. Override with `--config path/to/.gcp-auditor.yml`.

**Precedence:** CLI flags > environment variables > config file > defaults.

### Environment variables

| Variable | Description | Example |
|----------|-------------|---------|
| `GCP_AUDITOR_REGIONS` | Comma-separated regions | `us-central1,europe-west1` |
| `GCP_AUDITOR_MIN_SEVERITY` | Minimum severity filter | `high` |
| `GCP_AUDITOR_EXCLUDE_CHECKS` | Comma-separated check IDs to skip | `gcp-storage-005` |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to service account key | `/path/to/key.json` |

## CI/CD Integration

### GitHub Actions

```yaml
name: GCP Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  id-token: write
  contents: read
  security-events: write
  actions: read
  pull-requests: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install gcp-auditor
        run: pip install gcp-auditor

      - name: Authenticate to GCP
        uses: google-github-actions/auth@v2
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}

      - name: Set up Cloud SDK
        uses: google-github-actions/setup-gcloud@v2

      - name: Scan (SARIF)
        continue-on-error: true
        run: gcp-auditor scan --project ${{ secrets.GCP_PROJECT }} --format sarif --output results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
          category: gcp-auditor

      - name: Scan (Markdown)
        if: github.event_name == 'pull_request'
        continue-on-error: true
        run: gcp-auditor scan --project ${{ secrets.GCP_PROJECT }} --format markdown --output report.md

      - name: Post PR comment
        if: github.event_name == 'pull_request'
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: report.md
```

This gives you findings in the GitHub Security tab (via SARIF) and a Markdown summary on every PR.

## GCP Permissions

gcp-auditor requires **read-only** access. Assign the GCP `Viewer` role (`roles/viewer`) or specific service roles:

```bash
# Grant viewer role to service account
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:auditor@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/viewer"
```

gcp-auditor never modifies your infrastructure. It only makes read API calls.

## Risk Scoring

Uses CVSS v3.1 for standardized risk assessment:

| Severity | CVSS Range | Risk Level |
|----------|------------|------------|
| Critical | 9.0-10.0 | 🔴 |
| High | 7.0-8.9 | 🟠  |
| Medium | 4.0-6.9 | 🟡 |
| Low | 0.1-3.9 | 🟢 |

Each finding includes a CVSS vector (e.g., `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`) for detailed risk analysis.


## Roadmap

- More GKE, Cloud Run, and Cloud Functions checks
- Enhanced HTML reports
- Scan comparison/diff feature

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest -v

# Lint and format
ruff check src/ tests/
ruff format src/ tests/

# Type check
mypy src/
```

## Acknowledgements

This project was inspired by [cloud-audit](https://github.com/gebalamariusz/cloud-audit) by [@gebalamariusz](https://github.com/gebalamariusz). The original project provided the foundational architecture and scanner pattern. This fork extends it with GCP-specific checks, CVSS v3.1 scoring, additional report formats, and expanded coverage across GCP services.
