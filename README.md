# ISO 20022 pacs.008 Fraud Detection Harness

A Python test harness that generates realistic ISO 20022 pacs.008 interbank payment messages, injects fraud signals, streams data into Elastic Security, and provides a live terminal dashboard. Designed to demonstrate end-to-end financial fraud detection using Elastic ML, anomaly detection, and AI-assisted investigation.

---

## Architecture

```
harness.py                    → Live terminal dashboard + orchestration
    │
    ├── generator.py          → pacs.008 message factory (11 bank profiles)
    │       └── Fraud injection (6 types, configurable weights)
    │
    ├── elastic_shipper.py    → XML → JSON + ECS mapping + Elastic indexing
    │
    └── log_writer.py         → JSON-Lines log + raw XML files

elastic_setup.py              → One-shot Elastic Security configuration
    ├── Index template
    ├── ML anomaly detection jobs
    ├── ML datafeeds
    └── Detection rules
```

---

## Quick Start

### 1. Install dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure

Copy and edit the config file:

```bash
cp config.yaml.example config.yaml
```

Edit `config.yaml`:

```yaml
elastic:
  endpoint: "https://YOUR-DEPLOYMENT.es.eu-west-2.aws.elastic.cloud"
  api_key:  "YOUR_BASE64_API_KEY"
  index:    "iso20022-pacs008"
```

To get an API key: **Kibana → Stack Management → API Keys → Create API key** — copy the Base64 encoded value.

### 3. Set up Elastic

Run the setup script once to create the index template, ML jobs, and detection rules:

```bash
python3 elastic_setup.py --dry-run   # preview first
python3 elastic_setup.py             # apply
```

### 4. Run the harness

```bash
# Dry run — no Elastic needed
python3 harness.py --dry-run --total 100

# Live run at default rate (20 msg/min)
python3 harness.py

# Override rate and total
python3 harness.py --rate 60 --total 5000

# Run indefinitely
python3 harness.py --rate 20
```

---

## Sending Bank Profiles

The harness simulates 11 banks, each with distinct payment behaviour:

| Bank | BIC | Typical Amount | Role |
|---|---|---|---|
| Barclays | BARCGB22 | £4,900 | Large retail bank, high volume |
| HSBC | HBUKGB4B | £9,900 | Large corporate, international corridors |
| Deutsche Bank | DEUTDEDB | £25,000 | Wholesale/institutional, large amounts |
| BNP Paribas | BNPAFRPP | £23,000 | European wholesale |
| Lloyds | LOYDGB2L | £2,400 | Retail-heavy, domestic focus |
| NatWest | NWBKGB2L | £1,600 | Retail, mid-range |
| Santander UK | SANBGB2L | £1,300 | Retail/mortgage focus |
| Metro Bank | METRGB21 | £880 | Challenger bank |
| Starling | STRLGB2L | £640 | Fintech, small payments |
| Monzo | MONZGB2L | £536 | Fintech, frequent small payments |
| Northshire Community Bank | NSHBGB2L | £1,000 | Small community bank, low volume |

Each bank has preferred payment corridors — 80% of payments go to known counterparties, 20% go anywhere. This gives the ML distinct per-sender baselines to learn from.

---

## Fraud Types

| Type | Description | Injection rate |
|---|---|---|
| `amount_spike` | Amount far exceeds sender's normal range | ~15% of fraud |
| `sanctioned_country` | Payment routed via KP/IR/SY/CU/VE BIC | ~20% of fraud |
| `invalid_bic` | Malformed/non-existent BIC code | ~25% of fraud |
| `round_amount` | Suspiciously round large amounts (structuring) | ~15% of fraud |
| `rapid_succession` | Same debtor sends rapid cluster | ~15% of fraud |
| `dormant_account` | Payment from inactive account | ~10% of fraud |

Overall fraud rate defaults to 5% — configurable in `config.yaml`.

**Note:** `fraud.*` fields are intentionally excluded from Elastic documents. Detection is genuine — the ML and rules find fraud without being told what's fraudulent.

---

## Elastic Security Setup

### Index Template

Fields are mapped for both native pacs.008 access and ECS compatibility:

| Native field | ECS field | Type |
|---|---|---|
| `debtor.bic` | `source.address` | keyword |
| `creditor.bic` | `destination.address` | keyword |
| `amount` | `transaction.amount` | double |
| `uetr` | `transaction.id` | keyword |
| `@timestamp` | `@timestamp` | date |

### ML Anomaly Detection Jobs

| Job ID | Detector | What it finds |
|---|---|---|
| `pacs008-amount-spike` | `high_mean(amount)` by `debtor.bic` | Amounts anomalous relative to sender's own baseline |
| `pacs008-rare-bic` | `rare(creditor.bic)` over `debtor.bic` | Unusual/unseen creditor BICs per sender |
| `pacs008-new-corridor` | `rare(creditor.bic)` over `debtor.bic` (population) | Sender paying creditors outside normal corridors |

All jobs use 15-minute bucket spans and are grouped under `iso20022` and `security`.

### Detection Rules

| Rule | Type | Severity | Catches |
|---|---|---|---|
| ISO20022 - Rapid Succession Payments by Sender | Threshold (≥10 per sender/min) | Medium | Burst payment activity |
| ISO20022 - Payment to Sanctioned or Invalid BIC | Custom query | High | Known bad BICs |

### Data Frame Analytics

| Job ID | Type | Output |
|---|---|---|
| `pacs008-outlier-detection` | LOF Outlier Detection | Per-transaction outlier score in `pacs008-outlier-scores` |

---

## Configuration Reference

```yaml
elastic:
  endpoint: "https://..."          # Elasticsearch endpoint (.es. not .kb.)
  api_key:  "..."                  # Base64 API key from Kibana
  index:    "iso20022-pacs008"     # Target index name

cadence:
  msgs_per_minute: 20              # Normal send rate
  off_hours_multiplier: 0.1        # Quieter overnight
  burst_enabled: true              # Occasional payment bursts
  burst_probability: 0.05          # 5% chance per cycle
  burst_size: 10                   # Messages per burst

fraud:
  enabled: true
  overall_rate: 0.05               # ~5% of messages are fraudulent
  types:
    invalid_bic:       { weight: 0.25 }
    sanctioned_country:{ weight: 0.20 }
    round_amount:      { weight: 0.15 }
    rapid_succession:  { weight: 0.15 }
    amount_spike:      { weight: 0.15 }
    dormant_account:   { weight: 0.10 }

bank:
  name: "Northshire Community Bank"
  bic:  "NSHBGB2L"
  currency: "GBP"

logging:
  log_file: "iso20022_harness.log"
  log_xml:  true
  xml_dir:  "generated_xml"
```

---

## Output

### Log file (`iso20022_harness.log`)

JSON-Lines format — one document per line, ready for Filebeat or Elastic Agent ingestion.

### Generated XML (`generated_xml/`)

Raw pacs.008.001.08 XML, one file per message. Disable with `logging.log_xml: false`.

### Filebeat ingestion (optional)

```yaml
filebeat.inputs:
  - type: log
    paths: ["/path/to/iso20022_harness.log"]
    json.keys_under_root: true

output.elasticsearch:
  hosts: ["https://YOUR-DEPLOYMENT.es.eu-west-2.aws.elastic.cloud"]
  api_key: "YOUR_API_KEY"
  index: "iso20022-pacs008"
```

---

## Demo Flow

1. **Start the harness** — live payment stream with Rich terminal dashboard
2. **Discover** — show messages arriving in real time with correct field types
3. **Alerts** — detection rules firing on known fraud patterns
4. **Anomaly Explorer** — ML surfacing behavioural anomalies per sender
5. **Outlier scores** — per-transaction risk scoring from DFA
6. **AI Agent** — Claude investigating and summarising alerts in natural language

---

## Dependencies

- `pyiso20022` — pacs.008 message generation
- `xsdata` — XML serialisation
- `rich` — terminal dashboard
- `requests` — Elastic API client
- `pyyaml` — configuration
- `faker` — realistic data generation

---

## Security

`config.yaml` is excluded from version control via `.gitignore`. Never commit API keys or endpoint URLs. Use environment variables for CI/CD:

```bash
export ELASTIC_ENDPOINT="https://..."
export ELASTIC_API_KEY="..."
```

---

## Licence

MIT
