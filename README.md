# ISO 20022 pacs.008 Test Harness

Generates realistic interbank payment messages, injects fraud signals,
streams to Elastic Serverless, and renders a live terminal dashboard.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Edit config.yaml — add your Elastic endpoint + API key

# 3. Dry run (no Elastic needed)
python harness.py --dry-run --total 100

# 4. Live run against Elastic
python harness.py

# 5. Override rate or count on the fly
python harness.py --rate 60 --total 500
```

---

## Configuration (`config.yaml`)

### Elastic

```yaml
elastic:
  endpoint: "https://YOUR-DEPLOYMENT.es.us-east-1.aws.elastic.cloud"
  api_key:  "YOUR_BASE64_APIKEY"   # from Kibana → Stack Management → API Keys
  index:    "iso20022-pacs008"
```

To get an API key in Kibana:
1. **Stack Management → API Keys → Create API key**
2. Copy the **Base64** encoded value
3. Paste into `api_key` above

### Cadence

```yaml
cadence:
  msgs_per_minute: 20       # normal rate
  off_hours_multiplier: 0.1 # overnight quieter
  burst_enabled: true
  burst_probability: 0.05
  burst_size: 10
```

### Fraud Injection

Each fraud type has a `weight` (relative share of all fraud events):

| Type               | Description |
|--------------------|-------------|
| `invalid_bic`      | Malformed/non-existent BIC code |
| `sanctioned_country` | Payment routed via KP/IR/SY/CU/VE |
| `round_amount`     | Suspiciously round large amounts |
| `rapid_succession` | Same debtor sends rapid cluster |
| `dormant_account`  | Payment from inactive account |
| `amount_spike`     | Amount far exceeds normal range |

Set `fraud.overall_rate: 0.05` for ~5% fraudulent messages.

---

## Output

### Log file (`iso20022_harness.log`)
JSON-Lines format — one document per line, ready to stream into Elastic
via Filebeat, Logstash, or the Elastic Agent.

Each record includes:
- `@timestamp`, `message_id`, `uetr`
- `amount`, `currency`
- `debtor.*`, `creditor.*`
- `fraud.is_fraud`, `fraud.type`, `fraud.description`
- `pacs008.*` — full parsed XML as nested JSON
- `tags` — includes `fraud_suspect` when applicable
- ECS-compatible `event.*` fields

### XML files (`generated_xml/`)
Raw pacs.008 XML, one file per message (`<msg_id>.xml`).
Disable with `logging.log_xml: false` in config.

---

## Elastic Serverless Setup

### Index template (run once in Kibana Dev Tools)

```json
PUT _index_template/iso20022
{
  "index_patterns": ["iso20022-*"],
  "template": {
    "settings": { "number_of_shards": 1 },
    "mappings": {
      "properties": {
        "@timestamp":    { "type": "date" },
        "amount":        { "type": "double" },
        "fraud.is_fraud":{ "type": "boolean" },
        "fraud.type":    { "type": "keyword" },
        "debtor.bic":    { "type": "keyword" },
        "creditor.bic":  { "type": "keyword" },
        "tags":          { "type": "keyword" }
      }
    }
  }
}
```

### Suggested Kibana dashboards
- **Transaction volume** — histogram on `@timestamp`
- **Fraud rate over time** — filter `fraud.is_fraud: true`
- **Fraud type breakdown** — pie/bar on `fraud.type`
- **Amount distribution** — histogram on `amount`
- **BIC network** — creditor vs debtor BIC traffic

---

## Streaming the log file to Elastic

If you prefer file-based ingestion (Filebeat / Elastic Agent):

```yaml
# filebeat.yml snippet
filebeat.inputs:
  - type: log
    paths: ["/path/to/iso20022_harness.log"]
    json.keys_under_root: true
    json.add_error_key: true

output.elasticsearch:
  hosts: ["https://YOUR-DEPLOYMENT.es.us-east-1.aws.elastic.cloud"]
  api_key: "YOUR_API_KEY"
  index: "iso20022-pacs008"
```

---

## Architecture

```
harness.py
    │
    ├── generator.py      → Builds pacs.008 XML via pyiso20022
    │       └── Fraud injection (6 types, configurable weights)
    │
    ├── elastic_shipper.py → XML→JSON, bulk indexing to Elastic Serverless
    │
    └── log_writer.py     → JSON-Lines log + raw XML files
```
