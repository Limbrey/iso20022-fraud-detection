#!/usr/bin/env python3
"""
elastic_setup.py — One-shot Elastic Security setup script
Creates all index templates, ML jobs, and detection rules for the
ISO20022 pacs.008 fraud detection harness.

Usage:
    python3 elastic_setup.py                    # uses config.yaml
    python3 elastic_setup.py --config my.yaml
    python3 elastic_setup.py --dry-run          # print what would be created
"""

import argparse
import json
import sys
import time
from pathlib import Path

import requests
import yaml
from requests.auth import HTTPBasicAuth

# ── Colours for terminal output ───────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def ok(msg):    print(f"  {GREEN}✓{RESET} {msg}")
def err(msg):   print(f"  {RED}✗{RESET} {msg}")
def warn(msg):  print(f"  {YELLOW}⚠{RESET} {msg}")
def info(msg):  print(f"  {CYAN}→{RESET} {msg}")
def header(msg):print(f"\n{BOLD}{msg}{RESET}")


# ── Elastic client ─────────────────────────────────────────────────────────────

class ElasticClient:
    def __init__(self, config: dict, dry_run: bool = False):
        elastic = config.get("elastic", {})
        self.endpoint = elastic.get("endpoint", "").rstrip("/")
        self.api_key  = elastic.get("api_key")
        self.username = elastic.get("username")
        self.password = elastic.get("password")
        self.dry_run  = dry_run
        self._session = requests.Session()
        if self.api_key:
            self._session.headers.update({
                "Authorization": f"ApiKey {self.api_key}",
                "Content-Type": "application/json",
            })
        elif self.username and self.password:
            self._session.auth = HTTPBasicAuth(self.username, self.password)
            self._session.headers.update({"Content-Type": "application/json"})

    def put(self, path: str, body: dict) -> tuple[bool, dict]:
        if self.dry_run:
            print(f"    [DRY RUN] PUT {path}")
            return True, {}
        r = self._session.put(f"{self.endpoint}{path}", json=body, timeout=30)
        return r.status_code in (200, 201), r.json()

    def post(self, path: str, body: dict = None) -> tuple[bool, dict]:
        if self.dry_run:
            print(f"    [DRY RUN] POST {path}")
            return True, {}
        r = self._session.post(f"{self.endpoint}{path}", json=body or {}, timeout=30)
        return r.status_code in (200, 201), r.json()

    def get(self, path: str) -> tuple[bool, dict]:
        r = self._session.get(f"{self.endpoint}{path}", timeout=15)
        return r.status_code == 200, r.json()

    def test(self) -> tuple[bool, str]:
        try:
            ok_flag, data = self.get("/")
            if ok_flag:
                ver = data.get("version", {}).get("number", "unknown")
                return True, f"Elasticsearch {ver}"
            return False, f"Status error: {data}"
        except Exception as e:
            return False, str(e)

    def kibana_post(self, path: str, body: dict) -> tuple[bool, dict]:
        """POST to Kibana API (different base URL pattern for Serverless)."""
        # Kibana API uses same endpoint but different paths
        if self.dry_run:
            print(f"    [DRY RUN] KIBANA POST {path}")
            return True, {}
        headers = {**self._session.headers, "kbn-xsrf": "true"}
        r = requests.post(
            f"{self.endpoint}{path}",
            json=body,
            headers=headers,
            timeout=30
        )
        return r.status_code in (200, 201), r.json() if r.text else {}


# ── Index template ─────────────────────────────────────────────────────────────

INDEX_TEMPLATE = {
    "index_patterns": ["iso20022-pacs008*"],
    "template": {
        "mappings": {
            "properties": {
                "@timestamp":      {"type": "date"},
                "message_id":      {"type": "keyword"},
                "uetr":            {"type": "keyword"},
                "settlement_date": {"type": "date", "format": "yyyy-MM-dd"},
                "amount":          {"type": "double"},
                "currency":        {"type": "keyword"},
                "debtor": {
                    "properties": {
                        "bic":  {"type": "keyword"},
                        "name": {"type": "text"}
                    }
                },
                "creditor": {
                    "properties": {
                        "bic":  {"type": "keyword"},
                        "name": {"type": "text"}
                    }
                },
                "tags": {"type": "keyword"},
                "source": {
                    "properties": {
                        "address": {"type": "keyword"},
                        "user": {"properties": {"name": {"type": "keyword"}}}
                    }
                },
                "destination": {
                    "properties": {
                        "address": {"type": "keyword"},
                        "user": {"properties": {"name": {"type": "keyword"}}}
                    }
                },
                "transaction": {
                    "properties": {
                        "id":       {"type": "keyword"},
                        "amount":   {"type": "double"},
                        "currency": {"type": "keyword"}
                    }
                },
                "event": {
                    "properties": {
                        "id":       {"type": "keyword"},
                        "kind":     {"type": "keyword"},
                        "category": {"type": "keyword"},
                        "type":     {"type": "keyword"},
                        "dataset":  {"type": "keyword"}
                    }
                }
            }
        }
    }
}


# ── ML anomaly detection jobs ──────────────────────────────────────────────────

ML_JOBS = [
    {
        "id": "pacs008-amount-spike",
        "body": {
            "description": "Detects abnormally high payment amounts per sending bank. Models each debtor BIC independently so anomalies are relative to that bank's own baseline.",
            "groups": ["iso20022", "security"],
            "analysis_config": {
                "bucket_span": "15m",
                "detectors": [
                    {
                        "detector_description": "high_mean(amount) by debtor.bic",
                        "function": "high_mean",
                        "field_name": "amount",
                        "by_field_name": "debtor.bic"
                    }
                ],
                "influencers": ["debtor.bic", "creditor.bic"]
            },
            "analysis_limits": {"model_memory_limit": "50mb"},
            "data_description": {"time_field": "@timestamp"}
        }
    },
    {
        "id": "pacs008-rare-bic",
        "body": {
            "description": "Detects creditor BICs that appear rarely in the payment stream, modelled per sending bank. Catches invalid BIC codes, sanctioned institution routing, and payments to previously unseen counterparties.",
            "groups": ["iso20022", "security"],
            "analysis_config": {
                "bucket_span": "15m",
                "detectors": [
                    {
                        "detector_description": "rare by creditor.bic over debtor.bic",
                        "function": "rare",
                        "by_field_name": "creditor.bic",
                        "over_field_name": "debtor.bic"
                    }
                ],
                "influencers": ["creditor.bic", "debtor.bic"]
            },
            "analysis_limits": {"model_memory_limit": "50mb"},
            "data_description": {"time_field": "@timestamp"}
        }
    },
    {
        "id": "pacs008-new-corridor",
        "body": {
            "description": "Detects sending banks that are paying creditors outside their normal correspondent corridors. Catches new or unusual payment corridors that may indicate fraud, money laundering, or account compromise.",
            "groups": ["iso20022", "security"],
            "analysis_config": {
                "bucket_span": "15m",
                "detectors": [
                    {
                        "detector_description": "rare by creditor.bic over debtor.bic (population)",
                        "function": "rare",
                        "by_field_name": "creditor.bic",
                        "over_field_name": "debtor.bic"
                    }
                ],
                "influencers": ["creditor.bic", "debtor.bic"]
            },
            "analysis_limits": {"model_memory_limit": "50mb"},
            "data_description": {"time_field": "@timestamp"}
        }
    }
]


# ── ML datafeeds ───────────────────────────────────────────────────────────────

def datafeed_body(job_id: str, index: str) -> dict:
    return {
        "job_id": job_id,
        "indices": [index],
        "query": {"match_all": {}},
        "scroll_size": 1000,
        "delayed_data_check_config": {"enabled": True}
    }


# ── Detection rules ────────────────────────────────────────────────────────────

def detection_rules(index: str) -> list:
    return [
        {
            "name": "ISO20022 - Rapid Succession Payments by Sender",
            "description": "Detects when a single sending bank submits 10 or more pacs.008 payments within a short time window, indicative of rapid succession fraud or automated payment abuse.",
            "risk_score": 47,
            "severity": "medium",
            "type": "threshold",
            "index": [index],
            "query": "*",
            "language": "kuery",
            "threshold": {
                "field": ["debtor.bic"],
                "value": 10
            },
            "from": "now-1h",
            "interval": "1m",
            "enabled": True,
            "tags": ["iso20022", "fraud"],
            "threat": [
                {
                    "framework": "MITRE ATT&CK",
                    "tactic": {
                        "id": "TA0040",
                        "name": "Impact",
                        "reference": "https://attack.mitre.org/tactics/TA0040/"
                    },
                    "technique": [
                        {
                            "id": "T1657",
                            "name": "Financial Theft",
                            "reference": "https://attack.mitre.org/techniques/T1657/"
                        }
                    ]
                }
            ]
        },
        {
            "name": "ISO20022 - Payment to Sanctioned or Invalid BIC",
            "description": "Detects pacs.008 interbank payments where the creditor BIC matches a known invalid or sanctioned institution. Includes malformed BIC codes and BICs associated with sanctioned jurisdictions including North Korea, Iran, Syria and Cuba.",
            "risk_score": 73,
            "severity": "high",
            "type": "query",
            "index": [index],
            "query": "creditor.bic: (XXXXGB00 OR FAKEUS99 OR BADDBIC1 OR NOTABANX OR XXXXXXXX OR KOBAKPPY OR BTEJIRTE OR TEBEIRTE OR BSYRSYDA OR BCUBCUHA)",
            "language": "kuery",
            "from": "now-2h",
            "interval": "1m",
            "enabled": True,
            "tags": ["iso20022", "fraud", "sanctions"],
            "threat": [
                {
                    "framework": "MITRE ATT&CK",
                    "tactic": {
                        "id": "TA0040",
                        "name": "Impact",
                        "reference": "https://attack.mitre.org/tactics/TA0040/"
                    },
                    "technique": [
                        {
                            "id": "T1657",
                            "name": "Financial Theft",
                            "reference": "https://attack.mitre.org/techniques/T1657/"
                        }
                    ]
                }
            ]
        }
    ]


# ── Main setup routine ─────────────────────────────────────────────────────────

def run_setup(config: dict, dry_run: bool = False):
    index = config.get("elastic", {}).get("index", "iso20022-pacs008")
    client = ElasticClient(config, dry_run)

    # Test connection
    header("1. Testing connection")
    connected, detail = client.test()
    if connected:
        ok(detail)
    else:
        err(f"Cannot connect: {detail}")
        if not dry_run:
            sys.exit(1)

    # Index template
    header("2. Creating index template")
    success, resp = client.put("/_index_template/iso20022-pacs008", INDEX_TEMPLATE)
    if success:
        ok("Index template iso20022-pacs008 created")
    else:
        err(f"Failed: {resp.get('error', {}).get('reason', resp)}")

    # ML jobs
    header("3. Creating ML anomaly detection jobs")
    for job in ML_JOBS:
        success, resp = client.put(f"/_ml/anomaly_detectors/{job['id']}", job["body"])
        if success:
            ok(f"ML job: {job['id']}")
            # Create datafeed
            feed_id = f"datafeed-{job['id']}"
            success2, resp2 = client.put(
                f"/_ml/datafeeds/{feed_id}",
                datafeed_body(job["id"], index)
            )
            if success2:
                ok(f"  Datafeed: {feed_id}")
            else:
                reason = resp2.get('error', {}).get('reason', '')
                if 'already exists' in str(reason):
                    warn(f"  Datafeed already exists: {feed_id}")
                else:
                    err(f"  Datafeed failed: {reason}")
        else:
            reason = resp.get('error', {}).get('reason', '')
            if 'already exists' in str(reason):
                warn(f"ML job already exists: {job['id']}")
            else:
                err(f"Failed to create {job['id']}: {reason}")

    # Start datafeeds
    header("4. Starting ML datafeeds")
    for job in ML_JOBS:
        feed_id = f"datafeed-{job['id']}"
        success, resp = client.post(f"/_ml/datafeeds/{feed_id}/_start")
        if success:
            ok(f"Started: {feed_id}")
        else:
            reason = resp.get('error', {}).get('reason', '')
            if 'already been started' in str(reason):
                warn(f"Already running: {feed_id}")
            else:
                err(f"Failed to start {feed_id}: {reason}")

    # Detection rules via Kibana API
    header("5. Creating detection rules")
    rules = detection_rules(index)
    for rule in rules:
        # Use Kibana detection rules API
        kibana_endpoint = config.get("elastic", {}).get("endpoint", "").rstrip("/")
        kibana_endpoint = kibana_endpoint.replace(".es.", ".kb.")
        headers = {"Content-Type": "application/json", "kbn-xsrf": "true"}
        if client.api_key:
            headers["Authorization"] = f"ApiKey {client.api_key}"

        if dry_run:
            info(f"[DRY RUN] Rule: {rule['name']}")
            continue

        try:
            r = requests.post(
                f"{kibana_endpoint}/api/detection_engine/rules",
                json=rule,
                headers=headers,
                timeout=30
            )
            if r.status_code in (200, 201):
                ok(f"Rule: {rule['name']}")
            elif r.status_code == 409:
                warn(f"Rule already exists: {rule['name']}")
            else:
                err(f"Failed ({r.status_code}): {rule['name']} — {r.text[:200]}")
        except Exception as e:
            err(f"Exception creating rule {rule['name']}: {e}")

    header("Setup complete")
    print(f"\n  Index:     {index}")
    print(f"  ML jobs:   {len(ML_JOBS)} created")
    print(f"  Rules:     {len(rules)} created")
    print(f"\n  Run the harness:  python3 harness.py --rate 20")
    print(f"  Dry run:          python3 elastic_setup.py --dry-run\n")


def main():
    parser = argparse.ArgumentParser(description="ISO20022 Elastic Security Setup")
    parser.add_argument("--config",  default="config.yaml")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"{RED}Config not found: {config_path}{RESET}")
        sys.exit(1)

    with open(config_path) as f:
        config = yaml.safe_load(f)

    run_setup(config, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
