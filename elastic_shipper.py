"""
elastic_shipper.py — converts pacs.008 XML → JSON and ships to Elastic Serverless
"""
import json
import re
import logging
from datetime import datetime
from typing import Optional
import requests
from requests.auth import HTTPBasicAuth

logger = logging.getLogger("harness.elastic")


def xml_to_dict(xml: str) -> dict:
    """
    Lightweight XML → dict for pacs.008.  Strips namespaces, pulls key fields.
    Not a general-purpose parser — optimised for pacs.008.001.08 structure.
    """
    def _tag(tag):
        return re.sub(r'\{[^}]+\}', '', tag)

    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml)

        def node_to_dict(el):
            d = {}
            for child in el:
                key = _tag(child.tag)
                # Include attributes (e.g. Ccy on amount)
                val_text = child.text.strip() if child.text and child.text.strip() else None
                children = list(child)
                if children:
                    nested = node_to_dict(child)
                    if child.attrib:
                        nested.update({f"@{k}": v for k, v in child.attrib.items()})
                    if key in d:
                        if not isinstance(d[key], list):
                            d[key] = [d[key]]
                        d[key].append(nested)
                    else:
                        d[key] = nested
                else:
                    val = val_text
                    if child.attrib:
                        val = {"#text": val_text}
                        val.update({f"@{k}": v for k, v in child.attrib.items()})
                    if key in d:
                        if not isinstance(d[key], list):
                            d[key] = [d[key]]
                        d[key].append(val)
                    else:
                        d[key] = val
            return d

        return node_to_dict(root)
    except Exception as e:
        logger.warning(f"XML parse error: {e}")
        return {"raw_xml": xml}


def build_elastic_doc(msg, xml_dict: dict) -> dict:
    """
    Flatten the pacs.008 dict into an Elastic-friendly document.
    Writes both native pacs.008 fields and ECS-compatible fields
    so the Elastic Security solution can apply detection rules.
    fraud.* fields are intentionally omitted — those are the output
    of detection, not inputs to it.
    """
    doc = {
        # ── Core fields ───────────────────────────────────────────
        "@timestamp": msg.timestamp.isoformat() + "Z",
        "message_id": msg.msg_id,
        "uetr": msg.uetr,
        "settlement_date": msg.settlement_date.isoformat() if msg.settlement_date else None,

        # Native pacs.008 fields — readable, queryable
        "amount": msg.amount,
        "currency": msg.currency,
        "debtor": {
            "name": msg.debtor_name,
            "bic": msg.debtor_bic,
        },
        "creditor": {
            "name": msg.creditor_name,
            "bic": msg.creditor_bic,
        },

        # Full parsed pacs.008 structure for drill-down
        "pacs008": xml_dict,

        # ── ECS fields — Security solution compatible ─────────────
        "source": {
            "address": msg.debtor_bic,
            "user": {
                "name": msg.debtor_name,
            },
        },
        "destination": {
            "address": msg.creditor_bic,
            "user": {
                "name": msg.creditor_name,
            },
        },
        "transaction": {
            "id":       msg.uetr,
            "amount":   msg.amount,
            "currency": msg.currency,
        },
        "event": {
            "id":       msg.msg_id,
            "kind":     "event",
            "category": "network",
            "type":     "connection",
            "dataset":  "iso20022.pacs008",
        },
        "tags": ["iso20022", "pacs008"],
    }
    return doc


class ElasticShipper:
    def __init__(self, config: dict):
        self.cfg = config.get("elastic", {})
        self.endpoint = self.cfg.get("endpoint", "").rstrip("/")
        self.index = self.cfg.get("index", "iso20022-pacs008")
        self.api_key = self.cfg.get("api_key")
        self.username = self.cfg.get("username")
        self.password = self.cfg.get("password")
        self._session = requests.Session()
        self._configure_auth()
        self._ok = False

    def _configure_auth(self):
        if self.api_key:
            self._session.headers.update({
                "Authorization": f"ApiKey {self.api_key}",
                "Content-Type": "application/json",
            })
        elif self.username and self.password:
            self._session.auth = HTTPBasicAuth(self.username, self.password)
            self._session.headers.update({"Content-Type": "application/json"})

    def test_connection(self) -> tuple[bool, str]:
        """Returns (success, message)"""
        if not self.endpoint or self.endpoint == "https://YOUR-DEPLOYMENT.es.us-east-1.aws.elastic.cloud":
            return False, "Elastic endpoint not configured in config.yaml"
        try:
            r = self._session.get(f"{self.endpoint}/", timeout=10)
            if r.status_code in (200, 401):
                if r.status_code == 401:
                    return False, "Authentication failed — check api_key or credentials"
                self._ok = True
                info = r.json()
                version = info.get("version", {}).get("number", "unknown")
                return True, f"Connected to Elasticsearch {version}"
            return False, f"Unexpected status {r.status_code}: {r.text[:200]}"
        except Exception as e:
            return False, f"Connection error: {e}"

    def ship(self, msg, xml_dict: dict) -> tuple[bool, str]:
        """Ship one document. Returns (success, detail)."""
        if not self.endpoint or not self._ok:
            return False, "Not connected"
        doc = build_elastic_doc(msg, xml_dict)
        url = f"{self.endpoint}/{self.index}/_doc/{msg.uetr}"
        try:
            r = self._session.put(url, data=json.dumps(doc), timeout=15)
            if r.status_code in (200, 201):
                return True, r.json().get("result", "ok")
            return False, f"HTTP {r.status_code}: {r.text[:300]}"
        except Exception as e:
            return False, str(e)

    def bulk_ship(self, docs: list) -> tuple[int, int, str]:
        """Bulk index. Returns (ok_count, err_count, detail)."""
        if not self.endpoint or not self._ok:
            return 0, len(docs), "Not connected"
        lines = []
        for msg, xml_dict in docs:
            doc = build_elastic_doc(msg, xml_dict)
            meta = json.dumps({"index": {"_index": self.index, "_id": msg.uetr}})
            lines.append(meta)
            lines.append(json.dumps(doc))
        body = "\n".join(lines) + "\n"
        url = f"{self.endpoint}/_bulk"
        try:
            r = self._session.post(
                url,
                data=body,
                headers={**self._session.headers, "Content-Type": "application/x-ndjson"},
                timeout=30,
            )
            if r.status_code == 200:
                resp = r.json()
                errs = [i for i in resp.get("items", []) if "error" in i.get("index", {})]
                ok = len(docs) - len(errs)
                return ok, len(errs), f"bulk ok={ok} errors={len(errs)}"
            return 0, len(docs), f"HTTP {r.status_code}"
        except Exception as e:
            return 0, len(docs), str(e)
