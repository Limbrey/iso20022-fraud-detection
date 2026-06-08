"""
log_writer.py — writes generated messages to log file and optional XML directory
"""
import json
import os
import logging
from pathlib import Path
from datetime import datetime
from elastic_shipper import xml_to_dict, build_elastic_doc

logger = logging.getLogger("harness.log")


class LogWriter:
    def __init__(self, config: dict):
        self.cfg = config.get("logging", {})
        self.log_file = Path(self.cfg.get("log_file", "iso20022_harness.log"))
        self.log_xml = self.cfg.get("log_xml", True)
        self.xml_dir = Path(self.cfg.get("xml_dir", "generated_xml"))

        # Ensure output paths exist
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        if self.log_xml:
            self.xml_dir.mkdir(parents=True, exist_ok=True)

        self._fh = open(self.log_file, "a", encoding="utf-8")

    def write(self, msg, xml_dict: dict):
        """Append one JSON-lines record to the log file."""
        doc = build_elastic_doc(msg, xml_dict)
        line = json.dumps(doc, default=str)
        self._fh.write(line + "\n")
        self._fh.flush()

        if self.log_xml:
            xml_path = self.xml_dir / f"{msg.msg_id}.xml"
            xml_path.write_text(msg.xml, encoding="utf-8")

    def close(self):
        self._fh.close()

    def stats(self) -> dict:
        size = self.log_file.stat().st_size if self.log_file.exists() else 0
        return {
            "log_file": str(self.log_file),
            "size_bytes": size,
            "size_kb": round(size / 1024, 1),
        }
