from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class AuditLogger:
    """
    Tamper-evident append-only audit log implemented as a hash chain.

    Each entry includes:
      - timestamp (ISO-8601 UTC)
      - event type
      - payload (small, minimised)
      - prev_entry_hash
      - entry_hash  (sha256(prev_hash + canonical_json))
    """
    audit_log_path: Path
    _last_hash: str = "GENESIS"

    def _iso_utc(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _hash_entry(self, prev_hash: str, entry_json: str) -> str:
        h = hashlib.sha256()
        h.update(prev_hash.encode("utf-8"))
        h.update(entry_json.encode("utf-8"))
        return h.hexdigest()

    def append(self, event: str, payload: Dict[str, Any]) -> str:
        record = {
            "ts": self._iso_utc(),
            "event": event,
            "payload": payload,
            "prev_hash": self._last_hash,
        }

        # canonical JSON for deterministic hashing (sorted keys, no whitespace)
        entry_json = json.dumps(record, sort_keys=True, separators=(",", ":"))
        entry_hash = self._hash_entry(self._last_hash, entry_json)
        record["entry_hash"] = entry_hash

        # append line-delimited JSON
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")

        self._last_hash = entry_hash
        return entry_hash

    def count_entries(self) -> int:
        if not self.audit_log_path.exists():
            return 0
        with self.audit_log_path.open("r", encoding="utf-8") as f:
            return sum(1 for _ in f)
