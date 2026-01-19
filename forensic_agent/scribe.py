from __future__ import annotations
import csv
import sqlite3
from pathlib import Path
from typing import List, Tuple

from forensic_agent.audit import AuditLogger
from forensic_agent.config import ForensicConfig
from forensic_agent.models import StoredEvidence


class Scribe:
   #Scribe Agent

    """
    Reactive agent which performs reporting responsibilities: CSV export of path/type/hash, validation: CSV rows match SQLite manifest entries, operator summary output
    """

    def __init__(self, config: ForensicConfig, audit: AuditLogger):
        self.config = config
        self.audit = audit

    def generate_csv(self, run_id: str, evidence: List[StoredEvidence]) -> Path:
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        self.audit.append("REPORT_START", {"run_id": run_id, "rows": len(evidence)})

        with self.config.csv_report_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["run_id", "file_path", "extension", "size_bytes", "sha256", "archive_member"])
            for item in evidence:
                writer.writerow([
                    run_id,
                    str(item.path),
                    item.extension,
                    item.size_bytes,
                    item.sha256,
                    item.archive_member_name
                ])

        self.audit.append("REPORT_WRITTEN", {"csv_path": str(self.config.csv_report_path)})
        return self.config.csv_report_path

    def validate_csv_vs_sqlite(self, run_id: str) -> Tuple[bool, str]:
        """
        Ensures 'Store and present' constraint: CSV registers match catalogue (SQLite).
        """
        # load csv digests
        csv_digests = set()
        with self.config.csv_report_path.open("r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row["run_id"] == run_id:
                    csv_digests.add((row["file_path"], row["sha256"]))

        # load sqlite digests
        db_digests = set()
        conn = sqlite3.connect(self.config.sqlite_path)
        try:
            cur = conn.execute("""
                SELECT file_path, sha256 FROM evidence_manifest WHERE run_id = ?;
            """, (run_id,))
            for fp, sha in cur.fetchall():
                db_digests.add((fp, sha))
        finally:
            conn.close()

        if csv_digests == db_digests:
            return True, "CSV and SQLite manifest match"
        missing = db_digests - csv_digests
        extra = csv_digests - db_digests
        return False, f"Mismatch: missing_in_csv={len(missing)} extra_in_csv={len(extra)}"
