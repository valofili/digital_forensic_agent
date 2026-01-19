from __future__ import annotations
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Set, List

from forensic_agent.audit import AuditLogger
from forensic_agent.config import ForensicConfig
from forensic_agent.models import FileMatch, StoredEvidence, ReportSummary
from forensic_agent.surveyor import Surveyor
from forensic_agent.hasher_packer import HasherPacker
from forensic_agent.scribe import Scribe


class CoordinatorAgent:


    def __init__(self, config: ForensicConfig):
        self.config = config
        self.audit = AuditLogger(config.audit_log_path)
        self.surveyor = Surveyor(config, self.audit)
        self.hasher = HasherPacker(config, self.audit)
        self.scribe = Scribe(config, self.audit)

    def _new_run_id(self) -> str:
        return f"RUN-{uuid.uuid4()}"

    def run_task(self, root_path: Path, extensions: Set[str]) -> ReportSummary:
        run_id = self._new_run_id()

        self.audit.append("RUN_START", {
            "run_id": run_id,
            "case_id": self.config.case_id,
            "operator_id": self.config.operator_id,
            "root": str(root_path),
            "extensions": sorted(list(extensions))
        })

        # STEP 1: DISCOVER
        discovered: List[FileMatch] = self.surveyor.discover(root_path, extensions)

        # STEP 2 + 3: HASH + STORE (archive + sqlite)
        stored: List[StoredEvidence] = self.hasher.process(run_id, discovered)

        # STEP 4: REPORT (CSV)
        self.scribe.generate_csv(run_id, stored)

        # VALIDATE: CSV vs SQLite
        ok, message = self.scribe.validate_csv_vs_sqlite(run_id)
        self.audit.append("REPORT_VALIDATION", {"run_id": run_id, "ok": ok, "message": message})

        # RUN COMPLETE
        self.audit.append("RUN_DONE", {
            "run_id": run_id,
            "files_discovered": len(discovered),
            "files_processed": len(stored),
            "validation_ok": ok
        })

        return ReportSummary(
            csv_path=self.config.csv_report_path,
            sqlite_path=self.config.sqlite_path,
            archive_path=self.config.archive_path,
            audited_events=self.audit.count_entries(),
            files_processed=len(stored),
            validation_ok=ok,
            validation_message=message,
            run_id=run_id
        )
