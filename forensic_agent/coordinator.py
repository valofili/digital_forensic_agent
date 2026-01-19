from __future__ import annotations
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Set, List

from forensic_agent.audit import AuditLogger  #coordinating agent imports AuditLogger
from forensic_agent.config import ForensicConfig #coordinating agent imports Configuration Constraints
from forensic_agent.models import FileMatch, StoredEvidence, ReportSummary #coordinating agent imports  Data Models
from forensic_agent.surveyor import Surveyor #coordinating agent imports SurveyorAgent
from forensic_agent.hasher_packer import HasherPacker #coordinating agent imports HasherPackerAgent
from forensic_agent.scribe import Scribe #coordinating agent imports ScribeAgent


class CoordinatorAgent:
    """
    Central coordinating agent responsible for orchestrating the
    end-to-end digital forensic workflow.

    This agent does not perform forensic operations itself; instead,
    it manages agent collaboration, execution order, run identity,
    and audit traceability in line with a BDI-style coordinator role.
    """

    def __init__(self, config: ForensicConfig):
        # Shared configuration governing case metadata and output paths
        self.config = config

        # Centralised audit logger used by all collaborating agents
        self.audit = AuditLogger(config.audit_log_path)

        # Agent responsible for evidence discovery and filtering
        self.surveyor = Surveyor(config, self.audit)

        # Agent responsible for hashing, packaging, and manifest storage
        self.hasher = HasherPacker(config, self.audit)

        # Agent responsible for reporting and post-run validation
        self.scribe = Scribe(config, self.audit)

    def _new_run_id(self) -> str:
        # Generates a globally unique identifier for traceable forensic runs
        return f"RUN-{uuid.uuid4()}"

    def run_task(self, root_path: Path, extensions: Set[str]) -> ReportSummary:
        """
        Executes a complete forensic acquisition run.

        This method coordinates discovery, integrity preservation,
        reporting, validation, and audit logging, delegating all
        domain-specific work to specialised agents.
        """
        run_id = self._new_run_id()

        # Record forensic run initiation for chain-of-custody purposes
        self.audit.append("RUN_START", {
            "run_id": run_id,
            "case_id": self.config.case_id,
            "operator_id": self.config.operator_id,
            "root": str(root_path),
            "extensions": sorted(list(extensions))
        })

        # STEP 1: Discover candidate evidence files under policy constraints
        discovered: List[FileMatch] = self.surveyor.discover(root_path, extensions)

        # STEP 2 + 3: Hash files and store immutable evidence artefacts
        stored: List[StoredEvidence] = self.hasher.process(run_id, discovered)

        # STEP 4: Generate human-readable forensic report (CSV)
        self.scribe.generate_csv(run_id, stored)

        # Validate consistency between report and authoritative manifest
        ok, message = self.scribe.validate_csv_vs_sqlite(run_id)
        self.audit.append("REPORT_VALIDATION", {"run_id": run_id, "ok": ok, "message": message})

        # Record successful completion of the forensic run
        self.audit.append("RUN_DONE", {
            "run_id": run_id,
            "files_discovered": len(discovered),
            "files_processed": len(stored),
            "validation_ok": ok
        })

        # Return a concise, immutable summary for CLI or API consumers
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
