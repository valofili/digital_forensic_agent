from __future__ import annotations
import hashlib
import sqlite3
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from forensic_agent.audit import AuditLogger
from forensic_agent.config import ForensicConfig
from forensic_agent.models import FileMatch, StoredEvidence
from forensic_agent.policy import reject_symlink, canonicalise_and_validate_path


class HasherPacker:
    """
    Reactive agent responsible for evidence integrity preservation and storage.

    This agent computes cryptographic hashes, packages immutable evidence
    into an archive, records authoritative metadata in a manifest database,
    and emits audit events for each preservation step.
    """

    def __init__(self, config: ForensicConfig, audit: AuditLogger):
        # Shared configuration defining case metadata and output locations
        self.config = config

        # Audit logger for integrity and chain-of-custody events
        self.audit = audit

        # Initialise persistent manifest storage on agent creation
        self._init_db()

    def _init_db(self) -> None:
        # Ensure output directory exists before creating manifest database
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        # Create or migrate SQLite schema for evidence manifest
        conn = sqlite3.connect(self.config.sqlite_path)
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence_manifest (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    operator_id TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    extension TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    archive_member TEXT NOT NULL
                );
            """)
            # Indexes support efficient lookup and validation operations
            conn.execute("CREATE INDEX IF NOT EXISTS idx_manifest_sha ON evidence_manifest(sha256);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_manifest_path ON evidence_manifest(file_path);")
            conn.commit()
        finally:
            conn.close()

    def _iso_utc(self) -> str:
        # Returns a timezone-safe timestamp for forensic traceability
        return datetime.now(timezone.utc).isoformat()

    def _sha256_file(self, path: Path) -> str:
        # Computes SHA-256 digest using chunked reads to support large files
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def process(self, run_id: str, files: List[FileMatch]) -> List[StoredEvidence]:
        """
        Hashes, archives, and records evidence files for a single forensic run.

        This method enforces policy defensively, preserves file integrity,
        and produces authoritative storage artefacts.
        """
        self.audit.append("HASH_STORE_START", {"run_id": run_id, "count": len(files)})

        stored: List[StoredEvidence] = []

        # Ensure output directory exists prior to writing artefacts
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        # Open ZIP archive once to ensure atomic and efficient packaging
        with zipfile.ZipFile(self.config.archive_path, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            conn = sqlite3.connect(self.config.sqlite_path)
            try:
                for fm in files:
                    # Re-validate policy immediately before file access
                    dec = canonicalise_and_validate_path(fm.path, self.config.allowed_root)
                    if not dec.ok:
                        self.audit.append("POLICY_BLOCK", {"path": str(fm.path), "reason": dec.reason})
                        continue

                    # Prevent hashing of symbolic links or redirected content
                    dec = reject_symlink(fm.path)
                    if not dec.ok:
                        self.audit.append("POLICY_BLOCK", {"path": str(fm.path), "reason": dec.reason})
                        continue

                    try:
                        # Compute cryptographic fingerprint of file contents
                        digest = self._sha256_file(fm.path)
                    except Exception as e:
                        self.audit.append("HASH_ERROR", {"path": str(fm.path), "error": str(e)})
                        continue

                    # Use relative archive paths to retain traceability without leaking full paths
                    rel = fm.path.resolve(strict=False).relative_to(
                        self.config.allowed_root.resolve(strict=False)
                    )
                    member = str(rel).replace("\\", "/")

                    try:
                        # Copy evidence into immutable archive container
                        zf.write(fm.path, arcname=member)
                    except Exception as e:
                        self.audit.append("ARCHIVE_ERROR", {"path": str(fm.path), "error": str(e)})
                        continue

                    collected_at = self._iso_utc()

                    # Persist authoritative evidence metadata to manifest database
                    conn.execute("""
                        INSERT INTO evidence_manifest (
                            run_id, case_id, operator_id, collected_at,
                            file_path, file_size, extension, sha256, archive_member
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """, (
                        run_id, self.config.case_id, self.config.operator_id, collected_at,
                        str(fm.path), fm.size_bytes, fm.extension, digest, member
                    ))
                    conn.commit()

                    # Record successful preservation event for audit trail
                    self.audit.append("HASHED_STORED", {
                        "path": str(fm.path),
                        "sha256": digest,
                        "archive_member": member,
                        "size": fm.size_bytes
                    })

                    # Emit immutable record for downstream reporting
                    stored.append(
                        StoredEvidence(
                            path=fm.path,
                            sha256=digest,
                            size_bytes=fm.size_bytes,
                            extension=fm.extension,
                            archive_member_name=member
                        )
                    )
            finally:
                conn.close()

        # Record completion of hashing and storage phase
        self.audit.append("HASH_STORE_DONE", {"run_id": run_id, "stored": len(stored)})
        return stored
