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
    """Reactive agent for hashing + storage.
    performs, SHA-256 hashing, ZIP archive creation (copy evidence),SQLite manifest rows, audit log append
    """

    def __init__(self, config: ForensicConfig, audit: AuditLogger):
        self.config = config
        self.audit = audit
        self._init_db()

    def _init_db(self) -> None:
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
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
            conn.execute("CREATE INDEX IF NOT EXISTS idx_manifest_sha ON evidence_manifest(sha256);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_manifest_path ON evidence_manifest(file_path);")
            conn.commit()
        finally:
            conn.close()

    def _iso_utc(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _sha256_file(self, path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def process(self, run_id: str, files: List[FileMatch]) -> List[StoredEvidence]:
        self.audit.append("HASH_STORE_START", {"run_id": run_id, "count": len(files)})

        stored: List[StoredEvidence] = []
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        # open ZIP once for efficiency
        with zipfile.ZipFile(self.config.archive_path, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            conn = sqlite3.connect(self.config.sqlite_path)
            try:
                for fm in files:
                    # policy re-check just before read (defensive)
                    dec = canonicalise_and_validate_path(fm.path, self.config.allowed_root)
                    if not dec.ok:
                        self.audit.append("POLICY_BLOCK", {"path": str(fm.path), "reason": dec.reason})
                        continue

                    dec = reject_symlink(fm.path)
                    if not dec.ok:
                        self.audit.append("POLICY_BLOCK", {"path": str(fm.path), "reason": dec.reason})
                        continue

                    try:
                        digest = self._sha256_file(fm.path)
                    except Exception as e:
                        self.audit.append("HASH_ERROR", {"path": str(fm.path), "error": str(e)})
                        continue

                    # stable archive member name (avoid leaking full paths if desired)
                    # Here we include relative path from allowed root for traceability.
                    rel = fm.path.resolve(strict=False).relative_to(self.config.allowed_root.resolve(strict=False))
                    member = str(rel).replace("\\", "/")

                    try:
                        zf.write(fm.path, arcname=member)
                    except Exception as e:
                        self.audit.append("ARCHIVE_ERROR", {"path": str(fm.path), "error": str(e)})
                        continue

                    collected_at = self._iso_utc()
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

                    self.audit.append("HASHED_STORED", {
                        "path": str(fm.path),
                        "sha256": digest,
                        "archive_member": member,
                        "size": fm.size_bytes
                    })

                    stored.append(StoredEvidence(
                        path=fm.path, sha256=digest,
                        size_bytes=fm.size_bytes, extension=fm.extension,
                        archive_member_name=member
                    ))
            finally:
                conn.close()

        self.audit.append("HASH_STORE_DONE", {"run_id": run_id, "stored": len(stored)})
        return stored
