from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import FrozenSet


@dataclass(frozen=True)
class ForensicConfig:

    # Central configuration object.
    #
    # Specifies the constraints within which the agent operates on the HOST OS Filesystem:
    # allow-listed root
    # read-only evidence handling
    # no symlinks
    # size limit
    # specific file types
    #  outputs: ZIP, SQLite manifest, CSV, audit log
    #"""
    allowed_root: Path = Path.home() / "digital_agent_source_files"  # set to your allowed evidence root
    allowed_extensions: FrozenSet[str] = frozenset({".pdf", ".doc", ".docx", ".txt",".jpg","png"}) #allowed file extensions
    max_file_size_bytes: int = 50 * 1024 * 1024  # 50MB
    hash_algorithm: str = "sha256"

    output_dir: Path = Path("outputs")
    archive_path: Path = output_dir / "evidence.zip"
    sqlite_path: Path = output_dir / "manifest.db"
    csv_report_path: Path = output_dir / "report.csv"
    audit_log_path: Path = output_dir / "audit.log"

    # deterministic run metadata
    case_id: str = "CASE-001"
    operator_id: str = "operator-unknown"
