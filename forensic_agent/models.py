from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

#Class holding data model for storing File state, hashResult, Copy of Evidence, Report Summary
@dataclass(frozen=True)
class FileMatch:
    path: Path
    size_bytes: int
    extension: str


@dataclass(frozen=True)
class HashResult:
    path: Path
    sha256: str
    size_bytes: int
    extension: str


@dataclass(frozen=True)
class StoredEvidence:
    path: Path
    sha256: str
    size_bytes: int
    extension: str
    archive_member_name: str


@dataclass(frozen=True)
class ReportSummary:
    csv_path: Path
    sqlite_path: Path
    archive_path: Path
    audited_events: int
    files_processed: int
    validation_ok: bool
    validation_message: str
    run_id: str
