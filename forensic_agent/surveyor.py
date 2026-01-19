from __future__ import annotations
from pathlib import Path
from typing import Iterable, List, Set

from forensic_agent.models import FileMatch
from forensic_agent.policy import canonicalise_and_validate_path, reject_symlink
from forensic_agent.audit import AuditLogger
from forensic_agent.config import ForensicConfig


class Surveyor:
    """
    Reactive discovery agent responsible for locating candidate evidence files.

    This agent enforces forensic safety and policy constraints during traversal,
    ensuring that only admissible files within scope are passed downstream for
    hashing and preservation.
    """

    def __init__(self, config: ForensicConfig, audit: AuditLogger):
        # Shared configuration defining discovery scope and size constraints
        self.config = config

        # Audit logger used to record discovery decisions and policy enforcement
        self.audit = audit

    def discover(self, root: Path, extensions: Set[str]) -> List[FileMatch]:
        """
        Recursively scans the filesystem under the provided root directory
        and returns metadata for files that satisfy forensic policy rules.

        This method performs read-only inspection and does not modify evidence.
        """
        # Resolve root to a canonical absolute path without forcing existence
        root = root.resolve(strict=False)

        # Record discovery start for traceability and reproducibility
        self.audit.append("DISCOVERY_START", {
            "root": str(root),
            "extensions": sorted(list(extensions)),
            "max_size": self.config.max_file_size_bytes,
        })

        matches: List[FileMatch] = []

        # Walk filesystem recursively in read-only mode
        for path in root.rglob("*"):
            # Skip directories to avoid unnecessary stat and policy checks
            if path.is_dir():
                continue

            # Enforce allow-listed root and prevent path traversal attacks
            decision = canonicalise_and_validate_path(path, self.config.allowed_root)
            if not decision.ok:
                self.audit.append("POLICY_BLOCK", {"path": str(path), "reason": decision.reason})
                continue

            # Reject symbolic links to prevent indirect or mutable evidence access
            decision = reject_symlink(path)
            if not decision.ok:
                self.audit.append("POLICY_BLOCK", {"path": str(path), "reason": decision.reason})
                continue

            # Filter files by explicitly allowed extensions
            ext = path.suffix.lower()
            if ext not in extensions:
                continue

            try:
                # Retrieve file size without opening file contents
                size = path.stat().st_size
            except Exception as e:
                # Capture filesystem access failures for audit review
                self.audit.append("DISCOVERY_ERROR", {"path": str(path), "error": str(e)})
                continue

            # Enforce maximum size limit to control resource usage and scope
            if size > self.config.max_file_size_bytes:
                self.audit.append("POLICY_BLOCK", {
                    "path": str(path),
                    "reason": f"File exceeds max size ({size} > {self.config.max_file_size_bytes})"
                })
                continue

            # Record admissible file metadata for downstream processing
            matches.append(
                FileMatch(
                    path=path.resolve(strict=False),
                    size_bytes=size,
                    extension=ext
                )
            )

        # Record discovery completion and evidence count
        self.audit.append("DISCOVERY_DONE", {"found": len(matches)})
        return matches
