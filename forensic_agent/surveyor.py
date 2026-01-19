from __future__ import annotations
from pathlib import Path
from typing import Iterable, List, Set

from forensic_agent.models import FileMatch
from forensic_agent.policy import canonicalise_and_validate_path, reject_symlink
from forensic_agent.audit import AuditLogger
from forensic_agent.config import ForensicConfig


class Surveyor:
    """
    Reactive agent which performs discovery responsibilities:
     scan within allow-listed root, canonicalise paths, reject '..' traversal (via relative_to check), reject symlinks, enforce file extension + size limits
    """

    def __init__(self, config: ForensicConfig, audit: AuditLogger):
        self.config = config
        self.audit = audit

    def discover(self, root: Path, extensions: Set[str]) -> List[FileMatch]:
        root = root.resolve(strict=False)

        self.audit.append("DISCOVERY_START", {
            "root": str(root),
            "extensions": sorted(list(extensions)),
            "max_size": self.config.max_file_size_bytes,
        })

        matches: List[FileMatch] = []

        # Walk filesystem (read-only)
        for path in root.rglob("*"):
            # skip directories early
            if path.is_dir():
                continue

            # enforce policy: within allowed root
            decision = canonicalise_and_validate_path(path, self.config.allowed_root)
            if not decision.ok:
                self.audit.append("POLICY_BLOCK", {"path": str(path), "reason": decision.reason})
                continue

            # enforce policy: no symlinks
            decision = reject_symlink(path)
            if not decision.ok:
                self.audit.append("POLICY_BLOCK", {"path": str(path), "reason": decision.reason})
                continue

            ext = path.suffix.lower()
            if ext not in extensions:
                continue

            try:
                size = path.stat().st_size
            except Exception as e:
                self.audit.append("DISCOVERY_ERROR", {"path": str(path), "error": str(e)})
                continue

            if size > self.config.max_file_size_bytes:
                self.audit.append("POLICY_BLOCK", {
                    "path": str(path),
                    "reason": f"File exceeds max size ({size} > {self.config.max_file_size_bytes})"
                })
                continue

            matches.append(FileMatch(path=path.resolve(strict=False), size_bytes=size, extension=ext))

        self.audit.append("DISCOVERY_DONE", {"found": len(matches)})
        return matches
