from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path


class PolicyViolation(Exception):
    pass


@dataclass(frozen=True)
class PolicyDecision:
    ok: bool
    reason: str


def canonicalise_and_validate_path(path: Path, allowed_root: Path) -> PolicyDecision:
    """
    Canonicalised paths, Must be within allow-listed root, Blocks path traversal attempts
    """
    try:
        # Resolve removes '..' segments and yields canonical absolute path
        resolved = path.resolve(strict=False)
        root_resolved = allowed_root.resolve(strict=False)

        # Ensure path is within allowed root
        try:
            resolved.relative_to(root_resolved)
        except ValueError:
            return PolicyDecision(False, f"Path outside allowed root: {resolved}")

        return PolicyDecision(True, "OK")
    except Exception as e:
        return PolicyDecision(False, f"Canonicalisation failed: {e}")


def reject_symlink(path: Path) -> PolicyDecision:
    """
    Disallows symlinks as per design boundary.
    """
    try:
        if path.is_symlink():
            return PolicyDecision(False, "Symlink rejected")
        return PolicyDecision(True, "OK")
    except Exception as e:
        return PolicyDecision(False, f"Symlink check failed: {e}")
