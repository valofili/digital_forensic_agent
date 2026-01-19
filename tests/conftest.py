import tempfile
from pathlib import Path
import pytest
from forensic_agent.config import ForensicConfig
from forensic_agent.audit import AuditLogger


@pytest.fixture
def temp_root(tmp_path: Path) -> Path:
    """Temporary directory used as forensic root."""
    return tmp_path




@pytest.fixture
def audit_logger(forensic_config: ForensicConfig) -> AuditLogger:
    """Audit logger bound to temporary storage."""
    forensic_config.output_dir.mkdir(parents=True, exist_ok=True)
    return AuditLogger(forensic_config.audit_log_path)
