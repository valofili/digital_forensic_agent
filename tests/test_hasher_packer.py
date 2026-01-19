import zipfile
import sqlite3
from forensic_agent.hasher_packer import HasherPacker
from forensic_agent.models import FileMatch


def test_hasher_packer_creates_archive_and_manifest(
    temp_root, forensic_config, audit_logger
):
    f = temp_root / "evidence.txt"
    f.write_text("forensic data")

    file_match = FileMatch(
        path=f,
        size_bytes=f.stat().st_size,
        extension=".txt"
    )

    hp = HasherPacker(forensic_config, audit_logger)
    stored = hp.process("RUN-TEST", [file_match])

    assert len(stored) == 1
    assert forensic_config.archive_path.exists()

    with zipfile.ZipFile(forensic_config.archive_path) as zf:
        assert "evidence.txt" in zf.namelist()

    conn = sqlite3.connect(forensic_config.sqlite_path)
    rows = conn.execute("SELECT sha256 FROM evidence_manifest").fetchall()
    conn.close()

    assert len(rows) == 1
