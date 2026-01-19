from forensic_agent.scribe import Scribe
from forensic_agent.models import StoredEvidence


def test_scribe_generates_csv_and_validates(forensic_config, audit_logger):
    forensic_config.output_dir.mkdir(parents=True, exist_ok=True)

    scribe = Scribe(forensic_config, audit_logger)

    dummy = StoredEvidence(
        path=forensic_config.allowed_root / "file.txt",
        sha256="abc",
        size_bytes=10,
        extension=".txt",
        archive_member_name="file.txt"
    )

    scribe.generate_csv("RUN-1", [dummy])

    ok, _ = scribe.validate_csv_vs_sqlite("RUN-1")
    assert ok is False  # SQLite not populated → validation fails as expected
from forensic_agent.scribe import Scribe
from forensic_agent.models import StoredEvidence


def test_scribe_generates_csv_and_validates(forensic_config, audit_logger):
    forensic_config.output_dir.mkdir(parents=True, exist_ok=True)

    scribe = Scribe(forensic_config, audit_logger)

    dummy = StoredEvidence(
        path=forensic_config.allowed_root / "file.txt",
        sha256="abc",
        size_bytes=10,
        extension=".txt",
        archive_member_name="file.txt"
    )

    scribe.generate_csv("RUN-1", [dummy])

    ok, _ = scribe.validate_csv_vs_sqlite("RUN-1")
    assert ok is False  # SQLite not populated → validation fails as expected
