from forensic_agent.surveyor import Surveyor


def test_surveyor_discovers_allowed_files(temp_root, forensic_config, audit_logger):
    file_ok = temp_root / "doc1.txt"
    file_ok.write_text("evidence")

    surveyor = Surveyor(forensic_config, audit_logger)

    matches = surveyor.discover(temp_root, {".txt"})

    assert len(matches) == 1
    assert matches[0].path == file_ok.resolve()
    assert matches[0].extension == ".txt"


def test_surveyor_rejects_wrong_extension(temp_root, forensic_config, audit_logger):
    (temp_root / "doc1.exe").write_text("binary")

    surveyor = Surveyor(forensic_config, audit_logger)

    matches = surveyor.discover(temp_root, {".txt"})

    assert matches == []
