from forensic_agent.coordinator import CoordinatorAgent


def test_coordinator_runs_end_to_end(
    temp_root, forensic_config, audit_logger
):
    (temp_root / "doc.txt").write_text("evidence")

    coordinator = CoordinatorAgent(forensic_config)
    summary = coordinator.run_task(temp_root, {".txt"})

    assert summary.files_processed == 1
    assert summary.archive_path.exists()
    assert summary.audited_events > 0
