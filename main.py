from forensic_agent.config import ForensicConfig
from forensic_agent.coordinator import CoordinatorAgent


def main() -> None:
    # Ensure output directory exists
    ForensicConfig.output_dir.mkdir(parents=True, exist_ok=True)

    coordinator = CoordinatorAgent(config=ForensicConfig())

    summary = coordinator.run_task(
        root_path=ForensicConfig.allowed_root,
        extensions=set(ForensicConfig.allowed_extensions)
    )

    print("\n=== Digital Forensics Run Summary ===")
    print(f"Run ID: {summary.run_id}")
    print(f"Files processed: {summary.files_processed}")
    print(f"CSV report: {summary.csv_path}")
    print(f"SQLite manifest: {summary.sqlite_path}")
    print(f"ZIP archive: {summary.archive_path}")
    print(f"Audit events: {summary.audited_events}")
    print(f"Validation: {summary.validation_ok} ({summary.validation_message})")


if __name__ == "__main__":
    main()
