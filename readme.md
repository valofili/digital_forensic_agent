


# 📘 `README.md`

## Digital Forensic Agent — User Guide


## 1. Project Overview

This project implements a **multi-agent digital forensic acquisition system** in Python.  
The system discovers files within a controlled scope, preserves their integrity, records authoritative metadata, and generates audit-ready forensic reports.

### Generated artefacts

-   ZIP evidence archive
    
-   SQLite evidence manifest
    
-   CSV forensic report
    
-   Append-only audit log
    

----------

## 2. Downloading and Extracting the Project

```bash
unzip digital_forensic_agent.zip
cd digital_forensic_agent

```

----------

## 3. Environment Setup

### 3.1 Python Requirements

-   Python **3.10+**
    
-   pip
    

### 3.2 (Optional) Virtual Environment

```bash
python -m venv venv
source venv/bin/activate

```

### 3.3 Install Project in Development Mode

```bash
pip install -e .

```

----------

## 4. Creating Sample Evidence Files

```bash
mkdir sample_evidence
echo "Test evidence file" > sample_evidence/file1.txt
echo "Another document" > sample_evidence/file2.txt

```

----------

## 5. Running the Forensic Agent

```bash
python -m python main.py \
  --root sample_evidence \
  --ext .txt \
  --out forensic_output

```

### Execution Flow

1.  CoordinatorAgent starts a forensic run
    
2.  Surveyor discovers admissible files
    
3.  HasherPacker hashes and archives evidence
    
4.  Scribe generates reports and validation
    
5.  AuditLogger records all actions
    

----------

## 6. Output Artefacts

```text
forensic_output/
├── evidence.zip
├── manifest.db
├── report.csv
└── audit.log

```

----------

## 7. Validating Execution Results

### ZIP Archive

```bash
unzip -l forensic_output/evidence.zip

```

### SQLite Manifest

```bash
sqlite3 forensic_output/manifest.db
SELECT file_path, sha256 FROM evidence_manifest;

```

### CSV Report

Confirm file paths and hashes match the SQLite manifest.

### Audit Log

Each line in `audit.log` represents a forensic event forming a chronological chain of custody.

----------

## 8. Running Unit Tests

```bash
pytest -v

```

All tests should pass.

----------

## 9. Configuration Options (`config.py`)

The system is centrally configured using the `ForensicConfig` class.  
All agents consume this configuration to ensure **consistent policy enforcement**.

----------

### Evidence Scope

```python
allowed_root: Path = Path.home() / "digital_agent_source_files"

```

Restricts evidence collection to a single allow-listed directory.

----------

```python
allowed_extensions: FrozenSet[str] = frozenset({
    ".pdf", ".doc", ".docx", ".txt", ".jpg", "png"
})

```

Defines which file types are admissible.

----------

```python
max_file_size_bytes: int = 50 * 1024 * 1024

```

Prevents collection of excessively large files.

----------

```python
hash_algorithm: str = "sha256"

```

Defines the cryptographic hashing algorithm.

----------

### Output Artefacts

```python
output_dir: Path = Path("outputs")
archive_path: Path = output_dir / "evidence.zip"
sqlite_path: Path = output_dir / "manifest.db"
csv_report_path: Path = output_dir / "report.csv"
audit_log_path: Path = output_dir / "audit.log"

```

Controls where forensic artefacts are stored.

----------

### Case Metadata

```python
case_id: str = "CASE-001"
operator_id: str = "operator-unknown"

```

Associates artefacts with a specific case and operator.

----------

## Appendix A — Assumptions

-   Single-host forensic acquisition
    
-   Read-only evidence access
    
-   Deterministic execution
    

----------

## Appendix B — References

-   Casey, E. (2011). _Digital Evidence and Computer Crime_
    
-   NIST SP 800-86 — _Forensic Techniques Guide_
    

----------

----------

# 📘 `README_DEV.md`

## Digital Forensic Agent — Developer & Architecture Guide

----------

## 1. Architectural Overview

The system follows a **coordinated multi-agent architecture** with a central orchestrator and specialised reactive agents.

### Core Principles

-   Separation of concerns
    
-   Deterministic execution
    
-   Auditability and traceability
    
-   UML-aligned object-oriented design
    

----------

## 2. Project Structure

```text
forensic_agent/
├── cli.py               # Executable entry point
├── coordinator.py       # Orchestrator (BDI-style)
├── surveyor.py          # Discovery agent
├── hasher_packer.py     # Integrity + storage agent
├── scribe.py            # Reporting + validation agent
├── audit.py             # Append-only audit logger
├── policy.py            # Policy enforcement
├── models.py            # Typed domain models
└── config.py            # Central configuration

```

----------

## 3. Agent Responsibilities

### CoordinatorAgent

-   Controls execution flow
    
-   Generates run identifiers
    
-   Aggregates results
    

### Surveyor

-   Discovers files
    
-   Enforces scope, size, extension policies
    

### HasherPacker

-   Computes SHA-256 hashes
    
-   Preserves evidence in ZIP
    
-   Records metadata in SQLite
    

### Scribe

-   Generates CSV reports
    
-   Validates CSV vs SQLite
    

### AuditLogger

-   Maintains chain-of-custody
    

----------

## 4. Agent Communication Model

-   No external message bus
    
-   Communication via:
    
    -   Typed domain objects (`FileMatch`, `StoredEvidence`)
        
    -   Performative-like audit events (`DISCOVERY_START`, `HASHED_STORED`)
        
-   Central orchestration ensures deterministic sequencing
    

----------

## 5. Execution Model

### CLI Entry Point

```bash
python -main.py

```

The CLI is the system boundary and delegates execution to the CoordinatorAgent.

### Service / Daemon Suitability

-   Can be run as:
    
    -   Cron job
        
    -   Background service
        
    -   CI/CD pipeline step
        

----------

## 6. Configuration Design (Developer View)

All behaviour is controlled through `ForensicConfig`.

### Why this matters

-   Single source of truth
    
-   Easy adaptation per case
    
-   No code changes required
    

The configuration fields map directly to forensic controls:

-   Scope restriction (`allowed_root`)
    
-   Admissibility (`allowed_extensions`)
    
-   Integrity (`hash_algorithm`)
    
-   Traceability (`case_id`, `operator_id`)
    

----------

## 7. Deviations from Design Proposal

Proposal Element

Implementation

Message bus

Central orchestration

Distributed agents

Single-host agents

Agent framework

Plain Python

**Justification:**  
Improved determinism, auditability, and forensic reliability.

----------

## Appendix A — Extensibility

The system can be extended to:

-   Distributed agents
    
-   Live acquisition sources
    
-   Cryptographic signing
    
-   Real-time monitoring
    

----------

## Appendix B — References

-   Wooldridge, M. (2009). _An Introduction to Multi-Agent Systems_
    
-   Bell, G. (2020). _Forensic Readiness_
    
-   NIST SP 800-92 — _Logging and Monitoring_
    
