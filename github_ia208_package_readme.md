# GitHub IA-2(8) FedRAMP Package

Files:
- `github_ia208_evidence_collector.py` — automated evidence collector
- `github_ia208_traceability_matrix.csv` — 3PAO-ready traceability matrix
- `github_ia208_siem_mapping.csv` — SIEM field mapping for Splunk and Sentinel

Quick use:
1. Set `GITHUB_TOKEN` and `GITHUB_ORG`.
2. Run `python3 github_ia208_evidence_collector.py`.
3. Review the generated `github_ia208_evidence_<timestamp>` folder.
