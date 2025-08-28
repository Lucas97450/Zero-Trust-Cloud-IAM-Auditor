from pathlib import Path
from src.core.models import ScanResult

def save_markdown_report(result: ScanResult, out_dir: str):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    lines = []
    lines.append("# IAM Zero Trust Auditor — Rapport de Scan\n")
    lines.append(f"**Cloud:** {result.summary.cloud.value}  ")
    lines.append(f"**Policies scannées:** {result.summary.scanned_policies}  ")
    lines.append(f"**Findings totaux:** {result.summary.total_findings}  ")
    lines.append(f"**Score global:** {result.summary.score} / 100  \n")

    lines.append("## Histogramme par sévérité")
    for s, c in result.summary.counts_by_severity.items():
        lines.append(f"- {s.name}: {c}  ")
    lines.append("\n---\n")

    lines.append("## Détails des Findings\n")
    lines.append("| ID | Sévérité | Policy | Stmt | Titre | Description | Remédiation |")
    lines.append("|:---|:---------|:-------|:-----|:-----|:------------|:------------|")
    for f in result.findings:
        lines.append(
            f"| {f.id} | {f.severity.name} | {f.policy_name} | {f.statement_index or ''} | "
            f"{f.title} | {f.description} | {f.remediation or ''} |"
        )

    (out / "scan.md").write_text("\n".join(lines), encoding="utf-8")
