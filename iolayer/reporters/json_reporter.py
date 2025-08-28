import json
from pathlib import Path
from src.core.models import ScanResult

def save_json_report(result: ScanResult, out_dir: str):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    data = {
        "summary": {
            "cloud": result.summary.cloud.value,
            "scanned_policies": result.summary.scanned_policies,
            "total_findings": result.summary.total_findings,
            "score": result.summary.score,
            "counts_by_severity": {s.name: c for s, c in result.summary.counts_by_severity.items()},
        },
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.name,
                "policy_name": f.policy_name,
                "statement_index": f.statement_index,
                "description": f.description,
                "remediation": f.remediation,
                "references": f.references,
            }
            for f in result.findings
        ],
        "generator": result.generator,
    }

    with open(out / "scan.json", "w") as f:
        json.dump(data, f, indent=2)
