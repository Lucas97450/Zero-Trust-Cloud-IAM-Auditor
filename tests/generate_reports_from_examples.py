# generate_reports_from_examples.py
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
IOLAYER = ROOT / "iolayer"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(IOLAYER) not in sys.path:
    sys.path.insert(0, str(IOLAYER))


# --- Imports projet ---
import sys
sys.path.insert(0, str(ROOT))

from iolayer.parsers.aws_policy_parser import (
    parse_aws_policy,
    normalize_aws_policy,
    to_policy_objects,
)
from src.core.engine import run_on_policies
from iolayer.reporters import save_report


def main():
    examples_dir = ROOT / "examples" / "aws_policies"
    out_dir = ROOT / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Les mêmes fichiers que dans tes anciens tests
    filenames = [
        "bad_policy.json",
        "good_policy.json",
        "trust_bad.json",
        "passrole_bad.json",
        "admin_bad.json",
    ]

    policies = []
    for fn in filenames:
        path = examples_dir / fn
        if not path.exists():
            print(f"[WARN] Fichier manquant: {path}")
            continue
        raw = parse_aws_policy(str(path))
        norm = normalize_aws_policy(raw, name=fn)
        pol = to_policy_objects(norm, source_path=str(path))
        policies.append(pol)

    if not policies:
        print("Aucune policy chargée, rien à faire.")
        return

    result = run_on_policies(policies)
    save_report(result, str(out_dir))

    print("=== Rapport généré ===")
    print(f"- JSON : {out_dir / 'scan.json'}")
    print(f"- MD   : {out_dir / 'scan.md'}")
    print(f"- Score global : {result.summary.score} / 100")
    print(f"- Findings totaux : {result.summary.total_findings}")
    print("Histogramme par sévérité :")
    for sev, count in result.summary.counts_by_severity.items():
        print(f"  - {sev.name}: {count}")


if __name__ == "__main__":
    main()
