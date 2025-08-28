import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
IOLAYER = ROOT / "iolayer"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(IOLAYER) not in sys.path:
    sys.path.insert(0, str(IOLAYER))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from iolayer.parsers.aws_policy_parser import parse_aws_policy, normalize_aws_policy, to_policy_objects
from src.core.engine import run_on_policies
from iolayer.reporters import save_report


def load_policies_from_path(path: Path):
    """Charge un fichier JSON unique OU tous les fichiers JSON d’un dossier."""
    policies = []
    if path.is_file() and path.suffix == ".json":
        raw = parse_aws_policy(str(path))
        norm = normalize_aws_policy(raw, name=path.name)
        policies.append(to_policy_objects(norm, source_path=str(path)))
    elif path.is_dir():
        for f in path.glob("*.json"):
            raw = parse_aws_policy(str(f))
            norm = normalize_aws_policy(raw, name=f.name)
            policies.append(to_policy_objects(norm, source_path=str(f)))
    else:
        raise ValueError(f"Chemin non valide : {path}")
    return policies


def cli():
    parser = argparse.ArgumentParser(
        prog="iam-auditor",
        description="Zero Trust Cloud IAM Auditor (MVP AWS)."
    )
    subparsers = parser.add_subparsers(dest="command")

    # Sous-commande "scan"
    scan = subparsers.add_parser("scan", help="Scanner des policies IAM")
    scan.add_argument("--cloud", required=True, choices=["aws"], help="Cloud provider")
    scan.add_argument("--in", dest="in_path", required=True, help="Fichier ou dossier de policies JSON")
    scan.add_argument("--out", dest="out_dir", default="reports", help="Dossier de sortie (défaut: reports)")

    args = parser.parse_args()

    if args.command == "scan":
        in_path = Path(args.in_path)
        out_dir = Path(args.out_dir)

        policies = load_policies_from_path(in_path)
        if not policies:
            print(f"Aucune policy trouvée dans {in_path}")
            sys.exit(1)

        result = run_on_policies(policies)
        save_report(result, str(out_dir))

        print(f"[OK] Rapport généré dans {out_dir}")
        print(f"  - Findings : {result.summary.total_findings}")
        print(f"  - Score    : {result.summary.score}/100")
    else:
        parser.print_help()


if __name__ == "__main__":
    cli()
