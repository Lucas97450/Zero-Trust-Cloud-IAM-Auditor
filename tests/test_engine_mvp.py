# tests/test_engine_mvp.py
from __future__ import annotations
import sys
from pathlib import Path

# --- Prépare le PYTHONPATH pour importer depuis ./src ---
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# --- Imports projet ---
from iolayer.parsers.aws_policy_parser import (
    parse_aws_policy,
    normalize_aws_policy,
    to_policy_objects,
)
from src.core.engine import run_on_policies
from src.core.models import Severity


EXAMPLES = ROOT / "examples" / "aws_policies"


def _scan_one(filename: str):
    """Charge un JSON, normalise, convertit en objets et lance l'engine."""
    raw = parse_aws_policy(str(EXAMPLES / filename))
    norm = normalize_aws_policy(raw, name=filename)
    policy = to_policy_objects(norm, source_path=str(EXAMPLES / filename))
    result = run_on_policies([policy])
    return result


def test_bad_policy_triggers_R01_R02():
    """bad_policy.json: Action='*' + Resource='*' -> R01 (wildcard action) & R02 (wildcard resource)."""
    res = _scan_one("bad_policy.json")
    ids = [f.id for f in res.findings]
    assert "R01" in ids, "R01 (Wildcard Action) devrait être déclenchée"
    assert "R02" in ids, "R02 (Wildcard Resource) devrait être déclenchée"
    # Score non nul
    assert res.summary.score > 0
    # Sanity: pas de CRITICAL attendu ici par défaut
    assert all(f.severity in {Severity.HIGH} for f in res.findings)


def test_admin_bad_triggers_R03():
    """admin_bad.json: iam:* sur * -> R03 (admin implicite) CRITICAL."""
    res = _scan_one("admin_bad.json")
    ids = [f.id for f in res.findings]
    assert "R03" in ids, "R03 (Admin implicite) devrait être déclenchée"
    # Au moins un finding CRITICAL
    assert any(f.severity == Severity.CRITICAL for f in res.findings)
    assert res.summary.score > 0


def test_passrole_bad_triggers_R04():
    """passrole_bad.json: iam:PassRole non restreint -> R04."""
    res = _scan_one("passrole_bad.json")
    ids = [f.id for f in res.findings]
    assert "R04" in ids, "R04 (PassRole non restreint) devrait être déclenchée"
    assert res.summary.score > 0


def test_trust_bad_triggers_R05():
    """trust_bad.json: sts:AssumeRole + Principal='*' -> R05 CRITICAL."""
    res = _scan_one("trust_bad.json")
    ids = [f.id for f in res.findings]
    assert "R05" in ids, "R05 (AssumeRole avec Principal large) devrait être déclenchée"
    assert any(f.severity == Severity.CRITICAL for f in res.findings)
    assert res.summary.score > 0


def test_good_policy_has_no_findings_and_zero_score():
    """good_policy.json: actions ciblées + scope précis + MFA -> aucun finding, score 0."""
    res = _scan_one("good_policy.json")
    assert len(res.findings) == 0, f"Aucun finding attendu, obtenu: {res.findings}"
    assert res.summary.score == 0
