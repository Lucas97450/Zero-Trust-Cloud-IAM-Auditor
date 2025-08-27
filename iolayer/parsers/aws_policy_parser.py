import json
from typing import Any, Dict, List, Union, Tuple
from src.core.models import Cloud, Effect, Permission, Statement, Policy

AwsJson = Dict[str, Any]
NormalizedStatement = Dict[str, Any]
NormalizedPolicy = Dict[str, Any]

def parse_aws_policy(policy_file: str) -> AwsJson:
    with open(policy_file, "r", encoding="utf-8") as f:
        return json.load(f)


def _ensure_list(value: Union[str, List[str]]) -> List[str]:
    """Si value est une string => [value]. Si liste => la même liste (copie)."""
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    return [str(value)]


def _normalize_statement(stmt: Dict[str, Any]) -> NormalizedStatement:
    """
    Normalise un Statement AWS :
      - Effect: 'Allow'/'Deny' (string)
      - Action(s) [strings]
      - Resource(s) [strings]
      - Condition dict (par défaut {})
      - Principal (optionnel) string ou dict
    """
    effect = str(stmt.get("Effect", "")).strip() or "Allow"
    actions: List[str] = _ensure_list(stmt.get("Action", []))
    not_actions: List[str] = _ensure_list(stmt.get("NotAction", []))
    resources: List[str] = _ensure_list(stmt.get("Resource", []))
    not_resources: List[str] = _ensure_list(stmt.get("NotResource", []))
    condition: Dict[str, Any] = stmt.get("Condition") or {}
    principal = stmt.get("Principal")
    sid = stmt.get("Sid")

    return {
        "Sid": sid,
        "Effect": effect,
        "Action": actions,
        "NotAction": not_actions,
        "Resource": resources,
        "NotResource": not_resources,
        "Condition": condition,
        "Principal": principal,
        "_raw_keys": sorted(list(stmt.keys())),
    }

def normalize_aws_policy(raw: AwsJson, name: str = "") -> NormalizedPolicy:
    """
    Prend une policy AWS brute (dict) -> renvoie une policy **normalisée**:

    {
      "Name": "<optionnel>",
      "Version": "2012-10-17",
      "Statement": [ {Effect, Action[], Resource[], Condition{}, ...}, ... ],
      "Metadata": {...}
    }
    """
    version = str(raw.get("Version", "2012-10-17"))
    stmts = raw.get("Statement", [])
    
    # AWS accepte un Statement unique sous forme d'objet ; on force une liste.
    if isinstance(stmts, dict):
        stmts = [stmts]
    elif not isinstance(stmts, list):
        raise ValueError("Policy 'Statement' doit être un objet ou une liste d'objets.")

    normalized_statements: List[NormalizedStatement] = [
        _normalize_statement(s) for s in stmts
    ]

    return {
        "Name": name or raw.get("PolicyName") or raw.get("Id") or "",
        "Version": version,
        "Statement": normalized_statements,
        "Metadata": {
            "source": "aws_json_file",
            "statement_count": len(normalized_statements),
            "has_wildcard_action": any(
                any(a == "*" or a.endswith("*") for a in st.get("Action", []))
                for st in normalized_statements
            ),
            "has_wildcard_resource": any(
                any(r == "*" or r.endswith(":*") or r.endswith("/*") for r in st.get("Resource", []))
                for st in normalized_statements
            ),
        },
    }


def _split_service_action(sa: str) -> Tuple[str, str]:
    """
    Convertit 'iam:PassRole' -> ('iam', 'PassRole').
    """
    if sa == "*" or not sa:
        return "*","*"
    if ":" not in sa:
        return "*", sa
    service, action = sa.split(":", 1)
    service = service.strip() or "*"
    action = action.strip() or "*"
    return service, action

def _expand_permissions_from_statement(st: Dict[str, Any]) -> List[Permission]:
    """
    Prend un Statement **normalisé** (dict) et produit une liste de Permission.
    Produit le cross-product Action[] x Resource[] avec propagation des 'Condition'.
    """
    effect = (st.get("Effect") or "Allow").strip()
    actions: List[str] = st.get("Action", []) or []
    resources: List[str] = st.get("Resource", []) or []
    condition: Dict[str, Any] = st.get("Condition") or {}

    if not resources:
        resources = ["*"]

    perms: List[Permission] = []
    for a in actions:
        svc, act = _split_service_action(str(a))
        for r in resources:
            perms.append(Permission(service=svc, action=act, scope=str(r), conditions=condition))
    return perms


def to_policy_objects(normalized_policy: Dict[str, Any], source_path: str = "") -> Policy:
    """
    Convertit une policy **normalisée** (celle que retourne normalize_aws_policy)
    en objets internes (Policy, Statement, Permission) prêts pour l'engine.
    """
    name = normalized_policy.get("Name") or ""
    stmts = normalized_policy.get("Statement", []) or []
    statements: List[Statement] = []

    for st in stmts:
        perms = _expand_permissions_from_statement(st)
        effect_str = (st.get("Effect") or "Allow").strip()
        effect = Effect.ALLOW if effect_str.lower() == "allow".lower() else Effect.DENY
        statements.append(
            Statement(
                effect=effect,
                permissions=perms,
                principal=st.get("Principal"),
                sid=st.get("Sid"),
                raw_provider_obj=st,
            )
        )

    meta = dict(normalized_policy.get("Metadata") or {})
    if source_path:
        meta["source_path"] = source_path

    return Policy(
        cloud=Cloud.AWS,
        name=name or (source_path.split("/")[-1] if source_path else "aws_policy"),
        statements=statements,
        source_path=source_path or None,
        metadata=meta,
    )