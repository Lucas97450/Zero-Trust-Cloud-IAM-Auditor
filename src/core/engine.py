from __future__ import annotations
from typing import List, Dict, Any, Optional

from core.models import (
    Policy, Statement, Permission,
    Finding, Severity, Cloud,
    ScanResult, ScanSummary, compute_score, Effect
)

# services "sensibles" pour R03
ADMIN_SERVICES = {"iam","s3","ec2"}

def _statement_has_action(st: Statement, service: str, action: str) -> bool:
    for p in st.permissions:
        if p.service.lower() == service.lower() and p.action == action:
            return True
    raw = st.raw_provider_obj or {}
    acts = raw.get("Action", []) or []
    if isinstance(acts, str):
        acts = [acts]
    target = f"{service}:{action}".lower()
    for a in acts:
        if isinstance(a, str) and a.lower() == target:
            return True
    return False



def _statement_has_action(st: Statement, service: str, action: str) -> bool:
    """Vrai si le statement contient service:action via permissions OU via l'objet brut normalisé."""
    for p in st.permissions:
        if p.service.lower() == service.lower() and p.action == action:
            return True
    raw = st.raw_provider_obj or {}
    acts = raw.get("Action", []) or []
    if isinstance(acts, str):
        acts = [acts]
    for a in acts:
        if isinstance(a, str) and a.lower() == f"{service}:{action}".lower():
            return True
    return False

def _principal_is_broad(principal: Any) -> bool:
    """
    Retourne True si le Principal est trop large (ex: "*", {"AWS":"*"}, liste contenant "*").
    Conçu pour les trust policies (AssumeRole).
    """
    if principal is None:
        return False
    if isinstance(principal, str):
        return principal.strip() == "*"
    if isinstance(principal, list):
        return any(_principal_is_broad(p) for p in principal)
    if isinstance(principal, dict):
        # AWS / Service / Federated / CanonicalUser -> si une des clés vaut "*"
        for v in principal.values():
            if _principal_is_broad(v):
                return True
    return False

def _passrole_is_restricted(perm: Permission) -> bool:
    """
    "restreint" si scope != "*" ET (condition contient une restriction utile),
    MVP: on accepte toute Condition non vide comme un signe de restriction (améliorable).
    """
    has_scope_restriction = not perm.wildcard_scope()
    has_condition = bool(perm.conditions)
    return has_scope_restriction and has_condition

def _add_finding(
    findings: List[Finding],
    *,
    rid: str,
    title: str,
    description: str,
    severity: Severity,
    policy_name: str,
    statement_index: Optional[int],
    permission: Optional[Permission],
    remediation: str,
    references: Optional[List[str]] = None,
) -> None:
    findings.append(
        Finding(
            id=rid,
            title=title,
            description=description,
            severity=severity,
            policy_name=policy_name,
            statement_index=statement_index,
            permission=permission,
            remediation=remediation,
            references=references or [],
        )
    )


def _rule_R01_wildcard_action(policy: Policy, findings: List[Finding]) -> None:
    """R01: Action wildcard (* ou service:*) -> HIGH"""
    for si, st in enumerate(policy.statements):
        for perm in st.permissions:
            if perm.wildcard_action():
                _add_finding(
                    findings,
                    rid="R01",
                    title="Wildcard Action detected",
                    description="La policy autorise des actions trop larges ('*' ou 'service:*').",
                    severity=Severity.HIGH,
                    policy_name=policy.name,
                    statement_index=si,
                    permission=perm,
                    remediation="Lister explicitement les actions nécessaires (ex: s3:GetObject).",
                    references=[
                        "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
                    ],
                )


def _rule_R02_wildcard_resource(policy: Policy, findings: List[Finding]) -> None:
    """R02: Resource wildcard (*, arn:...:* ou arn:...:/*) -> HIGH - seulement pour regular policies"""
    for si, st in enumerate(policy.statements):
        if st.principal is not None:
            continue
        for perm in st.permissions:
            if perm.wildcard_scope():
                _add_finding(
                    findings,
                    rid="R02",
                    title="Wildcard Resource detected",
                    description="La policy cible des ressources trop larges ('*', 'arn:...:*', 'arn:.../*').",
                    severity=Severity.HIGH,
                    policy_name=policy.name,
                    statement_index=si,
                    permission=perm,
                    remediation="Restreindre la ressource à un ARN précis (ex: arn:aws:s3:::bucket/*).",
                    references=[
                        "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
                    ],
                )


def _rule_R03_admin_implicit(policy: Policy, findings: List[Finding]) -> None:
    """R03: Admin implicite via service sensible + wildcard action -> CRITICAL"""
    for si, st in enumerate(policy.statements):
        for perm in st.permissions:
            if perm.service.lower() in ADMIN_SERVICES and perm.wildcard_action():
                _add_finding(
                    findings,
                    rid="R03",
                    title="Implicit admin on sensitive service",
                    description=(
                        f"Actions larges sur un service sensible ({perm.service}:*), "
                        "équivalent à des droits d’admin implicites."
                    ),
                    severity=Severity.CRITICAL,
                    policy_name=policy.name,
                    statement_index=si,
                    permission=perm,
                    remediation="Remplacer les wildcards par une liste minimale d’actions nécessaires.",
                    references=[
                        "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html"
                    ],
                )


def _rule_R04_passrole_unrestricted(policy: Policy, findings: List[Finding]) -> None:
    """R04: iam:PassRole non restreint (scope '*' ou conditions absentes) -> HIGH/CRITICAL"""
    for si, st in enumerate(policy.statements):
        for perm in st.permissions:
            if perm.service.lower() == "iam" and perm.action == "PassRole":
                if not _passrole_is_restricted(perm):
                    _add_finding(
                        findings,
                        rid="R04",
                        title="PassRole is not properly restricted",
                        description=(
                            "iam:PassRole sans restriction claire (scope '*' et/ou pas de condition). "
                            "Risque de faire exécuter un service avec un rôle trop puissant."
                        ),
                        severity=Severity.HIGH,
                        policy_name=policy.name,
                        statement_index=si,
                        permission=perm,
                        remediation=(
                            "Limiter Resource au rôle attendu (ARN précis) et ajouter une Condition "
                            "(ex: StringEquals: iam:PassedToService)."
                        ),
                        references=[
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html"
                        ],
                    )


def _rule_R05_assumerole_broad_principal(policy: Policy, findings: List[Finding]) -> None:
    """R05: sts:AssumeRole avec Principal trop large -> CRITICAL (trust policy)"""
    for si, st in enumerate(policy.statements):
        if st.effect.value != Effect.ALLOW.value:
            continue

        # Détection robuste d'AssumeRole (permissions OU fallback brut)
        if not _statement_has_action(st, "sts", "AssumeRole"):
            continue

        # Lire Principal depuis l'objet Statement ou depuis le brut si absent
        principal = st.principal
        if principal is None and st.raw_provider_obj:
            principal = st.raw_provider_obj.get("Principal")

        if _principal_is_broad(principal):
            _add_finding(
                findings,
                rid="R05",
                title="AssumeRole with broad Principal",
                description=(
                    "La trust policy permet sts:AssumeRole à un Principal trop large ('*'). "
                    "Tout acteur pourrait assumer ce rôle."
                ),
                severity=Severity.CRITICAL,
                policy_name=policy.name,
                statement_index=si,
                permission=None,
                remediation="Restreindre le Principal à un compte/role/service spécifique (ARN explicite).",
                references=[
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_manage_modify.html#roles-managingrole-editing-trust-policy"
                ],
            )





def run_rules(policy: Policy) -> List[Finding]:
    """Applique l'ensemble des règles R01→R05 à une Policy et retourne la liste des findings."""
    findings: List[Finding] = []
    _rule_R01_wildcard_action(policy, findings)
    _rule_R02_wildcard_resource(policy, findings)
    _rule_R03_admin_implicit(policy, findings)
    _rule_R04_passrole_unrestricted(policy, findings)
    _rule_R05_assumerole_broad_principal(policy, findings)
    return findings

def run_on_policies(policies: List[Policy]) -> ScanResult:
    """Analyse un lot de policies -> Findings + Summary + Score (ScanResult)."""
    all_findings: List[Finding] = []
    cloud: Cloud = policies[0].cloud if policies else Cloud.AWS  # par défaut

    for policy in policies:
        all_findings.extend(run_rules(policy))

    score, counts = compute_score(all_findings)
    summary = ScanSummary(
        cloud=cloud,
        scanned_policies=len(policies),
        total_findings=len(all_findings),
        score=score,
        counts_by_severity=counts,
    )

    return ScanResult(
        policies=policies,
        findings=all_findings,
        summary=summary,
        generator={"name": "iam-auditor", "version": "0.1.0"},
    )