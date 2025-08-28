# IAM Zero Trust Auditor — Rapport de Scan

**Cloud:** aws  
**Policies scannées:** 5  
**Findings totaux:** 8  
**Score global:** 100 / 100  

## Histogramme par sévérité
- INFO: 0  
- LOW: 0  
- MEDIUM: 0  
- HIGH: 6  
- CRITICAL: 2  

---

## Détails des Findings

| ID | Sévérité | Policy | Stmt | Titre | Description | Remédiation |
|:---|:---------|:-------|:-----|:-----|:------------|:------------|
| R01 | HIGH | admin_bad.json |  | Wildcard Action detected | La policy autorise des actions trop larges ('*' ou 'service:*'). | Lister explicitement les actions nécessaires (ex: s3:GetObject). |
| R02 | HIGH | admin_bad.json |  | Wildcard Resource detected | La policy cible des ressources trop larges ('*', 'arn:...:*', 'arn:.../*'). | Restreindre la ressource à un ARN précis (ex: arn:aws:s3:::bucket/*). |
| R03 | CRITICAL | admin_bad.json |  | Implicit admin on sensitive service | Actions larges sur un service sensible (iam:*), équivalent à des droits d’admin implicites. | Remplacer les wildcards par une liste minimale d’actions nécessaires. |
| R02 | HIGH | passrole_bad.json |  | Wildcard Resource detected | La policy cible des ressources trop larges ('*', 'arn:...:*', 'arn:.../*'). | Restreindre la ressource à un ARN précis (ex: arn:aws:s3:::bucket/*). |
| R04 | HIGH | passrole_bad.json |  | PassRole is not properly restricted | iam:PassRole sans restriction claire (scope '*' et/ou pas de condition). Risque de faire exécuter un service avec un rôle trop puissant. | Limiter Resource au rôle attendu (ARN précis) et ajouter une Condition (ex: StringEquals: iam:PassedToService). |
| R05 | CRITICAL | trust_bad.json |  | AssumeRole with broad Principal | La trust policy permet sts:AssumeRole à un Principal trop large ('*'). Tout acteur pourrait assumer ce rôle. | Restreindre le Principal à un compte/role/service spécifique (ARN explicite). |
| R01 | HIGH | bad_policy.json |  | Wildcard Action detected | La policy autorise des actions trop larges ('*' ou 'service:*'). | Lister explicitement les actions nécessaires (ex: s3:GetObject). |
| R02 | HIGH | bad_policy.json |  | Wildcard Resource detected | La policy cible des ressources trop larges ('*', 'arn:...:*', 'arn:.../*'). | Restreindre la ressource à un ARN précis (ex: arn:aws:s3:::bucket/*). |