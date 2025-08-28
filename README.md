# Zero Trust Cloud IAM Auditor

## Contexte & Motivation

En sécurité cloud, la majorité des attaques et fuites de données sont liées à des mauvaises configurations IAM : droits trop larges, policies permissives ou trust policies ouvertes.
Pour réduire ces risques, les bonnes pratiques imposent le principe du Least Privilege (moindre privilège) : chaque identité (utilisateur, rôle, service) ne doit posséder que les permissions strictement nécessaires à sa fonction, et rien de plus.
Dans les environnements modernes (AWS, GCP, Azure), cela s’inscrit dans la démarche Zero Trust Security :

* Ne jamais faire confiance par défaut (ex. Principal="*" est interdit).
* Toujours limiter les actions (s3:GetObject plutôt que s3:*).
* Ajouter des garde-fous (aws:SourceArn, iam:PassedToService).
* Vérifier et auditer en continu les politiques IAM.

## Objectif du projet

IAM Zero Trust Auditor est un outil en Python qui :
* Analyse automatiquement les policies IAM AWS (JSON).
* Détecte 8 mauvaises pratiques critiques (escalade de privilèges, wildcard, trust policies ouvertes, etc.).
* Calcule un score de conformité basé sur le Principle of Least Privilege.
* Génère des rapports exploitables en Markdown, JSON, SARIF (intégrables en CI/CD, GitHub Code Scanning).
* S’utilise en CLI (iam-auditor scan --cloud aws) pour scanner un fichier ou un dossier de policies.

## Règles de détection IAM (R01 → R08)

IAM Zero Trust Auditor implémente 8 règles de sécurité permettant d’identifier les mauvaises pratiques IAM et de renforcer le principe du Least Privilege.

### R01 — Wildcard Actions
* **Condition** : `Action="*"` ou `Action="service:*"`.
* **Risque** : autorise toutes les API d’un service → risque de contrôle complet.
* **Remédiation** : limiter aux actions nécessaires (`s3:GetObject`, etc.).

### R02 — Wildcard Resources
* **Condition** : `Resource="*"` ou `arn:...:*`.
* **Risque** : permissions appliquées à toutes les ressources.
* **Remédiation** : utiliser des ARNs précis (`arn:aws:s3:::bucket/*`).

### R03 — Admin implicite
* **Condition** : `iam:*`, `s3:*`, `ec2:*` accordés sans restriction.
* **Risque** : équivalent caché à `AdministratorAccess`.
* **Remédiation** : réduire aux opérations strictement nécessaires.

### R04 — PassRole non restreint
* **Condition** : `iam:PassRole` avec `Resource="*"` ou sans condition utile.
* **Risque** : permet d’attribuer des rôles privilégiés → escalade de privilèges.
* **Remédiation** : restreindre à un rôle précis + ajouter `iam:PassedToService`.

### R05 — AssumeRole avec Principal large
* **Condition** : `sts:AssumeRole` avec `Principal="*"` ou `{"AWS":"*"}`.
* **Risque** : n’importe quel compte/service peut assumer le rôle.
* **Remédiation** : limiter le `Principal` à un ARN spécifique.

### R06 — Mutation de policy (escalade)
* **Condition** : `iam:CreatePolicyVersion` ou `iam:PutUserPolicy`.
* **Risque** : modification de policies → ajout de privilèges arbitraires.
* **Remédiation** : interdire ces actions sauf en administration contrôlée.

### R07 — Usage de NotAction / NotResource
* **Condition** : présence de `NotAction` ou `NotResource`.
* **Risque** : logique inverse trop large (ex: “tout sauf X”).
* **Remédiation** : remplacer par une liste explicite d’actions/ressources.

### R08 — Conditions de garde manquantes
* **Condition** : absence de `iam:PassedToService`, `aws:SourceArn` ou `aws:SourceAccount`.
* **Risque** : risque de détournement inter-service (cross-service abuse).
* **Remédiation** : ajouter une condition `StringEquals` sur `iam:PassedToService`, `SourceArn` ou `SourceAccount`.

