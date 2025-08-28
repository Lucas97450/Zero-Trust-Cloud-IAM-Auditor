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

## Règles de Détection (R01 → R08)

#### R01 — Wildcard Actions
Condition : Action="*" ou Action="service:*".
Risque : autorise toutes les API d’un service → contrôle total imprévu.
Exemple : s3:* permet de lister, modifier et supprimer des buckets.
Remédiation : restreindre aux actions précises nécessaires.

#### R02 — Wildcard Resources
Condition : Resource="*" ou arn:...:*.
Risque : accorde des permissions sur toutes les ressources au lieu d’un ARN ciblé.
Exemple : arn:aws:s3:::* → accès à tous les buckets.
Remédiation : utiliser des ARNs spécifiques (arn:aws:s3:::project-data-bucket/*).

R03 — Admin implicite
Condition : accès complet à des services sensibles (iam:*, s3:*, ec2:*).
Risque : permissions équivalentes à AdministratorAccess, souvent non intentionnelles.
Exemple : iam:* → gestion illimitée des rôles et policies IAM.
Remédiation : limiter aux opérations strictement nécessaires (ex. iam:ListRoles).

R04 — PassRole non restreint
Condition : iam:PassRole sans restriction (Resource="*" ou pas de condition utile).
Risque : un utilisateur peut s’attribuer des rôles privilégiés.
Exemple : iam:PassRole sans iam:PassedToService → possibilité de détourner un rôle admin.
Remédiation : restreindre à un rôle précis + ajouter condition iam:PassedToService.

R05 — AssumeRole avec Principal large
Condition : sts:AssumeRole avec Principal="*" ou {"AWS":"*"}.
Risque : n’importe quel compte (ou service externe) peut assumer le rôle.
Exemple : trust policy ouverte → fuite de secrets ou compromission inter-compte.
Remédiation : limiter Principal à un ARN de compte/role précis.

R06 — Mutation de policy (escalade)
Condition : iam:CreatePolicyVersion ou iam:PutUserPolicy.
Risque : un acteur peut modifier une policy existante pour s’octroyer des privilèges.
Exemple : CreatePolicyVersion avec Resource="*" → admin peut être injecté dans n’importe quelle policy.
Remédiation : interdire ces actions sauf cas d’administration strictement contrôlée.

R07 — Usage de NotAction / NotResource
Condition : NotAction ou NotResource utilisé.
Risque : logique inverse dangereuse (ex: “tout sauf X”) qui accorde beaucoup plus que prévu.
Exemple : NotAction=["s3:DeleteBucket"] + Resource="*" → autorise toutes les actions S3 sauf Delete.
Remédiation : remplacer par une liste explicite d’actions/ressources autorisées.

R08 — Conditions de garde manquantes
Condition : absence de clés de sécurité (iam:PassedToService, aws:SourceArn, aws:SourceAccount).
Risque : permissions cross-service sans garde-fou → risque de détournement inter-service.
Exemples :
iam:PassRole sans iam:PassedToService → rôle sensible utilisable partout.
sns:Publish sans aws:SourceArn → n’importe quel service peut publier sur un topic.
Remédiation : ajouter des conditions restrictives (StringEquals sur SourceArn, SourceAccount).
