# Zero Trust Cloud IAM Auditor

## Contexte & Motivation

En sécurité cloud, la majorité des attaques et fuites de données sont liées à des mauvaises configurations IAM : droits trop larges, policies permissives ou trust policies ouvertes.
Pour réduire ces risques, les bonnes pratiques imposent le principe du Least Privilege (moindre privilège) : chaque identité (utilisateur, rôle, service) ne doit posséder que les permissions strictement nécessaires à sa fonction, et rien de plus.
Dans les environnements modernes (AWS, GCP, Azure), cela s’inscrit dans la démarche Zero Trust Security :

* Ne jamais faire confiance par défaut (ex. Principal="*" est interdit).
* Toujours limiter les actions (s3:GetObject plutôt que s3:*).
* Ajouter des garde-fous (aws:SourceArn, iam:PassedToService).
* Vérifier et auditer en continu les politiques IAM.
