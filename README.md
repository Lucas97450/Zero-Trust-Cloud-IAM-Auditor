# Zero Trust Cloud IAM Auditor

Un scanner de politiques IAM avancé pour détecter les configurations dangereuses et assurer la conformité Zero Trust sur AWS, GCP et Azure.

## 🎯 Objectif

Détecter automatiquement les politiques IAM trop permissives (`*:*`, `*`, etc.) qui représentent des risques d'escalade de privilèges et violeraient les principes Zero Trust.

## 🏗️ Architecture

```
src/
├── scanners/          # Scanners spécifiques aux clouds
│   ├── aws_scanner.py
│   ├── gcp_scanner.py
│   └── azure_scanner.py
├── analyzers/         # Analyse des politiques
│   ├── policy_analyzer.py
│   ├── risk_detector.py
│   └── compliance_checker.py
├── reporters/         # Génération de rapports
│   ├── html_reporter.py
│   ├── json_reporter.py
│   └── csv_reporter.py
└── utils/            # Utilitaires
    ├── iam_parser.py
    └── config.py
```

## 🚀 Installation

```bash
pip install -r requirements.txt
```

## 📋 Fonctionnalités

- [ ] Parsing des politiques IAM (AWS/GCP/Azure)
- [ ] Détection des permissions trop larges
- [ ] Analyse des risques d'escalade
- [ ] Rapports de conformité Zero Trust
- [ ] Intégration CI/CD

## 🔧 Utilisation

```bash
python main.py scan --provider aws --policy-file policy.json
```

## 📊 Exemples

Voir le dossier `examples/` pour des exemples de politiques à analyser.

## 🧪 Tests

```bash
pytest tests/
```

## 📝 TODO

- [ ] Implémenter AWS IAM scanner
- [ ] Implémenter GCP IAM scanner  
- [ ] Implémenter Azure RBAC scanner
- [ ] Créer le détecteur de risques
- [ ] Développer les rapporteurs
- [ ] Ajouter les tests unitaires
- [ ] Documentation complète

## 🤝 Contribution

1. Fork le projet
2. Créer une branche feature
3. Commit les changements
4. Push vers la branche
5. Ouvrir une Pull Request

## 📄 Licence

MIT License


