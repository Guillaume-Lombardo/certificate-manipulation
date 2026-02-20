# Plan de Développement — `certificate-manipulation` (CLI orientée certificats CA internes)

## Résumé
Construire un package Python centré sur la manipulation de certificats X.509 internes (auto-signés ou CA interne), avec une CLI robuste et déterministe pour:
1. `combine` (agréger plusieurs certificats en bundle),
2. `split` (extraire un bundle en certificats unitaires),
3. `convert` (normaliser/renommer extension PEM/CRT),
puis ajouter `filter` en phase 2.

Décisions verrouillées:
- V1: `combine` + `split` + `convert` (pas de filtre avancé en V1)
- Backend: `cryptography` uniquement
- CLI: sous-commandes explicites
- Formats V1: PEM/CRT (X.509 texte PEM)
- Nommage `split`: basé sur sujet CN
- Nom de commande: `certificate-manipulation` (usage `uv tool run certificate-manipulation ...`)
- Certificat invalide: `fail` par défaut, configurable avec `skip`
- Fichier de sortie existant: versionnement automatique par défaut

## Contrats publics

### CLI
Commande racine:
- `certificate-manipulation <subcommand> [options]`

Sous-commandes V1:
- `combine`
  - `--inputs <path...>`
  - `--recursive`
  - `--output <path>`
  - `--deduplicate`
  - `--sort {input,subject,not_before}`
  - `--on-invalid {fail,skip}`
  - `--overwrite {version,force,fail}`
- `split`
  - `--input <path>`
  - `--output-dir <path>`
  - `--ext {pem,crt}`
  - `--filename-template {cn,index,fingerprint}`
  - `--on-invalid {fail,skip}`
  - `--overwrite {version,force,fail}`
- `convert`
  - `--input <path>`
  - `--output <path>`
  - `--to {pem,crt}`
  - `--overwrite {version,force,fail}`

Préparer la V2:
- `filter` (critères: `subject-cn`, `issuer-cn`, `not-after-lt`, `not-before-gt`, `fingerprint`)

### Interfaces Python
- `CertificateParser`
  - `parse_many_from_text(text: str) -> list[CertificateRecord]`
  - `load_from_file(path: Path) -> list[CertificateRecord]`
- `BundleService`
  - `combine(request: CombineRequest) -> CombineResult`
  - `split(request: SplitRequest) -> SplitResult`
  - `convert(request: ConvertRequest) -> ConvertResult`
- `NamingService`
  - `build_filename(record: CertificateRecord, strategy: NamingStrategy, index: int) -> str`
- `OutputPolicyService`
  - résolution `version/force/fail`

### Types/enums
- `OutputExt`: `PEM`, `CRT`
- `OverwritePolicy`: `VERSION`, `FORCE`, `FAIL`
- `InvalidCertPolicy`: `FAIL`, `SKIP`
- `SplitNamingStrategy`: `CN`, `INDEX`, `FINGERPRINT`
- `SortMode`: `INPUT`, `SUBJECT`, `NOT_BEFORE`

Modèles:
- `CertificateRecord`
- `CombineRequest/Result`
- `SplitRequest/Result`
- `ConvertRequest/Result`
- `OperationReport`

## Architecture cible
- `src/certificate_manipulation/cli.py`
- `src/certificate_manipulation/domain/models.py`
- `src/certificate_manipulation/domain/enums.py`
- `src/certificate_manipulation/services/bundle_service.py`
- `src/certificate_manipulation/services/naming_service.py`
- `src/certificate_manipulation/services/output_policy_service.py`
- `src/certificate_manipulation/adapters/x509_parser.py`
- `src/certificate_manipulation/adapters/fs_io.py`
- `src/certificate_manipulation/exceptions.py`

Flux:
1. CLI parse les options et construit les requêtes.
2. Service valide les contrats et normalise les chemins.
3. Adapter parse les certificats.
4. Service applique dedup/sort/naming/policy invalid.
5. Adapter écrit selon policy overwrite.
6. Retour résultats + logs + code retour CLI.

Codes de sortie:
- `0`: succès
- `1`: erreur de validation
- `2`: erreur d’exécution
- `3`: succès partiel (`skip` + certificats rejetés)

## Phasage
### Phase 1 (MVP)
- Enums + modèles + parser PEM X.509
- Commandes `combine`, `split`, `convert`
- Overwrite policy `version` (`file.crt`, `file.v2.crt`, ...)
- Nommage CN avec fallback `cert-<index>` + sanitation + anti-collision
- Documentation README avec exemples `uv tool run certificate-manipulation ...`

### Phase 2
- Commande `filter`
- Multi-critères en AND
- Rapport `matched/rejected`

### Phase 3
- Observabilité renforcée
- Bench sur gros bundles
- Guide de troubleshooting

## Tests et critères d’acceptation
### Unit
- Parse PEM simple/multiple
- Rejet cert invalide
- Nommage CN + sanitation + collision
- Overwrite `version/force/fail`
- Déduplication par fingerprint
- Conversion `.pem`/`.crt`

### Intégration
- `combine` avec mix valides/invalides (`fail` vs `skip`)
- `split` multi-certs avec collisions CN
- `convert` avec versionnement si sortie existante

### End-to-end
- `combine` sur fixtures
- `split` puis recombine et compare empreintes
- (Phase 2) `filter`

Definition of Done:
- commandes documentées
- tests unit/integration/end2end passants
- `ruff`, `ty`, `pre-commit` passants
- contrats publics documentés

## Assumptions
- V1 limitée à PEM/CRT
- Pas de clés privées en V1
- `filter` en phase 2
- default invalid policy = `fail`
- default overwrite policy = `version`
- usage local filesystem uniquement en V1
