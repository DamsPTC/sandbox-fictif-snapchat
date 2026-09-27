# Sandbox fictif Snapchat

Dépôt privé d'analyse statique de l'IPA fourni par le propriétaire du projet. Premier instantané : **27 septembre 2026**.

## Objectif et statut

Le propriétaire décrit son objectif comme une application Snapchat simulée, reliée à son propre serveur externe, à nettoyer de ses anciens tweaks et fonctions de type Snap++. Il indique aussi la présence d'un mécanisme présenté comme un contournement SS06 et souhaite revoir les contrôles d'appareil.

** les requêtes sont envoyés vers une faux serveur de sandbox Snapchat et non a Snapchat ** L'IPA contient des composants identifiés Snapchat, des références à des domaines Snapchat, des bibliothèques ajoutées et un binaire encodé. Le nom de ce dépôt désigne le projet de simulation 

La version `v0.1.0-audit` conserve l'original et fournit une base d'audit. Une version expérimentale `v0.2.0-profile-test` modifie maintenant les constantes de profil dans `SCRT` ; elle doit être resignée et n'a pas été exécutée sur iOS. L'efficacité d'un éventuel mécanisme SS06 n'a pas été testée.

## Essai de signature ARM64 — v0.2.3

La sortie Signulous v0.2.2 laisse encore SKEngine sans signature, même sous
forme de framework. C'est le seul binaire universel ARM64 + ARM64e ; les onze
autres binaires, tous ARM64 simples, ont été resignés. La version expérimentale
**`v0.2.3-arm64-signing`** conserve uniquement la tranche ARM64 existante de
SKEngine, octet pour octet, afin de tester cette différence. Le reste de l'IPA
reste identique à v0.2.2. Télécharger `Sandbox_iPhone12mini_arm64_v023.ipa`
et lancer une nouvelle signature complète. **La cause dans Signulous et
l'installation ne sont pas confirmées.** Voir [l'essai ARM64](docs/ARM64_SIGNING_TEST.md).

## SKEngine sous forme de framework — v0.2.2

Le contrôle de la sortie Signulous v0.2.1 confirme que CydiaSubstrate a été
resigné correctement, mais que les deux architectures de `SKEngine.dylib`
sont restées sans signature. La version **`v0.2.2-skengine-framework`** place
cette bibliothèque dans `Frameworks/SKEngine.framework` et corrige ses chemins
de chargement pour un nouvel essai. Les sections de code et de données restent
identiques. Télécharger `Sandbox_iPhone12mini_framework_v022.ipa` puis le faire
resigner entièrement. **Résultat du contrôle suivant : Signulous n'a pas signé
SKEngine dans cette version.** Voir le [diagnostic et le détail](docs/SKENGINE_FRAMEWORK.md).

## Nouvel essai de signature — v0.2.1

La release **`v0.2.1-resign-prep`** fournit `Sandbox_iPhone12mini_resign_v021.ipa`.
Elle retire les anciennes signatures de CydiaSubstrate et de SKEngine pour
préparer une nouvelle ressignature complète. Les bibliothèques, leurs sections
et le profil iPhone 12 mini sont conservés. **Cette IPA doit être resignée ;
l'installation n'est pas encore validée.** Voir la
[procédure et les limites](docs/RESIGN_PREPARATION.md).

## Profil iPhone 12 mini — version expérimentale

La release **`v0.2.0-profile-test`** contient `Sandbox_iPhone12mini_test_a_resigner.ipa`, le relevé des modifications et ses empreintes.

- Les deux chemins de construction du `User-Agent` utilisent `iPhone13,1` / iOS `17.4.1`.
- La liste d'exemptions interne utilise le modèle `iPhone13,1`, le numéro **fictif** `LAB12M000002` et le build `21E236`.
- Le patch conserve les instructions exécutables et les 8 499 autres entrées de l'archive à l'identique.

**Ce n'est pas un changement de l'identité matérielle ni du jeton Apple DeviceCheck.** La constante de numéro de série appartient à une liste d'exemptions ; elle n'est pas une implémentation de spoofing du numéro transmis au serveur. L'IPA modifiée conserve des signatures devenues invalides et nécessite une ressignature complète avant installation.

Le [détail du patch](docs/DEVICE_PROFILE.md), le [profil utilisé](profiles/iphone12mini-test.json) et le [rapport binaire](analysis/iphone12mini-profile-patch.json) précisent la portée et les vérifications.

## Fichiers à télécharger

Les fichiers volumineux sont joints à la release **`v0.1.0-audit`**, accessible dans la rubrique **Releases** du dépôt.

| Fichier | Contenu |
| --- | --- |
| `Snapchat_unban_SS06.ipa` | IPA original, octets inchangés |
| `Snapchat_desassemblage.zip` | Désassemblages compressés, inventaire, tables de symboles, chaînes extraites, documentation et scripts |
| `SHA256SUMS.txt` | Empreintes des deux fichiers précédents |

Le ZIP de désassemblage ne duplique pas les ressources de l'IPA ni ses exécutables. L'IPA original permet de les extraire avec les scripts. **Le désassemblage n'est pas un projet Xcode ni du code source reconstitué.**

## Empreinte de l'original

Source fournie : <https://neriostore.com/api/download/Snapchat_unban_SS06.ipa>

- Taille : **493 368 978 octets**.
- SHA-256 : `07765d546d122056e985d05d7673f6d2424007f9b69747688769fee7452cad0d`.
- Bundle : `app.neriostore.snapchatunbanss06`.
- Version déclarée : `13.67.1` ; build déclaré : `12.81.0.47`.

Ces valeurs décrivent cet instantané précis. Le contenu du lien de téléchargement peut évoluer.

## Premiers constats

- 8 500 entrées ZIP ; 12 fichiers Mach-O directement présents, soit 13 tranches d'architecture.
- Un Mach-O supplémentaire apparaît après décodage XOR `0x5a` de `Assets.der` : 13 fichiers et 14 tranches au total, binaire dérivé inclus.
- L'exécutable principal référence `SCRT.framework` et `SKEngine.dylib`.
- `CydiaSubstrate.framework` est présent ; son identifiant Mach-O fait référence à `libellekit.dylib`.
- Des références à `DeviceCheck`, `App Attest` et aux domaines simulé Snapchat sont présentes.
- Certaines plages portent un indicateur de chiffrement actif. Elles sont exclues du désassemblage et comptabilisées dans les rapports.

Une bibliothèque ou une chaîne présente ne prouve pas qu'elle est utilisée pendant une connexion. Voir [l'audit initial](docs/AUDIT_INITIAL.md), [la couverture](analysis/COVERAGE.md) et [la feuille de route](docs/ROADMAP.md).

## Organisation

| Chemin | Rôle |
| --- | --- |
| `analysis/summary.json` | Métadonnées de l'IPA et limites de l'analyse |
| `analysis/macho.json` | Architectures, sections, dépendances, chiffrement et couverture |
| `analysis/indicators.json` | Domaines extraits et chaînes sélectionnées ; indices statiques |
| `analysis/archive-files.tsv` | Inventaire complet avec SHA-256, dans le ZIP de release |
| `analysis/symbols/`, `analysis/strings/` | Symboles et chaînes, dans le ZIP de release |
| `disassembly/*.asm.gz` | Désassemblages linéaires, dans le ZIP de release |
| `scripts/` | Reproduction locale de l'analyse |

## Reproduire l'analyse

Prérequis : Python 3.10 ou supérieur et les dépendances de `requirements.txt`. Les commandes lisent des octets ; elles n'exécutent aucun binaire de l'IPA.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 scripts/analyze_ipa.py artifacts/Snapchat_unban_SS06.ipa \
  --output . --disassemble \
  --source-url https://neriostore.com/api/download/Snapchat_unban_SS06.ipa
python3 scripts/analyze_embedded.py --output .
python3 scripts/package_analysis.py --output .
```

Utiliser un dossier de sortie réservé à cette analyse. `analyze_embedded.py` applique uniquement l'encodage observé dans cet échantillon ; il ne constitue pas un déchiffreur générique. Les zones déclarées chiffrées par les en-têtes restent exclues.

Pour lire un désassemblage, décompresser le fichier `.asm.gz` avec un outil compatible gzip. Les adresses sont des adresses virtuelles Mach-O, sans ASLR. Les lignes `.byte` représentent des octets non décodés par Capstone. Un balayage linéaire peut interpréter des données comme des instructions ; il ne reconstruit pas le flux d'exécution.

## Suite du projet

Identifier les sources de l'application et du serveur de simulation, confirmer les destinations réseau effectives, puis planifier le retrait des bibliothèques ajoutées avec des tests de non-régression. La remise en état des contrôles d'appareil doit porter sur les composants effectivement maîtrisés par le projet. Les tâches sont détaillées dans [ROADMAP.md](docs/ROADMAP.md).

Ce projet est privée et les licences appartient au propriétaire du github Damien, ainsi que toutes les simulations et le serveur sandbox. Snapchat n’en est pas le propriétaire, seul son nom est utilisée a titre de test
