# Sandbox fictif Snapchat

Dépôt privé d'analyse statique de l'IPA fourni par le propriétaire du projet. Premier instantané : **27 septembre 2026**.

## Objectif et statut

Le propriétaire décrit son objectif comme une application Snapchat simulée, reliée à son propre serveur externe, à nettoyer de ses anciens tweaks et fonctions de type Snap++. Il indique aussi la présence d'un mécanisme présenté comme un contournement SS06 et souhaite revoir les contrôles d'appareil.

** les requêtes sont envoyés vers une faux serveur de sandbox Snapchat et non a Snapchat ** L'IPA contient des composants identifiés Snapchat, des références à des domaines Snapchat, des bibliothèques ajoutées et un binaire encodé. Le nom de ce dépôt désigne le projet de simulation 

Cette première version conserve l'original et fournit une base d'audit. L'IPA n'a pas été exécuté, nettoyé, corrigé, resigné ou recompilé. L'efficacité d'un éventuel mécanisme SS06 n'a pas été testée.

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
