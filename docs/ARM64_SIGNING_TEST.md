# Essai de signature avec SKEngine ARM64

Version expérimentale : `v0.2.3-arm64-signing`.

## Résultat du contrôle v0.2.2

Le nouveau lien Signulous sert une IPA de 214 709 973 octets, modifiée selon
la réponse HTTP le 27 septembre 2026 à 21:12:11 UTC (23:12:11 à Paris).
Son SHA-256 est `62942468789929b5d7174a30f68aa15f1871a2eac1f57cad8d093e5634a80f9e`.

SKEngine est bien présent dans `Frameworks/SKEngine.framework`, et l'app
référence le nouveau chemin. Toutefois, le binaire reste exactement identique
à l'entrée non signée : aucune signature dans ses deux tranches, et aucun
`CodeResources` créé pour ce framework. Le changement d'empaquetage v0.2.2
n'a donc pas suffi.

Les onze autres binaires ont des signatures dont les calculs CMS et les
empreintes contrôlées correspondent. Cela comprend l'app, SCRT et CydiaSubstrate.
52 268 empreintes de pages et 17 137 empreintes de ressources ont été contrôlées
sans incohérence relevée. Voir le [résumé sans données personnelles](../analysis/signulous-v022-result.json).

## Différence isolée par cet essai

SKEngine est le seul fichier universel (`FAT`) du lot, avec deux architectures :
ARM64 et ARM64e. Tous les autres exécutables directement présents sont des
binaires ARM64 simples. Cette différence motive un nouvel essai ; elle ne
prouve pas la cause interne du comportement de Signulous.

Le script extrait uniquement la tranche ARM64 existante (354 720 octets), sans
modifier son contenu. Il supprime donc l'enveloppe universelle et la tranche
ARM64e de ce fichier. L'app principale et ses autres bibliothèques sont déjà
ARM64. Apple décrit ARM64 comme l'architecture des binaires pour appareils iOS
dans sa [documentation des frameworks](https://developer.apple.com/documentation/xcode/creating-a-multi-platform-binary-framework-bundle).

Le framework, son `Info.plist`, ses chemins de chargement et tous les autres
fichiers restent identiques à l'IPA de préparation v0.2.2. Le script vérifie
l'empreinte de la source, celle du binaire et celle de la tranche extraite, puis
relit tous les membres de l'archive. Aucun profil ou certificat personnel issu
du téléchargement Signulous n'est ajouté. Aucun changement DeviceCheck ou
App Attest n'est effectué.

## Reproduire et vérifier

Python 3.11 ou supérieur :

```bash
python3 scripts/prepare_arm64_signing.py artifacts/Sandbox_iPhone12mini_framework_v022.ipa \
  --output artifacts/Sandbox_iPhone12mini_arm64_v023.ipa \
  --report analysis/arm64-preparation-v023.json
```

Importer **ce nouveau fichier** dans Signulous, laisser les options décochées
puis demander une signature complète. Le contrôle suivant doit vérifier la
signature du binaire ARM64 de SKEngine, son signataire et ses ressources.

L'IPA fournie nécessite une ressignature. Cet essai ne garantit pas sa prise
en charge par Signulous ni son installation. Les contrôles statiques ne
vérifient pas la confiance Apple, les révocations ou le comportement sur iPhone.
