# Préparation d'un nouvel essai de signature

Version expérimentale : `v0.2.1-resign-prep`.

L'IPA examinée après passage par Signulous avait une signature cohérente pour
`SCRT`, mais conservait les anciennes signatures de `CydiaSubstrate.framework`
et de `SKEngine.dylib`. Le fichier `CodeResources` de CydiaSubstrate avait été
réécrit sans recalculer la signature de son exécutable. C'est une incohérence
vérifiée ; aucun journal iOS n'a encore établi la cause exacte du refus observé.

## Ce que contient ce nouvel essai

`Sandbox_iPhone12mini_resign_v021.ipa` est préparée à partir de la release
`v0.2.0-profile-test`, **pas à partir de l'IPA personnelle signée par Signulous**.

- Retrait du bloc de signature et de sa commande `LC_CODE_SIGNATURE` dans
  CydiaSubstrate et dans les deux tranches de SKEngine.
- Ajustement du nombre et de la taille des commandes Mach-O, de la taille
  fichier de `__LINKEDIT` et des tailles des tranches FAT. Les offsets FAT,
  les adresses virtuelles, les sections, les symboles et les dépendances restent
  identiques. La table des chaînes se termine exactement à la fin de chaque
  tranche ; les octets d'alignement précédant l'ancienne signature sont retirés.
- Retrait des deux anciens fichiers `CodeResources` de l'app et de
  CydiaSubstrate, avec leurs entrées de répertoire ZIP. Le signataire doit les
  recréer.
- Nouveau nom de fichier pour distinguer cet essai du téléchargement précédent.
  La compression ZIP réduit sa taille de transfert sans modifier les autres
  fichiers.

Les deux bibliothèques restent présentes. Leurs 94 sections stockées dans les
trois tranches sont préservées, ainsi que les 8 494 autres entrées conservées.
Le framework SCRT, le profil iPhone 12 mini, les fonctionnalités et les
mécanismes DeviceCheck/App Attest ne sont pas modifiés par cette préparation.

Cette opération ne retire **pas** toutes les signatures de l'archive. Les autres
signatures, dont celle de SCRT invalidée par le patch de profil, nécessitent
toujours une ressignature complète. Aucun certificat ni profil issu du
téléchargement Signulous personnel n'est ajouté à cette release.

## Reproduire

Python 3.10 ou supérieur, bibliothèque standard :

```bash
python3 scripts/prepare_resign.py artifacts/Sandbox_iPhone12mini_test_a_resigner.ipa \
  --output artifacts/Sandbox_iPhone12mini_resign_v021.ipa \
  --report analysis/resign-preparation-v021.json
```

Le script exige l'empreinte exacte de l'entrée v0.2.0 et celle de chaque
bibliothèque. Il refuse d'écraser des fichiers existants ou de traiter une IPA
différente. Il vérifie que les droits embarqués des deux bibliothèques sont vides
avant de retirer leurs anciennes signatures. Les binaires ne sont jamais exécutés.

La méthode est cohérente avec le chemin de retrait de signature de
[`codesign_allocate` d'Apple](https://github.com/apple-oss-distributions/cctools/blob/main/misc/codesign_allocate.c) :
supprimer la commande et les données de signature, puis adapter la partie finale
du fichier. L'outil natif Apple n'est pas disponible dans cet environnement ;
son exécution n'est pas revendiquée.

## Vérifications et prochain essai

Le [rapport de préparation](../analysis/resign-preparation-v021.json) contient
les empreintes et les modifications. Le [contrôle indépendant](../analysis/resign-validation-v021.json)
confirme l'absence de signature des trois tranches ciblées, la cohérence des
limites de `__LINKEDIT` et de la table des chaînes, et l'identité de SCRT.
Tous les membres de l'archive de sortie ont été relus et leurs CRC vérifiés.

1. Télécharger **le nouveau fichier** `Sandbox_iPhone12mini_resign_v021.ipa`.
2. L'importer à nouveau dans « Upload & Sign App » de Signulous. Pour isoler ce
   changement, conserver les champs de personnalisation vides et les options
   affichées décochées.
3. Lancer sa signature et récupérer le lien d'installation de cette nouvelle
   entrée. Réutiliser le précédent lien ne sélectionne pas ce nouvel artefact.
4. Contrôler l'IPA de sortie : CydiaSubstrate et les deux tranches de SKEngine
   doivent avoir une signature cohérente avec celle de l'app ; les empreintes
   des ressources doivent correspondre. Ensuite seulement, tester l'installation.

**La sortie fournie ici n'est pas installable sans signature.** Il s'agit d'une
préparation destinée à tester si Signulous reprend correctement ces composants.
L'acceptation par Signulous, la validation Apple et l'installation sur iPhone ne
sont pas encore vérifiées. Le retrait des anciennes signatures ne garantit pas
que le service corrige son traitement des bibliothèques.
