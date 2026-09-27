# Profil expérimental iPhone 12 mini

Version : `v0.2.0-profile-test` — 27 septembre 2026.

## Modifications appliquées

| Élément | Avant | Après | Rôle observé |
| --- | --- | --- | --- |
| Modèle dans la liste d'exemptions | `iPhone10,3` | `iPhone13,1` | Critère interne de comparaison |
| Numéro dans la liste d'exemptions | `C39VWAELJCLF` | `LAB12M000002` | Numéro fictif de test, non attribué par Apple |
| Builds des deux entrées d'exemption | `20H115`, `20H364` | `21E236` dans les deux entrées | Aligne ces critères sur le profil iOS 17.4.1 |
| User-Agent, en-têtes fournis ensemble | iPhone X / iOS 16.7.12 | iPhone 12 mini / iOS 17.4.1 | Chaîne utilisée par `_new_setAllHTTPHeaderFields` |
| User-Agent, en-tête fourni individuellement | iPhone 5s / iOS 12.5.7 | Même chaîne iPhone 12 mini / iOS 17.4.1 | Chaîne utilisée par `_new_setValue_forHTTPHeaderField` |

La syntaxe finale est `Snapchat/%@ Beta (iPhone13,1; iOS 17.4.1; gzip)` ; le `%@` de version applicative est conservé. Le profil de données consommé par le script figure dans `profiles/iphone12mini-test.json`.

La combinaison iPhone 12 mini / iOS 17.4.1 / build 21E236 est attestée dans un [rapport de développement publié sur les forums Apple](https://developer.apple.com/forums/thread/764250). Le numéro `LAB12M000002` conserve une longueur de douze caractères mais n'est pas présenté comme un numéro de série Apple valide.

## Ce que ce patch fait et ne démontre pas

Le numéro de série et le modèle de la liste sont consommés par `___SH_ExemptList_block_invoke` dans `SCRT`. Les fonctions `SH_IsExemptDevice` comparent les informations lues avec ces critères. Changer une valeur de comparaison ne remplace pas les valeurs renvoyées par les API de l'appareil.

Le modèle annoncé dans le User-Agent est modifié dans les deux objets CFString concernés. L'utilisation effective de ces chemins pour chaque requête n'a pas été observée sur iOS. Le numéro fictif n'est pas automatiquement injecté dans les requêtes par ce patch. L'UDID de l'ancienne liste et les mécanismes d'IDFV existants ne sont pas modifiés.

Cette version est donc un **patch de constantes de test**, pas un système complet de changement d'identité matérielle. Aucun résultat de connexion ni de passage du blocage simulé SS06 n'est revendiqué.

## DeviceCheck et App Attest

L'exécutable principal référence le framework Apple DeviceCheck. Le framework SCRT contient notamment les noms `SCDeviceCheck`, `SCAttestationManager` et `setIosDeviceCheckToken:`. Ces indices et les anciens hooks ne démontrent pas à eux seuls quel jeton est envoyé, accepté ou refusé pendant une connexion.

Apple décrit `DCDevice` comme le fournisseur d'un jeton authentifié pour interroger ou modifier les données associées à l'appareil. Ce jeton est distinct d'une chaîne User-Agent ou d'une constante de numéro de série : [documentation DeviceCheck](https://developer.apple.com/documentation/devicecheck/dcdevice) et [présentation Apple](https://developer.apple.com/videos/play/wwdc2021/10244/).

Ce correctif conserve toutes les instructions exécutables de SCRT et tous les autres binaires. Il ne crée pas de jeton DeviceCheck/App Attest, ne réactive pas d'ancien hook et ne change pas les contrôles du serveur. Pour tester une nouvelle identité contre le serveur simulé, il reste à observer les champs réellement utilisés par ce serveur et les valeurs réellement transmises par le client.

## Méthode binaire

Le script accepte uniquement l'IPA exacte de `v0.1.0-audit`, contrôlée par SHA-256, puis vérifie l'empreinte du membre `Payload/Snapchat.app/Frameworks/SCRT.framework/SCRT`.

Les nouvelles chaînes tiennent dans les emplacements existants. La longueur CFString du User-Agent est corrigée. L'ancien User-Agent iPhone 5s est trop court pour recevoir la nouvelle chaîne : son objet CFString est redirigé vers la chaîne commune. Le format `DYLD_CHAINED_PTR_64_OFFSET` est vérifié et les bits de chaînage sont conservés. L'ancienne chaîne reste inutilisée dans le stockage binaire.

Le membre ZIP étant non compressé, les modifications sont effectuées à leurs positions exactes dans une copie de l'archive. Seuls les emplacements déclarés dans le rapport et les deux CRC ZIP du membre changent. Aucun décalage d'exécutable ou de section n'est introduit.

## Reproduire

Python 3.10 ou supérieur, bibliothèque standard ; le script réutilise le parseur Mach-O du dépôt. L'IPA est lue mais jamais exécutée.

```bash
python3 scripts/patch_test_profile.py artifacts/Snapchat_unban_SS06.ipa \
  --output artifacts/Sandbox_iPhone12mini_test_a_resigner.ipa \
  --report analysis/iphone12mini-profile-patch.json
```

Utiliser des chemins de sortie libres. Une autre IPA, y compris celle servie actuellement par le lien d'origine si sa signature a changé, est refusée. Une IPA déjà modifiée est également refusée.

## Validation et installation

Le rapport `analysis/iphone12mini-profile-patch.json` contient les anciennes et nouvelles valeurs, offsets, empreintes et le résultat des vérifications. L'archive est relue intégralement : les CRC de chaque membre sont vérifiés et les 8 499 autres entrées sont comparées octet par octet. Les instructions et les métadonnées Mach-O sont inchangées.

**Ressignature complète nécessaire avant installation.** La modification de SCRT invalide sa signature et le scellement des ressources de l'application. Cette IPA est une entrée pour le processus habituel de ressignature du projet ; elle n'est pas présentée comme immédiatement installable. Aucun certificat de signature n'a été utilisé dans cette opération. Aucun lancement sur iPhone ni test réseau n'a été effectué.
