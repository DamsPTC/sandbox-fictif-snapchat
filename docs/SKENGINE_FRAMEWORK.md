# SKEngine : correction de l'empaquetage

Version expérimentale : `v0.2.2-skengine-framework`.

## Résultat du nouvel essai Signulous v0.2.1

Le lien fourni le 27 septembre 2026 sert cette fois une nouvelle IPA de
214 709 162 octets. L'empreinte est
`e719c7ada405e3bb67ecbd973a5ded19bb6218e9d9b2db42528a5d060409b0ca`.
La réponse HTTP indique une modification à 20:55:24 UTC (22:55:24 à Paris).

- L'app principale, SCRT et CydiaSubstrate ont désormais des signatures dont
  les calculs CMS, les empreintes de pages et les empreintes de métadonnées
  contrôlées correspondent. CydiaSubstrate utilise le même signataire que l'app.
- Les 11 tranches signées contrôlées totalisent 52 268 vérifications de pages,
  sans incohérence relevée. Les 17 135 vérifications de ressources correspondent.
- Les deux tranches de `SKEngine.dylib` n'ont **aucune signature embarquée**.
  Le fichier est exactement celui préparé sans signature en v0.2.1.
- L'app charge encore ce fichier par `@executable_path/SKEngine.dylib`.

Le [résumé du contrôle](../analysis/signulous-v021-result.json) ne contient
ni UDID, ni profil personnel, ni certificat. Cette analyse ne valide pas la
confiance Apple, les révocations, les exigences de code imbriqué ou l'installation.
L'absence de journal iOS empêche d'attribuer avec certitude le message initial
à cette seule anomalie.

## Modification v0.2.2

Apple décrit l'intégration d'une bibliothèque iOS sous forme de framework :
[échange avec le support technique Apple](https://developer.apple.com/forums/thread/670761).
Le fait que Signulous traite les frameworks mais ignore ici la bibliothèque à
la racine motive cet essai ; le fonctionnement interne de Signulous n'est pas
connu et son traitement de ce nouveau fichier reste à vérifier.

La préparation repart de **l'IPA non resignée v0.2.1**, sans importer les
certificats ou profils du téléchargement personnel Signulous.

1. Déplacement de `SKEngine.dylib` vers
   `Payload/Snapchat.app/Frameworks/SKEngine.framework/SKEngine`.
2. Ajout d'un `Info.plist` de framework, avec `CFBundleExecutable=SKEngine`,
   le type `FMWK` et un minimum iOS 16.0 correspondant au binaire existant.
3. Remplacement du chemin de chargement dans l'app par
   `@rpath/SKEngine.framework/SKEngine`. Le chemin `@executable_path/Frameworks`
   existe déjà dans les chemins de recherche de l'app.
4. Mise en cohérence de l'identifiant de bibliothèque dans ses deux tranches.

Le dernier load command de l'app utilise huit octets supplémentaires de
remplissage nul existant. Aucune section, adresse, table de symboles, architecture
ou instruction n'est déplacée. Tous les octets hors des plages de métadonnées
explicitement modifiées sont comparés. Les autres entrées de l'archive sont
préservées et leurs CRC relus. Le contenu de SCRT et le patch de profil v0.2.0
restent inchangés. DeviceCheck et App Attest ne sont pas modifiés.

## Reproduction et limites

Python 3.11 ou supérieur :

```bash
python3 scripts/package_skengine_framework.py artifacts/Sandbox_iPhone12mini_resign_v021.ipa \
  --output artifacts/Sandbox_iPhone12mini_framework_v022.ipa \
  --report analysis/framework-preparation-v022.json
```

Le script exige l'empreinte exacte de l'IPA source et refuse d'écraser les
sorties. Le [rapport](../analysis/framework-preparation-v022.json) précise les
changements et les vérifications.

Cette IPA nécessite toujours une **ressignature complète**, notamment de l'app,
de CydiaSubstrate, de SCRT et du nouveau framework SKEngine. La modification du
chemin de chargement invalide l'ancienne signature de l'app.

Importer le nouveau fichier dans Signulous, conserver les options de
personnalisation décochées puis lancer sa signature. Contrôler ensuite les deux
tranches de `SKEngine.framework/SKEngine`, leur signataire et les ressources du
framework avant de conclure sur la signature. L'exécution iOS et l'installation
ne peuvent pas être validées par ces seuls contrôles statiques.
