# Audit initial — 27 septembre 2026

## Méthode

Téléchargement du lien fourni, empreinte SHA-256, lecture des entrées ZIP avec vérification CRC par `zipfile`, extraction des métadonnées plist, parsing des en-têtes Mach-O, inventaire des sections et dépendances, extraction des symboles et chaînes, désassemblage linéaire avec Capstone 5.0.7.

Aucun lancement sur iOS, aucune connexion à un serveur applicatif, aucune interception de trafic et aucune modification de l'IPA. Les chaînes correspondent à des octets présents dans les fichiers et ne démontrent pas un comportement à l'exécution.

## Identité déclarée par les fichiers

| Propriété | Valeur |
| --- | --- |
| Nom affiché / exécutable | Snapchat |
| Bundle ID | `app.neriostore.snapchatunbanss06` |
| Version / build | `13.67.1` / `12.81.0.47` |
| iOS minimum déclaré | `10.0` |
| Taille IPA | 493 368 978 octets |
| Taille cumulée des membres ZIP | 491 177 448 octets |

La version commerciale et le numéro de build sont deux valeurs distinctes. Les seules métadonnées ne permettent pas d'établir la version fonctionnelle réellement chargée.

## Composants à examiner pour le nettoyage

| Composant | Indices observés | Conclusion limitée |
| --- | --- | --- |
| `Snapchat` | Références de chargement à `SCRT.framework`, `SKEngine.dylib`, `DeviceCheck.framework` | Liaisons déclarées par le binaire principal |
| `SKEngine.dylib` | Deux tranches arm64 ; symboles de hooking, abonnement, verrouillage d'application et annonces | Bibliothèque additionnelle comportant ces noms de fonctions/classes ; activation non vérifiée |
| `SCRT.framework/SCRT` | Noms liés aux préférences, à la localisation simulée et aux contrôles d'appareil | Candidat à l'inventaire des modifications ; son rôle exact exige une analyse plus ciblée |
| `CydiaSubstrate.framework/CydiaSubstrate` | Identifiant interne `/usr/local/lib/libellekit.dylib` | Le nom du dossier ne suffit pas à identifier l'implémentation ; présence compatible avec une couche de hooking |
| `Assets.der` | 247 095 024 octets ; XOR `0x5a` du contenu donnant un en-tête Mach-O valide | Binaire encodé conservé comme dérivé analytique ; chargement à l'exécution non démontré |

Ces constats ne suffisent pas à attribuer les fonctionnalités à une version précise de Snap++ ni à certifier un contournement SS06 opérationnel.

## Serveurs et caractère fictif

Des chaînes présentes dans le binaire principal et dans le contenu décodé d'`Assets.der` citent notamment :

- `accounts.snapchat.com`
- `auth.snapchat.com`
- `aws.api.snapchat.com`
- `gcp.api.snapchat.com`

Ces références sont incompatibles avec une **certification sur la seule base de cet audit** que tous les accès seraient limités au serveur du propriétaire. Elles peuvent être utilisées, résiduelles ou remplacées dynamiquement : l'analyse statique ne tranche pas. Le propriétaire décrit une simulation avec serveur propre ; son adresse, ses sources et la configuration de routage n'ont pas été fournies dans cette tâche.

`analysis/indicators.json` fournit un index de recherche, pas une capture réseau. Les correspondances lexicales comme « bypass » peuvent désigner des fonctions sans rapport avec un bannissement et ne sont pas des preuves à elles seules.

## DeviceCheck et App Attest

Le binaire principal déclare le framework Apple `DeviceCheck` et contient des noms liés à `DCAppAttestService`. `SCRT` contient aussi des références aux contrôles d'appareil. Leur présence ne prouve ni qu'un contrôle est correctement implémenté, ni qu'il est neutralisé.

Pour diagnostiquer une simulation réellement maîtrisée : obtenir le code client/serveur, la configuration de l'environnement, les erreurs observées et des journaux expurgés ; vérifier ensuite le traitement des appareils non pris en charge, des erreurs réseau, des réponses invalides et de l'expiration des défis. Aucun correctif de contrôle d'appareil n'est livré dans cet instantané.

## Limites du désassemblage

Le désassemblage porte sur les sections marquées comme contenant des instructions dans les en-têtes Mach-O. Les portions déclarées chiffrées par un `cryptid` actif sont omises, même si leurs octets ressemblent à des instructions. Aucune tentative de déchiffrement FairPlay n'est effectuée. Le décodage XOR d'`Assets.der` ne supprime pas ce chiffrement déclaré.

Les totaux, portions exclues et octets non décodés figurent dans [COVERAGE.md](../analysis/COVERAGE.md) et `analysis/macho.json`. Les symboles absents, le code produit dynamiquement et les instructions non reconnues ne sont pas reconstitués. La réussite du parsing et du décodage linéaire ne garantit pas une interprétation sémantique correcte.

Les binaires extraits et le dérivé XOR peuvent être reproduits à partir de l'IPA ; ils ne sont pas dupliqués dans le ZIP d'analyse.
