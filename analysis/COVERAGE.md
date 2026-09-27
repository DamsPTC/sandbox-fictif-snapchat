# Couverture du désassemblage

Analyse linéaire des sections marquées comme instructions. Les octets exclus correspondent aux plages déclarées chiffrées ; les octets non décodés sont représentés par des lignes `.byte`.

| Binaire | Tranche | Octets des sections | Octets traités | Chiffrés exclus | Non décodés | Instructions |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `ScreenCaptureExtension` | arm64 | 44 844 | 40 748 | 4 096 | 0 | 10 187 |
| `SnapchatHomeScreenWidget` | arm64 | 271 380 | 267 284 | 4 096 | 0 | 66 821 |
| `SnapchatLocationPushExtension` | arm64 | 2 132 | 0 | 2 132 | 0 | 0 |
| `SnapchatShareExt` | arm64 | 385 628 | 381 532 | 4 096 | 0 | 95 383 |
| `SnapchatIntentsExtension` | arm64 | 409 952 | 405 856 | 4 096 | 0 | 101 464 |
| `SnapchatNotificationServiceExt` | arm64 | 245 004 | 240 908 | 4 096 | 0 | 60 227 |
| `Snapchat` | arm64 | 125 724 448 | 125 724 448 | 0 | 6 908 | 31 429 385 |
| `SKEngine.dylib` | arm64 | 193 628 | 193 628 | 0 | 0 | 48 407 |
| `SKEngine.dylib` | arm64e | 217 760 | 217 760 | 0 | 0 | 54 440 |
| `ExtensionsSharedDependencies` | arm64 | 4 297 228 | 4 297 228 | 0 | 60 | 1 074 292 |
| `SCRT` | arm64 | 485 664 | 485 664 | 0 | 0 | 121 416 |
| `CydiaSubstrate` | arm64 | 120 152 | 120 152 | 0 | 0 | 30 038 |
| `snappy` | arm64 | 19 044 | 19 044 | 0 | 0 | 4 761 |
| `Assets.der.xor5a.macho` | arm64 | 153 860 412 | 153 856 316 | 4 096 | 2 284 | 38 463 508 |
| **Total** | | 286 277 276 | 286 250 568 | 26 708 | 9 252 | 71 560 329 |

Les `.asm.gz` comprennent une ligne par instruction ou groupe d’octets non décodés. Les positions de chiffrement et les chemins exacts se trouvent dans `macho.json`. Le comptage ne garantit pas que chaque instruction appartienne à un chemin réellement exécuté.
