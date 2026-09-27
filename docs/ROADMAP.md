# Feuille de route

## 1. Établir le périmètre de la simulation

- Obtenir les sources client et serveur, l'adresse du serveur et sa configuration de développement.
- Distinguer les composants du projet des composants tiers, puis vérifier les destinations réseau effectives dans un environnement de test autorisé.
- Définir des comptes et données de test dédiés et un scénario de connexion reproductible.

Critère de fin : une simulation identifiable et reproductible, avec une liste de dépendances et de services validée.

## 2. Préparer le retrait des tweaks

- Cartographier les responsabilités et dépendances de `SCRT`, `SKEngine` et du composant nommé `CydiaSubstrate`.
- Identifier les réglages résiduels, écrans ajoutés, hooks et références de chargement associés.
- Préparer les suppressions à partir des sources quand elles sont disponibles, avec une comparaison avant/après et un moyen de retour arrière.
- Vérifier le lancement, la navigation, les médias, les notifications et les extensions après chaque retrait cohérent.

Critère de fin : les fonctionnalités indésirables ont disparu sans casser les parcours retenus. Supprimer une bibliothèque de l'archive sans traiter ses dépendances ne satisfait pas ce critère.

## 3. Fiabiliser les contrôles d'appareil de la simulation

- Documenter le contrat entre le client de test et le serveur du projet.
- Vérifier les défis, leur expiration, les rejouements, l'association à la session et le traitement des réponses invalides.
- Couvrir les appareils ou environnements non pris en charge, les erreurs réseau et les expirations avec des messages compréhensibles.
- Ajouter des journaux de diagnostic expurgés et distinguer explicitement l'environnement de test de la production.

Critère de fin : tests reproductibles côté client et serveur, erreurs observables et décisions de contrôle conformes au contrat documenté. Cette étape ne peut pas être validée avec le seul IPA.

## État livré

L'IPA original, l'analyse statique et les scripts sont archivés. Le nettoyage, les correctifs de contrôle d'appareil et la validation iOS restent à réaliser après obtention des éléments manquants.
