# Protection des données d'imagerie — architecture et garanties

**Document de référence.** Décrit comment les volumes d'imagerie médicale sont
protégés, ce que cette protection garantit, ce qu'elle ne garantit pas, et
comment le vérifier soi-même.

> Version anglaise : [SECURITY.md](SECURITY.md). Elle couvre en plus le cadre
> HIPAA, pertinent pour un IRB américain. Les deux versions doivent être mises à
> jour ensemble.

Destiné à trois lectures différentes :

| Vous êtes | Lisez |
|---|---|
| décideur, DPO, membre d'un comité d'éthique | sections 1, 2 et 7 |
| clinicien ou utilisateur du système | sections 1 à 4 |
| auditeur technique, ingénieur | tout, en particulier les sections 5, 6 et 8 |

---

## 1. En une page

**Le problème.** Analyser un scanner 3D (CBCT, IRM) avec des outils d'IA demande
une puissance de calcul qu'un poste clinique n'a pas. Il faut donc envoyer
l'examen sur un serveur distant. Mais un examen d'imagerie crânienne est une
donnée de santé identifiante : le volume contient le visage du patient, et les
fichiers portent souvent son nom.

**La réponse classique, et sa limite.** L'usage courant est le *defacing* :
effacer numériquement le visage avant l'envoi. C'est une dégradation
irréversible de l'examen, qui supprime des tissus mous parfois utiles au
diagnostic et crée des artefacts près des sinus et de l'os nasal. Et elle ne
constitue pas une anonymisation au sens strict : la ré-identification par
géométrie osseuse reste discutée dans la littérature scientifique.

**Notre approche.** Ne pas dégrader la donnée, mais la rendre inexploitable pour
quiconque n'est pas explicitement autorisé, à chaque étape :

1. **Sur le poste clinique** — l'examen est chiffré avant de quitter la machine.
   Ce qui part sur le réseau est une suite d'octets sans structure lisible.
2. **Pendant le transfert et le stockage** — sans la clé, le fichier ne
   contient aucune information exploitable, y compris le nom du patient.
3. **Pendant le calcul** — le traitement s'exécute dans une enclave matérielle
   dont la mémoire est chiffrée par le processeur lui-même. Ni l'administrateur
   du serveur, ni l'hébergeur, ni le fournisseur cloud ne peuvent lire les
   données pendant leur analyse.
4. **La clé n'est remise qu'à un code prouvé** — le poste clinique ne transmet
   la clé de déchiffrement qu'après avoir reçu une preuve cryptographique,
   signée par le fabricant du processeur, que le serveur exécute exactement le
   programme prévu, dans un environnement isolé.

**Ce que ça change.** On passe d'un argument de dégradation (« on a abîmé la
donnée pour qu'elle ne soit plus identifiante ») à un argument de
**confidentialité vérifiable** (« la donnée est intacte, et voici une preuve
signée que seul le code audité peut y accéder »).

**État d'avancement.** Les points 1 et 2 sont **implémentés, testés et
mesurables aujourd'hui** (section 5). Les points 3 et 4 relèvent d'une
architecture serveur **en cours de conception** (section 6). Ce document
distingue systématiquement les deux.

---

## 2. Les questions qu'on nous pose

### « Chiffrer, c'est comme mettre un mot de passe ? »

Non, et la différence compte. Un mot de passe protège un *accès* : le fichier
reste intact, un logiciel vérifie que vous avez le droit de l'ouvrir. Si on
contourne le logiciel, le fichier est là.

Le chiffrement transforme le *contenu*. Le fichier chiffré ne contient plus
l'examen sous une forme lisible — il contient une suite d'octets dont la
structure a disparu. Il n'y a rien à contourner : sans la clé, il n'existe
aucun moyen connu de retrouver l'image, quel que soit le logiciel utilisé.

Ordre de grandeur : la clé fait 256 bits, soit un nombre à 78 chiffres. Essayer
toutes les combinaisons dépasse ce qui est physiquement réalisable, et cette
affirmation ne repose pas sur notre appréciation : AES-256 est le standard
retenu par l'agence de normalisation américaine (NIST) et utilisé pour protéger
des informations classifiées.

### « Un fichier chiffré, ça veut dire que le patient n'est plus identifiable ? »

**Non**, et c'est le point le plus important de ce document.

Le chiffrement est *réversible par conception* — c'est même tout son intérêt,
puisque le clinicien doit pouvoir relire son examen. Tant qu'une clé existe
quelque part, la donnée reste rattachable à une personne.

Au sens du RGPD, un examen chiffré dont on détient la clé est une **donnée à
caractère personnel pseudonymisée** (art. 4-5), pas une donnée anonyme
(considérant 26). Toutes les obligations continuent de s'appliquer : base
légale, information des personnes, durée de conservation, analyse d'impact.

| | Réversible ? | Statut RGPD | Ce que ça protège |
|---|---|---|---|
| **Chiffrement** | oui, avec la clé | donnée personnelle | l'accès par un tiers sans la clé |
| **Pseudonymisation** | oui, avec la table | donnée personnelle | l'identification directe |
| **Anonymisation** | non | hors RGPD | l'identification, définitivement |
| **Defacing** | non, mais partiel | discuté | la reconnaissance faciale du volume |

Ce que le chiffrement apporte réellement : il réduit fortement le risque en cas
de fuite, il constitue une mesure technique au sens de l'article 32, et il peut
dispenser d'informer les personnes en cas de violation (art. 34-3a), les données
étant rendues incompréhensibles.

### « Qui peut lire mes examens ? »

Aujourd'hui, avec le chiffrement en place : **toute personne détenant le fichier
de clé**, et personne d'autre. La clé ne quitte pas le poste clinique tant que
l'architecture serveur (section 6) n'est pas déployée.

C'est une réponse volontairement précise et limitée. Elle signifie aussi que la
protection de ce fichier de clé est le point critique de tout l'édifice — voir
la section 7 sur les limites.

---

## 3. La chaîne de bout en bout

```
   POSTE CLINIQUE                                      SERVEUR DE CALCUL
   ───────────────                                     ─────────────────

   examen original
   (intact, non dégradé)
        │
        │ retrait des métadonnées identifiantes
        │ (nom, date de naissance, n° d'accession)
        ▼
   chiffrement AES-256-GCM ────── clé K ──────┐
        │                     (reste locale)  │
        ▼                                     │
   fichier .enc                               │  ┌─────────────────────────┐
        │                                     │  │  enclave matérielle     │
        │────────── transfert réseau ─────────┼─▶│  mémoire chiffrée par   │
        │        (contenu illisible)          │  │  le processeur          │
        │                                     │  │                         │
        │◀───── preuve d'attestation ─────────┼──┤  prouve quel code       │
        │       signée par le fabricant       │  │  elle exécute           │
        │                                     │  │                         │
        │  vérification de la preuve          │  │                         │
        │  (mesure du code, isolement,        │  │                         │
        │   versions de firmware)             │  │                         │
        │                                     │  │                         │
        └────── K, chiffrée pour l'enclave ───┼─▶│  déchiffre en mémoire   │
                                              │  │  analyse (IA)           │
                                              │  │  rechiffre le résultat  │
   résultat déchiffré localement ◀────────────┼──┤  efface, se détruit     │
                                              │  └─────────────────────────┘
```

Le point à retenir : **la clé n'est envoyée qu'après vérification**, et elle est
chiffrée spécifiquement pour l'enclave qui a fourni la preuve. Une copie
interceptée est inutilisable.

---

## 4. Ce qui est protégé, et contre qui

Un système de sécurité ne se décrit pas dans l'absolu : il se décrit face à un
adversaire donné. Voici la liste explicite.

| Situation | Protégé ? | Pourquoi |
|---|---|---|
| Vol ou perte d'un disque contenant les fichiers chiffrés | **oui** | sans la clé, aucune information exploitable |
| Interception du transfert réseau | **oui** | le contenu transféré est déjà chiffré |
| Serveur de stockage compromis | **oui** | les fichiers y sont stockés chiffrés |
| Sauvegardes exposées par erreur | **oui** | même raison |
| Administrateur système du serveur de calcul | **oui, avec le TEE** (section 6) | la mémoire est chiffrée par le processeur |
| Hébergeur ou fournisseur cloud | **oui, avec le TEE** | l'hyperviseur est exclu du périmètre de confiance |
| Vol du fichier de clé sur le poste clinique | **non** | qui détient la clé lit les données |
| Poste clinique compromis avant chiffrement | **non** | la donnée y est en clair par nature |
| Personne autorisée qui exfiltre volontairement | **non** | relève du contrôle d'accès et de la traçabilité, pas du chiffrement |

Cette dernière colonne est ce qu'un audit sérieux regarde en premier. Un système
qui prétend tout protéger n'a pas été analysé.

---

## 5. Niveau 1 — le chiffrement des fichiers (en place)

### Ce qui est utilisé

**AES-256 en mode GCM.** AES est normalisé par le NIST (FIPS 197) ; le mode GCM
l'est également (SP 800-38D). Ce ne sont pas des choix maison : c'est ce
qu'utilisent TLS, le chiffrement de disque et les principaux fournisseurs cloud.

Le mode GCM apporte une propriété qui va au-delà de la confidentialité :
l'**authentification**. Une modification d'un seul bit dans un fichier chiffré
est détectée au déchiffrement, qui échoue au lieu de produire une image
silencieusement corrompue. Pour de l'imagerie diagnostique, cette garantie
d'intégrité vaut autant que la confidentialité.

**Aucune cryptographie n'a été écrite pour ce projet.** Les opérations
cryptographiques sont déléguées à la bibliothèque `cryptography` de la Python
Cryptographic Authority, adossée à OpenSSL. Le code du projet organise les
appels ; il n'implémente aucun algorithme. C'est une exigence de base : la
cryptographie maison est la première cause d'échec des systèmes de ce type.

### Les propriétés obtenues

- **Le nom du patient ne fuit pas par le nom de fichier.** Le nom d'origine est
  stocké *à l'intérieur* de la zone chiffrée. Un fichier
  `DUPONT_Jean_CBCT.vtk` devient un conteneur où la chaîne « DUPONT »
  n'apparaît nulle part. Les fichiers peuvent être renommés en pseudonymes sans
  perte : le nom réel est restitué au déchiffrement.
- **Deux chiffrements du même examen produisent deux fichiers différents.**
  Comparer deux fichiers chiffrés ne permet pas de savoir s'ils contiennent le
  même examen.
- **Le réordonnancement, la troncature et la substitution de blocs sont
  détectés.** Chaque bloc est authentifié avec sa position et un marqueur de
  fin ; un bloc ne peut pas être déplacé, dupliqué, supprimé, ni recopié depuis
  un autre fichier.
- **Aucun fichier partiel n'est produit.** L'écriture passe par un fichier
  temporaire renommé en fin d'opération. Une coupure de courant ne laisse jamais
  un fichier incomplet qu'on pourrait croire valide.
- **La taille n'augmente pas.** Environ 2,7 Ko ajoutés sur 512 Mo.

### Performance mesurée

Mesures réalisées sur poste de travail Linux, sur un CBCT réel de 132,5 Mo :

| Opération | Débit | Temps sur ce CBCT |
|---|---|---|
| Chiffrement | ~390 Mo/s | 0,34 s |
| Déchiffrement | ~430 Mo/s | 0,31 s |

Le chiffrement n'est donc pas un frein au flux de travail clinique : il coûte
moins qu'une seconde par examen, et le facteur limitant est le disque, pas le
calcul cryptographique.

### Comment le vérifier soi-même

Ces vérifications sont reproductibles par un tiers, sans nous faire confiance.

**1. La suite de tests automatisés.** 80 tests, exécutables en une commande
(`uv run python -m unittest discover -s tests -t .`). Ils couvrent l'aller-retour
bit à bit sur données réelles, le refus d'une mauvaise clé, la détection d'un
bit modifié, la détection d'une troncature, et le comportement en cas de fichier
corrompu au milieu d'un lot.

**2. La commande d'audit intégrée** (`audit`). Elle applique sept contrôles à
chaque fichier chiffré :

| Contrôle | Question posée |
|---|---|
| structure | le conteneur est-il bien formé ? |
| entropie | le contenu est-il statistiquement indiscernable de données aléatoires ? |
| signatures de format | une signature de fichier connue (VTK, NIfTI, DICOM, gzip…) apparaît-elle en clair ? |
| nom d'origine | le nom du fichier est-il lisible dans le conteneur ? |
| aller-retour | le déchiffrement redonne-t-il exactement l'original (empreinte SHA-256) ? |
| identité à l'original | l'empreinte du fichier restitué est-elle celle de l'original ? |
| fuite de fragments | un fragment de l'original se retrouve-t-il tel quel dans le conteneur ? |

Sortie obtenue sur un CBCT réel :

```
  PASS  C_0001_T1.nii.gz.enc
    [ok  ] structure              header VOLCRYPT valide
    [ok  ] entropie               8.000 bits/octet (seuil 7.800)
    [ok  ] signatures format      aucune trouvee
    [ok  ] nom d'origine          'C_0001_T1.nii.gz' absent du conteneur
    [ok  ] round-trip             dechiffre, sha256 verifie, 138,908,750 octets
    [ok  ] identique a l'original sha256 du restitue == sha256 de l'original
    [ok  ] fuite de fragments     0 fragment de l'original dans le conteneur
```

Une entropie de 8,000 bits par octet est la valeur maximale possible : elle
signifie qu'aucune structure statistique n'est décelable dans le fichier.

**3. Le point méthodologique important.** Ces contrôles sont *positifs* : ils
vérifient une propriété attendue. Constater qu'un logiciel de visualisation
refuse d'ouvrir le fichier chiffré ne prouve rien — un fichier corrompu échoue
de la même façon. La suite de tests inclut d'ailleurs des cas de *faux*
chiffrement (fichier en clair simplement renommé, inversion triviale des octets)
et vérifie que l'audit les rejette.

**4. La revue du code.** Le module de chiffrement fait 268 lignes commentées, et
l'ensemble de la bibliothèque moins de 1 000 lignes. C'est lisible en une heure
par un ingénieur, et c'est délibéré : un composant de sécurité qu'on ne peut pas
relire ne peut pas être audité.

---

## 6. Niveau 2 — le traitement en enclave (à déployer)

Cette section décrit l'architecture cible. **Elle n'est pas déployée à ce
jour** ; elle est documentée ici parce qu'elle conditionne la portée des
garanties annoncées.

### Le problème que ça résout

Le chiffrement de la section 5 protège la donnée *au repos* et *en transit*.
Mais pour analyser un examen, il faut bien le déchiffrer quelque part. À cet
instant, sur un serveur ordinaire, l'image est en clair dans la mémoire, et
plusieurs acteurs peuvent la lire : l'administrateur de la machine,
l'hyperviseur qui gère la virtualisation, l'hébergeur. C'est une propriété
structurelle de la virtualisation classique, pas une négligence de
configuration.

### Le principe

Les processeurs récents (AMD SEV-SNP, Intel TDX) intègrent un moteur de
chiffrement entre le processeur et les barrettes mémoire. Les données d'une
machine virtuelle protégée sont chiffrées en mémoire avec une clé **générée
dans le processeur et non extractible** : il n'existe aucune instruction
permettant de la lire, même pour le système d'exploitation hôte. Le
surcoût de performance est de l'ordre de quelques pourcents.

Les cartes graphiques récentes de NVIDIA (H100 et suivantes) offrent un mode
équivalent, nécessaire ici puisque l'analyse par IA s'exécute sur GPU.

### L'attestation : ce qui transforme une confiance en preuve

C'est le mécanisme central, et celui qui a le plus de valeur pour un dossier
réglementaire.

Au démarrage, l'enclave produit un **rapport signé par le processeur** contenant
notamment une empreinte de tout ce qui a été chargé en mémoire (firmware, noyau,
programme), les versions de firmware, et la configuration de sécurité active.
Cette signature remonte à une clé gravée en usine dans la puce et certifiée par
le fabricant.

Concrètement, le poste clinique peut donc vérifier, **avant** de transmettre
quoi que ce soit :

- que le serveur exécute exactement le programme publié et audité, à l'octet
  près — toute modification change l'empreinte ;
- que le mode de débogage est désactivé, qu'aucune migration de la machine
  n'est autorisée, que les contre-mesures aux attaques par canaux auxiliaires
  sont actives ;
- que les versions de firmware ne sont pas des versions vulnérables connues ;
- que la carte graphique est bien en mode confidentiel.

Et surtout : le rapport contient une empreinte de la clé publique de l'enclave.
C'est ce lien qui garantit que la clé de déchiffrement est chiffrée **pour cette
enclave précise**, et non pour un intermédiaire qui relaierait une preuve
obtenue ailleurs.

### Le moment de la remise de clé

La clé n'est jamais déposée à l'avance : ni dans l'image système, ni dans une
variable d'environnement, ni dans un fichier de configuration — tous ces
emplacements sont lisibles par l'administrateur de l'infrastructure.

Elle est **demandée par l'enclave au moment précis où le calcul démarre**,
libérée après vérification, utilisée, puis effacée avec la destruction de la
machine virtuelle. Une machine virtuelle par examen : la fenêtre pendant
laquelle une clé existe en mémoire se compte en minutes.

La vérification n'est pas confiée aux postes cliniques — il faudrait y maintenir
les chaînes de certificats des fabricants et les listes de révocation. Elle est
centralisée dans un service dédié (« courtier de clés ») qui détient les clés et
ne les libère qu'après contrôle. Des implémentations existent, aussi bien en
logiciel libre (Confidential Containers / Trustee) que chez les fournisseurs
cloud.

### La condition non négociable

L'attestation compare une empreinte à une valeur attendue. Encore faut-il
pouvoir calculer cette valeur : cela exige une **construction reproductible** du
logiciel, où le même code source produit toujours la même empreinte, et la
publication signée de ces empreintes à chaque version. Sans cela, l'attestation
ne prouve rien, faute de référence de comparaison.

---

## 7. Limites — ce que ce système ne fait pas

Cette section est délibérément explicite. Un dossier qui n'énonce pas ses
limites est un dossier qu'on ne peut pas évaluer.

**Le chiffrement n'anonymise pas.** Développé en section 2. Les obligations
RGPD demeurent intégralement.

**La clé est le point critique.** Elle est aujourd'hui stockée en clair sur le
poste clinique, dans un fichier accessible à son seul propriétaire. Qui obtient
ce fichier obtient les données. Deux conséquences : sa sauvegarde hors ligne est
indispensable (sa perte rend les examens définitivement illisibles, sans
récupération possible), et sa protection relève de la sécurité du poste, pas de
ce système. Un stockage matériel dédié (HSM) ou un service de gestion de clés
constitue l'amélioration naturelle.

**Le retrait des métadonnées reste à faire en amont.** Le chiffrement conserve
fidèlement tout ce qu'on lui donne, métadonnées identifiantes comprises. Le
nettoyage des en-têtes DICOM (nom, date de naissance, numéro d'accession,
balises privées, annotations incrustées dans l'image) doit précéder le
chiffrement.

**Le poste clinique n'est pas protégé.** Avant chiffrement et après
déchiffrement, l'examen est en clair sur la machine de l'utilisateur. La
sécurité du poste (chiffrement de disque, verrouillage de session, mises à jour)
reste un prérequis.

**Le périmètre de confiance de l'enclave reste large.** Une enclave contient le
système d'exploitation complet et toutes les bibliothèques du programme. Une
faille dans le serveur applicatif contourne entièrement la protection
matérielle. D'où l'exigence d'une image minimale et d'une revue de code.

**La confiance au fabricant subsiste.** AMD, Intel et NVIDIA pourraient, en
théorie, extraire les clés de leurs puces ; une injonction judiciaire aussi.
C'est le compromis assumé de cette technologie : un calcul à vitesse quasi
native en échange d'une confiance dans le fondeur. Les techniques qui
supprimeraient cette hypothèse (chiffrement homomorphe) restent hors de portée
en performance pour de l'imagerie 3D.

**Certains canaux auxiliaires demeurent.** Le contenu de la mémoire est chiffré,
mais pas les *adresses* accédées. Un observateur privilégié peut en théorie
déduire de l'information des motifs d'accès. Pour un réseau de neurones dense,
ces motifs sont dictés par l'architecture du modèle et non par le contenu de
l'examen, ce qui limite fortement la portée de cette attaque — mais elle existe
et doit figurer dans l'analyse d'impact.

**L'attestation prouve l'identité du code, pas sa correction.** Elle certifie
que le programme exécuté est bien celui dont l'empreinte est publiée. Si ce
programme comporte une faille ou enregistre des données là où il ne devrait pas,
l'attestation le certifiera fidèlement. La revue de code reste nécessaire.

---

## 8. Positionnement réglementaire

Éléments pour un dossier RGPD, IRB ou HDS. Ils ne remplacent pas l'avis d'un
délégué à la protection des données.

**Nature des données.** Données de santé, catégorie particulière (art. 9). Le
chiffrement ne change pas cette qualification.

**Mesures techniques (art. 32).** Chiffrement au repos et en transit par
algorithme normalisé NIST ; garantie d'intégrité par chiffrement authentifié ;
protection en cours d'utilisation par enclave matérielle avec attestation à
distance (architecture cible, section 6).

**Violation de données (art. 34-3a).** Les données étant chiffrées par un
procédé de l'état de l'art et la clé n'étant pas compromise, une exposition des
fichiers chiffrés peut être analysée comme ne présentant pas de risque élevé
pour les personnes — appréciation à confirmer au cas par cas avec le DPO.

**Argument clinique en faveur de cette approche.** Le defacing entraîne une
perte d'information diagnostique et des artefacts à proximité des régions
d'intérêt. Le chiffrement préserve l'intégralité de l'examen. Cette préservation
constitue un argument recevable pour justifier une mesure technique alternative
dans une analyse d'impact.

**Traçabilité.** Empreintes SHA-256 conservées pour chaque examen, permettant de
démontrer qu'aucune altération n'est survenue entre le poste clinique et le
résultat.

---

## 9. Glossaire

**AES-256** — algorithme de chiffrement normalisé, avec une clé de 256 bits.
Standard mondial, utilisé notamment pour des informations classifiées.

**Attestation** — procédé par lequel un processeur produit une preuve signée de
ce qu'exécute une machine, vérifiable à distance par un tiers.

**Chiffrement authentifié (GCM)** — mode de chiffrement qui garantit à la fois
que le contenu est illisible et qu'il n'a pas été modifié.

**Clé** — nombre secret de 256 bits sans lequel un fichier chiffré est
inexploitable. Sa perte est irréversible.

**Empreinte (hash, SHA-256)** — signature numérique courte calculée à partir
d'un fichier. Deux fichiers différents produisent deux empreintes différentes ;
elle permet de vérifier qu'un fichier n'a pas changé.

**Enclave / TEE** — zone d'exécution isolée par le matériel, dont la mémoire est
chiffrée par le processeur et inaccessible au système hôte.

**Entropie** — mesure du désordre statistique. Un fichier correctement chiffré
atteint la valeur maximale de 8 bits par octet, indiquant qu'aucune structure
n'est décelable.

**Hyperviseur** — logiciel qui gère les machines virtuelles. Sur une
infrastructure classique, il peut lire la mémoire des machines qu'il héberge ;
les enclaves l'en empêchent.

**Pseudonymisation** — remplacement des identifiants directs, réversible via une
table de correspondance. Reste une donnée personnelle au sens du RGPD.

---

## Références

- FIPS 197 — *Advanced Encryption Standard*, NIST
- NIST SP 800-38D — *Galois/Counter Mode (GCM) and GMAC*
- Règlement (UE) 2016/679 (RGPD), art. 4-5, 9, 32, 34 et considérant 26
- `conf_computing.md` — note technique détaillée sur le calcul confidentiel
  (mécanismes matériels, protocole d'attestation, limites)
- `volume_crypto/README.md` et `volume_crypto/GUIDE_UTILISATION.md` —
  documentation de l'outil de chiffrement
