# Guide d'utilisation — voltcrypt

Guide pas a pas. Pour la vue d'ensemble et les details du format, voir
[README.md](README.md).

---

## Sommaire

1. [Installation](#1-installation)
2. [Premier essai en 5 minutes](#2-premier-essai-en-5-minutes)
3. [Le cycle de travail normal](#3-le-cycle-de-travail-normal)
4. [Les 6 commandes en detail](#4-les-6-commandes-en-detail)
5. [Verifier que le chiffrement est correct](#5-verifier-que-le-chiffrement-est-correct)
6. [Chiffrement, pseudonymisation, anonymisation](#6-chiffrement-pseudonymisation-anonymisation)
7. [Cas d'usage concrets](#7-cas-dusage-concrets)
8. [Utiliser voltcrypt depuis un script Python](#8-utiliser-voltcrypt-depuis-un-script-python)
9. [Gerer les cles](#9-gerer-les-cles)
10. [Adapter le comportement](#10-adapter-le-comportement)
11. [Depannage](#11-depannage)
12. [A ne pas faire](#12-a-ne-pas-faire)

---

## 1. Installation

Le projet est gere avec [uv](https://docs.astral.sh/uv/). Si tu ne l'as pas
encore installe :

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
exec $SHELL          # pour que la commande uv soit trouvee
uv --version
```

Ensuite, dans le dossier du projet :

```bash
cd ~/Projects/UNC/cryptography/volume_crypto
uv sync
```

`uv sync` lit [pyproject.toml](pyproject.toml), cree un `.venv/` local et y
installe la seule dependance reelle : `cryptography`. Aucun `pip install`,
aucun `source venv/bin/activate` — l'environnement reste confine au dossier.

Au passage, uv ecrit un fichier `uv.lock` qui fige les versions exactes.
Contrairement a `.venv/`, **ce fichier se versionne** : c'est lui qui garantit
qu'un collaborateur obtiendra exactement le meme environnement que toi.

Verifier que tout marche :

```bash
uv run python -m unittest discover -s tests -t .
```

Attendu : `Ran 80 tests ... OK`. Si les 80 tests passent, l'installation est
bonne.

### Les 3 commandes uv a connaitre

| Commande | Effet |
|---|---|
| `uv sync` | cree/met a jour `.venv` d'apres `pyproject.toml` |
| `uv run <cmd>` | lance `<cmd>` dans cet environnement (fait le `sync` au passage) |
| `uv add <paquet>` | ajoute une dependance au projet et l'installe |

Tu n'as donc jamais a activer l'environnement : **tout passe par `uv run`**.
`uv run main.py encrypt` fonctionne meme apres un `git clone` sur une machine
neuve, sans etape prealable.

> **Sans uv**, le projet reste utilisable : il n'a besoin que de la
> bibliotheque `cryptography` et de Python >= 3.9. `python main.py encrypt`
> fonctionne si elle est deja installee sur le systeme.

---

## 2. Premier essai en 5 minutes

Un fichier d'exemple est deja fourni dans `data/to_encrypt/`. Enchaine les
trois commandes :

```bash
uv run main.py gen-key
uv run main.py encrypt
uv run main.py decrypt
```

Puis verifie que le fichier restitue est identique a l'original :

```bash
diff data/to_encrypt/example_mandible.vtk data/decrypted/example_mandible.vtk && echo "IDENTIQUE"
```

Regarde a quoi ressemble le fichier chiffre :

```bash
head -c 200 data/encrypted/example_mandible.vtk.enc | xxd | head
```

Tu verras `VOLCRYPT` (le magic du format) puis du bruit. Aucune trace du
contenu VTK, ni du nom d'origine.

Quand tu es convaincu, supprime l'exemple et mets tes vraies donnees :

```bash
rm data/to_encrypt/example_mandible.vtk
rm -rf data/encrypted/* data/decrypted/*
```

---

## 3. Le cycle de travail normal

```
   data/to_encrypt/          data/encrypted/          data/decrypted/
   (tes volumes)      ──▶    (les .enc)        ──▶    (restitution)
                    encrypt                 decrypt

                          data/keys/master.key
                    la meme cle sert dans les deux sens
```

**Etape 0 — une seule fois par etude.** Genere la cle :

```bash
uv run main.py gen-key --label "etude CBCT 2026"
```

Sauvegarde-la immediatement ailleurs (voir [section 9](#9-gerer-les-cles)).

**Etape 1 — chiffrer.** Depose tes volumes dans `data/to_encrypt/`, avec les
sous-dossiers que tu veux, puis :

```bash
uv run main.py encrypt
```

Chaque fichier traite s'affiche avec sa taille, sa duree et son debit :

```
  + C_0001_T1.nii.gz  ->  C_0001_T1.nii.gz.enc  (132.5 Mo en 470.2 ms, 282 Mo/s)
  + C_0001_T1_Seg_Lower-Teeth.vtk  ->  ...vtk.enc  (875.2 Ko en 2.2 ms, 384 Mo/s)

3 traite(s), 0 ignore(s), 0 en erreur
Duree : 133.3 Mo en 473.2 ms (282 Mo/s)
```

La duree affichee va de l'appel jusqu'au moment ou le fichier est **en place et
exploitable**. Utile pour extrapoler : a 280 Mo/s, une cohorte de 200 CBCT de
130 Mo se chiffre en une minute et demie environ — le disque sera le facteur
limitant, pas le chiffrement.

L'arborescence est preservee :

```
data/to_encrypt/patient_01/T1/scan.nii
        ──▶  data/encrypted/patient_01/T1/scan.nii.enc
```

**Etape 2 — verifier avant de supprimer les originaux.** C'est l'etape que les
gens sautent et regrettent :

```bash
uv run main.py check
```

`check` dechiffre tout en memoire, sans rien ecrire, et compare le sha256 de
chaque fichier a celui enregistre au chiffrement. Si la sortie est `[ok]`, tes
`.enc` sont lisibles et intacts — tu peux transferer ou archiver.

**Etape 3 — restituer.** Sur la machine qui a la cle :

```bash
uv run main.py decrypt
```

---

## 4. Les 6 commandes en detail

### `gen-key` — generer une cle

```bash
uv run main.py gen-key
uv run main.py gen-key --key data/keys/etude_ALI.key --label "etude ALI 2026"
```

| Option | Effet |
|---|---|
| `--key CHEMIN` | ou ecrire la cle (defaut : `data/keys/master.key`) |
| `--label TEXTE` | commentaire libre stocke dans le fichier de cle |
| `--overwrite` | remplacer une cle existante — **dangereux**, voir ci-dessous |

Le fichier produit est un petit JSON en permissions `0600` :

```json
{
  "version": 1,
  "algorithm": "AES-256-GCM",
  "created_utc": "2026-08-14T14:32:10+00:00",
  "label": "etude CBCT 2026",
  "key_b64": "..."
}
```

Sans `--overwrite`, la commande **refuse** d'ecraser une cle existante : ecraser
une cle rend definitivement illisibles tous les fichiers chiffres avec elle.

### `encrypt` — chiffrer un dossier

```bash
uv run main.py encrypt
uv run main.py encrypt -i /media/disque/CBCT -o /media/nas/chiffre
```

| Option | Effet |
|---|---|
| `-i`, `--input` | dossier d'entree (defaut : `data/to_encrypt`) |
| `-o`, `--output` | dossier de sortie (defaut : `data/encrypted`) |
| `--key` | cle a utiliser (defaut : `data/keys/master.key`) |
| `--only-volumes` | ne traiter que les extensions volumiques (voir section 10) |
| `--no-recursive` | ne pas descendre dans les sous-dossiers |
| `--overwrite` | re-chiffrer les fichiers dont le `.enc` existe deja |

Par defaut, un `.enc` deja present est **ignore** (`~` dans la sortie). C'est
volontaire : sur un lot de 800 CBCT interrompu a mi-parcours, relancer la
commande ne refait que le travail restant.

Les fichiers caches (`.DS_Store`) et les `.part` (restes d'une execution
interrompue) sont toujours ignores.

### `decrypt` — dechiffrer un dossier

```bash
uv run main.py decrypt
uv run main.py decrypt -i /media/nas/chiffre -o ~/travail/volumes
```

Memes options que `encrypt`, sans `--only-volumes`.

Le nom du fichier restitue vient des **metadonnees chiffrees**, pas du nom du
`.enc`. Consequence pratique : tu peux renommer librement les conteneurs
(pseudonymes, identifiants d'etude) sans rien casser.

```bash
mv data/encrypted/DUPONT_Jean_T1.nii.enc data/encrypted/SUJ_047.enc
uv run main.py decrypt     # ressort bien DUPONT_Jean_T1.nii
```

### `list` — voir ce que contiennent les `.enc`

```bash
uv run main.py list
```

```
  FICHIER CHIFFRE                 NOM D ORIGINE              TAILLE
  SUJ_047.enc                     DUPONT_Jean_T1.nii         52,428,800 o
```

Ne lit que le bloc de metadonnees, donc instantane meme sur des fichiers de
plusieurs Go. Utile pour retrouver un fichier sans tout dechiffrer.

### `check` — verifier l'integrite

```bash
uv run main.py check
```

Dechiffre chaque fichier vers un temporaire immediatement supprime, et compare
le sha256. Detecte : mauvaise cle, bit corrompu par le transfert reseau,
fichier tronque, conteneur modifie.

A lancer **avant de supprimer les originaux** et **apres tout transfert**
(NAS, rsync, disque externe). Code de retour 1 si un fichier echoue, donc
utilisable dans un script :

```bash
uv run main.py check && rm -rf /media/disque/CBCT_originaux
```

### `audit` — prouver que le chiffrement est effectif

```bash
uv run main.py audit
uv run main.py audit --plain ~/mes_originaux     # si les originaux sont ailleurs
```

`check` repond a « mes fichiers sont-ils relisibles ? ». `audit` repond a la
question inverse : « sont-ils vraiment devenus illisibles ? ». Sept controles
par conteneur :

| Controle | Ce qu'il verifie |
|---|---|
| structure | header `VOLCRYPT` present et coherent |
| entropie | le corps est statistiquement indiscernable d'octets aleatoires (~8,000 bits/octet) |
| signatures format | aucune signature de format (VTK, NIfTI, NRRD, DICOM, HDF5, gzip, STL…) en clair |
| nom d'origine | le nom du fichier n'apparait nulle part en clair |
| round-trip | le dechiffrement redonne exactement le fichier de depart (sha256) |
| identique a l'original | le sha256 du restitue est celui de l'original |
| fuite de fragments | aucun fragment de 32 octets de l'original ne se retrouve dans le conteneur |

Les deux derniers ne s'executent que si l'original est encore disponible.

Sortie sur un vrai CBCT :

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

Sur les tres petits fichiers (< 1 Ko), l'entropie est declaree *non concluante*
plutot que d'echouer a tort : un echantillon aussi court ne permet
statistiquement aucune conclusion. Les six autres controles restent valides.

> **Pourquoi ne pas se contenter de « Slicer n'arrive pas a l'ouvrir » ?**
> Voir la [section 5](#5-verifier-que-le-chiffrement-est-correct).

---

## 5. Verifier que le chiffrement est correct

### « Slicer refuse d'ouvrir le .enc, donc c'est bien chiffre ? »

**Non.** C'est une condition necessaire, pas une preuve. Un fichier tronque,
un fichier corrompu, un fichier rempli de zeros echouent eux aussi a s'ouvrir.
« Illisible par Slicer » et « illisible par un attaquant » sont deux choses tres
differentes.

Un contre-exemple parlant : si on "chiffrait" un volume en inversant chaque
octet (`b ^ 0x42`), Slicer refuserait de l'ouvrir — et pourtant l'operation se
casse en trois lignes de Python. C'est exactement le cas que teste
`test_rejects_xor_style_fake_encryption` dans
[tests/test_audit.py](tests/test_audit.py) : l'audit le rejette, l'ouverture
dans Slicer ne le rejetterait pas.

### Ce qui constitue une vraie verification

Par ordre de force croissante :

1. **`uv run main.py check`** — tout est dechiffrable et le sha256 correspond.
   Repond a « ai-je perdu des donnees ? ».
2. **`uv run main.py audit`** — les sept controles ci-dessus. Repond a
   « la donnee est-elle reellement devenue inaccessible ? ».
3. **La revue du code** — [voltcrypt/crypto.py](voltcrypt/crypto.py) fait
   ~200 lignes commentees. L'algorithme est AES-256-GCM tel qu'implemente par
   la bibliotheque `cryptography` (elle-meme adossee a OpenSSL), pas une
   construction maison.

### Le controle manuel de 10 secondes

```bash
head -c 16 data/to_encrypt/scan.nii.gz | xxd    # 1f 8b 08 ...  <- magic gzip
head -c 16 data/encrypted/scan.nii.gz.enc | xxd # 56 4f 4c ...  <- "VOLCRYPT"
```

Puis cherche une chaine du format dans le conteneur :

```bash
grep -c "vtk DataFile" data/encrypted/mon_maillage.vtk.enc     # doit afficher 0
```

---

## 6. Chiffrement, pseudonymisation, anonymisation

Question distincte de la precedente, et plus importante pour un dossier IRB.

**Un fichier chiffre n'est pas un fichier anonymise.**

Le chiffrement est *reversible par conception* : c'est meme tout son interet.
Tant qu'une cle existe quelque part, la donnee reste rattachable a une
personne. Au sens du RGPD, une donnee chiffree dont tu detiens la cle est une
**donnee a caractere personnel pseudonymisee** — pas une donnee anonyme. Toutes
les obligations continuent de s'appliquer : base legale, information des
personnes, duree de conservation, analyse d'impact, notification en cas de
violation.

| | Reversible ? | Statut RGPD | Ce que ca protege |
|---|---|---|---|
| **Chiffrement** | oui, avec la cle | donnee personnelle | l'acces par un tiers sans la cle |
| **Pseudonymisation** (table de correspondance) | oui, avec la table | donnee personnelle | l'identification directe |
| **Anonymisation** (irreversible) | non | hors RGPD | l'identification, definitivement |
| **Defacing** | non, mais partiel | discute | la reconnaissance faciale du volume |

Ce que le chiffrement t'apporte reellement :

- il **reduit le risque en cas de fuite** : un `.enc` intercepte, un NAS
  compromis, un disque perdu ne livrent rien d'exploitable ;
- il constitue une **mesure technique** au sens de l'article 32 du RGPD, a
  citer dans ton analyse d'impact ;
- il permet, en cas de violation, de faire valoir que les donnees etaient
  inintelligibles — ce qui peut dispenser de l'information des personnes.

Ce qu'il ne fait pas :

- il **ne sort pas la donnee du champ du RGPD** ;
- il **ne dispense pas** de retirer les metadonnees identifiantes DICOM (nom,
  date de naissance, numero d'accession, tags prives, annotations incrustees) —
  a faire *avant* le chiffrement, puisque tout ce que tu chiffres reviendra tel
  quel au dechiffrement ;
- il **ne protege rien pendant le calcul** : des que Slicer, nnU-Net ou ton
  pipeline ouvre le fichier, la donnee est en clair en memoire. C'est
  precisement le probleme que traite [conf_computing.md](../conf_computing.md).

Reponse courte a « est-ce que le fait que ca ne s'ouvre pas dans Slicer prouve
que c'est de-identifie ? » : **non, ca ne prouve meme pas que c'est chiffre**,
et chiffre ne veut de toute facon pas dire de-identifie.

---

## 7. Cas d'usage concrets

### Chiffrer un disque externe sans copier dans `data/`

```bash
uv run main.py encrypt -i /media/luciacev/DISQUE/CBCT_2026 \
                       -o /media/luciacev/DISQUE/CBCT_2026_chiffre
```

Les dossiers `data/` ne sont que des defauts pratiques — rien n'oblige a passer
par eux.

### Une cle differente par etude ou par collaborateur

```bash
uv run main.py gen-key --key data/keys/etude_ALI.key   --label "ALI 2026"
uv run main.py gen-key --key data/keys/etude_AMASSS.key --label "AMASSS 2026"

uv run main.py encrypt --key data/keys/etude_ALI.key -i ~/data/ALI -o ~/chiffre/ALI
```

Interet : transmettre la cle `ALI` a un collaborateur ne lui donne pas acces aux
donnees `AMASSS`. C'est le moyen le plus simple de cloisonner.

### Ignorer les fichiers non volumiques

Si ton dossier contient aussi des `README`, des `.csv` de mesures, des captures
d'ecran, et que tu ne veux chiffrer que l'imagerie :

```bash
uv run main.py encrypt --only-volumes
```

La liste des extensions concernees est `VOLUME_EXTENSIONS` dans
[voltcrypt/config.py](voltcrypt/config.py).

### Envoyer des donnees a un collaborateur

```bash
# 1. Chiffrer
uv run main.py encrypt -i ~/data/etude -o ~/envoi --key data/keys/etude_ALI.key

# 2. Verifier avant envoi
uv run main.py check -i ~/envoi --key data/keys/etude_ALI.key

# 3. Transferer ~/envoi/ par le canal que tu veux (le contenu est chiffre)

# 4. Transmettre la cle par un canal DIFFERENT du canal des donnees :
#    pas le meme mail, pas la meme cle USB, pas le meme partage.
```

Le point 4 est le seul qui compte vraiment pour la securite. Envoyer la cle et
les donnees dans le meme mail annule tout l'interet du chiffrement.

### Archiver a long terme

```bash
uv run main.py encrypt -i ~/etude_2026 -o ~/archive/etude_2026
uv run main.py check -i ~/archive/etude_2026     # ne pas sauter cette etape
```

Puis conserve **avec l'archive** une note indiquant quelle cle la dechiffre
(le `label` de la cle, pas la cle elle-meme). Dans 3 ans, tu ne t'en souviendras
pas.

---

## 8. Utiliser voltcrypt depuis un script Python

### Un fichier

```python
from voltcrypt import crypto, keys

key = keys.load_key("data/keys/master.key")

crypto.encrypt_file("scan.nii.gz", "scan.nii.gz.enc", key)
crypto.decrypt_file("scan.nii.gz.enc", "scan_restaure.nii.gz", key)
```

### Un dossier

```python
from voltcrypt import batch, keys

key = keys.get_or_create_key("data/keys/master.key")   # cree la cle si absente

result = batch.encrypt_directory("mes_volumes/", "chiffres/", key)
print(result.summary())                 # "12 traite(s), 0 ignore(s), 0 en erreur"

for echec in result.failed:
    print(echec.source, echec.error)
```

`encrypt_directory` et `decrypt_directory` retournent un `BatchResult` avec
`.succeeded`, `.skipped`, `.failed` — chaque element portant `.source`,
`.output`, `.ok`, `.error`.

### Recuperer le temps de traitement

`encrypt_file` et `decrypt_file` retournent un objet `Timing` qui porte la
duree, la taille traitee et le chemin produit :

```python
resultat = crypto.encrypt_file("CBCT_full.nii.gz", "CBCT_full.nii.gz.enc", key)

resultat.seconds          # 0.4702        <- le temps demande
resultat.size             # 138908750     <- octets de donnee utile
resultat.mb_per_second    # 281.7
resultat.path             # PosixPath('CBCT_full.nii.gz.enc')
print(resultat)           # CBCT_full.nii.gz.enc : 132.5 Mo en 470.2 ms (282 Mo/s)
```

Le chronometre demarre a l'appel et s'arrete quand le fichier de sortie est
**en place et exploitable** — au `os.replace` qui renomme le `.part` en fichier
final. C'est bien le delai avant de pouvoir ouvrir le volume dans Slicer.

L'objet s'utilise aussi directement comme un chemin :

```python
resultat = crypto.decrypt_file(enc, "scan.nii.gz", key)
volume = nibabel.load(resultat)        # pas besoin de resultat.path
```

Pour un lot :

```python
lot = batch.encrypt_directory("mes_volumes/", "chiffres/", key)

lot.wall_seconds          # duree reelle du lot entier
lot.total_size            # octets traites (les fichiers ignores ne comptent pas)
lot.mb_per_second         # debit moyen
lot.timing_summary()      # '133.3 Mo en 473.2 ms (282 Mo/s)'

for fichier in lot.succeeded:
    print(fichier.output.name, fichier.seconds)   # duree fichier par fichier
```

`wall_seconds` mesure le lot du debut a la fin (parcours des dossiers inclus),
il est donc toujours superieur a la somme des durees par fichier.

Pour chronometrer autre chose — ton propre pre-traitement, un aller-retour
complet — le meme chronometre est disponible seul :

```python
from voltcrypt.timing import Chrono, human_duration

with Chrono() as chrono:
    ... # ce que tu veux mesurer
print(human_duration(chrono.seconds))     # '1 min 15 s'
```

### Barre de progression sur un gros volume

```python
def progression(fait, total):
    print(f"\r{100 * fait // total} %", end="", flush=True)

crypto.encrypt_file("CBCT_full.nii", "CBCT_full.nii.enc", key, progress=progression)
```

### Lire les metadonnees sans dechiffrer

```python
meta = crypto.read_metadata("SUJ_047.enc", key)
print(meta["name"], meta["size"])       # DUPONT_Jean_T1.nii 52428800
```

### Gerer les erreurs proprement

```python
from voltcrypt import crypto, keys

try:
    key = keys.load_key("data/keys/master.key")
    crypto.decrypt_file(src, dst, key)
except keys.KeyError_ as exc:
    print(f"Probleme de cle : {exc}")
except crypto.CryptoError as exc:
    print(f"Fichier illisible : {exc}")   # mauvaise cle, corruption, troncature
```

`decrypt_file` ne laisse jamais de fichier partiel derriere lui en cas d'echec :
l'ecriture se fait dans un `.part` renomme seulement a la toute fin.

---

## 9. Gerer les cles

C'est le seul point ou une erreur est irrattrapable. Trois regles.

**1. Sauvegarde la cle des sa creation, a deux endroits au moins.**

```bash
cp data/keys/master.key /media/cle_usb_hors_ligne/
```

Ou colle le contenu du fichier dans un gestionnaire de mots de passe. Sans la
cle, les fichiers chiffres sont du bruit — il n'existe aucune recuperation, et
c'est le comportement voulu.

**2. Ne la mets jamais dans git, ni dans un partage reseau, ni dans un mail
avec les donnees.** Le [.gitignore](.gitignore) exclut deja `data/keys/` et
`*.key`, mais verifie avant tout `git add` :

```bash
git status --short | grep -i key     # doit ne rien retourner
```

**3. Ne regenere jamais une cle par-dessus une cle utilisee.** `gen-key` refuse
de le faire sans `--overwrite`, justement pour ca. Si tu veux une nouvelle cle,
donne-lui un nouveau nom :

```bash
uv run main.py gen-key --key data/keys/etude_2027.key
```

### Changer de cle sur des fichiers deja chiffres

Il n'y a pas de commande dediee — il faut dechiffrer puis rechiffrer :

```bash
uv run main.py decrypt -i ~/chiffre_ancien -o /tmp/clair --key data/keys/ancienne.key
uv run main.py gen-key --key data/keys/nouvelle.key
uv run main.py encrypt -i /tmp/clair -o ~/chiffre_nouveau --key data/keys/nouvelle.key
uv run main.py check   -i ~/chiffre_nouveau --key data/keys/nouvelle.key
shred -u /tmp/clair/*     # effacer le clair intermediaire
```

Attention : pendant cette operation, les donnees existent en clair dans `/tmp`.
A faire sur une machine de confiance, jamais sur un partage.

---

## 10. Adapter le comportement

Presque tout est dans [voltcrypt/config.py](voltcrypt/config.py) — le reste du
code n'y accede que par ces constantes.

```python
PLAIN_DIR     = DATA_DIR / "to_encrypt"    # dossiers par defaut
ENCRYPTED_DIR = DATA_DIR / "encrypted"
DECRYPTED_DIR = DATA_DIR / "decrypted"
KEYS_DIR      = DATA_DIR / "keys"

CHUNK_SIZE = 4 * 1024 * 1024               # taille des blocs

ENCRYPTED_SUFFIX = ".enc"                  # extension des conteneurs

VOLUME_EXTENSIONS = (".vtk", ".nii", ...)  # filtre de --only-volumes
```

**Ajouter une extension** reconnue par `--only-volumes` : ajoute-la a
`VOLUME_EXTENSIONS`.

**`CHUNK_SIZE`** : 4 Mio est un bon compromis. Le monter (16 Mio) gagne
marginalement en vitesse sur de tres gros volumes et consomme plus de RAM par
fichier ; le descendre (256 Kio) reduit la RAM sur machine contrainte. La valeur
est enregistree dans chaque conteneur, donc **changer `CHUNK_SIZE` ne casse pas
les fichiers deja chiffres** — ils restent lisibles.

**Changer les dossiers par defaut** evite d'avoir a taper `-i` / `-o` a chaque
fois si tu travailles toujours au meme endroit.

---

## 11. Depannage

### `Cle introuvable : .../master.key`

La cle n'a pas encore ete generee, ou tu n'es pas dans le bon dossier.

```bash
cd ~/Projects/UNC/cryptography/volume_crypto
uv run main.py gen-key
```

### `bloc N illisible. Cause probable : mauvaise cle, ou fichier modifie/reordonne`

Dans l'ordre de probabilite :

1. **Mauvaise cle** — le cas le plus frequent. Verifie avec `--key` que tu
   pointes bien celle qui a servi au chiffrement (`uv run main.py list` echoue
   de la meme facon si la cle est mauvaise).
2. **Transfert corrompu** — relance le transfert, puis `check`.
3. **Fichier modifie** — un `.enc` ne se modifie pas ; s'il a ete edite,
   compresse-decompresse, ou ouvert par un logiciel qui l'a reecrit, il est
   perdu.

### `fichier tronque (bloc N manquant)`

Le `.enc` est incomplet : copie interrompue, disque plein pendant le transfert,
ou upload coupe. Recopie-le depuis la source.

### `... existe deja (--overwrite pour ecraser)`

Comportement normal : la sortie existe deja, elle est ignoree. Ajoute
`--overwrite` si tu veux vraiment la refaire.

### `Aucun fichier trouve dans ...`

Le dossier d'entree est vide, ou tu as mis `--only-volumes` et aucune extension
ne correspond, ou tes fichiers sont dans des sous-dossiers et tu as passe
`--no-recursive`.

### Un fichier `.part` traine dans un dossier

C'est le reste d'une execution interrompue. Il est sans valeur et toujours
ignore par les commandes — supprime-le.

### Le chiffrement semble lent

Ordre de grandeur normal sur cette machine : **~320 Mo/s au chiffrement,
~470 Mo/s au dechiffrement**. Nettement en dessous, le goulot est le disque ou
le reseau, pas le chiffrement — teste en local avant de conclure.

---

## 12. A ne pas faire

| A ne pas faire | Pourquoi |
|---|---|
| Supprimer les originaux avant `check` | tu n'as aucune preuve que les `.enc` sont relisibles |
| Envoyer la cle et les donnees par le meme canal | annule entierement l'interet du chiffrement |
| Committer `data/keys/` | la cle se retrouve dans l'historique git, pour toujours |
| `gen-key --overwrite` sur une cle en service | rend illisibles tous les fichiers deja chiffres |
| Compter sur ce script pour proteger la donnee *pendant le calcul* | il protege au repos ; en memoire tout est en clair (cf. [conf_computing.md](../conf_computing.md)) |
| Considerer le chiffrement comme une anonymisation | un volume chiffre reste une donnee de sante ; les obligations RGPD/IRB s'appliquent toujours |

Sur le dernier point : le chiffrement est une **mesure de securite**, pas une
mesure d'anonymisation. Il reduit le risque en cas de fuite, il ne fait pas
sortir la donnee du champ du RGPD.
