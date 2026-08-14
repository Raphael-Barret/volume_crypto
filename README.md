# voltcrypt — chiffrement de fichiers volumiques

Chiffrement **AES-256-GCM** de fichiers d'imagerie (`.vtk`, `.nii`, `.nii.gz`,
`.nrrd`, `.mha`, `.dcm`, `.stl`, …), fichier par fichier ou par dossier
complet, avec generation de la cle de dechiffrement.

> **Guide pas a pas, cas d'usage et depannage : [GUIDE_UTILISATION.md](GUIDE_UTILISATION.md).**
> Ce README donne la vue d'ensemble et les details du format.

Concu pour des volumes de plusieurs Go : lecture par blocs de 4 Mio, jamais de
chargement complet en RAM. Mesure sur cette machine : **~320 Mo/s au
chiffrement, ~470 Mo/s au dechiffrement**, pour un surcout de taille de
~2,7 Ko sur 512 Mo.

---

## Installation

Le projet utilise [uv](https://docs.astral.sh/uv/). Si tu ne l'as pas encore :

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Puis, dans ce dossier :

```bash
uv sync     # cree .venv et installe cryptography — c'est tout
```

## Utilisation en 3 commandes

```bash
cd volume_crypto

uv run main.py gen-key      # 1. genere data/keys/master.key  (une seule fois)
uv run main.py encrypt      # 2. data/to_encrypt/  ->  data/encrypted/
uv run main.py decrypt      # 3. data/encrypted/   ->  data/decrypted/
```

`uv run` cree et met a jour l'environnement tout seul — `uv sync` n'est meme
pas obligatoire, la premiere commande s'en charge.

Trois commandes de verification :

```bash
uv run main.py list         # nom d'origine et taille de chaque .enc
uv run main.py check        # « mes fichiers sont-ils relisibles ? »  (cle + sha256)
uv run main.py audit        # « sont-ils vraiment illisibles ? »      (7 controles)
```

`audit` verifie l'entropie du conteneur, l'absence de signature de format ou du
nom d'origine en clair, l'aller-retour sha256, et — si l'original est encore la
— qu'aucun fragment de celui-ci ne se retrouve dans le `.enc`. Voir
[la section dediee du guide](GUIDE_UTILISATION.md#5-verifier-que-le-chiffrement-est-correct).

## Pipeline client / serveur

Une demonstration de bout en bout est fournie : le volume est chiffre sur le
poste, envoye en HTTP, et **la cle n'est remise au serveur qu'apres qu'il a
prouve quel code il execute**.

```bash
uv run server.py                                          # terminal 1
uv run client.py data/to_encrypt/volume.nii.gz --trust-on-first-use   # terminal 2
```

Modifiez une seule ligne de `server.py` et le client refuse de livrer la cle.
Voir [PIPELINE.md](PIPELINE.md) — protocole, garanties et limites.

## Organisation des dossiers

```
volume_crypto/
├── pyproject.toml          # dependances (gerees par uv)
├── main.py                 # ligne de commande
├── server.py               # serveur de traitement (pipeline)
├── client.py               # poste clinique (pipeline)
├── voltcrypt/
│   ├── config.py           # ← chemins, taille de bloc, extensions (a modifier)
│   ├── keys.py             # generation / stockage des cles
│   ├── crypto.py           # chiffrement d'UN fichier (le coeur)
│   ├── batch.py            # chiffrement d'un DOSSIER
│   ├── audit.py            # controles de verification (commande audit)
│   ├── timing.py           # chronometrage et formatage des durees
│   ├── attestation.py      # preuve du code execute (pipeline)
│   └── keyexchange.py      # remise de cle chiffree (pipeline)
├── tests/
│   ├── test_keys.py
│   ├── test_crypto.py
│   ├── test_batch.py
│   ├── test_audit.py
│   ├── test_timing.py
│   └── test_pipeline.py
└── data/
    ├── to_encrypt/         # ← depose tes volumes ici
    ├── encrypted/          # → fichiers .enc
    ├── decrypted/          # → fichiers restitues
    └── keys/               # ← LES CLES. Ne jamais partager, ne jamais commiter.
```

L'arborescence est preservee :
`to_encrypt/patient_01/T1/scan.nii` → `encrypted/patient_01/T1/scan.nii.enc`.

## Options utiles

```bash
# Autres dossiers que ceux par defaut
uv run main.py encrypt -i /media/disque/CBCT -o /media/nas/chiffre

# Une cle par etude
uv run main.py gen-key --key data/keys/etude_ALI.key --label "etude ALI 2026"
uv run main.py encrypt --key data/keys/etude_ALI.key

# Ne chiffrer que les extensions volumiques (ignorer README, .csv, ...)
uv run main.py encrypt --only-volumes

# Re-traiter des fichiers deja produits
uv run main.py encrypt --overwrite
```

Par defaut, un fichier de sortie deja present est **ignore** — relancer la
commande ne refait donc que le travail restant, ce qui est pratique sur un gros
lot interrompu.

## Utilisation depuis Python

```python
from voltcrypt import crypto, keys, batch

key = keys.get_or_create_key("data/keys/master.key")

# Un fichier — le retour porte le chemin ET la duree
resultat = crypto.encrypt_file("scan.nii.gz", "scan.nii.gz.enc", key)
print(resultat.seconds)         # 0.4702
print(resultat)                 # scan.nii.gz.enc : 132.5 Mo en 470.2 ms (282 Mo/s)

crypto.decrypt_file("scan.nii.gz.enc", "scan_restaure.nii.gz", key)

# Un dossier
lot = batch.encrypt_directory("mes_volumes/", "chiffres/", key)
print(lot.wall_seconds, lot.timing_summary())

# Avec barre de progression
crypto.encrypt_file(src, dst, key,
                    progress=lambda fait, total: print(f"\r{100*fait//total} %", end=""))
```

## Tests

```bash
cd volume_crypto
uv run python -m unittest discover -s tests -t . -v     # 108 tests
# ou
uv run pytest tests -v                                 # pytest vient du groupe dev
```

Les tests couvrent l'aller-retour bit a bit (VTK ASCII, binaire, fichier vide,
fichier plus gros que la taille de bloc), le refus d'une mauvaise cle, la
detection d'un bit modifie ou d'une troncature, et le comportement du lot quand
un fichier est corrompu.

---

## Ce que fait le format `.enc`

```
HEADER (21 octets, en clair)
    magic "VOLCRYPT" | version | taille de bloc | nonce_base (8 octets aleatoires)

puis une suite de BLOCS :  [longueur 4 octets][ciphertext || tag GCM 16 octets]

    bloc 0        metadonnees chiffrees : nom d'origine, taille
    bloc 1..n     donnees du fichier
    bloc final    sha256 du contenu en clair
```

- **Nonce** = `nonce_base || index du bloc`. Le `nonce_base` etant tire au hasard
  pour chaque fichier, aucun nonce n'est jamais reutilise avec la meme cle —
  c'est le point critique de GCM.
- **AAD** de chaque bloc = header + index + drapeau « dernier bloc ». Un bloc ne
  peut donc pas etre reordonne, supprime, duplique, ni recopie depuis un autre
  fichier, et une troncature du fichier est detectee.
- **Le nom d'origine est chiffre** : `DUPONT_Jean_CBCT.vtk` n'apparait nulle part
  en clair dans le conteneur. Tu peux renommer librement les `.enc` (par exemple
  en pseudonymes) — `decrypt` retrouve le nom d'origine dans les metadonnees.
- **Ecriture atomique** : chaque sortie est ecrite en `.part` puis renommee. Une
  interruption ne laisse jamais un fichier a moitie ecrit qu'on croirait valide.

## Ce que ce script ne fait pas

- **Il ne protege pas la cle.** `data/keys/master.key` est en clair sur le
  disque, en 0600. Qui lit ce fichier lit tes volumes. Pour de la donnee
  patient reelle : sauvegarde la cle hors ligne, et regarde un KMS / HSM, ou
  la remise de cle conditionnee a une attestation (cf. `../conf_computing.md`).
- **Il ne protege que le repos.** Pendant le calcul, la donnee est en clair en
  memoire.
- **Il n'anonymise pas.** Chiffrer est reversible par conception : une donnee
  chiffree dont tu detiens la cle reste une donnee a caractere personnel au sens
  du RGPD. Retire les metadonnees DICOM identifiantes *avant* de chiffrer — tout
  ce que tu chiffres reviendra tel quel au dechiffrement. Detail en
  [section 6 du guide](GUIDE_UTILISATION.md#6-chiffrement-pseudonymisation-anonymisation).
- **Perdre la cle = perdre les donnees.** Il n'y a pas de recuperation. C'est
  le comportement voulu, mais fais des sauvegardes de `data/keys/`.
- **Pas de compression.** Un `.nii` non compresse chiffre reste aussi gros.
  Compresse avant (`.nii.gz`) si besoin — apres chiffrement, plus rien ne
  compresse.

## Pour adapter

Presque tout se regle dans [`voltcrypt/config.py`](voltcrypt/config.py) :
chemins des dossiers, `CHUNK_SIZE`, extensions reconnues. Le reste du code n'y
touche que par ces constantes.
