# Pipeline client / serveur — démonstration de bout en bout

Implémentation fonctionnelle de la chaîne décrite dans
[../SECURITE.md](../SECURITE.md) : un volume est chiffré sur le poste, envoyé
en HTTP à un serveur de traitement, et **la clé n'est remise qu'après que le
serveur a prouvé quel code il exécute**.

Le traitement lui-même est volontairement neutre (le serveur renvoie le volume
inchangé). L'objet de cette démonstration est la chaîne, pas le calcul.

---

## Essai en 3 commandes

Dans deux terminaux, depuis `volume_crypto/` :

```bash
# terminal 1
uv run server.py

# terminal 2
uv run client.py data/to_encrypt/mon_volume.nii.gz --trust-on-first-use
```

Sortie obtenue sur un CBCT réel de 132,5 Mo :

```
[1/7] Chiffrement local de C_0001_T1.nii.gz
      132.5 Mo chiffres en 269.9 ms (491 Mo/s)
      sha256 original : d8dc813d2eb95dc489bf833c3f8f66da...
[2/7] Envoi vers http://127.0.0.1:8000
      job f2e5448d cree — 132.5 Mo transferes en 140.1 ms (946 Mo/s)
      le serveur detient un fichier qu'il ne peut pas lire
[3/7] Demande d'attestation (nonce bca76f6ae65a...)
      mesure annoncee : e20bf2d5ba2d2484e371baf1d686e6b2...
[4/7] Verification de l'attestation
      signature valide, nonce correspondant, cle publique liee
      mesure du code conforme, politique acceptee
[5/7] Remise de la cle, chiffree pour le serveur atteste
      traitement termine cote serveur : identite (aucune transformation)
[6/7] Recuperation du resultat
      132.5 Mo recus en 93.9 ms
[7/7] Dechiffrement local et verification
      sha256 restitue : d8dc813d2eb95dc489bf833c3f8f66da...
      identique a l'original : OUI

[ok] Aller-retour complet en 1.60 s — le fichier restitue est identique a l'original.
```

---

## Les 7 étapes

| # | Étape | Ce que le serveur peut faire à ce stade |
|---|---|---|
| 1 | chiffrement local, clé tirée pour ce volume uniquement | — |
| 2 | envoi du `.enc` | stocker un fichier illisible |
| 3 | demande d'attestation avec un nonce aléatoire | produire une preuve |
| 4 | **vérification côté client** | rien — c'est le client qui décide |
| 5 | remise de la clé, chiffrée pour la clé publique attestée | ouvrir la clé, déchiffrer, traiter |
| 6 | récupération du résultat chiffré | — |
| 7 | déchiffrement local, comparaison SHA-256 | — |

**Si l'étape 4 échoue, le pipeline s'arrête là.** Le serveur conserve un fichier
qu'il ne peut pas exploiter, et la clé n'a jamais quitté le poste.

---

## Ce que la démonstration prouve

### 1. Le serveur ne voit que du chiffré avant l'étape 5

Vérifiable directement : après un envoi, inspecter `data/server_storage/`.
Le test `test_stored_file_contains_no_plaintext` le vérifie automatiquement, en
plaçant un marqueur reconnaissable dans le fichier source et en s'assurant qu'il
n'apparaît nulle part — ni le contenu, ni le nom du patient.

### 2. Un serveur modifié est refusé

Démonstration reproductible : ajoutez une ligne, même un commentaire, à
`server.py`, redémarrez-le, relancez le client.

```
=== mesure attendue par le client ===
e20bf2d5ba2d2484e371baf1d686e6b2834950ea671d447fb7f10662151bfd75
=== mesure du serveur modifie ===
6dab5593056163329ace098233e2310e552c951d6823c68d06ad8dc0e7069642

[4/7] Verification de l'attestation

[!] ATTESTATION REFUSEE — mesure du code inattendue :
    6dab559305616332... au lieu de e20bf2d5ba2d2484...
    La cle n'a PAS ete transmise.
```

La mesure couvre `server.py`, `crypto.py`, `keyexchange.py` et
`attestation.py` (liste dans `MEASURED_FILES`). C'est l'équivalent logiciel du
*launch measurement* d'une VM confidentielle, et **cette partie-là n'est pas
simulée** : le hash est bien celui du code réellement chargé.

### 3. Les attaques classiques du protocole sont bloquées

Chacune fait l'objet d'un test :

| Attaque | Contre-mesure | Test |
|---|---|---|
| rejouer une ancienne attestation | nonce du client dans le `report_data` | `test_evidence_is_bound_to_the_nonce` |
| mentir sur le code exécuté | signature de l'evidence | `test_evidence_signature_cannot_be_forged` |
| relayer l'attestation d'un autre serveur et substituer sa clé | liaison `report_data ↔ clé publique` | `test_relay_attack_is_detected` |
| intercepter la clé sur le réseau | X25519 + HKDF + AES-GCM | `test_wrapped_key_never_contains_the_key` |
| rejouer une clé sur un autre job | identifiant du job en donnée authentifiée | `test_key_is_bound_to_its_job` |

---

## Le protocole HTTP

| Route | Rôle |
|---|---|
| `GET /health` | disponibilité, mesure de code annoncée |
| `GET /attestation?nonce=<hex>` | evidence signée + clé publique éphémère |
| `POST /jobs` | envoi du volume chiffré (flux binaire), retourne un `job_id` |
| `POST /jobs/<id>/key` | remise de la clé enveloppée |
| `GET /jobs/<id>` | état et rapport de traitement |
| `GET /jobs/<id>/result` | résultat chiffré |

Envoi et téléchargement se font en flux, par blocs de 1 Mio : un volume de
plusieurs Go ne passe jamais entièrement en mémoire, ni côté client ni côté
serveur.

### La remise de clé

`voltcrypt/keyexchange.py`, équivalent simplifié de HPKE (RFC 9180) :

1. le serveur publie une clé publique X25519 **éphémère**, générée au démarrage
   et jamais écrite sur disque ;
2. le client génère sa propre paire éphémère et calcule un secret partagé
   (X25519) ;
3. HKDF-SHA256 en dérive une clé de 32 octets ;
4. la clé du volume est chiffrée en AES-256-GCM avec l'identifiant du job comme
   donnée authentifiée.

Le paquet peut circuler en clair : seul le détenteur de la clé privée du serveur
peut l'ouvrir, et seulement dans le contexte du job auquel il est destiné.

---

## Limites de cette démonstration

Elles sont importantes, et aucune n'est accidentelle.

**La racine de confiance est logicielle.** L'evidence est signée par une clé
Ed25519 posée sur le disque du serveur (`data/keys/attestation_root.key`). Un
administrateur du serveur peut la lire et fabriquer une attestation mensongère.
Cette démonstration protège donc contre un serveur **modifié par erreur**
(mauvaise version déployée, fichier corrompu, mauvaise machine), pas contre un
serveur **malveillant**.

En production, la signature doit venir du matériel : `SNP_GET_EXT_REPORT` sur
`/dev/sev-guest` chez AMD, `TDX_CMD_GET_REPORT0` sur `/dev/tdx_guest` chez
Intel, `nv-attestation-sdk` pour le GPU. **Seule la fonction de signature
change** — le protocole client, la vérification et la remise de clé restent
identiques. C'est précisément l'intérêt d'avoir écrit le protocole en entier.

**HTTP en clair.** Pas de TLS. Les métadonnées (tailles, identifiants de job)
circulent en clair, et l'attestation elle-même pourrait être interceptée — sans
conséquence pour la clé, qui est chiffrée pour la clé publique du serveur, mais
sans confidentialité sur le reste. En production, TLS terminé **à l'intérieur**
de l'enclave : un ingress ou un load balancer qui termine TLS devant la CVM
annule tout le bénéfice, puisque le trafic redevient lisible dans un espace
mémoire non protégé.

**L'effacement mémoire n'est pas garanti.** Le serveur supprime les fichiers en
clair et libère la clé, mais Python ne permet pas d'effacer de façon fiable les
copies laissées par l'interpréteur (les `bytes` sont immuables, le ramasse-miettes
décide seul). Une implémentation réelle utiliserait de la mémoire verrouillée
(`mlock`) et un langage permettant l'effacement explicite.

**Le stockage des jobs est sur disque.** `data/server_storage/` conserve les
fichiers chiffrés — c'est acceptable, ils sont illisibles — mais les résultats y
restent aussi après traitement, sans purge. À prévoir en production.

**Le résultat est rechiffré avec la clé du volume.** Simplification :
l'implémentation réelle utiliserait une clé de retour distincte, fournie par le
client, pour que le serveur n'ait jamais à réutiliser la clé d'entrée.

**Pas d'authentification du client.** N'importe qui peut déposer un job. Un
déploiement réel exige une authentification, des quotas et une journalisation.

---

## Fichiers

| Fichier | Rôle |
|---|---|
| `server.py` | serveur HTTP, enclave simulée, traitement |
| `client.py` | les 7 étapes côté poste clinique |
| `voltcrypt/attestation.py` | production et vérification de l'evidence, mesure de code |
| `voltcrypt/keyexchange.py` | remise de clé (X25519 + HKDF + AES-GCM) |
| `tests/test_pipeline.py` | 28 tests de bout en bout, avec vrai serveur HTTP |

Données produites :

| Chemin | Contenu |
|---|---|
| `data/server_storage/` | jobs reçus (toujours chiffrés) |
| `data/trust/attestation_root.pub` | racine de confiance, à connaître côté client |
| `data/trust/expected_measurement.txt` | mesure de référence attendue |
| `data/keys/attestation_root.key` | clé de signature du serveur (**simule** le matériel) |

---

## Options

```bash
uv run server.py --port 9000
uv run server.py --measurement          # affiche la mesure et quitte
uv run server.py --storage /data/jobs

uv run client.py volume.nii --server http://autre-machine:8000
uv run client.py volume.nii --expect <mesure_hex>    # mode strict
uv run client.py volume.nii -o ~/resultats
```

Le mode `--trust-on-first-use` n'est acceptable que sur un réseau de confiance,
pour une première prise de contact : il accepte la mesure annoncée et
l'enregistre. Ensuite, tout changement de code est refusé. En production, la
mesure attendue vient d'une publication signée, pas du serveur lui-même.

---

## Tests

```bash
uv run python -m unittest tests.test_pipeline -v
```

28 tests, qui démarrent chacun un vrai serveur HTTP sur un port libre. Les plus
importants sont ceux de `TestClientRefusesToReleaseTheKey` : ils vérifient qu'en
cas d'anomalie, **la clé ne part pas** et qu'aucun résultat n'est produit.
