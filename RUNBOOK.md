# Runbook : la chaine chiffree de bout en bout, sur deux machines

Ce fichier est autosuffisant. **Une session Claude qui execute ce protocole n'a
pas besoin de lire un autre fichier du depot**, et ne doit pas explorer le code
pour "comprendre d'abord" : tout ce qui est necessaire est ici.

Ce qui est mesure : le cout et le comportement de la chaine
chiffrement + attestation + traitement + restitution quand le client et le
serveur sont **deux machines differentes**, sur un vrai reseau. Toutes les
mesures publiees jusqu'ici ont ete prises en boucle locale, avec le client et
le serveur dans le meme processus. C'est le trou que ce protocole comble.

---

## 0. REGLE DE FER

**Ne jamais utiliser `--trust-on-first-use` pour une mesure.**

Ce drapeau fait accepter au client la mesure que le serveur annonce, quelle
qu'elle soit. Il est commode et il **detruit l'experience** : la propriete
demontree est precisement que le client refuse une cle a un serveur dont le
code ne correspond pas. Un client qui accepte d'avance ne demontre rien.

La mesure attendue se transporte **hors bande** : l'operateur la lit sur le
serveur et la transmet par un autre canal (message, telephone). C'est fastidieux
et c'est le coeur du dispositif.

Si l'attestation est refusee : **noter le refus et s'arreter**. Ne pas relancer
avec `--trust-on-first-use` pour "faire passer le test". Un refus est un
resultat, souvent le plus interessant.

---

## 1. Cote serveur (machine Linux avec le GPU)

Une seule personne fait ceci, une fois, avant que le client commence.

```bash
cd ~/Projects/UNC/cryptography/volume_crypto

# adresse joignable par le client (ici l'adresse du mesh Tailscale)
ADDR=$(tailscale ip -4)

# A. traitement identite : isole le cout de la chaine, sans calcul
python3 server.py --host "$ADDR" --port 8811

# B. vrai outil : chaine complete avec segmentation reelle
python3 server.py --host "$ADDR" --port 8811 \
  --tool BatchDentalSeg \
  --model ~/Projects/UNC/slicer-remote-tool-server/DATA/BatchDentalSeg/models/DentalSegmentator \
  --device cuda
```

Le serveur affiche au demarrage la ligne qui compte :

```
  mesure du code   : 18a70d58977111a8612bcbd7006a0c604f00d31a72a211eee060dc5357e1a4b2
```

**C'est cette valeur que le client doit recevoir hors bande.** On peut aussi
l'obtenir sans demarrer le serveur, avec exactement les memes options plus
`--measurement` :

```bash
python3 server.py --tool BatchDentalSeg --model ... --device cuda --measurement
```

> **La mesure depend des options.** Le runner et la politique declaree entrent
> dans le manifeste. La mesure du serveur A (identite) n'est pas celle du
> serveur B (vrai outil), et une mesure prise avec des options differentes de
> celles du serveur qui tourne sera refusee. Prendre la mesure du serveur qu'on
> lance, pas d'un autre.

Rappel affiche par le serveur lui-meme : racine de confiance **simulee**, HTTP
en clair. A ne faire tourner que sur un reseau prive.

---

## 2. Cote client (le MacBook)

### 2.1 Installation, en entier

```bash
git clone https://github.com/Raphael-Barret/volume_crypto.git
cd volume_crypto
python3 -m pip install --user 'cryptography>=3.4'
python3 -c "import cryptography; print('ok', cryptography.__version__)"
```

C'est tout. Le client est en bibliotheque standard plus `cryptography`. **Pas
de torch, pas de GPU, pas de 3D Slicer, pas de modeles.** Python 3.9 minimum.

### 2.2 Ce qu'il faut avoir recu de l'operateur

| | exemple |
|---|---|
| **La racine de confiance** | le contenu de `data/trust/attestation_root.pub` cote serveur |
| URL du serveur | `http://100.83.47.100:8811` |
| Mesure attendue, par configuration | `18a70d58...` (64 caracteres hex) |
| Le volume de test | un `.nii.gz`, le meme que cote serveur |

> **La racine de confiance est indispensable et elle manquait dans la premiere
> version de ce runbook.** Sans elle `client.py` echoue avant toute
> verification, et le controle `evidence_is_bound_to_the_nonce` de la batterie
> abandonne. Le fichier est gitignore et le serveur ne le publie pas : il faut
> le copier a la main dans `data/trust/attestation_root.pub` du depot clone.
> C'est une cle publique Ed25519 en PEM, trois lignes, sans risque a
> transmettre. L'oubli etait invisible en boucle locale, ou client et serveur
> partagent le meme `data/trust/`.

Deposer ce fichier n'est pas une intervention : c'est une entree que le client
est concu pour exiger, pas un contournement de panne.

### 2.3 Conditions reseau, avant les transferts

```bash
ping -c 20 100.83.47.100 | tail -2        # RTT moyen
route get 100.83.47.100 | grep interface  # utun* = tunnel, en* = lien direct
```

Noter les deux. **Une mesure distante sans sa condition reseau est inutilisable**,
parce qu'on ne peut plus separer le transfert du calcul.

### 2.4 Les trois executions

```bash
SRV=http://100.83.47.100:8811
SCAN=~/Downloads/MG_test_scan.nii.gz
M=<mesure attendue recue hors bande>

# R1. controle negatif, EN PREMIER : mesure volontairement fausse
python3 client.py "$SCAN" --server "$SRV" --expect 0000000000000000000000000000000000000000000000000000000000000000
#   attendu : ATTESTATION REFUSEE, la cle n'est pas transmise.
#   Si cela REUSSIT, arreter tout : la verification ne fonctionne pas,
#   et c'est le resultat le plus important de la journee.

# R2. chaine complete, traitement identite (serveur lance en mode A)
python3 client.py "$SCAN" --server "$SRV" --expect "$M" -o ./out_identity

# R3. chaine complete, vrai outil (serveur relance en mode B, mesure differente)
python3 client.py "$SCAN" --server "$SRV" --expect "$M_TOOL" -o ./out_tool
```

Le client imprime les 7 etapes avec leurs durees et debits. **Copier la sortie
complete**, pas seulement la derniere ligne.

### 2.5 Residence du clair, cote serveur

**Attention, point qui a coute trois tentatives lors du premier run.** En ligne
de commande, `client.py` n'imprime que les 8 premiers caracteres de
l'identifiant, le serveur n'expose aucune route de listing, et
`/jobs/<prefixe>` rend `job inconnu`. Pour recuperer l'identifiant complet,
appeler l'entree publique du module plutot que le CLI :

```bash
python3 -c "
import client, json
r = client.run('$SCAN', '$SRV', './out', expected_measurement='$M')
print(json.dumps(r, indent=2))"
```

Le dictionnaire retourne contient `job_id` en entier. Puis :

```bash
curl -s "$SRV/jobs/<job_id>" | python3 -m json.tool
```

Le champ `plaintext_residency_seconds` est la duree pendant laquelle le clair a
existe sur le serveur, et `workdir_backing` dit s'il etait en RAM (`memory`) ou
sur disque.

---

## 3. Ce qu'il faut ecrire

Un seul fichier, `results/encrypted_chain_<machine>.json`, sans restructurer le
schema : il est fusionne avec des mesures prises ailleurs.

```json
{
  "machine": {"model": "", "chip": "", "ram_gb": 0, "os": "", "python": ""},
  "network": {"path": "lan | vpn | ssh-tunnel", "interface": "",
              "rtt_ms": null, "server_url": ""},
  "server": {"runner": "identity | subprocess:<Tool>", "device": "",
             "expected_measurement": "", "announced_measurement": ""},
  "runs": [
    {"label": "R1_wrong_measurement | R2_identity | R3_real_tool",
     "scan_bytes": 0,
     "refused": false,
     "refusal_reason": "",
     "encrypt_seconds": null, "encrypt_mbps": null,
     "upload_seconds": null, "upload_mbps": null,
     "download_seconds": null,
     "total_seconds": null,
     "plaintext_residency_seconds": null,
     "workdir_backing": "",
     "output_identical_to_input": null,
     "stdout_verbatim": ""}
  ],
  "interventions": [],
  "notes": ""
}
```

`interventions` doit rester vide. Toute modification du depot, du serveur ou de
l'environnement pour "faire marcher" quelque chose y entre, et affaiblit le
resultat. C'est la bonne incitation.

---

## 4. Ce qu'il ne faut PAS conclure

- **Le temps total n'est pas le cout du chiffrement.** Sur un tunnel, il est
  domine par le transfert. Comparer R2 (identite) et R3 (vrai outil) sur la
  meme machine et le meme reseau donne la part du calcul ; comparer R2 a une
  mesure en boucle locale donne la part du reseau. Une seule execution ne
  separe rien.
- **Ceci ne mesure pas 3D Slicer.** Le client Slicer n'implemente pas cette
  chaine ; `client.py` est un client de demonstration distinct. Ce protocole
  mesure le protocole, pas le produit.
- **La racine de confiance est logicielle.** Le refus en R1 demontre qu'un
  serveur dont le code differe est rejete. Il ne demontre rien contre un
  administrateur malveillant, qui pourrait signer ce qu'il veut. Cette limite
  est structurelle et non un defaut de l'experience.
- **Une machine, un reseau, un jour.** Ne rien generaliser a d'autres liens ni
  a d'autres materiels.

---

## 5. Si quelque chose casse

| Symptome | Cause la plus probable |
|---|---|
| `serveur injoignable` | Serveur non demarre, ou lie a `127.0.0.1` au lieu d'une adresse joignable |
| `ATTESTATION REFUSEE` en R2 ou R3 | La mesure attendue ne correspond pas au serveur qui tourne : options differentes, ou code modifie depuis le demarrage |
| Mesure differente a chaque demarrage | Un fichier mesure a change. C'est le mecanisme qui fonctionne, pas une panne |
| `ModuleNotFoundError: cryptography` | Voir 2.1 |

Dans tous les cas : **noter le symptome verbatim dans `notes` et continuer**,
plutot que reparer en silence.
