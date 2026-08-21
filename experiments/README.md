# Les experiences, et ce que chacune produit

Chaque script ecrit un fichier dans `../evidence/`. Un chiffre du papier sans
son script est un chiffre qui derive en silence.

| Script | Produit | Repond a |
|---|---|---|
| `endtoend.py` | `endtoend.json` | le vrai aller-retour client/serveur en sept etapes, avec un outil reel puis en identite, sur le meme volume |
| `acceleration.py` | `acceleration.json` | ce que l'acceleration achete, meme machine, seul le device change |
| `batch_scaling.py` | `batch_scaling.json` | le facteur tient-il a l'echelle du lot, ou l'amortissement du chargement le deplace-t-il |
| `amasss_acceleration.py` | `amasss_acceleration.json` | le meme facteur sur l'outil dominant du catalogue |

Lancement : `uv run experiments/<script>.py` depuis la racine du projet.
Les trois derniers demandent un GPU, un checkout de `sadt-tools` avec ses
virtualenvs, et les poids sous `slicer-remote-tool-server/DATA/`.
