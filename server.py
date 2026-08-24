#!/usr/bin/env python3
"""Point d'entree du serveur de traitement.

    python server.py                    # ecoute sur 127.0.0.1:8000
    python server.py --port 9000
    python server.py --measurement      # affiche la mesure du code et quitte
    python server.py --manifest         # affiche le manifeste mesure et quitte

    # servir un VRAI outil, et ecouter sur une interface joignable :
    python server.py --host 100.83.47.100 --tool BatchDentalSeg --device cuda

Attention a --measurement : la mesure depend du runner actif, parce que le
manifeste inclut le runner et l'environnement de l'outil. La mesure affichee
par `--measurement` seul est celle du runner identite et ne vaut PAS pour un
serveur lance avec --tool. Prendre la mesure sur le serveur qui tourne.

Ce que ce serveur illustre, et qui est le point de la demonstration :

    il recoit des volumes CHIFFRES et ne peut RIEN en faire
    tant qu'il n'a pas prouve son identite pour obtenir la cle.

L'implementation vit dans le paquet `cryptoserve/`. Ce fichier ne garde que la
ligne de commande et les noms publics historiques. Le decoupage a une raison
precise : la frontiere du clair est desormais un module unique
(`cryptoserve/boundary.py`), ce qui permet de VERIFIER par le graphe d'imports
qu'aucun autre composant ne peut dechiffrer, au lieu de le promettre.

Limites assumees de cette demo : HTTP en clair (voir PIPELINE.md), stockage
des jobs sur disque, et racine de confiance logicielle (voir voltcrypt/
attestation.py). Ce n'est pas un serveur de production.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cryptoserve import measure
from cryptoserve.app import MAX_UPLOAD, Handler, serve
from cryptoserve.boundary import process as process_boundary
from cryptoserve.enclave import Enclave
from cryptoserve.jobs import Job, JobState, Store
from cryptoserve.runners import IdentityRunner
from cryptoserve.runners.subprocess_tool import SubprocessToolRunner
from voltcrypt import attestation, config

__all__ = [
    "serve", "Handler", "Enclave", "Store", "Job", "JobState",
    "MEASURED_FILES", "MAX_UPLOAD", "process_boundary", "measure",
]

#: Fichiers dont l'empreinte entre dans la mesure du serveur. Conserve pour
#: compatibilite : la mesure reelle porte desormais sur le MANIFESTE complet
#: (protocole + frontiere + runner + politique), voir cryptoserve/measure.py,
#: parce que mesurer le seul protocole laisse hors perimetre le code qui lit
#: effectivement le clair.
MEASURED_FILES = measure.PROTOCOL_FILES + measure.BOUNDARY_FILES


#: Emplacements par defaut, identiques a ceux de experiments/endtoend.py.
_UNC = Path.home() / "Projects" / "UNC"
_DEFAULT_RUNNER_PATH = _UNC / "slicer-remote-tool-server" / "server" / "execution" / "runner.py"


def _find_tool_dir(tool: str) -> Path:
    """Localise le dossier d'un outil sous sadt-tools/tools/.

    Le nom de l'outil et celui de son dossier ne coincident pas toujours :
    l'outil `BatchDentalSeg` vit dans `Batch_Dental_Seg`. On accepte les deux
    plutot que d'en faire un piege documente.
    """
    root = _UNC / "sadt-tools" / "tools"
    direct = root / tool
    if direct.exists():
        return direct
    if root.is_dir():
        target = tool.replace("_", "").lower()
        for candidate in sorted(root.iterdir()):
            if candidate.is_dir() and candidate.name.replace("_", "").lower() == target:
                return candidate
    return direct


def _build_runner(args):
    """Choisit le runner. Sans --tool, on garde le traitement identite.

    Le meme runner sert a calculer la mesure et a servir les jobs : c'est
    volontaire. Une mesure calculee avec un runner et servie avec un autre
    serait une attestation qui ne decrit pas ce qui tourne.
    """
    if not args.tool:
        return IdentityRunner()

    tool_dir = (Path(args.tool_dir) if args.tool_dir
                else _find_tool_dir(args.tool))
    runner_path = Path(args.runner_path) if args.runner_path else _DEFAULT_RUNNER_PATH

    if not runner_path.exists():
        raise SystemExit(f"runner du serveur d'outils introuvable : {runner_path}")
    if not tool_dir.exists():
        raise SystemExit(f"dossier de l'outil introuvable : {tool_dir}")

    params = {"device": args.device}
    if args.model:
        params["model"] = args.model
    return SubprocessToolRunner(
        tool=args.tool, tool_dir=tool_dir, runner_path=runner_path,
        params=params, input_argument=args.input_argument)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default=config.SERVER_HOST)
    parser.add_argument("--port", type=int, default=config.SERVER_PORT)
    parser.add_argument("--storage", help="dossier des jobs recus")
    parser.add_argument("--measurement", action="store_true",
                        help="afficher la mesure du code et quitter")
    parser.add_argument("--manifest", action="store_true",
                        help="afficher le manifeste mesure et quitter")
    parser.add_argument("--tool", help="nom de l'outil a servir "
                                       "(defaut : traitement identite)")
    parser.add_argument("--tool-dir", help="dossier de l'outil "
                                           "(defaut : sadt-tools/tools/<TOOL>)")
    parser.add_argument("--runner-path", help="runner du serveur d'outils")
    parser.add_argument("--model", help="chemin du modele passe a l'outil")
    parser.add_argument("--device", default="cuda", help="cuda ou cpu")
    parser.add_argument("--input-argument", default="scans")
    args = parser.parse_args(argv)

    runner = _build_runner(args)

    if args.measurement or args.manifest:
        # On passe par un Enclave et non par build_manifest(policy=None) : la
        # politique declaree entre dans le manifeste, donc un manifeste calcule
        # sans elle produit un digest qu'aucun serveur n'annoncera jamais. Ce
        # flag sert a donner au client la mesure attendue ; il doit donc rendre
        # exactement ce qu'un serveur lance avec les memes options annonce.
        enclave = Enclave(config.ATTESTATION_SIGNING_KEY, runner)
        if args.manifest:
            print(json.dumps(enclave.manifest.to_dict(), indent=2, ensure_ascii=False))
        else:
            print(enclave.measurement)
        return 0

    httpd = serve(args.host, args.port,
                  Path(args.storage) if args.storage else None,
                  runner=runner)
    enclave = httpd.RequestHandlerClass.enclave

    print(f"Serveur de traitement, http://{args.host}:{args.port}")
    print(f"  mesure du code   : {enclave.measurement}")
    print(f"  entrees mesurees : {len(enclave.manifest.entries)} "
          f"(runner : {enclave.runner.name})")
    print(f"  cle publique     : {enclave.public_key.hex()[:32]}... (ephemere)")
    print(f"  racine de confiance publiee dans : {config.TRUST_ROOT_PUBLIC_KEY}")
    print(f"  jobs stockes dans : {httpd.RequestHandlerClass.store.directory}")
    print()
    if args.host not in ("127.0.0.1", "localhost"):
        print(f"  ATTENTION : ecoute sur {args.host}, hors boucle locale.")
    print("  ATTENTION : racine de confiance SIMULEE, HTTP en clair.")
    print("  Demonstration de protocole, ne pas exposer sur un reseau.")
    print()
    print("  Ctrl-C pour arreter.")
    print()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nArret.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
