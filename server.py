#!/usr/bin/env python3
"""Point d'entree du serveur de traitement.

    python server.py                    # ecoute sur 127.0.0.1:8000
    python server.py --port 9000
    python server.py --measurement      # affiche la mesure du code et quitte
    python server.py --manifest         # affiche le manifeste mesure et quitte

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
    args = parser.parse_args(argv)

    if args.measurement or args.manifest:
        runner = IdentityRunner()
        manifest = measure.build_manifest(runner=runner, policy=None)
        if args.manifest:
            print(json.dumps(manifest.to_dict(), indent=2, ensure_ascii=False))
        else:
            print(manifest.digest)
        return 0

    httpd = serve(args.host, args.port,
                  Path(args.storage) if args.storage else None)
    enclave = httpd.RequestHandlerClass.enclave

    print(f"Serveur de traitement, http://{args.host}:{args.port}")
    print(f"  mesure du code   : {enclave.measurement}")
    print(f"  entrees mesurees : {len(enclave.manifest.entries)} "
          f"(runner : {enclave.runner.name})")
    print(f"  cle publique     : {enclave.public_key.hex()[:32]}... (ephemere)")
    print(f"  racine de confiance publiee dans : {config.TRUST_ROOT_PUBLIC_KEY}")
    print(f"  jobs stockes dans : {httpd.RequestHandlerClass.store.directory}")
    print()
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
