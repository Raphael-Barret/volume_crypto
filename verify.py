#!/usr/bin/env python3
"""Verifier un deploiement, sans lire son code source.

    uv run server.py                                  # terminal 1
    uv run verify.py --storage data/server_storage    # terminal 2

    uv run verify.py --url http://autre-machine:8000  # a distance
    uv run verify.py --json evidence/adversary.json   # artefact pour le papier

Sans `--storage`, les controles qui inspectent le disque du serveur rendent
`skip` avec leur raison plutot que `passed` par defaut : une batterie qui
conclut sans preuve ne vaut rien.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cryptoverify.battery import Battery
from cryptoverify.checks import run_all
from voltcrypt import config


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default=f"http://{config.SERVER_HOST}:{config.SERVER_PORT}")
    parser.add_argument("--storage", help="dossier des jobs, si accessible d'ici")
    parser.add_argument("--json", help="ecrire le rapport dans ce fichier")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    battery = Battery(args.url, Path(args.storage) if args.storage else None)
    run_all(battery)

    if not args.quiet:
        battery.print_report()

    report = battery.report()
    if args.json:
        target = Path(args.json)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        if not args.quiet:
            print(f"\necrit : {target}")

    # Code de sortie : 0 propre, 1 defauts trouves. Un `skip` ne fait pas
    # echouer, mais il est compte et visible dans le rapport.
    return 0 if report["clean"] else 1


if __name__ == "__main__":
    sys.exit(main())
