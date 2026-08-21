#!/usr/bin/env python3
"""Produit les artefacts de preuve : des fichiers, pas des affirmations.

    uv run evidence_report.py            # ecrit evidence/*.json
    uv run evidence_report.py --print    # affiche la table TCB

Regle du projet : tout chiffre destine a une publication doit avoir un fichier
qui le regenere, avec les conditions dans lesquelles il a ete obtenu. Un
tableau recopie a la main derive en silence ; un artefact regenere echoue
bruyamment.
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptoserve import measure, roots
from cryptoserve.runners import IdentityRunner

ROOT = Path(__file__).resolve().parent
EVIDENCE = ROOT / "evidence"


def _commit() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"],
                             cwd=ROOT, capture_output=True, text=True, timeout=10)
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _host() -> dict:
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
    }


def measurement_evidence(runner=None) -> dict:
    """Ce que la mesure couvre, et ce qu'elle ne couvre pas.

    C'est l'artefact qui repond au reproche fait au papier : la table
    imprimee vient d'ici, entrees et exclusions comprises.
    """
    runner = runner or IdentityRunner()
    manifest = measure.build_manifest(runner=runner, policy={"debug": False})
    by_kind: dict[str, int] = {}
    for entry in manifest.entries:
        by_kind[entry.kind] = by_kind.get(entry.kind, 0) + 1

    return {
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "commit": _commit(),
        "host": _host(),
        "runner": runner.name,
        "digest": manifest.digest,
        "entry_count": len(manifest.entries),
        "entries_by_kind": by_kind,
        "entries": [vars(e) for e in manifest.entries],
        "accepted_exclusions": manifest.exclusions,
        "trust_root": {
            "in_use": "simulated-software-root",
            "hardware_devices_present": roots.available_roots(),
            "note": ("racine logicielle : protege contre un serveur modifie "
                     "par erreur, pas contre un administrateur malveillant"),
        },
    }


def print_tcb_table(data: dict) -> None:
    """La table telle qu'elle irait dans un papier."""
    print(f"Mesure : {data['digest']}")
    print(f"Commit : {data['commit']}   runner : {data['runner']}")
    print()
    print(f"{'kind':<10} {'label':<46} digest")
    print("-" * 78)
    for entry in data["entries"]:
        print(f"{entry['kind']:<10} {entry['label']:<46} {entry['digest'][:16]}...")
    print("-" * 78)
    print(f"{data['entry_count']} entrees mesurees : "
          + ", ".join(f"{k} x{v}" for k, v in sorted(data["entries_by_kind"].items())))
    print()
    print("Hors perimetre, obtenu autrement (racine materielle, image "
          "reproductible, politique du site) :")
    for item in data["accepted_exclusions"]:
        print(f"  - {item}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--print", dest="show", action="store_true",
                        help="afficher la table TCB au lieu d'ecrire le fichier")
    args = parser.parse_args(argv)

    data = measurement_evidence()

    if args.show:
        print_tcb_table(data)
        return 0

    EVIDENCE.mkdir(exist_ok=True)
    target = EVIDENCE / "measurement.json"
    target.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    print(f"ecrit : {target.relative_to(ROOT)} "
          f"({data['entry_count']} entrees, digest {data['digest'][:16]}...)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
