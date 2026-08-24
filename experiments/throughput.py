"""Debit du chiffrement, sur cette machine, en RAM.

Ce script existe parce que le papier a un temps cite 553-563 Mo/s sans qu'aucun
fichier ne les porte : la mesure avait ete faite dans un terminal et jamais
enregistree. Un nombre publie dont l'artefact n'existe pas n'est pas
reproductible, il est seulement plausible.

    uv run python experiments/throughput.py

Le support compte autant que le processeur : mesurer depuis /dev/shm isole le
cout cryptographique du cout d'entree-sortie. Un chiffre pris sur disque est
plus bas et decrit le disque, pas le chiffrement.
"""
from __future__ import annotations

import json
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from voltcrypt import crypto, keys

SCAN = Path.home() / "Downloads" / "MG_test_scan.nii.gz"
PASSES = 3


def _cpu() -> str:
    try:
        out = subprocess.run(["lscpu"], capture_output=True, text=True).stdout
        for line in out.splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or "inconnu"


def main() -> int:
    if not SCAN.is_file():
        raise SystemExit(f"scan introuvable : {SCAN}")
    key = keys.generate_key()
    runs = []
    with tempfile.TemporaryDirectory(dir="/dev/shm") as tmp:
        tmp = Path(tmp)
        for _ in range(PASSES):
            enc = crypto.encrypt_file(SCAN, tmp / "e.enc", key)
            dec = crypto.decrypt_file(tmp / "e.enc", tmp / "d.out", key)
            runs.append({
                "encrypt_mb_s": round(enc.size / enc.seconds / 1e6, 1),
                "decrypt_mb_s": round(dec.size / dec.seconds / 1e6, 1),
            })
        overhead = (tmp / "e.enc").stat().st_size - SCAN.stat().st_size

    report = {
        "scan": SCAN.name,
        "scan_bytes": SCAN.stat().st_size,
        "backing_store": "/dev/shm (RAM)",
        "host": {"cpu": _cpu(), "platform": platform.platform()},
        "passes": PASSES,
        "runs": runs,
        "encrypt_mb_s_range": [min(r["encrypt_mb_s"] for r in runs),
                               max(r["encrypt_mb_s"] for r in runs)],
        "decrypt_mb_s_range": [min(r["decrypt_mb_s"] for r in runs),
                               max(r["decrypt_mb_s"] for r in runs)],
        "size_overhead_bytes": overhead,
        "note": "En RAM. Sur disque le chiffre est plus bas et mesure le disque. "
                "A comparer au lien reseau, pas dans l'absolu : c'est le rapport "
                "entre les deux qui porte l'argument du papier.",
    }
    Path("evidence").mkdir(exist_ok=True)
    Path("evidence/throughput.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(report["encrypt_mb_s_range"] + report["decrypt_mb_s_range"]))
    print("ecrit : evidence/throughput.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
