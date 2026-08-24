"""Le facteur d'acceleration plafonne-t-il avec la taille du lot ?

Le papier extrapole le cout d'une cohorte a partir d'un lot de quatre, et dit
lui-meme que c'est une extrapolation. C'est la derniere qui reste, et une
extrapolation est ce qu'un relecteur attaque en premier. Ce script la remplace
par une courbe.

Ce qui est deja su, et qui rend la courbe necessaire :

    lot de 4, GPU : 57 % SOUS le lineaire (34,8 s/scan contre 80,7)
    lot de 4, CPU : 22 % SOUS le lineaire (276,9 s/scan contre 353,8)

Donc le cout par scan baisse des deux cotes, plus vite du cote accelere, et le
facteur s'ELARGIT avec le lot au lieu de se conserver. Une courbe dit ou ca
s'arrete : le chargement du modele est un cout fixe, il finit par devenir
negligeable, et le facteur doit alors plafonner sur le rapport des couts de
calcul purs. C'est ce plateau qui repond a << combien coute une cohorte >>.

    uv run python experiments/batch_curve.py                  # tout
    uv run python experiments/batch_curve.py --tool AMASSS    # un seul outil
    uv run python experiments/batch_curve.py --sizes 1,2,4    # courbe partielle

Chaque point est ecrit des qu'il est mesure : une interruption laisse un
resultat partiel exploitable plutot que rien. Relancer reprend ce qui manque.

Les lots melangent quatre volumes distincts en rotation plutot que des copies
d'un meme fichier. Dix copies du meme fichier donneraient une charge par scan
constante, donc une comparaison plus propre, mais le cache disque et l'etat du
modele favoriseraient les copies suivantes et gonfleraient le benefice du lot.
La rotation coute un peu de variance et vaut mieux qu'un biais oriente.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

UNC = Path.home() / "Projects" / "UNC"
RUNNER = UNC / "slicer-remote-tool-server" / "server" / "execution" / "runner.py"

#: Quatre volumes distincts, 94 a 176 Mo. La rotation les repete jusqu'a n.
SCANS = [
    UNC / "slicer-remote-tool-server/DATA/AMASSS/testfiles/MG_test_scan.nii.gz",
    UNC / "cryptography/volume_crypto/data/to_encrypt/C_0001_T1.nii.gz",
    UNC / "slicer-remote-tool-server/DATA/ASO/testfiles/CBCT_FullyAuto/Pat_0002.nii.gz",
    UNC / "slicer-remote-tool-server/DATA/ASO/models/CBCT_Gold_Frankfurt_Horizontal_Midsagittal_Plane/MAMP_0002_T1.nii.gz",
]

TOOLS = {
    "BatchDentalSeg": {
        "dir": UNC / "sadt-tools/tools/Batch_Dental_Seg",
        "model": UNC / "slicer-remote-tool-server/DATA/BatchDentalSeg/models/DentalSegmentator",
        "report": "BatchDentalSeg_report.json",
    },
    "AMASSS": {
        "dir": UNC / "sadt-tools/tools/AMASSS",
        "model": UNC / "slicer-remote-tool-server/DATA/AMASSS/models/AMASS_Models",
        "report": "AMASSS_report.json",
    },
}

OUT = Path("evidence/batch_curve.json")


def budget_for(tool: str, device: str, n: int) -> int:
    """Plafond genereux, mais fini. Un depassement est un resultat, pas une panne."""
    per_scan = {"BatchDentalSeg": {"cuda": 90, "cpu": 380},
                "AMASSS": {"cuda": 85, "cpu": 1500}}[tool][device]
    return int(per_scan * n * 1.5) + 600


def stage(n: int, workdir: Path) -> Path:
    """Prepare un dossier de n scans, noms distincts, volumes en rotation."""
    d = workdir / f"scans_{n}"
    d.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        src = SCANS[i % len(SCANS)]
        shutil.copy2(src, d / f"{i:02d}_{src.name}")
    return d


def measure(tool: str, device: str, n: int, scans_dir: Path, workdir: Path) -> dict:
    spec = TOOLS[tool]
    out = workdir / f"out_{tool}_{device}_{n}"
    job = workdir / f"job_{tool}_{device}_{n}"
    out.mkdir(parents=True, exist_ok=True)
    job.mkdir(parents=True, exist_ok=True)
    (job / "job.json").write_text(json.dumps({
        "tool": tool, "job_dir": str(job),
        "params": {"scans": str(scans_dir), "model": str(spec["model"]),
                   "output_dir": str(out), "device": device}}))
    budget = budget_for(tool, device, n)
    started = time.perf_counter()
    try:
        r = subprocess.run(
            [str(spec["dir"] / ".venv/bin/python"), str(RUNNER),
             "--job", str(job / "job.json")],
            capture_output=True, text=True, timeout=budget,
            env={**os.environ, "SADT_TOOL_DIR": str(spec["dir"])})
        elapsed = time.perf_counter() - started
        row = {"tool": tool, "device": device, "batch_size": n,
               "status": "ok" if r.returncode == 0 else "failed",
               "seconds": round(elapsed, 1),
               "seconds_per_scan": round(elapsed / n, 1),
               "budget_seconds": budget}
        if r.returncode != 0:
            row["stderr_tail"] = r.stderr[-600:]
        return row
    except subprocess.TimeoutExpired:
        return {"tool": tool, "device": device, "batch_size": n,
                "status": "exceeded_budget", "seconds": budget,
                "seconds_per_scan": round(budget / n, 1), "budget_seconds": budget}
    finally:
        shutil.rmtree(out, ignore_errors=True)


def load() -> list:
    if OUT.is_file():
        return json.loads(OUT.read_text()).get("runs", [])
    return []


def save(runs: list) -> None:
    OUT.parent.mkdir(exist_ok=True)
    payload = {
        "scans": [s.name for s in SCANS],
        "scan_bytes": [s.stat().st_size for s in SCANS if s.is_file()],
        "composition": "quatre volumes distincts en rotation, noms distincts",
        "runs": runs,
        "factors": {},
        "note": "Un facteur par taille de lot. Il s'elargit si le chargement du "
                "modele s'amortit plus vite du cote accelere, et plafonne quand "
                "ce cout fixe devient negligeable des deux cotes.",
    }
    by = {(r["tool"], r["device"], r["batch_size"]): r for r in runs
          if r["status"] == "ok"}
    for tool in TOOLS:
        sizes = sorted({k[2] for k in by if k[0] == tool})
        payload["factors"][tool] = {
            str(n): round(by[(tool, "cpu", n)]["seconds"] / by[(tool, "cuda", n)]["seconds"], 2)
            for n in sizes
            if (tool, "cpu", n) in by and (tool, "cuda", n) in by}
    OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tool", choices=list(TOOLS), action="append",
                    help="limiter a un outil (repetable)")
    ap.add_argument("--sizes", default="1,2,4,8,10",
                    help="tailles de lot, separees par des virgules")
    ap.add_argument("--device", choices=["cuda", "cpu"], action="append")
    args = ap.parse_args(argv)

    tools = args.tool or list(TOOLS)
    devices = args.device or ["cuda", "cpu"]
    sizes = [int(x) for x in args.sizes.split(",")]

    for s in SCANS:
        if not s.is_file():
            raise SystemExit(f"volume introuvable : {s}")
    if not RUNNER.is_file():
        raise SystemExit(f"runner introuvable : {RUNNER}")

    runs = load()
    done = {(r["tool"], r["device"], r["batch_size"]) for r in runs}
    # L'appareil est la boucle EXTERNE, a dessein : le bras accelere coute une
    # vingtaine de fois moins que le bras CPU, donc parcourir tout le GPU
    # d'abord donne la forme complete de la courbe acceleree en quelques
    # minutes, avant d'engager les heures de CPU. Si la machine est reprise en
    # cours de route, on a une courbe entiere plutot que deux moities.
    todo = [(t, d, n) for d in devices for t in tools for n in sizes
            if (t, d, n) not in done]
    if not todo:
        print("rien a faire : tous les points sont deja mesures.")
        return 0
    print(f"{len(todo)} point(s) a mesurer, {len(done)} deja en base.\n", flush=True)

    with tempfile.TemporaryDirectory(prefix="batch_curve_") as t:
        workdir = Path(t)
        staged: dict[int, Path] = {}
        for tool, device, n in todo:
            if n not in staged:
                staged[n] = stage(n, workdir)
            print(f"  {tool:16s} {device:4s} n={n:<3d} ...", end="", flush=True)
            row = measure(tool, device, n, staged[n], workdir)
            runs.append(row)
            save(runs)          # ecrit a chaque point : une interruption laisse du resultat
            print(f" {row['status']:16s} {row['seconds']:>8.1f} s "
                  f"({row['seconds_per_scan']:.1f} s/scan)", flush=True)

    print()
    payload = json.loads(OUT.read_text())
    for tool, factors in payload["factors"].items():
        if factors:
            line = "  ".join(f"n={n}: {f}x" for n, f in sorted(factors.items(), key=lambda kv: int(kv[0])))
            print(f"{tool:16s} {line}")
    print(f"\necrit : {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
