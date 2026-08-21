#!/usr/bin/env python3
"""L'experience de parite, avec son temoin, et son artefact de preuve.

    uv run parity_experiment.py --tool Batch_Dental_Seg --repeats 2
    uv run parity_experiment.py --deterministic     # cudnn.benchmark desactive

Deux regimes, parce qu'ils ne repondent pas a la meme question :

    par defaut       conditions reelles. On mesure le plancher de variance de
                     l'outil (bras clair contre clair) et on demande si la
                     chaine en sort. C'est ce qu'un utilisateur observe.
    --deterministic  `cudnn.benchmark` desactive et `cudnn.deterministic`
                     actif. Le plancher tombe a zero et on peut exiger la
                     bit-identite. C'est une propriete de l'outil, pas du
                     thermique de la carte.

Les bras sont ENTRELACES (clair, chaine, clair, chaine, ...) et non groupes.
Deux executions lancees dos a dos partagent l'etat du GPU et sous-estiment la
variance ; c'est l'erreur de protocole qui a rendu le premier temoin nul.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptoserve import boundary, parity
from cryptoserve.jobs import Job
from cryptoserve.runners.subprocess_tool import SubprocessToolRunner
from voltcrypt import crypto, keys

ROOT = Path(__file__).resolve().parent
UNC = Path.home() / "Projects" / "UNC"
RUNNER = UNC / "slicer-remote-tool-server" / "server" / "execution" / "runner.py"
DATA = UNC / "slicer-remote-tool-server" / "DATA"

#: Force le mode deterministe dans le processus de l'outil, sans toucher a son
#: code : la variable est lue par le `sitecustomize` injecte ci-dessous.
DETERMINISM_SHIM = """
import torch
torch.backends.cudnn.benchmark = False
torch.backends.cudnn.deterministic = True
"""

COMPARE = r'''
import sys, numpy as np, nibabel as nib
a = np.asarray(nib.load(sys.argv[1]).dataobj)
b = np.asarray(nib.load(sys.argv[2]).dataobj)
diff = int((a != b).sum()); total = int(a.size)
labels = sorted(set(np.unique(a)).union(np.unique(b)) - {0})
d = []
for l in labels:
    x, y = (a == l), (b == l)
    s = x.sum() + y.sum()
    d.append(1.0 if s == 0 else 2.0 * (x & y).sum() / s)
print(diff, total, min(d) if d else 1.0, sum(d)/len(d) if d else 1.0)
'''


def _interpreter(tool_dir: Path) -> Path:
    return tool_dir / ".venv" / "bin" / "python"


def _env(tool_dir: Path, deterministic: bool, shim_dir: Path | None) -> dict:
    env = {**os.environ, "SADT_TOOL_DIR": str(tool_dir)}
    if deterministic and shim_dir is not None:
        env["PYTHONPATH"] = f"{shim_dir}{os.pathsep}{env.get('PYTHONPATH', '')}"
    return env


def clear_run(tool: str, tool_dir: Path, model: Path, scan: Path, tmp: Path,
              tag: str, deterministic: bool, shim_dir: Path | None) -> Path:
    out = tmp / f"out_{tag}"; job_dir = tmp / f"job_{tag}"
    out.mkdir(parents=True); job_dir.mkdir(parents=True)
    job = {"tool": tool, "job_dir": str(job_dir),
           "params": {"scans": str(scan), "model": str(model),
                      "output_dir": str(out), "device": "cuda"}}
    (job_dir / "job.json").write_text(json.dumps(job))
    completed = subprocess.run(
        [str(_interpreter(tool_dir)), str(RUNNER), "--job", str(job_dir / "job.json")],
        capture_output=True, text=True, timeout=3600,
        env=_env(tool_dir, deterministic, shim_dir))
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr[-1500:])
    return next(out.rglob("*_Seg.nii.gz"))


def chain_run(tool: str, tool_dir: Path, model: Path, scan: Path, tmp: Path,
              tag: str, deterministic: bool, shim_dir: Path | None):
    key = keys.generate_key()
    container = tmp / f"scan_{tag}.enc"
    crypto.encrypt_file(scan, container, key)
    if deterministic and shim_dir is not None:
        os.environ["PYTHONPATH"] = f"{shim_dir}{os.pathsep}{os.environ.get('PYTHONPATH','')}"
    runner = SubprocessToolRunner(
        tool=tool, tool_dir=tool_dir, runner_path=RUNNER,
        params={"model": str(model), "device": "cuda"}, input_argument="scans")
    outcome = boundary.process(Job(tag, container, container.stat().st_size),
                               key, runner)
    archive = tmp / f"res_{tag}"
    crypto.decrypt_file(outcome.result_path, archive, key)
    restored = tmp / f"restored_{tag}"; restored.mkdir()
    shutil.unpack_archive(archive, restored, format="gztar")
    return next(restored.rglob("*_Seg.nii.gz")), outcome


def agreement(tool_dir: Path, left: Path, right: Path) -> parity.Agreement:
    completed = subprocess.run(
        [str(_interpreter(tool_dir)), "-c", COMPARE, str(left), str(right)],
        capture_output=True, text=True, timeout=900)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr[-800:])
    diff, total, dmin, dmean = completed.stdout.split()
    return parity.Agreement(int(diff), int(total), float(dmin), float(dmean))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tool", default="Batch_Dental_Seg")
    parser.add_argument("--entry", default="BatchDentalSeg")
    parser.add_argument("--model", default="DentalSegmentator")
    parser.add_argument("--scan", default=str(ROOT / "data" / "to_encrypt" / "C_0001_T1.nii.gz"))
    parser.add_argument("--repeats", type=int, default=2,
                        help="paires clair/chaine entrelacees")
    parser.add_argument("--deterministic", action="store_true",
                        help="desactiver cudnn.benchmark dans l'outil")
    parser.add_argument("--json", default=str(ROOT / "evidence" / "parity.json"))
    args = parser.parse_args(argv)

    tool_dir = UNC / "sadt-tools" / "tools" / args.tool
    model = DATA / args.entry / "models" / args.model
    scan = Path(args.scan)
    for path, label in [(tool_dir / ".venv", "virtualenv"), (RUNNER, "runner"),
                        (model, "modele"), (scan, "scan")]:
        if not path.exists():
            print(f"absent : {label} ({path})", file=sys.stderr)
            return 2

    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        shim_dir = None
        if args.deterministic:
            shim_dir = tmp / "shim"; shim_dir.mkdir()
            (shim_dir / "sitecustomize.py").write_text(DETERMINISM_SHIM)

        clears, chains, outcomes = [], [], []
        for index in range(args.repeats):
            print(f"paire {index + 1}/{args.repeats} : clair ...", flush=True)
            clears.append(clear_run(args.entry, tool_dir, model, scan, tmp,
                                    f"c{index}", args.deterministic, shim_dir))
            print(f"paire {index + 1}/{args.repeats} : chaine ...", flush=True)
            produced, outcome = chain_run(args.entry, tool_dir, model, scan, tmp,
                                          f"g{index}", args.deterministic, shim_dir)
            chains.append(produced); outcomes.append(outcome)

        if len(clears) < 2:
            print("il faut au moins deux paires pour estimer un temoin",
                  file=sys.stderr)
            return 2

        control = agreement(tool_dir, clears[0], clears[1])
        treatment = agreement(tool_dir, clears[0], chains[0])
        verdict = parity.judge(control, treatment)

        payload = {
            "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "host": {"platform": platform.platform(), "python": sys.version.split()[0]},
            "tool": args.entry,
            "scan": scan.name,
            "scan_bytes": scan.stat().st_size,
            "repeats": args.repeats,
            "interleaved": True,
            "cudnn_benchmark_disabled": args.deterministic,
            "verdict": verdict.to_dict(),
            "residency_seconds": [round(o.residency_seconds, 3) for o in outcomes],
            "workdir_backing": [o.workdir_backing for o in outcomes],
            "tool_seconds": [o.report.get("tool_seconds") for o in outcomes],
        }

        target = Path(args.json)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")

        print()
        print(f"temoin     clair vs clair  : {control.differing_voxels:,} voxels, "
              f"Dice min {control.dice_min:.6f}")
        print(f"traitement clair vs chaine : {treatment.differing_voxels:,} voxels, "
              f"Dice min {treatment.dice_min:.6f}")
        print(f"VERDICT : {'parite tenue' if verdict.passed else 'PARITE REFUSEE'}")
        print(f"          {verdict.reason}")
        print(f"ecrit : {target.relative_to(ROOT)}")
        return 0 if verdict.passed else 1


if __name__ == "__main__":
    sys.exit(main())
