"""Ce que l'acceleration achete, mesure sans avoir besoin d'un second poste.

La grille prevue comparait trois configurations sur deux machines. Faute d'un
portable sans GPU, on isole le SEUL facteur qui porte l'argument d'acces : la
presence d'une acceleration. Meme outil, meme scan, meme machine, device cuda
puis cpu.

Ce que cela mesure : le cout de calcul en l'absence d'acceleration.
Ce que cela ne mesure PAS, et qui doit etre dit : la charge d'installation, la
maintenance de l'environnement, ni le comportement d'un vrai portable de
clinique. Un budget de 30 minutes est fixe d'avance ; le depassement est un
resultat, pas un echec.
"""
import json, os, subprocess, tempfile, time
from pathlib import Path

UNC = Path.home()/"Projects"/"UNC"
TOOLS = UNC/"sadt-tools"/"tools"/"Batch_Dental_Seg"
RUNNER = UNC/"slicer-remote-tool-server"/"server"/"execution"/"runner.py"
MODEL = UNC/"slicer-remote-tool-server"/"DATA"/"BatchDentalSeg"/"models"/"DentalSegmentator"
SCAN = Path(__file__).resolve().parent/"data"/"to_encrypt"/"C_0001_T1.nii.gz"
BUDGET = 1800

def run(device, tmp):
    out = tmp/f"out_{device}"; job = tmp/f"job_{device}"
    out.mkdir(parents=True); job.mkdir(parents=True)
    (job/"job.json").write_text(json.dumps({
        "tool":"BatchDentalSeg","job_dir":str(job),
        "params":{"scans":str(SCAN),"model":str(MODEL),
                  "output_dir":str(out),"device":device}}))
    started = time.perf_counter()
    try:
        r = subprocess.run([str(TOOLS/".venv"/"bin"/"python"), str(RUNNER),
                            "--job", str(job/"job.json")],
                           capture_output=True, text=True, timeout=BUDGET,
                           env={**os.environ, "SADT_TOOL_DIR": str(TOOLS)})
        elapsed = time.perf_counter() - started
        if r.returncode != 0:
            return {"device": device, "status": "failed",
                    "seconds": round(elapsed,1), "stderr_tail": r.stderr[-400:]}
        return {"device": device, "status": "ok", "seconds": round(elapsed,1)}
    except subprocess.TimeoutExpired:
        return {"device": device, "status": "exceeded_budget",
                "seconds": BUDGET, "budget_seconds": BUDGET}

with tempfile.TemporaryDirectory() as t:
    tmp = Path(t)
    rows = []
    for device in ("cuda", "cpu"):
        print(f"{device} ...", flush=True)
        rows.append(run(device, tmp))
        print("  ", rows[-1], flush=True)

Path("evidence").mkdir(exist_ok=True)
Path("evidence/acceleration.json").write_text(json.dumps({
    "scan": SCAN.name, "scan_bytes": SCAN.stat().st_size,
    "tool": "BatchDentalSeg", "budget_seconds": BUDGET,
    "note": ("meme machine, meme scan, meme outil ; isole la presence "
             "d'acceleration. Ne mesure ni l'installation ni la maintenance."),
    "runs": rows}, indent=2) + "\n")
print()
for r in rows:
    print(f"{r['device']:<6} {r['status']:<18} {r['seconds']:>8} s")
if len(rows) == 2 and all(r["status"] == "ok" for r in rows):
    print(f"rapport cpu/gpu : {rows[1]['seconds']/rows[0]['seconds']:.1f}x")
