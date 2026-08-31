"""AMASSS sur CPU : lever la reserve << borne inferieure >> du papier.

Le facteur 4,4 a ete mesure sur Batch_Dental_Seg, l'un des outils les plus
legers du catalogue. Le papier dit donc que 4,4 est une borne inferieure et
que le cout CPU de l'outil dominant n'a pas ete mesure. Ce script le mesure.

Cinq structures (MAND, MAX, CB, CV, UAW), le reglage par defaut, sur le scan
de test d'AMASSS. Budget d'une heure par bras ; un depassement est un resultat.
"""
import json, os, subprocess, tempfile, time
from pathlib import Path

#: Racine des depots. Codee en dur, elle supposait l'arborescence du poste
#: d'origine et faisait echouer toute execution ailleurs des la premiere ligne.
#: Surchargeable par SADT_ROOT, avec la valeur historique par defaut.
UNC = Path(os.environ.get("SADT_ROOT", Path.home() / "Projects" / "UNC"))
TOOLS = UNC/"sadt-tools"/"tools"/"AMASSS"
RUNNER = UNC/"slicer-remote-tool-server"/"server"/"execution"/"runner.py"
MODEL = UNC/"slicer-remote-tool-server"/"DATA"/"AMASSS"/"models"/"AMASS_Models"
SCAN = UNC/"slicer-remote-tool-server"/"DATA"/"AMASSS"/"testfiles"/"MG_test_scan.nii.gz"
BUDGET = 3600

def run(device, tmp):
    out = tmp/f"out_{device}"; job = tmp/f"job_{device}"
    out.mkdir(parents=True); job.mkdir(parents=True)
    (job/"job.json").write_text(json.dumps({
        "tool":"AMASSS","job_dir":str(job),
        "params":{"scans":str(SCAN),"model":str(MODEL),
                  "output_dir":str(out),"device":device}}))
    started = time.perf_counter()
    try:
        r = subprocess.run([str(TOOLS/".venv"/"bin"/"python"), str(RUNNER),
                            "--job", str(job/"job.json")],
                           capture_output=True, text=True, timeout=BUDGET,
                           env={**os.environ, "SADT_TOOL_DIR": str(TOOLS)})
        elapsed = time.perf_counter() - started
        return {"device": device, "status": "ok" if r.returncode==0 else "failed",
                "seconds": round(elapsed,1),
                "stderr_tail": "" if r.returncode==0 else r.stderr[-500:]}
    except subprocess.TimeoutExpired:
        return {"device": device, "status": "exceeded_budget", "seconds": BUDGET}

with tempfile.TemporaryDirectory() as t:
    tmp = Path(t); rows = []
    for device in ("cuda", "cpu"):
        print(f"AMASSS {device} ...", flush=True)
        rows.append(run(device, tmp)); print("  ", rows[-1], flush=True)

Path("evidence").mkdir(exist_ok=True)
payload = {"tool":"AMASSS","scan":SCAN.name,"structures":"MAND,MAX,CB,CV,UAW",
           "budget_seconds":BUDGET,"runs":rows,
           "comparison_tool":{"name":"BatchDentalSeg","cuda":80.7,"cpu":353.8,
                              "factor":4.38}}
if all(r["status"]=="ok" for r in rows):
    payload["factor"] = round(rows[1]["seconds"]/rows[0]["seconds"], 2)
Path("evidence/amasss_acceleration.json").write_text(json.dumps(payload,indent=2)+"\n")
print()
for r in rows: print(f"{r['device']:<6} {r['status']:<18} {r['seconds']:>8} s")
if "factor" in payload:
    print(f"facteur AMASSS : {payload['factor']}x   "
          f"(BatchDentalSeg : 4.38x)")
