"""Le facteur CPU/GPU tient-il a l'echelle du lot ?

Le papier extrapole arithmetiquement du cout par scan au cout d'une cohorte.
Cette extrapolation suppose la linearite, et elle est fausse par construction :
le checkpoint est charge UNE fois par lot, donc le cout fixe s'amortit et le
facteur mesure sur un scan unique surestime le facteur d'un lot.

De combien, c'est ce qu'on mesure ici plutot que de le supposer.
"""
import json, os, shutil, subprocess, tempfile, time
from pathlib import Path

#: Racine des depots. Codee en dur, elle supposait l'arborescence du poste
#: d'origine et faisait echouer toute execution ailleurs des la premiere ligne.
#: Surchargeable par SADT_ROOT, avec la valeur historique par defaut.
UNC = Path(os.environ.get("SADT_ROOT", Path.home() / "Projects" / "UNC"))
TOOLS = UNC/"sadt-tools"/"tools"/"Batch_Dental_Seg"
RUNNER = UNC/"slicer-remote-tool-server"/"server"/"execution"/"runner.py"
MODEL = UNC/"slicer-remote-tool-server"/"DATA"/"BatchDentalSeg"/"models"/"DentalSegmentator"
SCANS = [
    UNC/"cryptography/volume_crypto/data/to_encrypt/C_0001_T1.nii.gz",
    UNC/"slicer-remote-tool-server/DATA/AMASSS/testfiles/MG_test_scan.nii.gz",
    UNC/"slicer-remote-tool-server/DATA/ASO/testfiles/CBCT_FullyAuto/Pat_0002.nii.gz",
    UNC/"slicer-remote-tool-server/DATA/ASO/models/CBCT_Gold_Frankfurt_Horizontal_Midsagittal_Plane/MAMP_0002_T1.nii.gz",
]
BUDGET = 3600

def run_batch(device, scans_dir, tmp):
    out = tmp/f"out_{device}"; job = tmp/f"job_{device}"
    out.mkdir(parents=True); job.mkdir(parents=True)
    (job/"job.json").write_text(json.dumps({
        "tool":"BatchDentalSeg","job_dir":str(job),
        "params":{"scans":str(scans_dir),"model":str(MODEL),
                  "output_dir":str(out),"device":device}}))
    started = time.perf_counter()
    try:
        r = subprocess.run([str(TOOLS/".venv"/"bin"/"python"), str(RUNNER),
                            "--job", str(job/"job.json")],
                           capture_output=True, text=True, timeout=BUDGET,
                           env={**os.environ, "SADT_TOOL_DIR": str(TOOLS)})
        elapsed = time.perf_counter() - started
        report = out/"BatchDentalSeg_report.json"
        summary = json.loads(report.read_text())["summary"] if report.is_file() else "?"
        return {"device": device, "status": "ok" if r.returncode == 0 else "failed",
                "seconds": round(elapsed,1), "summary": summary,
                "stderr_tail": "" if r.returncode == 0 else r.stderr[-400:]}
    except subprocess.TimeoutExpired:
        return {"device": device, "status": "exceeded_budget", "seconds": BUDGET}

with tempfile.TemporaryDirectory() as t:
    tmp = Path(t)
    scans_dir = tmp/"scans"; scans_dir.mkdir()
    present = []
    for s in SCANS:
        if s.is_file():
            shutil.copy(s, scans_dir/s.name); present.append(s.name)
    print(f"lot de {len(present)} scans : {', '.join(present)}", flush=True)

    rows = []
    for device in ("cuda", "cpu"):
        print(f"{device} ...", flush=True)
        rows.append(run_batch(device, scans_dir, tmp))
        print("  ", rows[-1], flush=True)

Path("evidence").mkdir(exist_ok=True)
single = {"cuda": 80.7, "cpu": 353.8}
payload = {"batch_size": len(present), "scans": present,
           "single_scan_reference_seconds": single, "runs": rows,
           "note": ("le checkpoint est charge une fois par lot, donc le cout "
                    "fixe s'amortit ; comparer le facteur du lot au facteur "
                    "par scan teste l'hypothese de linearite du papier.")}
if all(r["status"] == "ok" for r in rows):
    g, c = rows[0]["seconds"], rows[1]["seconds"]
    payload["batch_factor"] = round(c/g, 2)
    payload["single_scan_factor"] = round(single["cpu"]/single["cuda"], 2)
    payload["seconds_per_scan"] = {"cuda": round(g/len(present),1),
                                   "cpu": round(c/len(present),1)}
Path("evidence/batch_scaling.json").write_text(json.dumps(payload, indent=2)+"\n")
print()
for r in rows:
    print(f"{r['device']:<6} {r['status']:<18} {r['seconds']:>8} s   {r.get('summary','')}")
if "batch_factor" in payload:
    print(f"facteur lot : {payload['batch_factor']}x   "
          f"facteur scan unique : {payload['single_scan_factor']}x")
    print(f"par scan : cuda {payload['seconds_per_scan']['cuda']} s, "
          f"cpu {payload['seconds_per_scan']['cpu']} s")
