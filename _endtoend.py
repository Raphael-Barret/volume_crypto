"""Les deux chiffres que la review v2 reproche d'avoir inventes.

    N1  un VRAI aller-retour client/serveur, avec le vrai outil derriere la
        porte. Pas un appel de fonction en processus : sept etapes HTTP.
    N2  la residence du clair sur LE MEME volume de 132,5 Mo en traitement
        identite, pour ne plus apparier un 60 Ko avec un 132,5 Mo.
"""
import json, shutil, tempfile, threading, time
from pathlib import Path

import client
from cryptoserve.app import serve
from cryptoserve.runners import IdentityRunner
from cryptoserve.runners.subprocess_tool import SubprocessToolRunner

UNC = Path.home()/"Projects"/"UNC"
TOOLS = UNC/"sadt-tools"/"tools"/"Batch_Dental_Seg"
RUNNER = UNC/"slicer-remote-tool-server"/"server"/"execution"/"runner.py"
MODEL = UNC/"slicer-remote-tool-server"/"DATA"/"BatchDentalSeg"/"models"/"DentalSegmentator"
SCAN = Path(__file__).resolve().parent/"data"/"to_encrypt"/"C_0001_T1.nii.gz"

def measure(runner, label, tmp):
    storage = tmp/f"storage_{label}"
    httpd = serve("127.0.0.1", 0, storage=storage, quiet=True, runner=runner)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    enclave = httpd.RequestHandlerClass.enclave
    out = tmp/f"out_{label}"; out.mkdir(parents=True, exist_ok=True)
    try:
        started = time.perf_counter()
        result = client.run(SCAN, f"http://127.0.0.1:{port}", out,
                            expected_measurement=enclave.measurement, verbose=False)
        wall = time.perf_counter() - started
        status = json.loads(__import__("urllib.request", fromlist=["x"])
                            .urlopen(f"http://127.0.0.1:{port}/jobs/{result['job_id']}")
                            .read().decode())
        return {
            "label": label,
            "runner": runner.name,
            "scan_bytes": SCAN.stat().st_size,
            "client_wall_seconds": round(wall, 3),
            "plaintext_residency_seconds": status.get("plaintext_residency_seconds"),
            "workdir_backing": status.get("report", {}).get("workdir_backing"),
            "tool_seconds": status.get("report", {}).get("tool_seconds"),
        }
    finally:
        httpd.shutdown(); httpd.server_close(); thread.join(timeout=5)

with tempfile.TemporaryDirectory() as t:
    tmp = Path(t)
    rows = []
    print("N2 : identite, sur le CBCT complet ...", flush=True)
    rows.append(measure(IdentityRunner(), "identity", tmp))
    print("N1 : vrai outil, vraie chaine HTTP ...", flush=True)
    rows.append(measure(SubprocessToolRunner(
        tool="BatchDentalSeg", tool_dir=TOOLS, runner_path=RUNNER,
        params={"model": str(MODEL), "device": "cuda"},
        input_argument="scans"), "real_tool", tmp))

Path("evidence").mkdir(exist_ok=True)
Path("evidence/endtoend.json").write_text(json.dumps(rows, indent=2) + "\n")
print()
print(f"{'condition':<12} {'charge':>12} {'aller-retour':>14} {'residence clair':>17} {'support':>9}")
print("-"*72)
for r in rows:
    print(f"{r['label']:<12} {r['scan_bytes']/1e6:>10.1f} Mo "
          f"{r['client_wall_seconds']:>12.2f} s {str(r['plaintext_residency_seconds']):>15} s "
          f"{str(r['workdir_backing']):>9}")
