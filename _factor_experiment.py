"""Un facteur a la fois. Quatre bras, tous EN CLAIR, aucun chiffrement.

    P  entree d'origine, sortie /tmp        <- reference
    Q  entree d'origine, sortie /dev/shm    <- P vs Q isole la SORTIE
    R  copie /dev/shm,   sortie /tmp        <- P vs R isole l'ENTREE
    S  copie /dev/shm,   sortie /dev/shm    <- P vs S reproduit A vs B
"""
import json, os, shutil, subprocess, tempfile
from pathlib import Path

UNC = Path.home()/"Projects"/"UNC"
TOOLS = UNC/"sadt-tools"/"tools"/"Batch_Dental_Seg"
RUNNER = UNC/"slicer-remote-tool-server"/"server"/"execution"/"runner.py"
MODEL = UNC/"slicer-remote-tool-server"/"DATA"/"BatchDentalSeg"/"models"/"DentalSegmentator"
SCAN = UNC/"cryptography"/"volume_crypto"/"data"/"to_encrypt"/"C_0001_T1.nii.gz"
KEEP = Path("/tmp/factor_out"); shutil.rmtree(KEEP, ignore_errors=True); KEEP.mkdir()

def invoke(scans, out, job_dir, tag):
    for d in (out, job_dir): d.mkdir(parents=True, exist_ok=True)
    job = {"tool":"BatchDentalSeg","job_dir":str(job_dir),
           "params":{"scans":str(scans),"model":str(MODEL),
                     "output_dir":str(out),"device":"cuda"}}
    (job_dir/"job.json").write_text(json.dumps(job))
    r = subprocess.run([str(TOOLS/".venv"/"bin"/"python"), str(RUNNER),
                        "--job", str(job_dir/"job.json")],
                       capture_output=True, text=True, timeout=3600,
                       env={**os.environ, "SADT_TOOL_DIR": str(TOOLS)})
    assert r.returncode == 0, r.stderr[-1200:]
    produced = next(out.rglob("*_Seg.nii.gz"))
    kept = KEEP/f"{tag}.nii.gz"; shutil.copy(produced, kept)
    return kept

COMPARE = r'''
import sys, numpy as np, nibabel as nib
a = np.asarray(nib.load(sys.argv[1]).dataobj); b = np.asarray(nib.load(sys.argv[2]).dataobj)
print(int((a != b).sum()), int(a.size))
'''
def diff(p, q):
    r = subprocess.run([str(TOOLS/".venv"/"bin"/"python"), "-c", COMPARE, str(p), str(q)],
                       capture_output=True, text=True, timeout=900)
    d, t = r.stdout.split(); return int(d), int(t)

shm_roots, results = [], {}
with tempfile.TemporaryDirectory() as t:
    tmp = Path(t)
    def shm_copy(tag):
        root = Path(tempfile.mkdtemp(prefix="voltcrypt_job_", dir="/dev/shm"))
        shm_roots.append(root)
        staged = root/"input_stage"/SCAN.name
        staged.parent.mkdir(parents=True); shutil.copy(SCAN, staged)
        return root, staged

    print("P : entree origine, sortie /tmp ...", flush=True)
    results["P"] = invoke(SCAN, tmp/"outP", tmp/"jobP", "P")

    print("Q : entree origine, sortie /dev/shm ...", flush=True)
    rootQ = Path(tempfile.mkdtemp(prefix="voltcrypt_job_", dir="/dev/shm")); shm_roots.append(rootQ)
    results["Q"] = invoke(SCAN, rootQ/"outputs", rootQ/"job", "Q")

    print("R : copie /dev/shm, sortie /tmp ...", flush=True)
    _, stagedR = shm_copy("R")
    results["R"] = invoke(stagedR, tmp/"outR", tmp/"jobR", "R")

    print("S : copie /dev/shm, sortie /dev/shm ...", flush=True)
    rootS, stagedS = shm_copy("S")
    results["S"] = invoke(stagedS, rootS/"outputs", rootS/"job", "S")

for root in shm_roots:
    shutil.rmtree(root, ignore_errors=True)

print()
pairs = [("P vs Q  (sortie seule)", "P", "Q"),
         ("P vs R  (entree seule)", "P", "R"),
         ("P vs S  (les deux)",     "P", "S"),
         ("R vs S  (sortie, entree fixee)", "R", "S"),
         ("Q vs S  (entree, sortie fixee)", "Q", "S")]
for label, a, b in pairs:
    d, total = diff(results[a], results[b])
    print(f"{label:<34} {d:>8,} voxels sur {total:,}")
