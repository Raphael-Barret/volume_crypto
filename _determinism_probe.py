"""Le mecanisme candidat tient-il ? Deux executions IDENTIQUES, meme entree,
meme repertoire, en desactivant puis en laissant cudnn.benchmark.

Aucune chaine chiffree ici. Si l'ecart apparait entre deux runs en clair des
qu'on change l'etat du GPU entre les deux, le chiffrement est disculpe.
"""
import json, os, subprocess, tempfile
from pathlib import Path

UNC = Path.home()/"Projects"/"UNC"
TOOLS = UNC/"sadt-tools"/"tools"/"Batch_Dental_Seg"
RUNNER = UNC/"slicer-remote-tool-server"/"server"/"execution"/"runner.py"
MODEL = UNC/"slicer-remote-tool-server"/"DATA"/"BatchDentalSeg"/"models"/"DentalSegmentator"
SCAN = UNC/"cryptography"/"volume_crypto"/"data"/"to_encrypt"/"C_0001_T1.nii.gz"

def invoke(tmp, tag, extra_env=None):
    out = tmp/f"out_{tag}"; job_dir = tmp/f"job_{tag}"
    out.mkdir(parents=True); job_dir.mkdir(parents=True)
    job = {"tool":"BatchDentalSeg","job_dir":str(job_dir),
           "params":{"scans":str(SCAN),"model":str(MODEL),
                     "output_dir":str(out),"device":"cuda"}}
    (job_dir/"job.json").write_text(json.dumps(job))
    env = {**os.environ, "SADT_TOOL_DIR": str(TOOLS), **(extra_env or {})}
    r = subprocess.run([str(TOOLS/".venv"/"bin"/"python"), str(RUNNER),
                        "--job", str(job_dir/"job.json")],
                       capture_output=True, text=True, timeout=3600, env=env)
    assert r.returncode == 0, r.stderr[-1200:]
    return next(out.rglob("*_Seg.nii.gz"))

COMPARE = r'''
import sys, numpy as np, nibabel as nib
a = np.asarray(nib.load(sys.argv[1]).dataobj); b = np.asarray(nib.load(sys.argv[2]).dataobj)
print(int((a != b).sum()), int(a.size))
'''
def diff(p, q):
    r = subprocess.run([str(TOOLS/".venv"/"bin"/"python"), "-c", COMPARE, str(p), str(q)],
                       capture_output=True, text=True, timeout=600)
    d, t = r.stdout.split(); return int(d), int(t)

# Charge GPU entre les deux runs, pour changer l'etat que cudnn chronometre.
LOAD = r'''
import torch
x = torch.randn(4096, 4096, device="cuda")
for _ in range(200): x = (x @ x.T).relu() / 1e4
torch.cuda.synchronize()
'''

with tempfile.TemporaryDirectory() as t:
    tmp = Path(t)
    print("run 1 (clair) ...", flush=True); a = invoke(tmp, "a")
    print("charge GPU intercalee ...", flush=True)
    subprocess.run([str(TOOLS/".venv"/"bin"/"python"), "-c", LOAD], timeout=600)
    print("run 2 (clair, apres charge) ...", flush=True); b = invoke(tmp, "b")

    d, total = diff(a, b)
    print()
    print(f"clair vs clair, avec une charge GPU intercalee : {d:,} voxels sur {total:,}")
    print("INTERPRETATION :",
          "l'etat du GPU suffit a changer la sortie, le chiffrement est disculpe"
          if d > 0 else
          "l'etat du GPU ne suffit pas ici, chercher ailleurs")
