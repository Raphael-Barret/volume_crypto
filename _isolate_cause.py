"""D'ou viennent les 283 voxels ? Du chiffrement, ou de la disposition ?

Le chiffrement est deja disculpe : l'aller-retour rend les memes octets, verifie
par SHA-256 sur 138 908 750 octets. Restent les differences d'ENVIRONNEMENT
entre les deux executions. On les separe :

    A  clair, disposition habituelle   (entree dans le depot, sortie dans /tmp)
    B  clair, disposition de la chaine (entree et sortie dans /dev/shm)  <- sans crypto
    C  la chaine complete              (chiffrement + /dev/shm)

    A vs B  isole la disposition seule
    B vs C  isole le chiffrement seul
    A vs C  l'ecart deja observe

Les sorties sont conservees pour pouvoir etre reanalysees sans relancer le GPU.
"""
import json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

UNC = Path.home()/"Projects"/"UNC"
TOOLS = UNC/"sadt-tools"/"tools"/"Batch_Dental_Seg"
RUNNER = UNC/"slicer-remote-tool-server"/"server"/"execution"/"runner.py"
MODEL = UNC/"slicer-remote-tool-server"/"DATA"/"BatchDentalSeg"/"models"/"DentalSegmentator"
SCAN = UNC/"cryptography"/"volume_crypto"/"data"/"to_encrypt"/"C_0001_T1.nii.gz"
KEEP = Path("/tmp/isolate_out"); KEEP.mkdir(exist_ok=True)

def invoke(scans, out, job_dir):
    for d in (out, job_dir): d.mkdir(parents=True, exist_ok=True)
    job = {"tool":"BatchDentalSeg","job_dir":str(job_dir),
           "params":{"scans":str(scans),"model":str(MODEL),
                     "output_dir":str(out),"device":"cuda"}}
    (job_dir/"job.json").write_text(json.dumps(job))
    r = subprocess.run([str(TOOLS/".venv"/"bin"/"python"), str(RUNNER),
                        "--job", str(job_dir/"job.json")],
                       capture_output=True, text=True, timeout=3600,
                       env={**os.environ, "SADT_TOOL_DIR": str(TOOLS)})
    assert r.returncode == 0, r.stderr[-1500:]
    return next(out.rglob("*_Seg.nii.gz"))

def run_A(tmp):
    return invoke(SCAN, tmp/"outA", tmp/"jobA")

def run_B():
    """Meme disposition que la chaine, mais AUCUN chiffrement."""
    root = Path(tempfile.mkdtemp(prefix="voltcrypt_job_", dir="/dev/shm"))
    staged = root/"input_stage"/SCAN.name
    staged.parent.mkdir(parents=True)
    shutil.copy(SCAN, staged)
    produced = invoke(staged, root/"outputs", root/"job")
    kept = KEEP/"B_Seg.nii.gz"; shutil.copy(produced, kept)
    shutil.rmtree(root, ignore_errors=True)
    return kept

def run_C(tmp):
    from cryptoserve import boundary
    from cryptoserve.jobs import Job
    from cryptoserve.runners.subprocess_tool import SubprocessToolRunner
    from voltcrypt import crypto, keys
    key = keys.generate_key()
    container = tmp/"scan.enc"
    crypto.encrypt_file(SCAN, container, key)
    runner = SubprocessToolRunner(tool="BatchDentalSeg", tool_dir=TOOLS,
                                  runner_path=RUNNER,
                                  params={"model":str(MODEL),"device":"cuda"},
                                  input_argument="scans")
    outcome = boundary.process(Job("c", container, container.stat().st_size), key, runner)
    archive = tmp/"res"; crypto.decrypt_file(outcome.result_path, archive, key)
    restored = tmp/"restored"; restored.mkdir()
    shutil.unpack_archive(archive, restored, format="gztar")
    produced = next(restored.rglob("*_Seg.nii.gz"))
    kept = KEEP/"C_Seg.nii.gz"; shutil.copy(produced, kept)
    return kept

COMPARE = r'''
import sys, numpy as np, nibabel as nib
a = np.asarray(nib.load(sys.argv[1]).dataobj)
b = np.asarray(nib.load(sys.argv[2]).dataobj)
print(int((a != b).sum()), int(a.size))
'''
def diff(p, q):
    r = subprocess.run([str(TOOLS/".venv"/"bin"/"python"), "-c", COMPARE, str(p), str(q)],
                       capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, r.stderr[-500:]
    d, t = r.stdout.split(); return int(d), int(t)

with tempfile.TemporaryDirectory() as t:
    tmp = Path(t)
    print("A : clair, disposition habituelle ...", flush=True)
    a = run_A(tmp); shutil.copy(a, KEEP/"A_Seg.nii.gz"); a = KEEP/"A_Seg.nii.gz"
    print("B : clair, disposition de la chaine (sans crypto) ...", flush=True)
    b = run_B()
    print("C : chaine complete ...", flush=True)
    c = run_C(tmp)

print()
for name, (d, total) in [("A vs B  (disposition seule)", diff(a, b)),
                         ("B vs C  (chiffrement seul)", diff(b, c)),
                         ("A vs C  (les deux)", diff(a, c))]:
    print(f"{name:<32} {d:>8,} voxels differents sur {total:,}")
