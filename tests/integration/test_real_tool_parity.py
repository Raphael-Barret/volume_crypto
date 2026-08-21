"""L'assertion qui porte tout : un vrai outil derriere la porte d'attestation
rend exactement ce qu'il rend en clair.

C'est le correctif du reproche principal fait au papier. Tant que ce test
n'existe pas, les deux moities du systeme, l'acces et la confidentialite, ne
se rencontrent dans aucune experience : la chaine chiffree n'a jamais fait
tourner autre chose que la fonction identite, et l'outil n'a jamais tourne
derriere la porte.

Le test est ecrit AVANT le runner qu'il valide. Il echoue donc au depart, et
c'est voulu : c'est la definition de ce que le runner doit accomplir.

Il est ignore, jamais contourne, quand l'environnement manque : outil sans
virtualenv, poids absents, scan absent, ou pas de GPU. Un skip est visible
dans le rapport de tests ; un test qui s'adapte silencieusement ne l'est pas.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from voltcrypt import crypto, keys

UNC = Path.home() / "Projects" / "UNC"
TOOLS_DIR = UNC / "sadt-tools" / "tools"
RUNNER = UNC / "slicer-remote-tool-server" / "server" / "execution" / "runner.py"
DATA_DIR = UNC / "slicer-remote-tool-server" / "DATA"

#: Outil de reference pour ce test. Choisi parce qu'il est complet
#: (pyproject.toml + uv.lock + .venv), ce qui est la condition pour que son
#: environnement entre dans la mesure : voir cryptoserve/envdigest.py.
TOOL = "Batch_Dental_Seg"
TOOL_ENTRY = "BatchDentalSeg"
MODEL = DATA_DIR / TOOL_ENTRY / "models" / "DentalSegmentator"
SCAN = UNC / "cryptography" / "volume_crypto" / "data" / "to_encrypt" / "C_0001_T1.nii.gz"


def _missing() -> str:
    """Ce qui manque, en clair, pour que le skip soit informatif."""
    venv = TOOLS_DIR / TOOL / ".venv" / "bin" / "python"
    checks = {
        f"virtualenv de {TOOL}": venv.is_file(),
        "runner du serveur d'outils": RUNNER.is_file(),
        f"poids {MODEL.name}": MODEL.is_dir(),
        "scan CBCT de reference": SCAN.is_file(),
    }
    absent = [name for name, present in checks.items() if not present]
    return ", ".join(absent)


#: Fichier de journal produit par l'outil : il n'est pas un resultat, il
#: raconte l'execution. Compare separement, champ par champ.
_RUN_LOG = "BatchDentalSeg_report.json"

#: Les SEULS champs du journal dont on accepte qu'ils different, et pourquoi.
#: Toute autre difference est un desaccord de resultat et fait echouer le test.
#: Cette liste est courte volontairement : chaque entree est une chose que le
#: test cesse de verifier, et elle doit se justifier en une ligne.
_RUN_DEPENDENT_FIELDS = {
    "duration_seconds": "chronometre : ne peut pas etre identique entre deux runs",
}


def _hash_tree(root: Path) -> dict[str, str]:
    """Empreinte de chaque fichier produit, par chemin relatif.

    Les chemins absolus ne sont jamais compares : une execution a ecrit dans
    un repertoire de job, l'autre dans un repertoire temporaire, et cette
    difference n'est pas un desaccord de resultat. Le journal d'execution est
    exclu ici et compare separement par _compare_run_logs.
    """
    import hashlib
    tree = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name not in {"job.json", "result.json", _RUN_LOG}:
            digest = hashlib.sha256()
            with open(path, "rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
            tree[path.relative_to(root).as_posix()] = digest.hexdigest()
    return tree


def _load_run_log(root: Path) -> dict:
    import json
    matches = list(root.rglob(_RUN_LOG))
    return json.loads(matches[0].read_text(encoding="utf-8")) if matches else {}


@unittest.skipIf(_missing(), f"environnement incomplet : {_missing()}")
class TestARealToolRunsBehindTheGate(unittest.TestCase):
    """Un outil reel, son propre interpreteur, et la chaine chiffree."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmp = Path(cls._tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _params(self, scans: Path, output_dir: Path) -> dict:
        return {
            "scans": str(scans),
            "model": str(MODEL),
            "output_dir": str(output_dir),
            "device": "cuda",
        }

    def _run_in_the_clear(self, scans: Path, output_dir: Path) -> dict:
        """L'outil tel qu'il tourne aujourd'hui : entree lisible, sortie lisible."""
        import json

        job_dir = self.tmp / "clear_job"
        job_dir.mkdir(exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        job = {"tool": TOOL_ENTRY, "job_dir": str(job_dir),
               "params": self._params(scans, output_dir)}
        (job_dir / "job.json").write_text(json.dumps(job))

        interpreter = TOOLS_DIR / TOOL / ".venv" / "bin" / "python"
        completed = subprocess.run(
            [str(interpreter), str(RUNNER), "--job", str(job_dir / "job.json")],
            capture_output=True, text=True, timeout=3600,
            env={**os.environ, "SADT_TOOL_DIR": str(TOOLS_DIR / TOOL)},
        )
        self.assertEqual(completed.returncode, 0,
                         f"l'outil a echoue en clair :\n{completed.stderr[-2000:]}")
        return _hash_tree(output_dir)

    def _run_behind_the_gate(self, scans: Path) -> dict:
        """Le meme outil, mais le serveur recoit du chiffre et doit prouver son
        code avant d'obtenir la cle."""
        from cryptoserve import boundary
        from cryptoserve.jobs import Job
        from cryptoserve.runners.subprocess_tool import SubprocessToolRunner

        key = keys.generate_key()
        container = self.tmp / "scan.enc"
        crypto.encrypt_file(scans, container, key)

        # Ce que le serveur detient avant la cle : des octets illisibles.
        blob = container.read_bytes()
        self.assertNotIn(scans.name.encode(), blob,
                         "le nom du fichier ne doit pas etre lisible")

        runner = SubprocessToolRunner(
            tool=TOOL_ENTRY,
            tool_dir=TOOLS_DIR / TOOL,
            runner_path=RUNNER,
            params={"model": str(MODEL), "device": "cuda"},
            input_argument="scans",
        )
        job = Job("parity", container, container.stat().st_size)
        outcome = boundary.process(job, key, runner)

        # Le resultat ressort chiffre ; on le rouvre cote client.
        restored = self.tmp / "restored"
        restored.mkdir(exist_ok=True)
        archive = self.tmp / "result_plain"
        crypto.decrypt_file(outcome.result_path, archive, key)
        shutil.unpack_archive(archive, restored, format="gztar")
        return _hash_tree(restored)

    def test_output_is_identical_through_the_encrypted_chain(self):
        scans = self.tmp / "scans"
        scans.mkdir(exist_ok=True)
        shutil.copy(SCAN, scans / SCAN.name)

        clear_out = self.tmp / "clear_out"
        in_the_clear = self._run_in_the_clear(scans / SCAN.name, clear_out)
        self.assertTrue(in_the_clear, "l'outil n'a produit aucun fichier en clair")

        gate_out = self.tmp / "restored"
        behind_the_gate = self._run_behind_the_gate(scans / SCAN.name)

        # 1. Les resultats, octet par octet. Aucune tolerance ici.
        self.assertEqual(
            sorted(behind_the_gate), sorted(in_the_clear),
            "les deux executions doivent produire les memes fichiers")
        for name, digest in sorted(in_the_clear.items()):
            self.assertEqual(
                behind_the_gate[name], digest,
                f"{name} differe entre l'execution en clair et la chaine chiffree")

        # 2. Le journal d'execution, champ par champ, exclusions declarees.
        clear_log = _load_run_log(clear_out)
        gate_log = _load_run_log(gate_out)
        self.assertTrue(clear_log, "journal d'execution absent en clair")
        self.assertTrue(gate_log, "journal d'execution absent apres la chaine")
        self.assertEqual(sorted(clear_log), sorted(gate_log),
                         "le journal doit porter les memes champs")
        for field in sorted(clear_log):
            if field in _RUN_DEPENDENT_FIELDS:
                continue
            self.assertEqual(
                gate_log[field], clear_log[field],
                f"champ '{field}' du journal : desaccord entre les deux executions")

        # 3. Ce que ce test NE verifie pas, dit a voix haute.
        for field, reason in _RUN_DEPENDENT_FIELDS.items():
            self.assertIn(field, clear_log,
                          f"exclusion declaree pour un champ absent : {field} "
                          f"({reason}). Retirer l'exclusion devenue inutile.")

    def test_the_tool_environment_is_inside_the_measurement(self):
        """Le correctif de la base de confiance, sur un vrai environnement."""
        from cryptoserve import measure
        from cryptoserve.runners.subprocess_tool import SubprocessToolRunner

        runner = SubprocessToolRunner(
            tool=TOOL_ENTRY,
            tool_dir=TOOLS_DIR / TOOL,
            runner_path=RUNNER,
            params={"model": str(MODEL)},
            input_argument="scans",
        )
        manifest = measure.build_manifest(runner=runner)
        labels = " ".join(e.label for e in manifest.entries)
        self.assertIn("venv", labels,
                      "le virtualenv de l'outil doit entrer dans la mesure")
        self.assertIn("uv.lock", labels + " " + str(runner.tcb_files()),
                      "le lockfile de l'outil doit entrer dans la mesure")


if __name__ == "__main__":
    unittest.main()
