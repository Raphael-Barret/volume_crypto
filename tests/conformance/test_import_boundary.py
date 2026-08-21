"""La frontiere du clair est-elle vraiment une frontiere ?

Ces tests ne verifient pas un comportement, ils verifient une PROPRIETE DU
CODE : qu'aucun module de `cryptoserve` autre que `boundary` ne peut exprimer
un dechiffrement. C'est la difference entre << nous faisons attention >> et
<< le code ne sait pas faire autrement >>.

Si un jour quelqu'un ajoute `crypto.decrypt_file` dans `app.py` pour aller
plus vite, ce test echoue avant la revue de code.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

CRYPTOSERVE = Path(__file__).resolve().parents[2] / "cryptoserve"

#: Les primitives qui font apparaitre du clair. Toute reference a l'une
#: d'elles, hors frontiere, casse la revendication.
PLAINTEXT_PRIMITIVES = {"decrypt_file", "read_metadata", "encrypt_file"}

#: Le seul module autorise a les nommer.
BOUNDARY_MODULE = "boundary.py"


def _python_files() -> list[Path]:
    return sorted(p for p in CRYPTOSERVE.rglob("*.py")
                  if "__pycache__" not in p.parts)


def _referenced_names(tree: ast.AST) -> set[str]:
    """Tous les noms d'attributs et d'identifiants cites dans un module."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.ImportFrom):
            names.update(alias.name for alias in node.names)
    return names


class TestOnlyTheBoundaryCanDecrypt(unittest.TestCase):

    def test_the_boundary_module_exists(self):
        self.assertTrue((CRYPTOSERVE / BOUNDARY_MODULE).is_file(),
                        "sans boundary.py, la revendication n'a plus de lieu")

    def test_no_other_module_names_a_plaintext_primitive(self):
        offenders = []
        for path in _python_files():
            if path.name == BOUNDARY_MODULE:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            used = _referenced_names(tree) & PLAINTEXT_PRIMITIVES
            if used:
                offenders.append(f"{path.relative_to(CRYPTOSERVE)} : {sorted(used)}")
        self.assertEqual(offenders, [],
                         "seul boundary.py peut manipuler du clair, or : "
                         + " ; ".join(offenders))

    def test_the_boundary_does_use_them(self):
        """Test miroir : sans lui, le precedent passerait si on supprimait tout."""
        tree = ast.parse((CRYPTOSERVE / BOUNDARY_MODULE).read_text(encoding="utf-8"))
        used = _referenced_names(tree) & PLAINTEXT_PRIMITIVES
        self.assertTrue(used, "la frontiere devrait dechiffrer, sinon elle n'est rien")


class TestTheBoundaryCleansUp(unittest.TestCase):
    """Le clair ne doit survivre a aucun chemin de sortie."""

    def test_workdir_is_removed_on_success_and_on_failure(self):
        import shutil
        import tempfile
        from pathlib import Path as P

        from cryptoserve import boundary
        from cryptoserve.jobs import Job
        from cryptoserve.runners.base import RunOutcome
        from voltcrypt import crypto, keys

        class Exploding:
            name = "exploding"

            def tcb_files(self):
                return []

            def run(self, plain_input, workdir, metadata):
                raise RuntimeError("le traitement a echoue")

        class Fine:
            name = "fine"

            def tcb_files(self):
                return []

            def run(self, plain_input, workdir, metadata):
                out = workdir / "output"
                out.write_bytes(plain_input.read_bytes())
                return RunOutcome(output_path=out, report={})

        tmp = P(tempfile.mkdtemp())
        try:
            source = tmp / "scan.nii"
            source.write_bytes(b"x" * 4096)
            key = keys.generate_key()
            container = tmp / "scan.nii.enc"
            crypto.encrypt_file(source, container, key)

            def workdirs_now():
                roots = [P(tempfile.gettempdir()), P("/dev/shm")]
                found = []
                for root in roots:
                    if root.is_dir():
                        found += list(root.glob("voltcrypt_job_*"))
                return found

            before = set(workdirs_now())

            job = Job("okjob", container, source.stat().st_size)
            boundary.process(job, key, Fine())
            self.assertEqual(set(workdirs_now()) - before, set(),
                             "chemin nominal : aucun repertoire de travail ne survit")

            job2 = Job("badjob", container, source.stat().st_size)
            with self.assertRaises(RuntimeError):
                boundary.process(job2, key, Exploding())
            self.assertEqual(set(workdirs_now()) - before, set(),
                             "chemin d'echec : aucun repertoire de travail ne survit")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_residency_is_measured_and_positive(self):
        import shutil
        import tempfile
        from pathlib import Path as P

        from cryptoserve import boundary
        from cryptoserve.jobs import Job
        from cryptoserve.runners import IdentityRunner
        from voltcrypt import crypto, keys

        tmp = P(tempfile.mkdtemp())
        try:
            source = tmp / "scan.nii"
            source.write_bytes(b"y" * 100_000)
            key = keys.generate_key()
            container = tmp / "scan.nii.enc"
            crypto.encrypt_file(source, container, key)

            job = Job("job", container, source.stat().st_size)
            outcome = boundary.process(job, key, IdentityRunner())

            self.assertGreater(outcome.residency_seconds, 0.0)
            self.assertIn(outcome.workdir_backing, {"memory", "disk"})
            self.assertEqual(outcome.report["workdir_backing"],
                             outcome.workdir_backing)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
