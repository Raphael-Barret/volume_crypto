"""La mesure couvre-t-elle ce qu'elle pretend couvrir ?

Deux tests portent tout le poids, et ils vont par paire :

    toute entree du manifeste change le digest quand elle change ;
    un fichier HORS manifeste ne change pas le digest.

Le second est la definition EXECUTABLE de la base de confiance. Sans lui, on
pourrait mesurer le disque entier et croire avoir tout couvert ; avec lui, la
liste des exclusions cesse d'etre une politique ecrite quelque part et devient
un fait verifiable.
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from cryptoserve import envdigest, measure
from cryptoserve.runners import IdentityRunner


class TestManifestEntriesAreLoadBearing(unittest.TestCase):
    """Chaque entree compte, et le test le prouve entree par entree."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_every_manifest_file_changes_the_digest_when_touched(self):
        """Parametre sur le manifeste : une entree ajoutee est couverte le
        jour ou elle est ajoutee, sans qu'on pense a ecrire un test."""
        files = measure.PROTOCOL_FILES + measure.BOUNDARY_FILES
        self.assertGreater(len(files), 4,
                           "la mesure doit depasser les quatre fichiers de protocole")

        baseline = measure.build_manifest(runner=IdentityRunner()).digest

        for target in files:
            with self.subTest(file=target.name):
                original = target.read_bytes()
                backup = self.tmp / f"{target.name}.bak"
                backup.write_bytes(original)
                try:
                    target.write_bytes(original + b"\n# mutation\n")
                    mutated = measure.build_manifest(runner=IdentityRunner()).digest
                    self.assertNotEqual(
                        mutated, baseline,
                        f"modifier {target.name} doit changer la mesure")
                finally:
                    target.write_bytes(backup.read_bytes())

        self.assertEqual(measure.build_manifest(runner=IdentityRunner()).digest,
                         baseline, "restauration incomplete")

    def test_order_of_entries_is_part_of_the_digest(self):
        a = measure.Manifest(entries=[
            measure.ManifestEntry("protocol", "x", "aa"),
            measure.ManifestEntry("protocol", "y", "bb"),
        ])
        b = measure.Manifest(entries=[
            measure.ManifestEntry("protocol", "y", "bb"),
            measure.ManifestEntry("protocol", "x", "aa"),
        ])
        self.assertNotEqual(a.digest, b.digest)

    def test_removing_an_entry_changes_the_digest(self):
        full = measure.build_manifest(runner=IdentityRunner())
        shorter = measure.Manifest(entries=full.entries[:-1])
        self.assertNotEqual(full.digest, shorter.digest)

    def test_the_policy_is_inside_the_measurement(self):
        """Une politique annoncee mais non mesuree pourrait deriver en silence."""
        strict = measure.build_manifest(runner=IdentityRunner(),
                                        policy={"debug": False})
        loose = measure.build_manifest(runner=IdentityRunner(),
                                       policy={"debug": True})
        self.assertNotEqual(strict.digest, loose.digest)


class TestTheTrustedComputingBaseIsBounded(unittest.TestCase):
    """Ce que la mesure NE couvre PAS, dit explicitement."""

    def test_a_file_outside_the_manifest_does_not_change_the_digest(self):
        """Le test qui definit la base de confiance.

        Il doit passer : un fichier hors perimetre n'a aucun effet. C'est
        exactement la raison pour laquelle la liste des exclusions doit etre
        publiee, et pourquoi WP2 a fait entrer la frontiere et le runner dans
        le manifeste : ils ne peuvent pas rester du cote de ce test.
        """
        baseline = measure.build_manifest(runner=IdentityRunner()).digest
        outsider = Path(__file__).resolve().parents[2] / "README.md"
        original = outsider.read_bytes()
        try:
            outsider.write_bytes(original + b"\n<!-- hors perimetre -->\n")
            self.assertEqual(
                measure.build_manifest(runner=IdentityRunner()).digest, baseline,
                "un fichier hors manifeste ne doit pas peser sur la mesure")
        finally:
            outsider.write_bytes(original)

    def test_exclusions_are_declared_and_published(self):
        manifest = measure.build_manifest(runner=IdentityRunner())
        payload = manifest.to_dict()
        self.assertIn("accepted_exclusions", payload)
        self.assertTrue(payload["accepted_exclusions"])
        joined = " ".join(payload["accepted_exclusions"]).lower()
        for expected in ["noyau", "interpreteur", "gpu", "materiel"]:
            self.assertIn(expected, joined,
                          f"exclusion non declaree : {expected}")

    def test_the_boundary_is_inside_the_manifest(self):
        """La regression que ce work package existe pour empecher."""
        manifest = measure.build_manifest(runner=IdentityRunner())
        kinds = {e.kind for e in manifest.entries}
        labels = " ".join(e.label for e in manifest.entries)
        self.assertIn("boundary", kinds,
                      "le module qui manipule le clair doit etre mesure")
        self.assertIn("boundary.py", labels)

    def test_the_runner_is_inside_the_manifest(self):
        manifest = measure.build_manifest(runner=IdentityRunner())
        self.assertIn("runner", {e.kind for e in manifest.entries},
                      "le code qui lit le clair doit etre mesure")


class TestEnvironmentDigest(unittest.TestCase):
    """La mesure d'un virtualenv, qui est ce qui manquait."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.venv = self.tmp / "tool" / ".venv"
        (self.venv / "lib").mkdir(parents=True)
        (self.venv / "lib" / "mod.py").write_text("VERSION = 1\n")
        (self.venv / "lib" / "big.so").write_bytes(b"\x00" * 4096)
        self.lock = self.tmp / "tool" / "uv.lock"
        self.lock.write_text('name = "torch"\nversion = "2.2.0"\n')

    def tearDown(self):
        self._tmp.cleanup()

    def _digest(self, mode="inventory"):
        return envdigest.digest_environment("tool", self.venv, self.lock, mode)

    def test_is_stable(self):
        self.assertEqual(self._digest().digest, self._digest().digest)

    def test_changing_the_lockfile_changes_the_digest(self):
        before = self._digest().digest
        self.lock.write_text('name = "torch"\nversion = "2.5.0"\n')
        self.assertNotEqual(self._digest().digest, before)

    def test_adding_a_file_changes_the_digest(self):
        before = self._digest().digest
        (self.venv / "lib" / "new.py").write_text("x = 1\n")
        self.assertNotEqual(self._digest().digest, before)

    def test_a_size_change_is_caught_in_inventory_mode(self):
        before = self._digest().digest
        (self.venv / "lib" / "mod.py").write_text("VERSION = 1234\n")
        self.assertNotEqual(self._digest().digest, before)

    def test_inventory_mode_misses_a_same_size_substitution(self):
        """La limite du mode rapide, testee plutot que passee sous silence.

        Ce test DOIT passer : il documente que `inventory` ne detecte pas une
        substitution de meme taille. C'est pour cela que le mode retenu figure
        dans le manifeste, et que `content` existe pour les releases.
        """
        before = self._digest("inventory").digest
        (self.venv / "lib" / "mod.py").write_text("VERSION = 2\n")   # meme taille
        self.assertEqual(self._digest("inventory").digest, before,
                         "mode inventory : substitution de meme taille invisible")

    def test_content_mode_catches_what_inventory_misses(self):
        before = self._digest("content").digest
        (self.venv / "lib" / "mod.py").write_text("VERSION = 2\n")   # meme taille
        self.assertNotEqual(self._digest("content").digest, before,
                            "mode content : la substitution doit etre vue")

    def test_pycache_does_not_move_the_digest(self):
        """Importer un module ne doit pas changer la mesure du serveur."""
        before = self._digest().digest
        cache = self.venv / "lib" / "__pycache__"
        cache.mkdir()
        (cache / "mod.cpython-312.pyc").write_bytes(b"\x00" * 100)
        self.assertEqual(self._digest().digest, before)

    def test_reports_what_it_covered(self):
        result = self._digest()
        self.assertEqual(result.file_count, 2)
        self.assertEqual(result.total_bytes, 4096 + len("VERSION = 1\n"))
        self.assertEqual(result.mode, "inventory")
        self.assertGreater(result.seconds, 0.0)


if __name__ == "__main__":
    unittest.main()
