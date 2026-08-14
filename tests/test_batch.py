"""Tests du traitement par dossier."""

import os
import tempfile
import unittest
from pathlib import Path

from voltcrypt import batch, config, keys


class BatchTestCase(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.plain = self.tmp / "to_encrypt"
        self.enc = self.tmp / "encrypted"
        self.dec = self.tmp / "decrypted"
        for d in (self.plain, self.enc, self.dec):
            d.mkdir()
        self.key = keys.generate_key()

    def tearDown(self):
        self._tmp.cleanup()

    def make(self, relative, data=b"donnees"):
        path = self.plain / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path


class TestFileSelection(BatchTestCase):

    def test_finds_files_recursively(self):
        self.make("a.vtk")
        self.make("sous_dossier/b.nii")
        found = {p.name for p in batch.iter_files(self.plain)}
        self.assertEqual(found, {"a.vtk", "b.nii"})

    def test_non_recursive(self):
        self.make("a.vtk")
        self.make("sous/b.nii")
        found = {p.name for p in batch.iter_files(self.plain, recursive=False)}
        self.assertEqual(found, {"a.vtk"})

    def test_extension_filter(self):
        self.make("scan.nii.gz")
        self.make("notes.txt")
        self.make("mesh.vtk")
        found = {p.name for p in batch.iter_files(self.plain,
                                                  extensions=config.VOLUME_EXTENSIONS)}
        self.assertEqual(found, {"scan.nii.gz", "mesh.vtk"})

    def test_hidden_and_part_files_are_ignored(self):
        self.make(".DS_Store")
        self.make("interrompu.enc.part")
        self.make("bon.vtk")
        found = {p.name for p in batch.iter_files(self.plain)}
        self.assertEqual(found, {"bon.vtk"})

    def test_missing_directory_yields_nothing(self):
        self.assertEqual(list(batch.iter_files(self.tmp / "absent")), [])


class TestBatchRoundTrip(BatchTestCase):

    def test_full_pipeline(self):
        files = {
            "patient_01/scan.nii": os.urandom(2048),
            "patient_01/mandible.vtk": b"# vtk DataFile Version 3.0\n",
            "patient_02/scan.nrrd": os.urandom(1024),
        }
        for name, data in files.items():
            self.make(name, data)

        enc_result = batch.encrypt_directory(self.plain, self.enc, self.key, verbose=False)
        self.assertEqual(len(enc_result.succeeded), 3)
        self.assertFalse(enc_result.failed)

        dec_result = batch.decrypt_directory(self.enc, self.dec, self.key, verbose=False)
        self.assertEqual(len(dec_result.succeeded), 3)
        self.assertFalse(dec_result.failed)

        for name, data in files.items():
            restored = self.dec / name
            self.assertTrue(restored.exists(), f"{name} n'a pas ete restitue")
            self.assertEqual(restored.read_bytes(), data, f"{name} differe de l'original")

    def test_folder_structure_is_preserved(self):
        self.make("T1/patient_01/scan.nii")
        batch.encrypt_directory(self.plain, self.enc, self.key, verbose=False)
        self.assertTrue((self.enc / "T1/patient_01/scan.nii.enc").exists())

    def test_existing_output_is_skipped(self):
        self.make("a.vtk")
        batch.encrypt_directory(self.plain, self.enc, self.key, verbose=False)
        second = batch.encrypt_directory(self.plain, self.enc, self.key, verbose=False)
        self.assertEqual(len(second.skipped), 1)
        self.assertEqual(len(second.succeeded), 0)

    def test_overwrite_flag(self):
        self.make("a.vtk")
        batch.encrypt_directory(self.plain, self.enc, self.key, verbose=False)
        second = batch.encrypt_directory(self.plain, self.enc, self.key,
                                         overwrite=True, verbose=False)
        self.assertEqual(len(second.succeeded), 1)

    def test_empty_input_directory(self):
        result = batch.encrypt_directory(self.plain, self.enc, self.key, verbose=False)
        self.assertEqual(len(result), 0)

    def test_wrong_key_reports_failures_without_crashing(self):
        self.make("a.vtk")
        batch.encrypt_directory(self.plain, self.enc, self.key, verbose=False)
        result = batch.decrypt_directory(self.enc, self.dec, keys.generate_key(),
                                         verbose=False)
        self.assertEqual(len(result.failed), 1)
        self.assertEqual(len(list(self.dec.rglob("*"))), 0)

    def test_one_bad_file_does_not_stop_the_batch(self):
        self.make("bon.vtk", b"contenu")
        batch.encrypt_directory(self.plain, self.enc, self.key, verbose=False)
        (self.enc / "casse.enc").write_bytes(b"pas un conteneur")

        result = batch.decrypt_directory(self.enc, self.dec, self.key, verbose=False)
        self.assertEqual(len(result.succeeded), 1)
        self.assertEqual(len(result.failed), 1)

    def test_renamed_container_restores_the_original_name(self):
        """Le nom d'origine vient des metadonnees, pas du nom du .enc."""
        self.make("scan_original.nii", b"volume")
        batch.encrypt_directory(self.plain, self.enc, self.key, verbose=False)
        (self.enc / "scan_original.nii.enc").rename(self.enc / "anonyme_001.enc")

        batch.decrypt_directory(self.enc, self.dec, self.key, verbose=False)
        self.assertTrue((self.dec / "scan_original.nii").exists())

    def test_summary_text(self):
        self.make("a.vtk")
        result = batch.encrypt_directory(self.plain, self.enc, self.key, verbose=False)
        self.assertIn("1 traite(s)", result.summary())


if __name__ == "__main__":
    unittest.main()
