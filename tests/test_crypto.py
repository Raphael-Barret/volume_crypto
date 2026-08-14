"""Tests du chiffrement fichier a fichier.

On teste surtout :
  - l'aller-retour bit a bit sur des donnees realistes (VTK ASCII, NIfTI binaire)
  - les fichiers plus gros que la taille de bloc
  - le refus d'une mauvaise cle
  - la detection d'une alteration ou d'une troncature
"""

import os
import tempfile
import unittest
from pathlib import Path

from voltcrypt import crypto, keys

# Un petit VTK ASCII, tel qu'en produit Slicer / VTK.
VTK_SAMPLE = b"""# vtk DataFile Version 3.0
mandible surface
ASCII
DATASET POLYDATA
POINTS 3 float
0.0 0.0 0.0
1.0 0.0 0.0
0.0 1.0 0.0
POLYGONS 1 4
3 0 1 2
"""


class CryptoTestCase(unittest.TestCase):
    """Base : un dossier temporaire et une cle par test."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.key = keys.generate_key()

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name, data):
        path = self.tmp / name
        path.write_bytes(data)
        return path

    def roundtrip(self, name, data, chunk_size=crypto.config.CHUNK_SIZE):
        src = self.write(name, data)
        enc = self.tmp / (name + ".enc")
        dec = self.tmp / ("out_" + name)
        crypto.encrypt_file(src, enc, self.key, chunk_size=chunk_size)
        crypto.decrypt_file(enc, dec, self.key)
        return enc, dec


class TestRoundTrip(CryptoTestCase):

    def test_vtk_ascii(self):
        _, dec = self.roundtrip("mandible.vtk", VTK_SAMPLE)
        self.assertEqual(dec.read_bytes(), VTK_SAMPLE)

    def test_binary_volume(self):
        # ~1 Mo de binaire facon volume NIfTI brut
        data = os.urandom(1024 * 1024)
        _, dec = self.roundtrip("scan.nii", data)
        self.assertEqual(dec.read_bytes(), data)

    def test_empty_file(self):
        _, dec = self.roundtrip("vide.nrrd", b"")
        self.assertEqual(dec.read_bytes(), b"")

    def test_single_byte(self):
        _, dec = self.roundtrip("un.raw", b"\x00")
        self.assertEqual(dec.read_bytes(), b"\x00")

    def test_file_larger_than_chunk(self):
        # 5 blocs et demi, pour exercer le decoupage
        data = os.urandom(1000 * 5 + 500)
        _, dec = self.roundtrip("gros.mha", data, chunk_size=1000)
        self.assertEqual(dec.read_bytes(), data)

    def test_exactly_one_chunk(self):
        data = os.urandom(4096)
        _, dec = self.roundtrip("pile.vtk", data, chunk_size=4096)
        self.assertEqual(dec.read_bytes(), data)

    def test_ciphertext_differs_from_plaintext(self):
        enc, _ = self.roundtrip("mandible.vtk", VTK_SAMPLE)
        blob = enc.read_bytes()
        self.assertNotIn(b"vtk DataFile", blob)
        self.assertNotIn(b"POLYGONS", blob)

    def test_same_file_twice_gives_different_ciphertext(self):
        """Le nonce est tire par fichier : deux chiffrements ne se ressemblent pas."""
        src = self.write("a.vtk", VTK_SAMPLE)
        one = self.tmp / "one.enc"
        two = self.tmp / "two.enc"
        crypto.encrypt_file(src, one, self.key)
        crypto.encrypt_file(src, two, self.key)
        self.assertNotEqual(one.read_bytes(), two.read_bytes())


class TestMetadata(CryptoTestCase):

    def test_original_name_is_preserved(self):
        enc, _ = self.roundtrip("patient_01_T1.nii.gz", b"donnees")
        self.assertEqual(crypto.original_name(enc, self.key), "patient_01_T1.nii.gz")

    def test_metadata_size(self):
        data = b"x" * 4321
        enc, _ = self.roundtrip("scan.vtk", data)
        self.assertEqual(crypto.read_metadata(enc, self.key)["size"], 4321)

    def test_filename_is_not_readable_in_the_container(self):
        """Le nom d'origine ne doit pas apparaitre en clair dans le .enc."""
        enc, _ = self.roundtrip("DUPONT_Jean_CBCT.vtk", VTK_SAMPLE)
        self.assertNotIn(b"DUPONT", enc.read_bytes())


class TestSecurity(CryptoTestCase):

    def test_wrong_key_is_refused(self):
        enc, _ = self.roundtrip("scan.vtk", VTK_SAMPLE)
        other = keys.generate_key()
        with self.assertRaises(crypto.CryptoError):
            crypto.decrypt_file(enc, self.tmp / "nope.vtk", other)

    def test_no_partial_output_on_failure(self):
        enc, _ = self.roundtrip("scan.vtk", VTK_SAMPLE)
        out = self.tmp / "nope.vtk"
        with self.assertRaises(crypto.CryptoError):
            crypto.decrypt_file(enc, out, keys.generate_key())
        self.assertFalse(out.exists(), "aucun fichier partiel ne doit rester")
        self.assertFalse((self.tmp / "nope.vtk.part").exists())

    def test_flipped_bit_is_detected(self):
        enc, _ = self.roundtrip("scan.nii", os.urandom(50_000))
        blob = bytearray(enc.read_bytes())
        blob[len(blob) // 2] ^= 0x01  # un seul bit au milieu du ciphertext
        enc.write_bytes(blob)
        with self.assertRaises(crypto.CryptoError):
            crypto.decrypt_file(enc, self.tmp / "out.nii", self.key)

    def test_truncation_is_detected(self):
        """Couper la fin d'un .enc doit echouer, pas produire un fichier partiel."""
        enc, _ = self.roundtrip("scan.nii", os.urandom(5000), chunk_size=1000)
        blob = enc.read_bytes()
        enc.write_bytes(blob[: len(blob) // 2])
        with self.assertRaises(crypto.CryptoError):
            crypto.decrypt_file(enc, self.tmp / "out.nii", self.key)

    def test_not_a_container(self):
        fake = self.write("faux.enc", b"pas un conteneur du tout")
        with self.assertRaises(crypto.CryptoError):
            crypto.decrypt_file(fake, self.tmp / "out", self.key)

    def test_missing_source(self):
        with self.assertRaises(crypto.CryptoError):
            crypto.encrypt_file(self.tmp / "absent.vtk", self.tmp / "o.enc", self.key)


class TestProgress(CryptoTestCase):

    def test_progress_callback_is_called(self):
        seen = []
        src = self.write("gros.nii", os.urandom(3000))
        crypto.encrypt_file(src, self.tmp / "g.enc", self.key,
                            chunk_size=1000, progress=lambda d, t: seen.append((d, t)))
        self.assertEqual(len(seen), 3)
        self.assertEqual(seen[-1], (3000, 3000))


if __name__ == "__main__":
    unittest.main()
