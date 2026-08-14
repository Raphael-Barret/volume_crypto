"""Tests de l'audit.

Le point important n'est pas que l'audit dise "ok" sur du vrai chiffrement :
c'est qu'il dise "FAIL" sur du faux. On lui soumet donc des conteneurs
volontairement mauvais.
"""

import os
import struct
import tempfile
import unittest
from pathlib import Path

from voltcrypt import audit, crypto, keys

VTK_SAMPLE = (b"# vtk DataFile Version 3.0\nmandible\nASCII\nDATASET POLYDATA\n"
              b"POINTS 3 float\n0.0 0.0 0.0\n1.0 0.0 0.0\n0.0 1.0 0.0\n") * 40


class AuditTestCase(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.key = keys.generate_key()

    def tearDown(self):
        self._tmp.cleanup()

    def encrypted(self, name="DUPONT_Jean_T1.vtk", data=VTK_SAMPLE):
        src = self.tmp / name
        src.write_bytes(data)
        enc = self.tmp / (name + ".enc")
        crypto.encrypt_file(src, enc, self.key)
        return src, enc


class TestEntropy(unittest.TestCase):

    def test_random_data_is_near_8_bits(self):
        self.assertGreater(audit.shannon_entropy(os.urandom(100_000)), 7.99)

    def test_repeated_byte_is_zero(self):
        self.assertEqual(audit.shannon_entropy(b"\x00" * 10_000), 0.0)

    def test_text_is_low(self):
        self.assertLess(audit.shannon_entropy(VTK_SAMPLE), 5.0)

    def test_floor_is_reachable_by_real_random_data(self):
        """Le seuil ne doit jamais faire echouer du vrai aleatoire.

        30 tirages par taille : c'est ce test qui a rattrape un seuil trop
        serre sur les petits fichiers.
        """
        for size in (1_024, 2_048, 10_000, 100_000):
            floor = audit.expected_entropy_floor(size)
            for _ in range(30):
                self.assertGreaterEqual(audit.shannon_entropy(os.urandom(size)), floor,
                                        f"faux positif sur {size} octets aleatoires")

    def test_small_samples_are_declared_inconclusive(self):
        for size in (0, 63, 200, 1_023):
            self.assertEqual(audit.expected_entropy_floor(size), 0.0)


class TestSignatureDetection(unittest.TestCase):

    def test_detects_vtk(self):
        found = audit.find_plaintext_signatures(b"xxx# vtk DataFile Version 3.0xxx")
        self.assertTrue(any("VTK" in f for f in found))

    def test_detects_nifti_and_hdf5(self):
        self.assertTrue(audit.find_plaintext_signatures(b"...n+1\x00..."))
        self.assertTrue(audit.find_plaintext_signatures(b"\x89HDF\r\n\x1a\n"))

    def test_no_false_positive_on_random(self):
        self.assertEqual(audit.find_plaintext_signatures(os.urandom(200_000)), [])


class TestFragmentLeak(unittest.TestCase):

    def test_finds_fragments_when_content_is_copied(self):
        plain = os.urandom(50_000)
        blob = b"HEADER" + plain          # "chiffrement" qui ne chiffre rien
        self.assertGreater(audit.find_leaked_fragments(blob, plain), 0)

    def test_none_when_properly_encrypted(self):
        plain = os.urandom(50_000)
        self.assertEqual(audit.find_leaked_fragments(os.urandom(60_000), plain), 0)


class TestAuditOnRealContainers(AuditTestCase):

    def test_valid_container_passes_every_check(self):
        src, enc = self.encrypted()
        report = audit.audit_container(enc, self.key, plain_path=src)
        self.assertTrue(report.passed, f"echecs : {[c.name for c in report.failures]}")
        names = {c.name for c in report.checks}
        self.assertEqual(names, {"structure", "entropie", "signatures format",
                                 "nom d'origine", "round-trip",
                                 "identique a l'original", "fuite de fragments"})

    def test_binary_volume_passes(self):
        src, enc = self.encrypted("scan.nii", os.urandom(200_000))
        self.assertTrue(audit.audit_container(enc, self.key, plain_path=src).passed)

    def test_small_file_passes(self):
        src, enc = self.encrypted("petit.vtk", b"abc")
        self.assertTrue(audit.audit_container(enc, self.key, plain_path=src).passed)

    def test_works_without_the_original(self):
        _, enc = self.encrypted()
        report = audit.audit_container(enc, self.key)
        self.assertTrue(report.passed)
        self.assertNotIn("fuite de fragments", {c.name for c in report.checks})


class TestAuditCatchesBadEncryption(AuditTestCase):
    """L'audit doit refuser tout ce qui n'est pas reellement chiffre."""

    def _fail_names(self, report):
        return {c.name for c in report.failures}

    def test_rejects_a_plain_file_renamed_enc(self):
        fake = self.tmp / "faux.enc"
        fake.write_bytes(VTK_SAMPLE)
        report = audit.audit_container(fake, self.key)
        self.assertFalse(report.passed)
        self.assertIn("structure", self._fail_names(report))

    def test_rejects_a_container_carrying_the_plaintext(self):
        """Conteneur valide en apparence, mais le clair est colle a la fin."""
        src, enc = self.encrypted()
        with open(enc, "ab") as handle:
            handle.write(VTK_SAMPLE)
        report = audit.audit_container(enc, self.key, plain_path=src)
        self.assertFalse(report.passed)
        failures = self._fail_names(report)
        self.assertIn("signatures format", failures)
        self.assertIn("fuite de fragments", failures)

    def test_rejects_xor_style_fake_encryption(self):
        """Un 'chiffrement' par XOR d'un octet garde toute la structure."""
        plain = VTK_SAMPLE
        fake = self.tmp / "xor.enc"
        header = struct.pack(">8sBI", crypto.MAGIC, 1, 4096) + os.urandom(8)
        fake.write_bytes(header + bytes(b ^ 0x42 for b in plain))

        report = audit.audit_container(fake, self.key)
        self.assertFalse(report.passed)
        failures = self._fail_names(report)
        self.assertIn("entropie", failures)   # le texte XORe reste tres structure
        self.assertIn("round-trip", failures)

    def test_rejects_wrong_key(self):
        _, enc = self.encrypted()
        report = audit.audit_container(enc, keys.generate_key())
        self.assertFalse(report.passed)
        self.assertIn("round-trip", self._fail_names(report))

    def test_rejects_container_with_the_filename_in_clear(self):
        src, enc = self.encrypted("DUPONT_Jean_T1.vtk")
        with open(enc, "ab") as handle:
            handle.write(b"DUPONT_Jean_T1.vtk")
        report = audit.audit_container(enc, self.key)
        self.assertFalse(report.passed)
        self.assertIn("nom d'origine", self._fail_names(report))

    def test_rejects_altered_container(self):
        src, enc = self.encrypted("scan.nii", os.urandom(100_000))
        blob = bytearray(enc.read_bytes())
        blob[len(blob) // 2] ^= 0x01
        enc.write_bytes(blob)
        report = audit.audit_container(enc, self.key, plain_path=src)
        self.assertFalse(report.passed)
        self.assertIn("round-trip", self._fail_names(report))


if __name__ == "__main__":
    unittest.main()
