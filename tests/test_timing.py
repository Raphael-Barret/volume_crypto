"""Tests du chronometrage."""

import os
import tempfile
import time
import unittest
from pathlib import Path

from voltcrypt import batch, crypto, keys, timing


class TestFormatting(unittest.TestCase):

    def test_durations(self):
        self.assertEqual(timing.human_duration(0.0004), "400 us")
        self.assertEqual(timing.human_duration(0.05), "50.0 ms")
        self.assertEqual(timing.human_duration(1.5), "1.50 s")
        self.assertEqual(timing.human_duration(75), "1 min 15 s")
        self.assertEqual(timing.human_duration(3725), "1 h 02 min")

    def test_sizes(self):
        self.assertEqual(timing.human_size(238), "238.0 o")
        self.assertEqual(timing.human_size(1536), "1.5 Ko")
        self.assertEqual(timing.human_size(138_908_750), "132.5 Mo")

    def test_speed(self):
        self.assertEqual(timing.human_speed(100 * 1024 * 1024, 1.0), "100 Mo/s")

    def test_speed_is_dash_when_measurement_is_meaningless(self):
        """Debit affiche seulement quand il veut dire quelque chose."""
        self.assertEqual(timing.human_speed(1000, 0.0001), "-")   # trop bref
        self.assertEqual(timing.human_speed(0, 1.0), "-")         # rien traite
        self.assertEqual(timing.human_speed(238, 0.0012), "-")    # fichier minuscule


class TestChrono(unittest.TestCase):

    def test_measures_elapsed_time(self):
        with timing.Chrono() as chrono:
            time.sleep(0.05)
        self.assertGreaterEqual(chrono.seconds, 0.05)
        self.assertLess(chrono.seconds, 1.0)

    def test_frozen_after_exit(self):
        with timing.Chrono() as chrono:
            time.sleep(0.01)
        first = chrono.seconds
        time.sleep(0.02)
        self.assertEqual(chrono.seconds, first, "la duree ne doit plus bouger")

    def test_readable_during_the_block(self):
        with timing.Chrono() as chrono:
            time.sleep(0.02)
            self.assertGreater(chrono.seconds, 0.0)


class TestTimingOnFiles(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.key = keys.generate_key()
        self.data = os.urandom(2 * 1024 * 1024)   # 2 Mio
        self.src = self.tmp / "scan.nii"
        self.src.write_bytes(self.data)

    def tearDown(self):
        self._tmp.cleanup()

    def test_encrypt_returns_a_timing(self):
        result = crypto.encrypt_file(self.src, self.tmp / "scan.nii.enc", self.key)
        self.assertIsInstance(result, timing.Timing)
        self.assertGreater(result.seconds, 0.0)
        self.assertEqual(result.size, len(self.data))
        self.assertGreater(result.mb_per_second, 0.0)

    def test_decrypt_returns_a_timing(self):
        enc = self.tmp / "scan.nii.enc"
        crypto.encrypt_file(self.src, enc, self.key)
        result = crypto.decrypt_file(enc, self.tmp / "out.nii", self.key)
        self.assertGreater(result.seconds, 0.0)
        self.assertEqual(result.size, len(self.data),
                         "la taille mesuree est celle de la donnee en clair")

    def test_timing_is_usable_as_a_path(self):
        """os.PathLike : le retour reste utilisable comme un chemin."""
        result = crypto.encrypt_file(self.src, self.tmp / "scan.nii.enc", self.key)
        self.assertEqual(Path(result).name, "scan.nii.enc")
        with open(result, "rb") as handle:      # doit fonctionner directement
            self.assertEqual(handle.read(8), crypto.MAGIC)

    def test_timing_string_is_readable(self):
        result = crypto.encrypt_file(self.src, self.tmp / "scan.nii.enc", self.key)
        text = str(result)
        self.assertIn("scan.nii.enc", text)
        self.assertIn("2.0 Mo", text)

    def test_bigger_file_takes_longer(self):
        small = self.tmp / "small.nii"
        small.write_bytes(os.urandom(100_000))
        t_small = crypto.encrypt_file(small, self.tmp / "s.enc", self.key)
        t_big = crypto.encrypt_file(self.src, self.tmp / "b.enc", self.key)
        self.assertGreater(t_big.seconds, t_small.seconds)


class TestBatchTiming(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.plain = self.tmp / "in"
        self.plain.mkdir()
        self.key = keys.generate_key()
        for name in ("a.nii", "b.vtk", "c.nrrd"):
            (self.plain / name).write_bytes(os.urandom(500_000))

    def tearDown(self):
        self._tmp.cleanup()

    def test_batch_reports_total_time_and_size(self):
        result = batch.encrypt_directory(self.plain, self.tmp / "enc", self.key,
                                         verbose=False)
        self.assertEqual(result.total_size, 1_500_000)
        self.assertGreater(result.wall_seconds, 0.0)
        self.assertGreater(result.mb_per_second, 0.0)

    def test_each_file_carries_its_own_duration(self):
        result = batch.encrypt_directory(self.plain, self.tmp / "enc", self.key,
                                         verbose=False)
        for item in result.succeeded:
            self.assertGreater(item.seconds, 0.0)
            self.assertEqual(item.size, 500_000)

    def test_wall_time_covers_the_whole_batch(self):
        """Le temps du lot inclut le parcours des dossiers, pas seulement le calcul."""
        result = batch.encrypt_directory(self.plain, self.tmp / "enc", self.key,
                                         verbose=False)
        per_file = sum(r.seconds for r in result.succeeded)
        self.assertGreaterEqual(result.wall_seconds, per_file)

    def test_skipped_files_do_not_count_in_the_total(self):
        dst = self.tmp / "enc"
        batch.encrypt_directory(self.plain, dst, self.key, verbose=False)
        second = batch.encrypt_directory(self.plain, dst, self.key, verbose=False)
        self.assertEqual(second.total_size, 0)

    def test_timing_summary_is_readable(self):
        result = batch.encrypt_directory(self.plain, self.tmp / "enc", self.key,
                                         verbose=False)
        self.assertIn("Mo", result.timing_summary())


if __name__ == "__main__":
    unittest.main()
