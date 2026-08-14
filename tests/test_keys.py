"""Tests de la generation / sauvegarde / relecture des cles."""

import json
import stat
import tempfile
import unittest
from pathlib import Path

from voltcrypt import keys


class TestKeyGeneration(unittest.TestCase):

    def test_key_is_32_bytes(self):
        self.assertEqual(len(keys.generate_key()), 32)

    def test_keys_are_different_each_time(self):
        generated = {keys.generate_key() for _ in range(50)}
        self.assertEqual(len(generated), 50, "le generateur doit etre aleatoire")


class TestKeyStorage(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.path = self.tmp / "test.key"

    def tearDown(self):
        self._tmp.cleanup()

    def test_save_then_load_roundtrip(self):
        key = keys.generate_key()
        keys.save_key(key, self.path, label="test")
        self.assertEqual(keys.load_key(self.path), key)

    def test_key_file_is_owner_only(self):
        keys.save_key(keys.generate_key(), self.path)
        mode = stat.S_IMODE(self.path.stat().st_mode)
        self.assertEqual(mode, 0o600, "la cle ne doit etre lisible que par son proprietaire")

    def test_label_is_stored(self):
        keys.save_key(keys.generate_key(), self.path, label="etude CBCT 2026")
        payload = json.loads(self.path.read_text())
        self.assertEqual(payload["label"], "etude CBCT 2026")
        self.assertEqual(payload["algorithm"], "AES-256-GCM")

    def test_overwrite_is_refused_by_default(self):
        keys.save_key(keys.generate_key(), self.path)
        with self.assertRaises(FileExistsError):
            keys.save_key(keys.generate_key(), self.path)

    def test_overwrite_when_explicitly_asked(self):
        keys.save_key(keys.generate_key(), self.path)
        new = keys.generate_key()
        keys.save_key(new, self.path, overwrite=True)
        self.assertEqual(keys.load_key(self.path), new)

    def test_missing_file_raises_clear_error(self):
        with self.assertRaises(keys.KeyError_):
            keys.load_key(self.tmp / "inexistante.key")

    def test_corrupted_file_raises(self):
        self.path.write_text("ceci n'est pas du json")
        with self.assertRaises(keys.KeyError_):
            keys.load_key(self.path)

    def test_wrong_key_size_is_rejected(self):
        with self.assertRaises(keys.KeyError_):
            keys.save_key(b"trop court", self.path)

    def test_get_or_create_creates_then_reuses(self):
        first = keys.get_or_create_key(self.path)
        second = keys.get_or_create_key(self.path)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
