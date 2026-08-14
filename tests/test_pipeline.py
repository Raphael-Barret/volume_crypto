"""Tests de bout en bout du pipeline client/serveur.

Chaque test demarre un vrai serveur HTTP sur un port libre, fait passer un
fichier par les 7 etapes, et verifie le resultat. Rien n'est simule cote
transport : ce sont de vraies requetes.

Les tests les plus importants ne sont pas ceux qui verifient que ca marche,
mais ceux qui verifient que **la cle n'est pas transmise** quand quelque chose
cloche : TestClientRefusesToReleaseTheKey.
"""

import os
import shutil
import tempfile
import threading
import unittest
from pathlib import Path

import client
import server
from voltcrypt import attestation, config, crypto, keyexchange, keys


class ServerFixture(unittest.TestCase):
    """Demarre un serveur sur un port libre, l'arrete a la fin."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.storage = self.tmp / "server_storage"
        self.output = self.tmp / "out"

        # port 0 = le systeme en choisit un libre
        self.httpd = server.serve("127.0.0.1", 0, storage=self.storage, quiet=True)
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

        self.enclave = self.httpd.RequestHandlerClass.enclave
        self.measurement = self.enclave.measurement

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        self._tmp.cleanup()

    def sample(self, name="scan.nii", size=200_000):
        path = self.tmp / name
        path.write_bytes(os.urandom(size))
        return path


class TestHappyPath(ServerFixture):

    def test_full_round_trip(self):
        source = self.sample()
        result = client.run(source, self.url, self.output,
                            expected_measurement=self.measurement, verbose=False)

        self.assertTrue(result["identical"])
        self.assertEqual(result["original_sha256"], result["result_sha256"])
        restored = self.output / source.name
        self.assertEqual(restored.read_bytes(), source.read_bytes())

    def test_works_on_a_vtk_file(self):
        source = self.tmp / "mesh.vtk"
        source.write_bytes(b"# vtk DataFile Version 3.0\nASCII\n" * 100)
        result = client.run(source, self.url, self.output,
                            expected_measurement=self.measurement, verbose=False)
        self.assertTrue(result["identical"])

    def test_empty_file(self):
        source = self.tmp / "vide.nrrd"
        source.write_bytes(b"")
        result = client.run(source, self.url, self.output,
                            expected_measurement=self.measurement, verbose=False)
        self.assertTrue(result["identical"])

    def test_file_larger_than_one_chunk(self):
        source = self.sample("gros.nii", size=9 * 1024 * 1024)
        result = client.run(source, self.url, self.output,
                            expected_measurement=self.measurement, verbose=False)
        self.assertTrue(result["identical"])

    def test_server_reports_what_it_did(self):
        source = self.sample()
        result = client.run(source, self.url, self.output,
                            expected_measurement=self.measurement, verbose=False)
        report = result["server_report"]
        self.assertEqual(report["original_name"], "scan.nii")
        self.assertEqual(report["size"], 200_000)


class TestServerSeesOnlyCiphertext(ServerFixture):
    """Ce que le serveur detient avant d'avoir la cle."""

    def test_stored_file_contains_no_plaintext(self):
        marker = b"PATIENT_DUPONT_JEAN_1970"
        source = self.tmp / "DUPONT_Jean_T1.nii"
        source.write_bytes(marker + os.urandom(50_000))

        client.run(source, self.url, self.output,
                   expected_measurement=self.measurement, verbose=False)

        stored = list(self.storage.glob("*.enc"))
        self.assertTrue(stored)
        for path in stored:
            blob = path.read_bytes()
            self.assertNotIn(marker, blob, "le contenu ne doit jamais apparaitre")
            self.assertNotIn(b"DUPONT", blob, "le nom ne doit jamais apparaitre")

    def test_upload_of_a_non_container_is_rejected(self):
        plain = self.tmp / "clair.nii"
        plain.write_bytes(b"ceci n'est pas chiffre")
        with self.assertRaises(client.PipelineError) as caught:
            client._post_file(f"{self.url}/jobs", plain)
        self.assertIn("conteneur", str(caught.exception))


class TestClientRefusesToReleaseTheKey(ServerFixture):
    """Le coeur du dispositif : quand la cle ne doit PAS partir."""

    def _expect_refusal(self, **kwargs):
        source = self.sample()
        with self.assertRaises(client.PipelineError) as caught:
            client.run(source, self.url, self.output, verbose=False, **kwargs)
        return str(caught.exception)

    def test_refuses_when_measurement_differs(self):
        """Le serveur n'execute pas le code attendu."""
        message = self._expect_refusal(expected_measurement="00" * 32)
        self.assertIn("ATTESTATION REFUSEE", message)
        self.assertIn("mesure du code inattendue", message)
        self.assertIn("PAS ete transmise", message)

    def test_refuses_when_no_reference_measurement_is_known(self):
        """Sans reference, on ne peut rien conclure : on s'arrete."""
        message = self._expect_refusal(expected_measurement=None)
        self.assertIn("aucune mesure de reference", message)

    def test_job_stays_unprocessed_after_refusal(self):
        """Apres un refus, le serveur garde un fichier inexploitable."""
        self._expect_refusal(expected_measurement="00" * 32)
        stored = list(self.storage.glob("*.enc"))
        self.assertEqual(len(stored), 1)
        self.assertEqual(list(self.storage.glob("*.result.enc")), [],
                         "aucun resultat ne doit avoir ete produit")


class TestAttestationProtocol(ServerFixture):
    """Les proprietes du protocole, testees directement."""

    def _evidence(self, nonce):
        answer = client._get_json(f"{self.url}/attestation?nonce={nonce.hex()}")
        return (attestation.Evidence(**answer["evidence"]),
                bytes.fromhex(answer["signature"]))

    def test_evidence_is_bound_to_the_nonce(self):
        """Une evidence obtenue avec un nonce ne vaut pas pour un autre."""
        nonce = os.urandom(32)
        evidence, signature = self._evidence(nonce)
        root = attestation.load_public_key(config.TRUST_ROOT_PUBLIC_KEY)

        # Le nonce d'origine passe...
        attestation.verify_evidence(
            evidence, signature, root, nonce,
            bytes.fromhex(evidence.public_key),
            attestation.Policy(expected_measurement=self.measurement))

        # ...un autre nonce est rejete (rejeu impossible).
        with self.assertRaises(attestation.AttestationError) as caught:
            attestation.verify_evidence(
                evidence, signature, root, os.urandom(32),
                bytes.fromhex(evidence.public_key),
                attestation.Policy(expected_measurement=self.measurement))
        self.assertIn("nonce", str(caught.exception))

    def test_evidence_signature_cannot_be_forged(self):
        """Modifier l'evidence invalide la signature."""
        nonce = os.urandom(32)
        evidence, signature = self._evidence(nonce)
        evidence.measurement = "00" * 32          # un attaquant ment sur le code
        root = attestation.load_public_key(config.TRUST_ROOT_PUBLIC_KEY)

        with self.assertRaises(attestation.AttestationError) as caught:
            attestation.verify_evidence(
                evidence, signature, root, nonce,
                bytes.fromhex(evidence.public_key), attestation.Policy())
        self.assertIn("signature invalide", str(caught.exception))

    def test_relay_attack_is_detected(self):
        """Un intermediaire substitue SA cle publique a celle de l'enclave."""
        nonce = os.urandom(32)
        evidence, signature = self._evidence(nonce)
        root = attestation.load_public_key(config.TRUST_ROOT_PUBLIC_KEY)
        _, attacker_key = keyexchange.generate_recipient_keypair()

        with self.assertRaises(attestation.AttestationError) as caught:
            attestation.verify_evidence(
                evidence, signature, root, nonce,
                expected_server_key=attacker_key,     # <- cle de l'attaquant
                policy=attestation.Policy(expected_measurement=self.measurement))
        self.assertIn("cle publique attestee", str(caught.exception))

    def test_short_nonce_is_rejected(self):
        with self.assertRaises(client.PipelineError):
            client._get_json(f"{self.url}/attestation?nonce=abcd")


class TestKeyExchange(ServerFixture):
    """Proprietes de la remise de cle."""

    def test_key_cannot_be_opened_by_another_recipient(self):
        key = keys.generate_key()
        _, server_public = keyexchange.generate_recipient_keypair()
        other_private, _ = keyexchange.generate_recipient_keypair()

        packet = keyexchange.wrap_key(key, server_public)
        with self.assertRaises(keyexchange.KeyExchangeError):
            keyexchange.unwrap_key(packet, other_private)

    def test_key_is_bound_to_its_job(self):
        """Un paquet destine a un job ne s'ouvre pas sur un autre."""
        key = keys.generate_key()
        private, public = keyexchange.generate_recipient_keypair()

        packet = keyexchange.wrap_key(key, public, aad=b"job-A")
        self.assertEqual(keyexchange.unwrap_key(packet, private, aad=b"job-A"), key)
        with self.assertRaises(keyexchange.KeyExchangeError):
            keyexchange.unwrap_key(packet, private, aad=b"job-B")

    def test_wrapped_key_never_contains_the_key(self):
        key = keys.generate_key()
        _, public = keyexchange.generate_recipient_keypair()
        self.assertNotIn(key, keyexchange.wrap_key(key, public))

    def test_server_rejects_a_key_it_cannot_open(self):
        """Cle chiffree pour un autre destinataire : le serveur refuse."""
        source = self.sample()
        job_key = keys.generate_key()
        encrypted = self.tmp / "x.enc"
        crypto.encrypt_file(source, encrypted, job_key)
        job_id = client._post_file(f"{self.url}/jobs", encrypted)["job_id"]

        _, wrong_public = keyexchange.generate_recipient_keypair()
        packet = keyexchange.wrap_key(job_key, wrong_public, aad=job_id.encode())

        with self.assertRaises(client.PipelineError) as caught:
            client._post_json(f"{self.url}/jobs/{job_id}/key",
                              {"wrapped_key": packet.hex()})
        self.assertIn("illisible", str(caught.exception))


class TestServerRobustness(ServerFixture):

    def test_unknown_job(self):
        with self.assertRaises(client.PipelineError):
            client._get_json(f"{self.url}/jobs/inexistant")

    def test_unknown_route(self):
        with self.assertRaises(client.PipelineError):
            client._get_json(f"{self.url}/nimporte/quoi")

    def test_key_cannot_be_submitted_twice(self):
        source = self.sample()
        result = client.run(source, self.url, self.output,
                            expected_measurement=self.measurement, verbose=False)
        job_id = result["job_id"]
        _, public = keyexchange.generate_recipient_keypair()
        packet = keyexchange.wrap_key(keys.generate_key(), public,
                                      aad=job_id.encode())
        with self.assertRaises(client.PipelineError) as caught:
            client._post_json(f"{self.url}/jobs/{job_id}/key",
                              {"wrapped_key": packet.hex()})
        self.assertIn("deja", str(caught.exception))

    def test_health_endpoint(self):
        payload = client._get_json(f"{self.url}/health")
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["measurement"], self.measurement)

    def test_unreachable_server_gives_a_useful_message(self):
        with self.assertRaises(client.PipelineError) as caught:
            client._get_json("http://127.0.0.1:1/health")
        self.assertIn("injoignable", str(caught.exception))


class TestCodeMeasurement(unittest.TestCase):
    """La mesure de code est reelle, pas simulee."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_same_files_give_same_measurement(self):
        a = self.tmp / "a.py"
        a.write_text("print('hello')")
        self.assertEqual(attestation.measure_code([a]), attestation.measure_code([a]))

    def test_one_changed_byte_changes_the_measurement(self):
        a = self.tmp / "a.py"
        a.write_text("print('hello')")
        before = attestation.measure_code([a])
        a.write_text("print('hellO')")
        self.assertNotEqual(attestation.measure_code([a]), before)

    def test_adding_a_file_changes_the_measurement(self):
        a = self.tmp / "a.py"
        a.write_text("x = 1")
        before = attestation.measure_code([a])
        b = self.tmp / "b.py"
        b.write_text("y = 2")
        self.assertNotEqual(attestation.measure_code([a, b]), before)

    def test_renaming_a_file_changes_the_measurement(self):
        a = self.tmp / "a.py"
        a.write_text("x = 1")
        before = attestation.measure_code([a])
        renamed = self.tmp / "b.py"
        shutil.move(a, renamed)
        self.assertNotEqual(attestation.measure_code([renamed]), before)

    def test_real_server_measurement_is_stable(self):
        self.assertEqual(attestation.measure_code(server.MEASURED_FILES),
                         attestation.measure_code(server.MEASURED_FILES))


if __name__ == "__main__":
    unittest.main()
