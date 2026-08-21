"""La batterie attrape-t-elle ce qu'elle pretend attraper ?

Une batterie de controles qui rend toujours << propre >> est pire qu'aucune
batterie : elle rassure. Chaque controle de `cryptoverify` est donc confronte
a un serveur DELIBEREMENT casse, et doit le voir.

Meme discipline que pour le test de frontiere : on n'affirme pas qu'un test
protege, on injecte le defaut et on regarde le test tomber.
"""

from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from cryptoserve import boundary, measure
from cryptoserve.app import serve
from cryptoverify.battery import Battery, Verdict
from cryptoverify import checks


class ServerUnderTest:
    """Un serveur reel sur un port libre, arrete a la sortie du bloc."""

    def __init__(self, storage: Path):
        self.storage = storage

    def __enter__(self):
        self.httpd = serve("127.0.0.1", 0, storage=self.storage, quiet=True)
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


class DefectCase(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.storage = self.tmp / "storage"

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, check):
        with ServerUnderTest(self.storage) as server:
            battery = Battery(server.url, self.storage)
            return battery._record(check.__name__, "", lambda: check(battery))


class TestTheBatterySeesAHealthyServer(DefectCase):
    """Le controle temoin : sans defaut, tout doit passer."""

    def test_all_checks_pass_against_an_unmodified_server(self):
        with ServerUnderTest(self.storage) as server:
            battery = Battery(server.url, self.storage)
            checks.run_all(battery)
            failures = [f for f in battery.findings if f.verdict is Verdict.FAILED]
            self.assertEqual(
                failures, [],
                "un serveur sain doit passer : "
                + "; ".join(f"{f.name} ({f.detail})" for f in failures))


class TestTheBatteryCatchesSeededDefects(DefectCase):
    """Un defaut par test, et le controle qui doit le voir."""

    def test_defect_1_plaintext_written_to_the_job_store(self):
        """Le serveur laisse une copie lisible a cote du conteneur."""
        real = boundary.process

        def leaky(job, key, runner):
            outcome = real(job, key, runner)
            # Le defaut : une copie du clair reste dans le stockage.
            from voltcrypt import crypto
            leaked = job.encrypted_path.parent / f"{job.job_id}.leak.enc"
            crypto.decrypt_file(job.encrypted_path, leaked, key)
            leaked.rename(leaked.with_suffix(".enc"))
            return outcome

        with mock.patch.object(boundary, "process", leaky):
            with ServerUnderTest(self.storage) as server:
                battery = Battery(server.url, self.storage)
                # Le canari doit d'abord etre traite pour que la fuite existe.
                checks.check_plaintext_residency_is_bounded_and_reported(battery)
                verdict, detail, _ = checks.check_stored_bytes_are_unreadable(battery)
        self.assertIs(verdict, Verdict.FAILED,
                      "une copie lisible dans le stockage doit etre vue")
        self.assertIn("clair", detail.lower() + " contenu")

    def test_defect_2_the_boundary_is_dropped_from_the_manifest(self):
        """La mesure ne couvre plus le module qui lit le clair."""
        with mock.patch.object(measure, "BOUNDARY_FILES", []):
            finding = self._run(
                checks.check_announced_measurement_matches_the_published_manifest)
        self.assertIs(finding.verdict, Verdict.FAILED)
        self.assertIn("boundary", finding.detail)

    def test_defect_3_the_runner_is_dropped_from_the_manifest(self):
        """La mesure ne couvre plus le code qui invoque le traitement."""
        class NoTcbRunner:
            name = "no-tcb"

            def tcb_files(self):
                return []

            def tcb_entries(self):
                return []

            def run(self, plain_input, workdir, metadata):
                from cryptoserve.runners.base import RunOutcome
                out = workdir / "output"
                out.write_bytes(plain_input.read_bytes())
                return RunOutcome(output_path=out, report={})

        with ServerUnderTest(self.storage) as server:
            server.httpd.RequestHandlerClass.enclave.runner = NoTcbRunner()
            enclave = server.httpd.RequestHandlerClass.enclave
            enclave.manifest = measure.build_manifest(runner=NoTcbRunner(),
                                                      policy=enclave.policy())
            enclave.measurement = enclave.manifest.digest
            battery = Battery(server.url, self.storage)
            verdict, detail, _ = \
                checks.check_announced_measurement_matches_the_published_manifest(battery)
        self.assertIs(verdict, Verdict.FAILED)
        self.assertIn("runner", detail)

    def test_defect_4_announced_measurement_does_not_match_the_manifest(self):
        """Le serveur annonce une mesure qui n'est pas celle de son manifeste."""
        with ServerUnderTest(self.storage) as server:
            server.httpd.RequestHandlerClass.enclave.measurement = "ff" * 32
            battery = Battery(server.url, self.storage)
            verdict, detail, _ = \
                checks.check_announced_measurement_matches_the_published_manifest(battery)
        self.assertIs(verdict, Verdict.FAILED)
        self.assertIn("manifeste", detail)

    def test_defect_5_residency_is_never_reported(self):
        """Le serveur ne dit pas combien de temps le clair a existe."""
        from cryptoserve.jobs import Job

        real_public = Job.public

        def silent(self):
            payload = real_public(self)
            payload.pop("plaintext_residency_seconds", None)
            return payload

        with mock.patch.object(Job, "public", silent):
            finding = self._run(
                checks.check_plaintext_residency_is_bounded_and_reported)
        self.assertIs(finding.verdict, Verdict.FAILED)
        self.assertIn("residence", finding.detail)


class TestSkipIsNotPass(unittest.TestCase):
    """Un controle qui ne peut pas s'executer ne doit jamais rendre `passed`."""

    def test_storage_check_skips_without_access(self):
        battery = Battery("http://127.0.0.1:1", storage_dir=None)
        finding = battery._record(
            "check_stored_bytes_are_unreadable", "",
            lambda: checks.check_stored_bytes_are_unreadable(battery))
        self.assertIs(finding.verdict, Verdict.SKIPPED)
        self.assertIn("stockage", finding.detail)

    def test_an_unreachable_server_skips_rather_than_passes(self):
        battery = Battery("http://127.0.0.1:1")
        finding = battery._record(
            "check_evidence_is_bound_to_the_nonce", "",
            lambda: checks.check_evidence_is_bound_to_the_nonce(battery))
        self.assertIs(finding.verdict, Verdict.SKIPPED)


if __name__ == "__main__":
    unittest.main()
