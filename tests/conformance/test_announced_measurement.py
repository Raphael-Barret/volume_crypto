"""La mesure qu'on distribue est-elle celle que le serveur annonce ?

Le client refuse la cle si la mesure annoncee differe de celle qu'il attend.
L'operateur obtient cette mesure attendue par `server.py --measurement`, et la
transporte hors bande jusqu'au poste client. Si ce flag rend autre chose que
ce qu'un serveur annonce, tout le dispositif devient inutilisable : chaque
transfert legitime est refuse, et la seule facon de continuer est de
desactiver la verification, c'est-a-dire de supprimer la propriete demontree.

C'est arrive. `--measurement` construisait le manifeste avec `policy=None`
alors que l'enclave y met sa politique declaree, donc les deux digests ne
pouvaient pas coincider. Le defaut est reste invisible parce que la mesure
d'un cote et l'annonce de l'autre n'avaient jamais ete comparees.
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

import server
from cryptoserve.enclave import Enclave
from cryptoserve.runners import IdentityRunner
from voltcrypt import config


def _cli_measurement(*argv: str) -> str:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = server.main(["--measurement", *argv])
    assert code == 0, code
    return buffer.getvalue().strip()


class AnnouncedMeasurementTest(unittest.TestCase):

    def test_cli_matches_what_a_running_server_announces(self):
        """Le flag doit rendre la mesure annoncee, pas une approximation."""
        announced = Enclave(config.ATTESTATION_SIGNING_KEY,
                            IdentityRunner()).measurement
        self.assertEqual(_cli_measurement(), announced)

    def test_declared_policy_is_inside_the_measurement(self):
        """La raison du defaut, fixee comme propriete plutot que comme note.

        Si la politique cesse d'entrer dans le digest, ce test tombe et la
        correction ci-dessus perd son sens : on saura pourquoi la reecrire.
        """
        from cryptoserve import measure

        runner = IdentityRunner()
        without = measure.build_manifest(runner=runner, policy=None).digest
        with_policy = measure.build_manifest(
            runner=runner, policy={"debug": False}).digest
        self.assertNotEqual(without, with_policy)

    def test_a_runner_that_brings_a_tcb_changes_the_measurement(self):
        """Servir un outil reel ne peut pas passer sous l'attestation identite.

        Sinon un serveur mesure avec le traitement identite pourrait servir
        n'importe quel outil sous la meme preuve.

        Portee exacte, verifiee et non supposee : le runner entre dans le
        manifeste par son CODE (`tcb_files()`) et par sa base de confiance
        (`tcb_entries()`, soit l'uv.lock de l'outil et l'empreinte de son
        environnement). Il n'y entre PAS par son nom. Un runner dont le code
        vit hors des fichiers mesures et qui ne declare aucune entree serait
        donc indistinguable du traitement identite. Les runners livres vivent
        tous dans `cryptoserve/runners/`, qui est mesure ; la limite compte
        pour qui en ajoute un ailleurs.
        """
        identity = Enclave(config.ATTESTATION_SIGNING_KEY,
                           IdentityRunner()).measurement

        class ToolLikeRunner(IdentityRunner):
            def tcb_entries(self):
                return [("tool", "Whatever/uv.lock", "0" * 64)]

        other = Enclave(config.ATTESTATION_SIGNING_KEY,
                        ToolLikeRunner()).measurement
        self.assertNotEqual(identity, other)


if __name__ == "__main__":
    unittest.main()
