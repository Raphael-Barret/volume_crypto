"""La machine a etats refuse-t-elle ce qu'elle doit refuser ?

Un bug de protocole est un bug de SEQUENCE, et les tests par l'exemple n'en
trouvent pas. Ici on enumere les transitions et on verifie que celles qui ne
sont pas au tableau echouent, sans effet de bord.

Ce fichier prepare la couche 3 du plan de test (machine a etats sous
hypothesis) : l'enumeration exhaustive suffit tant que le graphe reste petit,
et elle a l'avantage de nommer chaque cas.
"""

from __future__ import annotations

import itertools
import tempfile
import unittest
from pathlib import Path

from cryptoserve.jobs import TRANSITIONS, Job, JobState, Store, TransitionError


def _job(state=JobState.RECEIVED) -> Job:
    job = Job("j", Path("/nowhere.enc"), 10)
    job.state = state
    return job


class TestTransitionTable(unittest.TestCase):

    def test_every_pair_is_allowed_or_refused_as_declared(self):
        for source, target in itertools.product(JobState, JobState):
            with self.subTest(source=source.value, target=target.value):
                job = _job(source)
                if target in TRANSITIONS[source]:
                    job.to(target)
                    self.assertEqual(job.state, target)
                else:
                    with self.assertRaises(TransitionError):
                        job.to(target)
                    self.assertEqual(job.state, source,
                                     "une transition refusee ne doit rien changer")

    def test_terminal_states_are_terminal(self):
        for terminal in (JobState.DONE, JobState.FAILED):
            with self.subTest(state=terminal.value):
                self.assertEqual(TRANSITIONS[terminal], frozenset(),
                                 "un job termine ne repart pas")

    def test_no_state_can_reach_itself(self):
        """Rejouer une cle ne doit pas relancer un traitement."""
        for state in JobState:
            self.assertNotIn(state, TRANSITIONS[state])


class TestStoreClaimIsExclusive(unittest.TestCase):
    """Deux cles concurrentes sur un meme job : une seule passe."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self._tmp.name))
        self.store.create("job", Path("/nowhere.enc"), 10)

    def tearDown(self):
        self._tmp.cleanup()

    def test_second_claim_is_refused(self):
        first = self.store.claim("job")
        self.assertIsNotNone(first)
        self.assertEqual(first.state, JobState.PROCESSING)
        with self.assertRaises(TransitionError):
            self.store.claim("job")

    def test_claim_on_an_unknown_job_returns_none(self):
        self.assertIsNone(self.store.claim("inconnu"))

    def test_a_finished_job_cannot_be_claimed_again(self):
        job = self.store.claim("job")
        job.to(JobState.DONE)
        with self.assertRaises(TransitionError):
            self.store.claim("job")

    def test_concurrent_claims_elect_exactly_one_winner(self):
        import threading

        self.store.create("race", Path("/nowhere.enc"), 10)
        winners, losers = [], []
        barrier = threading.Barrier(8)

        def attempt():
            barrier.wait()
            try:
                if self.store.claim("race") is not None:
                    winners.append(1)
            except TransitionError:
                losers.append(1)

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(len(winners), 1,
                         "exactement une cle doit lancer le traitement")
        self.assertEqual(len(losers), 7)


class TestPublicViewLeaksNothing(unittest.TestCase):
    """Ce qu'un job accepte de dire de lui."""

    def test_no_absolute_paths_in_the_public_view(self):
        job = Job("j", Path("/srv/storage/secret_patient.enc"), 10)
        payload = job.public()
        self.assertNotIn("secret_patient", str(payload),
                         "le nom du conteneur ne sort pas du serveur")
        self.assertNotIn("encrypted_path", payload)
        self.assertNotIn("result_path", payload)


if __name__ == "__main__":
    unittest.main()
