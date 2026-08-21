"""Le critere de parite refuse-t-il ce qu'il doit refuser ?

Le module `parity` a ete ecrit parce que la bit-identite ne tenait pas face a
un outil non deterministe. Il ne doit pas devenir pour autant une tolerance
qui accepte tout : ces tests verifient les deux bords.
"""

from __future__ import annotations

import unittest

from cryptoserve.parity import Agreement, judge


def A(diff, total=1_000_000, dice_min=1.0, dice_mean=1.0):
    return Agreement(diff, total, dice_min, dice_mean)


class TestDeterministicTool(unittest.TestCase):
    """Temoin nul : rien n'autorise a tolerer un ecart."""

    def test_identical_through_the_chain_passes(self):
        verdict = judge(A(0), A(0))
        self.assertTrue(verdict.passed)
        self.assertIn("bit-identique", verdict.reason)

    def test_any_deviation_fails_when_the_tool_is_deterministic(self):
        verdict = judge(A(0), A(1))
        self.assertFalse(verdict.passed)
        self.assertIn("deterministe", verdict.reason)


class TestNondeterministicTool(unittest.TestCase):

    def test_chain_within_the_tool_variance_passes(self):
        verdict = judge(A(1000, dice_min=0.9999), A(1200, dice_min=0.9999))
        self.assertTrue(verdict.passed)

    def test_chain_far_beyond_the_tool_variance_fails(self):
        verdict = judge(A(1000, dice_min=0.9999), A(50_000, dice_min=0.9999))
        self.assertFalse(verdict.passed)
        self.assertIn("budget", verdict.reason)

    def test_a_collapsed_dice_fails_even_inside_the_voxel_budget(self):
        """Peu de voxels differents mais une etiquette perdue : refuse.

        Le compte de voxels seul peut masquer la disparition d'une petite
        structure ; le plancher de Dice existe pour cela.
        """
        verdict = judge(A(1000, dice_min=0.9999), A(1100, dice_min=0.5))
        self.assertFalse(verdict.passed)
        self.assertIn("Dice", verdict.reason)

    def test_the_tolerance_factor_is_not_a_blank_cheque(self):
        control = A(100, dice_min=0.9999)
        inside = judge(control, A(300, dice_min=0.9999))
        outside = judge(control, A(301, dice_min=0.9999))
        self.assertTrue(inside.passed)
        self.assertFalse(outside.passed)


class TestVerdictIsReportable(unittest.TestCase):

    def test_carries_both_samples_for_the_evidence_file(self):
        payload = judge(A(10, dice_min=0.999), A(20, dice_min=0.999)).to_dict()
        self.assertIn("control", payload)
        self.assertIn("treatment", payload)
        self.assertIn("reason", payload)
        self.assertIn("tolerance_factor", payload)


if __name__ == "__main__":
    unittest.main()
