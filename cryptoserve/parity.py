"""Comparer deux executions d'un outil, quand l'outil n'est pas deterministe.

Pourquoi ce module existe : le premier critere de parite retenu etait la
bit-identite, et une experience de controle l'a invalide. Deux executions du
meme outil EN CLAIR, sans chiffrement nulle part, produisent des voxels
differents (non-determinisme CUDA de nnU-Net). Comparer octet a octet donnait
donc un test qui echoue une fois sur deux, c'est-a-dire un test qu'on finit
par desactiver.

Le critere correct est une comparaison a deux echantillons :

    temoin      ecart entre deux executions en clair
    traitement  ecart entre une execution en clair et une execution a travers
                la chaine chiffree

La chaine est disculpee si le traitement ne depasse pas le temoin. C'est une
revendication plus faible que la bit-identite, et c'est la seule que les
donnees autorisent. Un outil deterministe, lui, rend un temoin nul, et le
meme code conclut alors a la bit-identite sans qu'on ait deux protocoles.

Les mesures sont celles du protocole de parite amont, pas de nouvelles :
desaccord au niveau des voxels, et Dice par etiquette.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class Agreement:
    """L'accord entre deux volumes d'etiquettes."""

    differing_voxels: int
    total_voxels: int
    dice_min: float
    dice_mean: float

    @property
    def differing_fraction(self) -> float:
        return self.differing_voxels / self.total_voxels if self.total_voxels else 0.0

    @property
    def identical(self) -> bool:
        return self.differing_voxels == 0


@dataclass
class ParityVerdict:
    """Le verdict, avec ce sur quoi il repose."""

    control: Agreement
    treatment: Agreement
    tolerance_factor: float
    passed: bool
    reason: str

    def to_dict(self) -> dict:
        return {
            "control": {
                "differing_voxels": self.control.differing_voxels,
                "differing_fraction": self.control.differing_fraction,
                "dice_min": self.control.dice_min,
                "dice_mean": self.control.dice_mean,
            },
            "treatment": {
                "differing_voxels": self.treatment.differing_voxels,
                "differing_fraction": self.treatment.differing_fraction,
                "dice_min": self.treatment.dice_min,
                "dice_mean": self.treatment.dice_mean,
            },
            "tolerance_factor": self.tolerance_factor,
            "passed": self.passed,
            "reason": self.reason,
        }


def judge(control: Agreement, treatment: Agreement,
          tolerance_factor: float = 3.0,
          deterministic_dice_floor: float = 0.999) -> ParityVerdict:
    """La chaine chiffree ajoute-t-elle de la variance a celle de l'outil ?

    Deux regimes, un seul code :

    - **outil deterministe** (temoin nul) : on exige alors la bit-identite du
      traitement. Rien n'autorise a tolerer un ecart que l'outil lui-meme ne
      produit pas.
    - **outil non deterministe** : le traitement doit rester dans
      `tolerance_factor` fois le temoin, ET garder un Dice au-dessus du
      plancher. Le facteur existe parce qu'un temoin a un seul tirage estime
      mal une variance ; il n'est pas une permission de deriver.
    """
    if control.identical:
        if treatment.identical:
            return ParityVerdict(control, treatment, tolerance_factor, True,
                                 "outil deterministe, sortie bit-identique a "
                                 "travers la chaine")
        return ParityVerdict(
            control, treatment, tolerance_factor, False,
            f"outil deterministe (temoin a 0 voxel d'ecart), mais la chaine "
            f"introduit {treatment.differing_voxels} voxels d'ecart")

    budget = control.differing_voxels * tolerance_factor
    if treatment.differing_voxels > budget:
        return ParityVerdict(
            control, treatment, tolerance_factor, False,
            f"la chaine s'ecarte de {treatment.differing_voxels} voxels alors "
            f"que l'outil seul varie de {control.differing_voxels} "
            f"(budget {budget:.0f})")

    if treatment.dice_min < deterministic_dice_floor:
        return ParityVerdict(
            control, treatment, tolerance_factor, False,
            f"Dice minimal {treatment.dice_min:.6f} sous le plancher "
            f"{deterministic_dice_floor}")

    return ParityVerdict(
        control, treatment, tolerance_factor, True,
        f"la chaine ({treatment.differing_voxels} voxels) reste dans la "
        f"variance propre de l'outil ({control.differing_voxels} voxels), "
        f"Dice minimal {treatment.dice_min:.6f}")
