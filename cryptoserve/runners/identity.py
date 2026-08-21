"""Bras temoin : rend l'entree inchangee.

Ce runner n'est pas du code mort et ne doit pas etre supprime quand un vrai
outil arrive. Il mesure le cout du protocole seul (chiffrer, transferer,
attester, livrer la cle, dechiffrer, rechiffrer). Sans lui, impossible de dire
quelle part d'un aller-retour revient a la confidentialite et quelle part
revient au calcul.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .base import RunOutcome


class IdentityRunner:
    """Copie l'entree vers la sortie, et rend quelques statistiques."""

    name = "identity"

    def tcb_files(self) -> list[Path]:
        """Ce runner ne depend que de lui-meme et de la bibliotheque standard."""
        return [Path(__file__).resolve()]

    def tcb_entries(self) -> list[tuple[str, str, str]]:
        """Aucun environnement externe : rien a declarer au-dela du fichier."""
        return []

    def run(self, plain_input: Path, workdir: Path, metadata: dict) -> RunOutcome:
        content = plain_input.read_bytes()
        output = workdir / "output"
        output.write_bytes(content)
        return RunOutcome(
            output_path=output,
            report={
                "original_name": metadata.get("name"),
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "processing": "identite (aucune transformation)",
                "runner": self.name,
            },
        )
