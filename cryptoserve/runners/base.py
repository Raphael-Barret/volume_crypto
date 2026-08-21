"""Le contrat d'un runner : ce qui s'execute une fois la donnee en clair.

Un runner recoit du clair. C'est le seul composant, avec la frontiere
elle-meme, a qui cela arrive, et c'est pour cette raison qu'il doit declarer
`tcb_files()` : la liste de ce qu'un client doit avoir mesure avant de
livrer sa cle. Un runner qui declare une liste incomplete ment sur son propre
perimetre de confiance, et le test tests/conformance/test_tcb_closure.py est
la pour attraper cela.

Deux implementations sont prevues :

    identity.py         renvoie l'entree inchangee. Bras temoin : sert a
                        separer le cout du protocole du cout de l'outil.
    subprocess_tool.py  execute un vrai outil dans son propre virtualenv,
                        avec le meme contrat que slicer-remote-tool-server.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable


@dataclass
class RunOutcome:
    """Ce qu'un runner rend a la frontiere.

    `output_path` designe du CLAIR, dans le repertoire de travail de la
    frontiere. La frontiere le rechiffre puis detruit le repertoire ; le
    runner n'ecrit jamais ailleurs.
    """

    output_path: Path
    report: dict = field(default_factory=dict)


@runtime_checkable
class Runner(Protocol):
    """Ce que la frontiere attend d'un runner."""

    #: Nom court, publie dans le rapport et dans /health.
    name: str

    def tcb_files(self) -> list[Path]:
        """Fichiers dont l'empreinte doit entrer dans la mesure du serveur.

        Tout ce qui peut lire le clair. Pour un outil isole, cela inclut son
        `uv.lock` et l'inventaire de son virtualenv, pas seulement le module
        Python qui l'appelle.
        """
        ...

    def run(self, plain_input: Path, workdir: Path, metadata: dict) -> RunOutcome:
        """Traite `plain_input`, ecrit dans `workdir`, rend un RunOutcome."""
        ...
