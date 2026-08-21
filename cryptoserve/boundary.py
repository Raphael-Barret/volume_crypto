"""La frontiere du clair. Le seul endroit du serveur ou la donnee est lisible.

C'est le module central de cette architecture, et sa forme est deliberee.

Partout ailleurs dans `cryptoserve/`, on ne manipule que des conteneurs
chiffres : les routes HTTP deplacent des octets illisibles, le magasin de jobs
ne connait que des chemins vers du `.enc`, la machine a etats ne voit que des
noms d'etats. Le clair n'existe qu'a l'interieur d'un seul appel de fonction,
`process()`, dans un repertoire que cette fonction cree et detruit.

Ce que cela achete : la revendication << le serveur ne peut pas lire les
donnees >> cesse d'etre une promesse sur le comportement du code et devient
une propriete du graphe d'imports, verifiable mecaniquement. Le test
tests/conformance/test_import_boundary.py echoue si un autre module de
`cryptoserve` importe une primitive de dechiffrement.

Ce que cela n'achete pas, et qu'il faut dire : le runner, lui, recoit du
clair. C'est inevitable, un outil doit lire ce qu'il traite. La consequence
est que le runner fait partie de la base de confiance et doit entrer dans la
mesure attestee, ce que `runners.base.Runner.tcb_files()` sert a declarer.
La frontiere delimite le clair ; elle ne le supprime pas.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Les seuls imports de primitives de dechiffrement autorises dans cryptoserve.
from voltcrypt import crypto
from voltcrypt.timing import Chrono

from .runners.base import Runner

#: Repertoire memoire, quand il existe. Le clair n'atteint alors jamais le
#: disque. Linux monte /dev/shm en tmpfs ; ailleurs, on retombe sur le disque
#: et le rapport le dit, plutot que de laisser croire le contraire.
_SHM = Path("/dev/shm")

#: On n'utilise /dev/shm que si le volume tient dans cette fraction de la
#: place libre : on y ecrit l'entree et la sortie, donc il faut deux fois la
#: taille, plus une marge pour le reste du systeme.
_SHM_SAFETY = 0.4


@dataclass
class BoundaryOutcome:
    """Ce que la frontiere rend, une fois le clair detruit."""

    result_path: Path
    report: dict
    #: Duree exacte pendant laquelle du clair a existe, en secondes.
    residency_seconds: float
    #: "memory" si le travail s'est fait en tmpfs, "disk" sinon.
    workdir_backing: str


def _choose_workdir_parent(expected_size: int) -> tuple[Optional[Path], str]:
    """Repertoire memoire si le volume y tient, disque sinon."""
    try:
        if _SHM.is_dir() and os.access(_SHM, os.W_OK):
            free = shutil.disk_usage(_SHM).free
            if expected_size * 2 < free * _SHM_SAFETY:
                return _SHM, "memory"
    except OSError:
        pass
    return None, "disk"


def process(job, key: bytes, runner: Runner) -> BoundaryOutcome:
    """Dechiffre, traite, rechiffre. Le clair ne survit pas a cet appel.

    `job` est un `jobs.Job` ; il n'est pas type ici pour que `boundary` ne
    dependre pas du magasin de jobs, ce qui garde ce module testable seul.

    Toutes les sorties, y compris en cas d'echec du runner, passent par le
    `finally` qui detruit le repertoire de travail. La duree de residence est
    mesuree du premier octet dechiffre jusqu'a la destruction effective, et
    non jusqu'au retour de la fonction : c'est la duree qui compte.
    """
    parent, backing = _choose_workdir_parent(job.size)
    workdir = Path(tempfile.mkdtemp(prefix="voltcrypt_job_", dir=parent))
    chrono = Chrono()
    try:
        # --- Ici commence le clair -----------------------------------------
        plain = workdir / "input"
        timing = crypto.decrypt_file(job.encrypted_path, plain, key)
        metadata = crypto.read_metadata(job.encrypted_path, key)

        outcome = runner.run(plain, workdir, metadata)

        # --- Rechiffrement avant de ressortir -------------------------------
        result_path = job.encrypted_path.parent / f"{job.job_id}.result.enc"
        crypto.encrypt_file(outcome.output_path, result_path, key)

        # Destruction ici, et non dans le `finally`, pour que la duree
        # mesuree couvre jusqu'a la disparition effective du clair. Le
        # `finally` reste le filet du chemin d'echec ; rmtree est idempotent.
        shutil.rmtree(workdir, ignore_errors=True)
        residency = chrono.seconds
        # --- Ici finit le clair ---------------------------------------------

        report = dict(outcome.report)
        report["decrypt_seconds"] = round(timing.seconds, 4)
        report["workdir_backing"] = backing
        return BoundaryOutcome(
            result_path=result_path,
            report=report,
            residency_seconds=residency,
            workdir_backing=backing,
        )
    finally:
        # Filet du chemin d'echec : si le corps a rendu la main normalement,
        # le repertoire a deja disparu et cet appel ne fait rien.
        # Best effort dans tous les cas : Python ne
        # garantit pas l'effacement des copies laissees en memoire par
        # l'interpreteur (voir PIPELINE.md). En tmpfs, la destruction du
        # repertoire libere les pages ; sur disque, les blocs restent
        # jusqu'a reecriture, et c'est une limite qu'on assume et qu'on ecrit.
        shutil.rmtree(workdir, ignore_errors=True)
