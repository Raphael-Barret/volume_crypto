"""Les jobs et leur machine a etats.

Un job traverse un chemin unique et court. Le rendre explicite plutot que de
le laisser dans des comparaisons de chaines eparpillees a un but precis : la
machine a etats est ce qu'on teste dans tests/protocol/, et une transition
interdite doit etre refusee par une seule fonction, pas par six `if`.

    RECEIVED  --key accepted-->  PROCESSING  --ok-->     DONE
                                             --erreur--> FAILED

Aucune transition ne revient en arriere. Une cle presentee deux fois trouve un
job qui n'est plus en RECEIVED et se fait refuser sans qu'on ait besoin d'un
verrou explicite dans la route.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


class JobState(str, Enum):
    """Etat d'un job. Herite de str pour rester serialisable tel quel."""

    RECEIVED = "received"
    PROCESSING = "processing"
    DONE = "done"
    FAILED = "failed"


#: Transitions autorisees. Tout ce qui n'est pas la est refuse.
TRANSITIONS: dict[JobState, frozenset[JobState]] = {
    JobState.RECEIVED: frozenset({JobState.PROCESSING}),
    JobState.PROCESSING: frozenset({JobState.DONE, JobState.FAILED}),
    JobState.DONE: frozenset(),
    JobState.FAILED: frozenset(),
}


class TransitionError(RuntimeError):
    """Transition interdite. Le job reste dans son etat d'origine."""


@dataclass
class Job:
    """Un traitement. Ne contient jamais de clair ni de cle.

    `encrypted_path` et `result_path` designent des conteneurs chiffres. Aucun
    champ de cette classe ne peut contenir de donnee lisible : c'est ce qui
    permet de la journaliser et de la serialiser sans precaution.
    """

    job_id: str
    encrypted_path: Path
    size: int
    state: JobState = JobState.RECEIVED
    created_utc: str = ""
    result_path: Optional[Path] = None
    report: dict = field(default_factory=dict)
    error: str = ""
    #: Duree pendant laquelle du clair a existe cote serveur, en secondes.
    #: Reste None tant qu'aucun traitement n'a eu lieu. Mesure, pas promesse.
    plaintext_residency_seconds: Optional[float] = None

    def to(self, target: JobState) -> None:
        """Change d'etat, ou refuse."""
        if target not in TRANSITIONS[self.state]:
            raise TransitionError(
                f"transition refusee : {self.state.value} -> {target.value}")
        self.state = target

    def public(self) -> dict:
        """Ce que le serveur accepte de dire d'un job."""
        payload = {
            "job_id": self.job_id,
            "state": self.state.value,
            "size": self.size,
            "created_utc": self.created_utc,
            "report": self.report,
            "error": self.error,
        }
        if self.plaintext_residency_seconds is not None:
            payload["plaintext_residency_seconds"] = round(
                self.plaintext_residency_seconds, 4)
        return payload


class Store:
    """Jobs en cours. En memoire : redemarrer le serveur les oublie."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def create(self, job_id: str, path: Path, size: int) -> Job:
        job = Job(job_id, path, size,
                  created_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        with self._lock:
            self._jobs[job_id] = job
        return job

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def claim(self, job_id: str) -> Optional[Job]:
        """Passe un job de RECEIVED a PROCESSING, atomiquement.

        Renvoie le job si la reservation a reussi, None si le job n'existe pas.
        Leve TransitionError si le job n'etait pas en RECEIVED : c'est ce qui
        empeche deux cles concurrentes de lancer deux traitements.
        """
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            job.to(JobState.PROCESSING)
            return job

    def ids(self) -> list[str]:
        with self._lock:
            return list(self._jobs)
