"""Executer un vrai outil, dans son propre interpreteur, derriere la porte.

Ce runner ne reimplemente rien : il invoque exactement ce que le serveur
d'outils invoque deja,

    <tool_dir>/.venv/bin/python <runner_path> --job <job_dir>/job.json

C'est le point important de la greffe. La couche de confidentialite n'est pas
un second systeme pose a cote ; elle SUBSTITUE l'etape de traitement. Le
contrat d'outil, le format du job, l'isolation par virtualenv, tout reste ce
qu'il etait. Ce qui change est qu'en amont la donnee est arrivee chiffree et
qu'en aval elle repart chiffree.

Et c'est ce runner qui repond au reproche sur la base de confiance : par
`tcb_entries()`, il fait entrer le virtualenv de l'outil dans la mesure
attestee. Le code qui lit effectivement le clair cesse d'etre hors perimetre.
"""

from __future__ import annotations

import json
import os
import subprocess
import tarfile
from pathlib import Path
from typing import Optional

from voltcrypt.timing import Chrono

from .. import envdigest
from .base import RunOutcome

#: Variable que le runner du serveur d'outils lit pour situer le dossier de
#: l'outil quand il ne peut pas le deduire de l'interpreteur.
TOOL_DIR_ENV = "SADT_TOOL_DIR"


class SubprocessToolRunner:
    """Fait tourner un outil isole sur la donnee dechiffree par la frontiere."""

    def __init__(self, tool: str, tool_dir: Path, runner_path: Path,
                 params: Optional[dict] = None, input_argument: str = "scans",
                 digest_mode: envdigest.Mode = "inventory",
                 timeout_seconds: int = 3600) -> None:
        self.tool = tool
        self.tool_dir = Path(tool_dir)
        self.runner_path = Path(runner_path)
        self.params = dict(params or {})
        self.input_argument = input_argument
        self.digest_mode = digest_mode
        self.timeout_seconds = timeout_seconds
        self._cached_env: Optional[envdigest.EnvironmentDigest] = None

    # -- Identite ----------------------------------------------------------

    @property
    def name(self) -> str:
        return f"subprocess:{self.tool}"

    @property
    def interpreter(self) -> Path:
        return self.tool_dir / ".venv" / "bin" / "python"

    @property
    def lock_file(self) -> Path:
        return self.tool_dir / "uv.lock"

    # -- Base de confiance -------------------------------------------------

    def tcb_files(self) -> list[Path]:
        """Fichiers qui decident de ce qui s'execute.

        Le runner du serveur d'outils en fait partie : c'est lui qui importe
        le module de l'outil et appelle son `run()`.
        """
        candidates = [
            Path(__file__).resolve(),
            self.runner_path,
            self.tool_dir / "pyproject.toml",
            self.lock_file,
        ]
        return [p for p in candidates if p.is_file()]

    def tcb_entries(self) -> list[tuple[str, str, str]]:
        """Le virtualenv de l'outil, mesure.

        C'est l'entree qui manquait : sans elle, un client verifie le
        protocole et ignore le stack de plusieurs gigaoctets qui ouvre
        effectivement ses donnees.
        """
        digest = self.environment_digest()
        return [("tool-environment", digest.as_entry_label(), digest.digest)]

    def environment_digest(self) -> envdigest.EnvironmentDigest:
        """Mesure du virtualenv, calculee une fois puis conservee.

        Le cache est volontaire et sa portee est la duree de vie du serveur :
        un environnement qui change sous un serveur en marche est un incident
        d'exploitation, pas un cas nominal, et le redemarrage change la mesure.
        """
        if self._cached_env is None:
            self._cached_env = envdigest.digest_environment(
                tool=self.tool,
                venv_dir=self.tool_dir / ".venv",
                lock_file=self.lock_file,
                mode=self.digest_mode,
            )
        return self._cached_env

    # -- Execution ---------------------------------------------------------

    def run(self, plain_input: Path, workdir: Path, metadata: dict) -> RunOutcome:
        """Ecrit le job, lance l'outil, archive ses sorties.

        La frontiere chiffre UN fichier, alors qu'un outil produit un dossier.
        Les sorties sont donc rassemblees dans une archive avant de repasser la
        frontiere, ce qui garde la regle simple : un job, un conteneur.
        """
        job_dir = workdir / "job"
        output_dir = workdir / "outputs"
        job_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Le nom d'origine vient des metadonnees chiffrees, pas du reseau : le
        # serveur ne l'a appris qu'apres avoir obtenu la cle.
        original_name = metadata.get("name") or plain_input.name
        staged = workdir / "input_stage" / original_name
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_bytes(plain_input.read_bytes())

        params = dict(self.params)
        params[self.input_argument] = str(staged)
        params["output_dir"] = str(output_dir)

        job = {"tool": self.tool, "job_dir": str(job_dir), "params": params}
        job_file = job_dir / "job.json"
        job_file.write_text(json.dumps(job), encoding="utf-8")

        chrono = Chrono()
        completed = subprocess.run(
            [str(self.interpreter), str(self.runner_path), "--job", str(job_file)],
            capture_output=True, text=True, timeout=self.timeout_seconds,
            env={**os.environ, TOOL_DIR_ENV: str(self.tool_dir)},
        )
        seconds = chrono.seconds

        if completed.returncode != 0:
            # La queue de stderr seulement : c'est ce que le serveur d'outils
            # conserve, et gonfler le message n'aide personne.
            raise RuntimeError(
                f"l'outil {self.tool} a echoue (code {completed.returncode}) : "
                f"{completed.stderr[-1500:]}")

        produced = sorted(p for p in output_dir.rglob("*") if p.is_file())
        if not produced:
            raise RuntimeError(f"l'outil {self.tool} n'a produit aucun fichier")

        archive = workdir / "outputs.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for path in produced:
                tar.add(path, arcname=path.relative_to(output_dir).as_posix())

        return RunOutcome(
            output_path=archive,
            report={
                "runner": self.name,
                "tool": self.tool,
                "original_name": original_name,
                "tool_seconds": round(seconds, 3),
                "outputs": [p.relative_to(output_dir).as_posix() for p in produced],
                "output_count": len(produced),
                "archive_bytes": archive.stat().st_size,
            },
        )
