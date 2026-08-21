"""Mesurer un environnement d'outil, pas seulement un fichier de protocole.

C'est le correctif du reproche central fait au papier : l'attestation mesurait
quatre fichiers de protocole, alors que ce qui lit le clair est le virtualenv
de l'outil. Un client qui verifie la mesure ne verifiait donc pas le code qui
ouvre effectivement ses donnees.

Deux modes, et le choix est publie dans le manifeste plutot que suppose :

    inventory   digest du `uv.lock` + inventaire du virtualenv (chemins
                relatifs, tailles, bits d'execution). Rapide, resiste au
                remplacement d'un fichier par un autre de taille differente,
                mais PAS a la substitution d'un contenu de meme taille.
    content     digest du `uv.lock` + contenu de chaque fichier. Couverture
                complete, cout proportionnel a la taille de l'environnement.

`inventory` est le defaut parce qu'un stack torch pese environ 4,9 Go et
qu'onze d'entre eux pesent environ 26 Go apres deduplication. `content` est
destine aux releases, ou le cout se paie une fois.

L'equivalent industriel de `content` est le hachage dm-verity de l'image
conteneur, tel que Confidential Containers le produit ; l'equivalent de
`inventory` n'a pas d'equivalent industriel, et c'est pour cela que le mode
retenu figure dans le manifeste : un digest bon marche que le lecteur peut
voir a travers vaut mieux qu'un digest cher presente sans reserve.

Ce module est aussi la ou l'isolation par outil paie une seconde fois :
un `uv.lock` par outil est deja un manifeste. L'architecture construite pour
les conflits de dependances est celle qui rend la base de confiance
enumerable.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Literal

Mode = Literal["inventory", "content"]

#: Repertoires sans effet sur ce qui s'execute : les exclure evite qu'un
#: simple import fasse changer la mesure.
_IGNORED_DIRS = {"__pycache__", ".git", ".pytest_cache", ".ruff_cache"}
_IGNORED_SUFFIXES = {".pyc", ".pyo"}


@dataclass
class EnvironmentDigest:
    """Le resultat, avec de quoi juger ce qu'il couvre."""

    tool: str
    mode: Mode
    digest: str
    file_count: int
    total_bytes: int
    lock_digest: str
    seconds: float

    def as_entry_label(self) -> str:
        return f"{self.tool}:venv[{self.mode}]"


def _walk(root: Path) -> Iterator[Path]:
    """Fichiers de l'environnement, dans un ordre stable et reproductible."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _IGNORED_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.suffix in _IGNORED_SUFFIXES:
                continue
            yield path


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def digest_environment(tool: str, venv_dir: Path, lock_file: Path,
                       mode: Mode = "inventory") -> EnvironmentDigest:
    """Mesure l'environnement d'un outil.

    `lock_file` entre TOUJOURS par son contenu, quel que soit le mode : c'est
    le seul document qui dit quelles versions sont censees etre la, et il est
    petit.
    """
    from voltcrypt.timing import Chrono

    chrono = Chrono()
    venv_dir = Path(venv_dir)
    lock_file = Path(lock_file)

    if not lock_file.is_file():
        raise FileNotFoundError(f"lockfile absent : {lock_file}")
    if not venv_dir.is_dir():
        raise FileNotFoundError(f"virtualenv absent : {venv_dir}")

    lock_digest = _file_digest(lock_file)

    running = hashlib.sha256()
    running.update(b"voltcrypt-env-v1\x00")
    running.update(tool.encode("utf-8") + b"\x00")
    running.update(mode.encode("ascii") + b"\x00")
    running.update(lock_digest.encode("ascii") + b"\x00")

    count = 0
    total = 0
    for path in _walk(venv_dir):
        try:
            stat = path.stat()
        except OSError:
            continue
        relative = path.relative_to(venv_dir).as_posix()
        executable = bool(stat.st_mode & 0o111)
        running.update(relative.encode("utf-8") + b"\x00")
        running.update(str(stat.st_size).encode("ascii") + b"\x00")
        running.update(b"x\x00" if executable else b"-\x00")
        if mode == "content":
            running.update(_file_digest(path).encode("ascii") + b"\x00")
        count += 1
        total += stat.st_size

    return EnvironmentDigest(
        tool=tool,
        mode=mode,
        digest=running.hexdigest(),
        file_count=count,
        total_bytes=total,
        lock_digest=lock_digest,
        seconds=chrono.seconds,
    )
