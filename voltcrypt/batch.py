"""Traitement par dossier : chiffrer / dechiffrer tout un lot de fichiers.

L'arborescence relative du dossier d'entree est preservee dans le dossier de
sortie (data/to_encrypt/patient_01/scan.nii -> data/encrypted/patient_01/scan.nii.enc).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Optional, Sequence

from . import config, crypto
from .timing import Chrono, human_duration, human_size, human_speed


@dataclass
class FileResult:
    """Resultat pour un fichier."""
    source: Path
    output: Optional[Path] = None
    ok: bool = True
    skipped: bool = False
    error: str = ""
    seconds: float = 0.0     # duree de traitement de ce fichier
    size: int = 0            # octets de donnee utile traites


@dataclass
class BatchResult:
    """Resultat pour un lot complet."""
    results: list[FileResult] = field(default_factory=list)

    #: Duree reelle du lot, du premier fichier au dernier (inclut le parcours
    #: des dossiers). Toujours >= a la somme des durees par fichier.
    wall_seconds: float = 0.0

    @property
    def succeeded(self) -> list[FileResult]:
        return [r for r in self.results if r.ok and not r.skipped]

    @property
    def skipped(self) -> list[FileResult]:
        return [r for r in self.results if r.skipped]

    @property
    def failed(self) -> list[FileResult]:
        return [r for r in self.results if not r.ok]

    @property
    def total_size(self) -> int:
        """Octets de donnee utile effectivement traites."""
        return sum(r.size for r in self.succeeded)

    @property
    def mb_per_second(self) -> float:
        if self.wall_seconds <= 0:
            return 0.0
        return self.total_size / self.wall_seconds / (1024 * 1024)

    def __len__(self) -> int:
        return len(self.results)

    def summary(self) -> str:
        return (f"{len(self.succeeded)} traite(s), "
                f"{len(self.skipped)} ignore(s), "
                f"{len(self.failed)} en erreur")

    def timing_summary(self) -> str:
        """'139.4 Mo en 1.83 s (76 Mo/s)' — la ligne a retenir."""
        return (f"{human_size(self.total_size)} en "
                f"{human_duration(self.wall_seconds)} "
                f"({human_speed(self.total_size, self.wall_seconds)})")


# ---------------------------------------------------------------------------
# Selection des fichiers
# ---------------------------------------------------------------------------

def iter_files(
    directory: str | Path,
    recursive: bool = True,
    extensions: Optional[Sequence[str]] = None,
) -> Iterator[Path]:
    """Liste les fichiers d'un dossier.

    extensions=None -> tout est pris (sauf fichiers caches et .part).
    extensions=config.VOLUME_EXTENSIONS -> seulement la donnee volumique.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return
    pattern = "**/*" if recursive else "*"
    for path in sorted(directory.glob(pattern)):
        if not path.is_file():
            continue
        if path.name.startswith(".") or path.suffix == ".part":
            continue
        if extensions and not _matches(path, extensions):
            continue
        yield path


def _matches(path: Path, extensions: Iterable[str]) -> bool:
    name = path.name.lower()
    return any(name.endswith(ext.lower()) for ext in extensions)


# ---------------------------------------------------------------------------
# Lots
# ---------------------------------------------------------------------------

def encrypt_directory(
    src_dir: str | Path = config.PLAIN_DIR,
    dst_dir: str | Path = config.ENCRYPTED_DIR,
    key: bytes = b"",
    recursive: bool = True,
    extensions: Optional[Sequence[str]] = None,
    overwrite: bool = False,
    chunk_size: int = config.CHUNK_SIZE,
    verbose: bool = True,
) -> BatchResult:
    """Chiffre tous les fichiers de src_dir vers dst_dir (suffixe .enc ajoute)."""
    src_dir, dst_dir = Path(src_dir), Path(dst_dir)
    batch = BatchResult()
    chrono = Chrono()

    for path in iter_files(src_dir, recursive=recursive, extensions=extensions):
        relative = path.relative_to(src_dir)
        out = dst_dir / relative.parent / (relative.name + config.ENCRYPTED_SUFFIX)

        if out.exists() and not overwrite:
            batch.results.append(FileResult(path, out, skipped=True,
                                            error="existe deja (--overwrite pour ecraser)"))
            _log(verbose, f"  ~ {relative}  (deja chiffre, ignore)")
            continue
        try:
            timing = crypto.encrypt_file(path, out, key, chunk_size=chunk_size)
            batch.results.append(FileResult(path, out, seconds=timing.seconds,
                                            size=timing.size))
            _log(verbose, f"  + {relative}  ->  {out.name}  "
                          f"({human_size(timing.size)} en "
                          f"{human_duration(timing.seconds)}, "
                          f"{human_speed(timing.size, timing.seconds)})")
        except Exception as exc:
            batch.results.append(FileResult(path, out, ok=False, error=str(exc)))
            _log(verbose, f"  ! {relative}  ECHEC : {exc}")

    batch.wall_seconds = chrono.seconds
    return batch


def decrypt_directory(
    src_dir: str | Path = config.ENCRYPTED_DIR,
    dst_dir: str | Path = config.DECRYPTED_DIR,
    key: bytes = b"",
    recursive: bool = True,
    overwrite: bool = False,
    verbose: bool = True,
) -> BatchResult:
    """Dechiffre tous les .enc de src_dir vers dst_dir.

    Le nom d'origine est relu depuis les metadonnees chiffrees du conteneur,
    et non depuis le nom du fichier .enc (qui peut avoir ete renomme).
    """
    src_dir, dst_dir = Path(src_dir), Path(dst_dir)
    batch = BatchResult()
    chrono = Chrono()

    for path in iter_files(src_dir, recursive=recursive,
                           extensions=[config.ENCRYPTED_SUFFIX]):
        relative = path.relative_to(src_dir)
        try:
            name = crypto.original_name(path, key)
        except Exception as exc:
            batch.results.append(FileResult(path, ok=False, error=str(exc)))
            _log(verbose, f"  ! {relative}  ECHEC : {exc}")
            continue

        # Path(...).name : on ne garde que le nom de fichier, jamais un chemin
        # relatif venu des metadonnees (protection contre un "../..").
        name = Path(name).name or (relative.name + ".decrypted")
        out = dst_dir / relative.parent / name
        if out.exists() and not overwrite:
            batch.results.append(FileResult(path, out, skipped=True,
                                            error="existe deja (--overwrite pour ecraser)"))
            _log(verbose, f"  ~ {relative}  (deja dechiffre, ignore)")
            continue
        try:
            timing = crypto.decrypt_file(path, out, key)
            batch.results.append(FileResult(path, out, seconds=timing.seconds,
                                            size=timing.size))
            _log(verbose, f"  + {relative}  ->  {name}  "
                          f"({human_size(timing.size)} en "
                          f"{human_duration(timing.seconds)}, "
                          f"{human_speed(timing.size, timing.seconds)})")
        except Exception as exc:
            batch.results.append(FileResult(path, out, ok=False, error=str(exc)))
            _log(verbose, f"  ! {relative}  ECHEC : {exc}")

    batch.wall_seconds = chrono.seconds
    return batch


# ---------------------------------------------------------------------------

def _log(verbose: bool, message: str) -> None:
    if verbose:
        print(message)
