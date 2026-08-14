"""Mesure du temps de traitement.

Ce qui est chronometre : de l'appel a la fonction jusqu'au moment ou le fichier
de sortie est en place et exploitable — c'est-a-dire jusqu'au `os.replace` qui
renomme le `.part` en fichier final. Avant cet instant, rien n'est utilisable ;
apres, le fichier est complet et ouvrable par Slicer ou par ton pipeline.

Note : la mesure ne va pas jusqu'a l'ecriture physique sur le plateau ou la
NAND. Comme tout programme, on s'arrete au cache du systeme de fichiers — le
fichier est lisible par n'importe quel processus des cet instant.

L'horloge utilisee est `time.perf_counter()`, monotone : un changement d'heure
systeme ne fausse pas la mesure.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path


def human_duration(seconds: float) -> str:
    """0.000_4 -> '0.4 ms' | 1.55 -> '1.55 s' | 3725 -> '1 h 02 min'."""
    if seconds < 0.001:
        return f"{seconds * 1e6:.0f} us"
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"
    if seconds < 3600:
        return f"{int(seconds // 60)} min {int(seconds % 60):02d} s"
    return f"{int(seconds // 3600)} h {int((seconds % 3600) // 60):02d} min"


def human_size(n: float) -> str:
    """1536 -> '1.5 Ko'."""
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if n < 1024 or unit == "To":
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} To"


def human_speed(size: int, seconds: float) -> str:
    """Debit lisible, ou '-' quand la mesure n'aurait pas de sens.

    Sur un fichier de quelques centaines d'octets, le temps est domine par les
    appels systeme : afficher un debit induirait en erreur.
    """
    if seconds <= 0.001 or size < 1024 * 1024:
        return "-"
    return f"{size / seconds / (1024 * 1024):.0f} Mo/s"


@dataclass
class Timing:
    """Resultat d'un chiffrement / dechiffrement, avec sa duree.

    S'utilise directement comme un chemin (implemente `os.PathLike`) :

        resultat = crypto.encrypt_file(src, dst, key)
        print(resultat.seconds)          # 1.83
        print(resultat)                  # scan.nii.enc : 138.9 Mo en 1.83 s (76 Mo/s)
        open(resultat, "rb")             # fonctionne : c'est aussi un chemin
    """
    path: Path
    seconds: float
    size: int          # octets de donnee utile traites (taille en clair)

    def __fspath__(self) -> str:
        """Rend l'objet utilisable partout ou un chemin est attendu."""
        return str(self.path)

    @property
    def mb_per_second(self) -> float:
        """Debit en Mo/s (0.0 si la duree est trop courte pour etre fiable)."""
        if self.seconds <= 0:
            return 0.0
        return self.size / self.seconds / (1024 * 1024)

    def __str__(self) -> str:
        return (f"{self.path.name} : {human_size(self.size)} en "
                f"{human_duration(self.seconds)} ({human_speed(self.size, self.seconds)})")


class Chrono:
    """Chronometre a utiliser en `with`.

        with Chrono() as chrono:
            ...
        print(chrono.seconds)

    `chrono.seconds` est consultable pendant le bloc (temps ecoule) comme
    apres (duree totale).
    """

    def __init__(self) -> None:
        self._start = time.perf_counter()
        self._end: float | None = None

    def __enter__(self) -> "Chrono":
        self._start = time.perf_counter()
        return self

    def __exit__(self, *exc_info) -> None:
        self._end = time.perf_counter()

    @property
    def seconds(self) -> float:
        end = self._end if self._end is not None else time.perf_counter()
        return end - self._start

    def __str__(self) -> str:
        return human_duration(self.seconds)
