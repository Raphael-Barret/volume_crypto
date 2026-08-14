"""Verification independante : "mes fichiers sont-ils VRAIMENT chiffres ?"

Le fait qu'un logiciel refuse d'ouvrir un .enc ne prouve rien : un fichier
tronque ou corrompu echoue lui aussi a s'ouvrir. Ce module fait des controles
positifs, qui echouent bruyamment si quelque chose ne va pas.

Controles effectues sur chaque conteneur :

  1. structure     le header VOLCRYPT est present et coherent
  2. entropie      le corps chiffre est statistiquement indiscernable
                   d'octets aleatoires (~8 bits d'entropie par octet)
  3. signatures    aucune signature de format connu (VTK, NIfTI, NRRD, DICOM,
                   HDF5, STL, gzip...) n'apparait en clair dans le conteneur
  4. nom           le nom du fichier d'origine n'apparait pas en clair
  5. round-trip    le dechiffrement redonne exactement le fichier de depart
                   (sha256 identique)
  6. fuite         [si l'original est fourni] aucun fragment de l'original
                   ne se retrouve tel quel dans le conteneur

Usage :  python main.py audit
"""

from __future__ import annotations

import hashlib
import math
import os
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import crypto

#: Signatures de formats, cherchees en clair dans le conteneur.
#: Toutes font >= 4 octets pour limiter les faux positifs sur du flux aleatoire.
FORMAT_SIGNATURES = {
    b"# vtk DataFile": "VTK legacy",
    b"<VTKFile": "VTK XML",
    b"NRRD000": "NRRD",
    b"ObjectType": "MetaImage (.mha/.mhd)",
    b"n+1\x00": "NIfTI",
    b"ni1\x00": "NIfTI (paire .hdr/.img)",
    b"DICM": "DICOM",
    b"\x89HDF\r\n\x1a\n": "HDF5",
    b"solid ": "STL ASCII",
    b"ply\nformat": "PLY",
    b"\x93NUMPY": "NumPy .npy",
    b"PK\x03\x04": "ZIP / .npz",
    b"mtllib ": "OBJ",
    b"# Insight Transform File": "ITK transform",
}


@dataclass
class Check:
    """Un controle unitaire."""
    name: str
    passed: bool
    detail: str = ""

    def __str__(self) -> str:
        mark = "ok  " if self.passed else "FAIL"
        return f"    [{mark}] {self.name:<22} {self.detail}"


@dataclass
class AuditReport:
    """Resultat de l'audit d'un conteneur."""
    path: Path
    checks: list[Check] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks)

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if not c.passed]

    def __str__(self) -> str:
        head = f"  {'PASS' if self.passed else 'ECHEC'}  {self.path.name}"
        return "\n".join([head] + [str(c) for c in self.checks])


# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    """Entropie de Shannon en bits par octet. 8.0 = aleatoire parfait."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


#: En dessous de cette taille, le test d'entropie n'a aucune puissance
#: statistique et on ne s'en sert pas. Voir expected_entropy_floor().
MIN_ENTROPY_SAMPLE = 1024


def expected_entropy_floor(n: int, margin: float = 0.20) -> float:
    """Seuil d'entropie acceptable pour n octets reellement aleatoires.

    Un petit fichier ne PEUT pas atteindre 8.0 bits/octet : sur 200 octets on
    ne voit pas les 256 valeurs possibles, donc l'entropie empirique est
    mecaniquement basse meme sur de l'aleatoire parfait. L'esperance vaut
    environ 8 - 255/(2*n*ln2).

    Cette approximation n'est fiable qu'a partir de ~500 octets ; mesure sur
    300 tirages d'os.urandom :

        n        E[H] mesuree   formule
        186         6.912        7.011   <- la formule surestime
        500         7.581        7.632
        1000        7.803        7.816
        4096        7.955        7.955   <- exacte

    En dessous de MIN_ENTROPY_SAMPLE on retourne 0.0 : le controle est declare
    non concluant plutot que de produire un faux "FAIL". Les autres controles
    (signatures, round-trip, fragments) restent valides a toute taille.
    """
    if n < MIN_ENTROPY_SAMPLE:
        return 0.0
    return max(0.0, 8.0 - 255.0 / (2 * n * math.log(2)) - margin)


def find_plaintext_signatures(blob: bytes) -> list[str]:
    """Signatures de formats trouvees en clair dans le conteneur."""
    found = []
    for signature, label in FORMAT_SIGNATURES.items():
        if signature in blob:
            found.append(f"{label} ({signature[:12]!r})")
    return found


def find_leaked_fragments(blob: bytes, plain: bytes, samples: int = 200,
                          length: int = 32) -> int:
    """Compte les fragments de `plain` qu'on retrouve tels quels dans `blob`.

    On echantillonne `samples` fragments de `length` octets repartis dans le
    fichier d'origine. Sur du chiffrement correct, le resultat doit etre 0.
    """
    if len(plain) < length:
        return 0
    step = max(1, (len(plain) - length) // samples)
    leaked = 0
    for offset in range(0, len(plain) - length, step):
        fragment = plain[offset:offset + length]
        if len(set(fragment)) < 4:
            continue  # fragment trop uniforme (zeros de padding) : non concluant
        if fragment in blob:
            leaked += 1
    return leaked


# ---------------------------------------------------------------------------

def audit_container(
    path: str | Path,
    key: bytes,
    plain_path: Optional[str | Path] = None,
) -> AuditReport:
    """Audite un conteneur .enc. `plain_path` = l'original, si tu l'as encore."""
    path = Path(path)
    report = AuditReport(path)
    blob = path.read_bytes()

    # 1. Structure
    if blob[:8] == crypto.MAGIC:
        report.checks.append(Check("structure", True, "header VOLCRYPT valide"))
    else:
        report.checks.append(Check("structure", False, "ce n'est pas un conteneur VOLCRYPT"))
        return report

    body = blob[len(crypto.MAGIC):]

    # 2. Entropie
    entropy = shannon_entropy(body)
    floor = expected_entropy_floor(len(body))
    if floor == 0.0:
        report.checks.append(Check("entropie", True,
                                   f"{entropy:.3f} bits/octet (fichier trop court pour conclure)"))
    else:
        report.checks.append(Check("entropie", entropy >= floor,
                                   f"{entropy:.3f} bits/octet (seuil {floor:.3f})"))

    # 3. Signatures de formats en clair
    signatures = find_plaintext_signatures(blob)
    report.checks.append(Check("signatures format", not signatures,
                               "aucune trouvee" if not signatures
                               else "TROUVEES : " + ", ".join(signatures)))

    # 4. Nom d'origine en clair + 5. round-trip
    try:
        meta = crypto.read_metadata(path, key)
        name = meta["name"]
        leaked_name = name.encode("utf-8") in blob or name.encode("utf-16-le") in blob
        report.checks.append(Check("nom d'origine", not leaked_name,
                                   f"{name!r} absent du conteneur" if not leaked_name
                                   else f"{name!r} LISIBLE en clair"))

        tmp = Path(tempfile.gettempdir()) / f"voltcrypt_audit_{os.getpid()}.tmp"
        try:
            crypto.decrypt_file(path, tmp, key)
            restored = tmp.read_bytes()
            report.checks.append(Check("round-trip", True,
                                       f"dechiffre, sha256 verifie, {len(restored):,} octets"))
        finally:
            tmp.unlink(missing_ok=True)
    except Exception as exc:
        report.checks.append(Check("round-trip", False, str(exc)))
        return report

    # 6. Fuite de fragments de l'original
    if plain_path is not None:
        plain = Path(plain_path).read_bytes()
        if hashlib.sha256(plain).hexdigest() != hashlib.sha256(restored).hexdigest():
            report.checks.append(Check("identique a l'original", False,
                                       "le fichier restitue DIFFERE de l'original"))
        else:
            report.checks.append(Check("identique a l'original", True,
                                       "sha256 du restitue == sha256 de l'original"))
        leaked = find_leaked_fragments(blob, plain)
        report.checks.append(Check("fuite de fragments", leaked == 0,
                                   "0 fragment de l'original dans le conteneur" if not leaked
                                   else f"{leaked} fragment(s) de l'original RETROUVES en clair"))

    return report
