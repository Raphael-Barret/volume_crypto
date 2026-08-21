"""La surface de mesure : ce que le client verifie avant de livrer sa cle.

Point de depart de la revue du papier (finding S2) : mesurer quatre fichiers
de protocole ne suffit pas, parce que ce qui lit le clair n'est pas le
protocole, c'est le runner et, en production, le virtualenv de l'outil.

Ce module construit donc un MANIFESTE ordonne plutot qu'une liste de
fichiers, et le digest porte sur le manifeste entier :

    protocole   les modules qui deplacent les octets et livrent la cle
    frontiere   boundary.py, le seul a manipuler du clair
    runner      le code qui invoque le traitement, via Runner.tcb_files()
    politique   la configuration de securite annoncee

WP2 y ajoutera, par outil, le digest de `uv.lock` et l'inventaire du
virtualenv installe : c'est la que l'isolation par outil paie une seconde
fois, parce qu'un lockfile par outil est deja un manifeste.

Deux tests rendent ce module honnete plutot que decoratif :

    modifier une entree du manifeste change le digest ;
    modifier un fichier HORS manifeste ne le change pas.

Le second est la definition executable de la base de confiance, et la liste
de ses exclusions est ce que le papier imprime.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent

#: Modules du protocole. Ils ne voient que du chiffre, mais ils decident a qui
#: la cle est livree : les modifier change qui peut lire.
PROTOCOL_FILES: list[Path] = [
    _HERE / "app.py",
    _HERE / "enclave.py",
    _HERE / "jobs.py",
    _HERE / "measure.py",
    _ROOT / "voltcrypt" / "crypto.py",
    _ROOT / "voltcrypt" / "keyexchange.py",
    _ROOT / "voltcrypt" / "attestation.py",
]

#: La frontiere, seule a manipuler du clair. Separee du reste parce que sa
#: presence dans la mesure est ce qui donne un sens a la revendication.
BOUNDARY_FILES: list[Path] = [_HERE / "boundary.py"]

#: Ce que la mesure ne couvre PAS, et que le client doit donc obtenir
#: autrement (racine materielle, image reproductible, politique du site).
#: Cette liste est publiee : une base de confiance non dite est une base de
#: confiance non evaluee.
ACCEPTED_EXCLUSIONS: list[str] = [
    "systeme d'exploitation et noyau",
    "interpreteur Python et bibliotheque standard",
    "paquets tiers (cryptography, et dependances du runner)",
    "pilote et micrologiciel GPU",
    "materiel et micrologiciel plateforme",
]


@dataclass
class ManifestEntry:
    """Une ligne du manifeste : d'ou elle vient, ce qu'elle vaut."""

    kind: str
    label: str
    digest: str


@dataclass
class Manifest:
    """Le manifeste complet et son digest."""

    entries: list[ManifestEntry] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=lambda: list(ACCEPTED_EXCLUSIONS))

    @property
    def digest(self) -> str:
        """Digest du manifeste entier, ordre compris.

        On hache la forme canonique du manifeste, pas la concatenation des
        fichiers : ajouter une entree, en retirer une, ou en changer l'ordre
        change le resultat, ce qu'un simple hachage de contenus ne ferait pas.
        """
        canonical = json.dumps(
            [[e.kind, e.label, e.digest] for e in self.entries],
            separators=(",", ":"), ensure_ascii=True,
        ).encode("ascii")
        return hashlib.sha256(canonical).hexdigest()

    def to_dict(self) -> dict:
        return {
            "digest": self.digest,
            "entries": [vars(e) for e in self.entries],
            "accepted_exclusions": self.exclusions,
        }


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _label(path: Path) -> str:
    """Chemin relatif a la racine du projet, pour que la mesure soit
    reproductible ailleurs que sur cette machine."""
    try:
        return path.resolve().relative_to(_ROOT).as_posix()
    except ValueError:
        return path.name


def build_manifest(runner=None, policy: Optional[dict] = None) -> Manifest:
    """Construit le manifeste pour cette configuration de serveur."""
    manifest = Manifest()

    for path in PROTOCOL_FILES:
        manifest.entries.append(
            ManifestEntry("protocol", _label(path), _file_digest(path)))

    for path in BOUNDARY_FILES:
        manifest.entries.append(
            ManifestEntry("boundary", _label(path), _file_digest(path)))

    if runner is not None:
        for path in runner.tcb_files():
            manifest.entries.append(
                ManifestEntry("runner", _label(Path(path)), _file_digest(Path(path))))

    if policy is not None:
        canonical = json.dumps(policy, sort_keys=True,
                               separators=(",", ":")).encode("utf-8")
        manifest.entries.append(
            ManifestEntry("policy", "declared-policy",
                          hashlib.sha256(canonical).hexdigest()))

    return manifest
