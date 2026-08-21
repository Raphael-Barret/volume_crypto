"""Les racines de confiance : qui signe l'evidence, et ce que cela vaut.

Tout l'interet d'avoir ecrit le protocole en entier tient dans ce fichier :
entre la demonstration et la production, SEULE la fonction de signature
change. Le protocole client, la verification, la liaison au nonce, la liaison
a la cle publique et la remise de cle restent identiques.

Rendre cela explicite dans le code plutot que dans une docstring a une raison.
Un lecteur qui demande << et en vrai, vous feriez comment ? >> doit pouvoir
lire les points d'appel exacts, pas une intention.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass
class Attestation:
    """Une evidence signee, quelle que soit son origine."""

    signature: bytes
    #: Ce qui identifie la racine : cle publique locale, ou chaine de
    #: certificats du fondeur en production.
    root_identity: str
    kind: str


class TrustRoot(Protocol):
    """Ce qui signe une evidence."""

    kind: str

    def sign(self, payload: bytes) -> Attestation:
        ...


class SoftwareRoot:
    """Racine LOGICIELLE : une cle Ed25519 sur le disque du serveur.

    Protege contre un serveur MODIFIE PAR ERREUR : mauvaise version deployee,
    fichier corrompu, mauvaise machine. Ne protege PAS contre un
    administrateur malveillant, qui peut lire la cle et fabriquer une
    attestation mensongere. C'est la limite assumee de la demonstration, et
    elle est ecrite partout ou elle s'applique.
    """

    kind = "simulated-software-root"

    def __init__(self, signing_key_path: Path) -> None:
        from voltcrypt import attestation
        self._key = attestation.load_or_create_signing_key(signing_key_path)

    @property
    def signing_key(self):
        return self._key

    def sign(self, payload: bytes) -> Attestation:
        return Attestation(
            signature=self._key.sign(payload),
            root_identity=self._key.public_key().public_bytes_raw().hex(),
            kind=self.kind,
        )


class HardwareRoot:
    """Racine MATERIELLE. Non implementee : le materiel n'est pas la.

    Ce n'est pas une lacune du plan, c'est sa frontiere. Les points d'appel
    exacts sont documentes ici pour que la substitution soit une tache
    delimitee et non une recherche :

    AMD SEV-SNP
        ioctl SNP_GET_EXT_REPORT sur /dev/sev-guest. Le champ `report_data`
        (64 octets) recoit le meme sha512(cle_publique || nonce) que la
        version logicielle. La signature est produite par la VCEK, chainee a
        la racine AMD, et se verifie contre le KDS AMD.

    Intel TDX
        ioctl TDX_CMD_GET_REPORT0 sur /dev/tdx_guest pour obtenir un TDREPORT,
        converti en Quote par le Quote Generation Service. Meme `report_data`.

    GPU NVIDIA (Hopper et suivants, mode confidentiel)
        nv-attestation-sdk, verification aupres du NRAS. Necessaire des que
        l'inference tourne sur GPU : mesurer la VM sans mesurer le GPU laisse
        le clair visible la ou il est effectivement traite.

    Ce qui change ici et nulle part ailleurs :
        - `sign()` renvoie un rapport materiel au lieu d'une signature Ed25519
        - `root_identity` devient une chaine de certificats
        - la verification cliente valide cette chaine au lieu d'une cle epinglee

    Ce qui NE change pas : la mesure du manifeste, la liaison au nonce, la
    liaison a la cle publique ephemere, l'enveloppe de cle, et la decision de
    livrer ou non la cle, qui reste chez le client.
    """

    kind = "hardware-root"

    #: Peripheriques attendus, dans l'ordre ou on les essaierait.
    DEVICES = ("/dev/sev-guest", "/dev/tdx_guest")

    def __init__(self) -> None:
        raise NotImplementedError(
            "racine materielle absente : aucun peripherique parmi "
            f"{', '.join(self.DEVICES)}. Voir la docstring pour les points "
            "d'appel exacts. La demonstration utilise SoftwareRoot, et le dit."
        )

    def sign(self, payload: bytes) -> Attestation:   # pragma: no cover
        raise NotImplementedError


def available_roots() -> dict[str, bool]:
    """Ce que cette machine peut reellement offrir. Sert au rapport."""
    return {device: Path(device).exists() for device in HardwareRoot.DEVICES}
