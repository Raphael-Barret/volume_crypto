"""La garde des cles : ce qui, en production, vivrait dans la VM confidentielle.

La cle privee ephemere est generee au demarrage, n'est jamais ecrite sur
disque ni journalisee, et est la seule facon d'ouvrir les cles que les clients
envoient. La cle de signature d'attestation, elle, est aujourd'hui un fichier
Ed25519 sur le disque du serveur : c'est la racine de confiance LOGICIELLE, et
c'est la limite assumee de cette demonstration (voir voltcrypt/attestation.py).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from voltcrypt import attestation, keyexchange

from . import measure
from .runners.base import Runner


class Enclave:
    """Detient les cles, annonce la mesure, produit l'evidence."""

    def __init__(self, signing_key_path: Path, runner: Runner) -> None:
        self.private_key, self.public_key = keyexchange.generate_recipient_keypair()
        self.signing_key = attestation.load_or_create_signing_key(signing_key_path)
        self.runner = runner
        self.manifest = measure.build_manifest(runner=runner, policy=self.policy())
        self.measurement = self.manifest.digest
        self.started_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def policy(self) -> dict:
        """Configuration de securite annoncee au client.

        En production ces valeurs viendraient du rapport materiel et non du
        programme lui-meme : un serveur ne peut pas s'auto-certifier.
        """
        return {
            "debug": False,
            "swap": False,
            "tee": "SIMULATED, aucune protection materielle",
            "gpu_confidential": False,
        }

    def attest(self, nonce: bytes) -> tuple[attestation.Evidence, bytes]:
        return attestation.produce_evidence(
            public_key=self.public_key,
            nonce=nonce,
            measurement=self.measurement,
            signing_key=self.signing_key,
            policy=self.policy(),
        )
