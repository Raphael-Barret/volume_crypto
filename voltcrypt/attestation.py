"""Attestation : prouver QUEL code tourne, avant de lui confier une cle.

┌──────────────────────────────────────────────────────────────────────────┐
│  AVERTISSEMENT — RACINE DE CONFIANCE SIMULEE                             │
│                                                                          │
│  Ce module reproduit fidelement le PROTOCOLE d'attestation, mais sa      │
│  racine de confiance est une cle Ed25519 logicielle, posee sur le        │
│  disque du serveur. Un administrateur du serveur peut la lire et         │
│  fabriquer une attestation mensongere.                                   │
│                                                                          │
│  Il ne protege donc PAS contre un serveur malveillant. Il protege        │
│  contre un serveur MODIFIE PAR ERREUR (mauvaise version deployee,        │
│  fichier corrompu, mauvaise machine) et il valide le protocole.          │
│                                                                          │
│  En production, la signature doit venir du materiel :                    │
│    - AMD SEV-SNP : ioctl SNP_GET_EXT_REPORT sur /dev/sev-guest,          │
│      signature par la VCEK, chainee a la racine AMD                      │
│    - Intel TDX   : ioctl TDX_CMD_GET_REPORT0 sur /dev/tdx_guest,         │
│      puis Quote via le Quote Generation Service                          │
│    - GPU NVIDIA  : nv-attestation-sdk, verification aupres du NRAS       │
│                                                                          │
│  Seule la fonction _sign_evidence() change alors. Le reste du fichier    │
│  et tout le protocole client restent identiques.                         │
└──────────────────────────────────────────────────────────────────────────┘

Ce que l'attestation etablit, dans l'ordre de verification :

  1. signature      l'evidence vient bien de la racine de confiance attendue
  2. nonce          elle a ete produite APRES ma demande (pas de rejeu)
  3. report_data    elle porte l'empreinte de la cle publique du serveur
                    -> c'est ce lien qui interdit l'attaque par relais
  4. measurement    le serveur execute le code que j'attends, a l'octet pres
  5. policy         la configuration de securite annoncee me convient
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

EVIDENCE_VERSION = 1

#: Type de racine de confiance. En production : "amd-sev-snp", "intel-tdx".
KIND_SIMULATED = "simulated-software-root"


class AttestationError(Exception):
    """L'attestation est invalide : la cle ne doit PAS etre transmise."""


# ---------------------------------------------------------------------------
# Mesure du code
# ---------------------------------------------------------------------------

def measure_code(paths: Sequence[Path]) -> str:
    """Empreinte SHA-256 d'un ensemble de fichiers source.

    Equivalent logiciel du `launch_measurement` d'une VM confidentielle : le
    hash cumulatif de ce qui est charge. Le nom de chaque fichier entre dans le
    calcul, donc renommer, ajouter ou retirer un fichier change la mesure.

    Cette mesure-la est REELLE, pas simulee : modifier une seule ligne du
    serveur change l'empreinte, et le client refuse alors de livrer la cle.
    """
    digest = hashlib.sha256()
    for path in sorted(Path(p).resolve() for p in paths):
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(path.read_bytes())
        digest.update(b"\x00")
    return digest.hexdigest()


def compute_report_data(public_key: bytes, nonce: bytes) -> str:
    """SHA-512(cle publique || nonce) — le champ qui lie l'evidence a la cle.

    Sans le nonce, une evidence resterait valide indefiniment et pourrait etre
    rejouee par un serveur dont le code s'est revele vulnerable depuis.
    """
    return hashlib.sha512(public_key + nonce).hexdigest()


# ---------------------------------------------------------------------------
# Production (cote serveur)
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    """Ce que le serveur presente pour prouver son identite."""
    version: int
    kind: str
    measurement: str
    public_key: str          # hex, cle publique ephemere du serveur
    nonce: str               # hex, fourni par le client
    report_data: str         # hex, SHA-512(public_key || nonce)
    policy: dict = field(default_factory=dict)
    produced_utc: str = ""

    def canonical(self) -> bytes:
        """Serialisation deterministe : c'est elle qui est signee."""
        return json.dumps(asdict(self), sort_keys=True,
                          separators=(",", ":")).encode("utf-8")


def produce_evidence(
    public_key: bytes,
    nonce: bytes,
    measurement: str,
    signing_key: Ed25519PrivateKey,
    policy: Optional[dict] = None,
) -> tuple[Evidence, bytes]:
    """Fabrique l'evidence et la signe. Retourne (evidence, signature)."""
    evidence = Evidence(
        version=EVIDENCE_VERSION,
        kind=KIND_SIMULATED,
        measurement=measurement,
        public_key=public_key.hex(),
        nonce=nonce.hex(),
        report_data=compute_report_data(public_key, nonce),
        policy=policy or {},
        produced_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    return evidence, signing_key.sign(evidence.canonical())


# ---------------------------------------------------------------------------
# Verification (cote client)
# ---------------------------------------------------------------------------

@dataclass
class Policy:
    """Ce que le client exige avant de livrer la cle."""
    expected_measurement: Optional[str] = None   # None = accepte (mode TOFU)
    require_debug_off: bool = True
    require_swap_off: bool = True

    def check(self, evidence: Evidence) -> list[str]:
        """Retourne la liste des manquements (vide = conforme)."""
        problems = []
        if self.expected_measurement and evidence.measurement != self.expected_measurement:
            problems.append(
                f"mesure du code inattendue : {evidence.measurement[:16]}... "
                f"au lieu de {self.expected_measurement[:16]}...")
        if self.require_debug_off and evidence.policy.get("debug", True):
            problems.append("le mode debug est actif sur le serveur")
        if self.require_swap_off and evidence.policy.get("swap", True):
            problems.append("le swap est actif : la donnee en clair peut atteindre le disque")
        return problems


def verify_evidence(
    evidence: Evidence,
    signature: bytes,
    trusted_public_key: Ed25519PublicKey,
    expected_nonce: bytes,
    expected_server_key: bytes,
    policy: Optional[Policy] = None,
) -> None:
    """Verifie l'evidence de bout en bout. Leve AttestationError au premier echec.

    L'ordre compte : on ne regarde le contenu qu'apres avoir etabli qu'il vient
    de la racine de confiance.
    """
    policy = policy or Policy()

    # 1. Signature
    try:
        trusted_public_key.verify(signature, evidence.canonical())
    except InvalidSignature as exc:
        raise AttestationError(
            "signature invalide : l'evidence ne vient pas de la racine de "
            "confiance attendue (ou a ete modifiee en transit)") from exc

    if evidence.version != EVIDENCE_VERSION:
        raise AttestationError(f"version d'evidence non supportee : {evidence.version}")

    # 2. Fraicheur — l'evidence repond bien a MA demande
    if bytes.fromhex(evidence.nonce) != expected_nonce:
        raise AttestationError(
            "nonce different de celui envoye : evidence rejouee ou destinee a "
            "une autre session")

    # 3. Binding cle publique <-> evidence (interdit l'attaque par relais)
    if bytes.fromhex(evidence.public_key) != expected_server_key:
        raise AttestationError(
            "la cle publique attestee n'est pas celle qui m'a ete presentee")
    if evidence.report_data != compute_report_data(expected_server_key, expected_nonce):
        raise AttestationError(
            "report_data incoherent : le lien entre l'evidence et la cle "
            "publique est rompu")

    # 4 et 5. Identite du code et configuration
    problems = policy.check(evidence)
    if problems:
        raise AttestationError("; ".join(problems))


# ---------------------------------------------------------------------------
# Racine de confiance simulee (fichiers de cles)
# ---------------------------------------------------------------------------

def load_or_create_signing_key(path: str | Path) -> Ed25519PrivateKey:
    """Cle de signature du serveur. SIMULE la racine materielle."""
    path = Path(path)
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)

    key = Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    path.chmod(0o600)
    return key


def export_public_key(key: Ed25519PrivateKey, path: str | Path) -> Path:
    """Ecrit la cle publique que le client devra connaitre a l'avance."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return path


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    """Relit la cle publique de la racine de confiance."""
    path = Path(path)
    if not path.exists():
        raise AttestationError(
            f"Racine de confiance introuvable : {path}\n"
            f"Elle est produite au premier demarrage du serveur.")
    return serialization.load_pem_public_key(path.read_bytes())
