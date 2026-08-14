"""Remise de cle a un destinataire distant, sans jamais l'exposer en clair.

Probleme resolu : le poste clinique detient la cle K d'un volume. Il doit la
confier au serveur qui va faire le calcul, sans qu'elle soit lisible par
quiconque observe le reseau, ni par l'infrastructure qui heberge le serveur.

Mecanisme (equivalent simplifie de HPKE, RFC 9180) :

    1. le destinataire publie une cle publique X25519 EPHEMERE, generee au
       demarrage et jamais ecrite sur disque
    2. l'expediteur genere sa propre paire ephemere, calcule un secret partage
       par echange Diffie-Hellman sur courbe elliptique (X25519)
    3. ce secret est passe dans HKDF-SHA256 pour deriver une cle de
       chiffrement de 32 octets
    4. K est chiffree en AES-256-GCM avec cette cle

Consequences :
  - seul le detenteur de la cle privee du destinataire peut ouvrir le paquet ;
  - une capture reseau ne donne rien, meme conservee des annees ;
  - l'`aad` (donnees authentifiees) lie le paquet a un contexte precis — ici
    l'identifiant du job et le nonce d'attestation. Un paquet destine a un job
    ne peut pas etre rejoue sur un autre.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

#: Etiquette de derivation. La changer rend les anciens paquets illisibles :
#: c'est voulu, elle identifie la version du protocole.
_INFO_PREFIX = b"voltcrypt-key-wrap-v1"

_PUBLIC_KEY_SIZE = 32
_NONCE_SIZE = 12


class KeyExchangeError(Exception):
    """Paquet illisible : mauvais destinataire, contexte different, alteration."""


def generate_recipient_keypair() -> tuple[X25519PrivateKey, bytes]:
    """Genere la paire ephemere du destinataire.

    Retourne (cle privee, cle publique en octets bruts). La cle privee doit
    rester en memoire : ne jamais l'ecrire sur disque, ne jamais la journaliser.
    """
    private = X25519PrivateKey.generate()
    return private, public_bytes(private)


def public_bytes(private: X25519PrivateKey) -> bytes:
    """Cle publique correspondante, en 32 octets bruts."""
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def wrap_key(key: bytes, recipient_public: bytes, aad: bytes = b"") -> bytes:
    """Chiffre `key` a destination de `recipient_public`.

    Le paquet produit fait 32 + 12 + len(key) + 16 octets et peut circuler en
    clair : il n'est ouvrable que par le destinataire.
    """
    if len(recipient_public) != _PUBLIC_KEY_SIZE:
        raise KeyExchangeError(
            f"Cle publique invalide : {_PUBLIC_KEY_SIZE} octets attendus, "
            f"{len(recipient_public)} recus.")

    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = public_bytes(ephemeral)
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_public))

    wrapping_key = _derive(shared, ephemeral_public, recipient_public)
    nonce = os.urandom(_NONCE_SIZE)
    sealed = AESGCM(wrapping_key).encrypt(nonce, key, aad)
    return ephemeral_public + nonce + sealed


def unwrap_key(packet: bytes, private: X25519PrivateKey, aad: bytes = b"") -> bytes:
    """Ouvre un paquet produit par wrap_key(). Leve KeyExchangeError sinon."""
    if len(packet) < _PUBLIC_KEY_SIZE + _NONCE_SIZE + 16:
        raise KeyExchangeError("Paquet tronque.")

    ephemeral_public = packet[:_PUBLIC_KEY_SIZE]
    nonce = packet[_PUBLIC_KEY_SIZE:_PUBLIC_KEY_SIZE + _NONCE_SIZE]
    sealed = packet[_PUBLIC_KEY_SIZE + _NONCE_SIZE:]

    try:
        shared = private.exchange(X25519PublicKey.from_public_bytes(ephemeral_public))
    except Exception as exc:
        raise KeyExchangeError(f"Cle publique ephemere invalide ({exc}).") from exc

    wrapping_key = _derive(shared, ephemeral_public, public_bytes(private))
    try:
        return AESGCM(wrapping_key).decrypt(nonce, sealed, aad)
    except InvalidTag as exc:
        raise KeyExchangeError(
            "Paquet illisible : destinataire different, contexte (job/nonce) "
            "different, ou paquet altere."
        ) from exc


def _derive(shared: bytes, ephemeral_public: bytes, recipient_public: bytes) -> bytes:
    """HKDF-SHA256 sur le secret partage, lie aux deux cles publiques."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_INFO_PREFIX + ephemeral_public + recipient_public,
    ).derive(shared)
