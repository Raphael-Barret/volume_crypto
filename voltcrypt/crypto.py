"""Chiffrement / dechiffrement de fichiers en AES-256-GCM, par blocs.

Pourquoi par blocs : un CBCT ou un maillage peut peser plusieurs Go. On ne
charge jamais le fichier entier en RAM, on le decoupe en blocs de CHUNK_SIZE
octets, chacun chiffre et authentifie independamment.

Format du conteneur .enc
------------------------

    HEADER (21 octets, en clair)
        magic       8   b"VOLCRYPT"
        version     1   = 1
        chunk_size  4   uint32 big-endian
        nonce_base  8   aleatoire, tire une fois par fichier

    puis une suite de BLOCS, chacun :
        length      4   uint32 big-endian = taille de blob
        blob        n   ciphertext || tag GCM (16 octets)

    Bloc d'index 0        = metadonnees JSON (nom d'origine, taille).
    Blocs d'index >= 1    = donnees du fichier.
    Dernier bloc          = JSON {"sha256": ...} du contenu en clair.

Nonce : nonce_base (8 octets) || index du bloc (4 octets BE) = 12 octets.
Le nonce_base etant unique par fichier, aucun nonce n'est jamais reutilise
avec la meme cle (le point critique de GCM).

Donnees authentifiees (AAD) de chaque bloc : HEADER || index || flag_dernier.
Consequence : on ne peut ni reordonner, ni supprimer, ni tronquer, ni
recopier un bloc d'un fichier vers un autre sans que le dechiffrement echoue.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path
from typing import Callable, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config
from .timing import Chrono, Timing

MAGIC = b"VOLCRYPT"
VERSION = 1
_HEADER_FMT = ">8sBI"          # magic, version, chunk_size
_HEADER_FIXED = struct.calcsize(_HEADER_FMT)      # 13 octets
_NONCE_BASE_SIZE = 8
_HEADER_SIZE = _HEADER_FIXED + _NONCE_BASE_SIZE
_LENGTH_FMT = ">I"
_LENGTH_SIZE = struct.calcsize(_LENGTH_FMT)
_TAG_SIZE = 16

#: Signature d'un callback de progression : (octets_traites, octets_total)
ProgressCallback = Callable[[int, int], None]


class CryptoError(Exception):
    """Fichier chiffre invalide, tronque, altere, ou mauvaise cle."""


# ---------------------------------------------------------------------------
# API publique
# ---------------------------------------------------------------------------

def encrypt_file(
    src: str | Path,
    dst: str | Path,
    key: bytes,
    chunk_size: int = config.CHUNK_SIZE,
    progress: Optional[ProgressCallback] = None,
) -> Timing:
    """Chiffre `src` vers `dst`.

    Retourne un `Timing` : le chemin produit, la duree, la taille traitee.
    L'objet s'utilise aussi directement comme un chemin (`os.PathLike`).
    Le chronometre s'arrete quand le fichier final est en place.
    """
    src, dst = Path(src), Path(dst)
    if not src.is_file():
        raise CryptoError(f"Fichier source introuvable : {src}")

    chrono = Chrono()
    aesgcm = AESGCM(key)
    nonce_base = os.urandom(8)
    header = struct.pack(_HEADER_FMT, MAGIC, VERSION, chunk_size) + nonce_base

    total = src.stat().st_size
    digest = hashlib.sha256()
    done = 0

    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.parent / (dst.name + ".part")  # ecriture atomique

    try:
        with open(src, "rb") as fin, open(tmp, "wb") as fout:
            fout.write(header)

            # Bloc 0 : metadonnees (nom d'origine, taille). Chiffrees elles
            # aussi : le nom du patient ne doit pas fuiter par le nom de fichier.
            meta = {"name": src.name, "size": total}
            _write_block(fout, aesgcm, nonce_base, header, 0,
                         json.dumps(meta).encode("utf-8"), last=False)

            index = 1
            while True:
                data = fin.read(chunk_size)
                if not data:
                    break
                digest.update(data)
                done += len(data)
                _write_block(fout, aesgcm, nonce_base, header, index, data, last=False)
                index += 1
                if progress:
                    progress(done, total)

            # Bloc final : sha256 du clair. Son flag last=True est dans l'AAD,
            # donc une troncature du fichier est detectee au dechiffrement.
            trailer = json.dumps({"sha256": digest.hexdigest()}).encode("utf-8")
            _write_block(fout, aesgcm, nonce_base, header, index, trailer, last=True)

        os.replace(tmp, dst)   # <- a partir d'ici le fichier est exploitable
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise

    return Timing(dst, chrono.seconds, total)


def decrypt_file(
    src: str | Path,
    dst: str | Path,
    key: bytes,
    progress: Optional[ProgressCallback] = None,
    verify_hash: bool = True,
) -> Timing:
    """Dechiffre `src` vers `dst`.

    Retourne un `Timing` : le chemin produit, la duree, la taille restituee.
    Le chronometre s'arrete quand le volume est ouvrable (Slicer, nibabel...).

    Leve CryptoError si la cle est mauvaise, ou si le fichier a ete tronque,
    reordonne ou modifie d'un seul bit.
    """
    src, dst = Path(src), Path(dst)
    if not src.is_file():
        raise CryptoError(f"Fichier chiffre introuvable : {src}")

    chrono = Chrono()
    aesgcm = AESGCM(key)
    digest = hashlib.sha256()
    total = src.stat().st_size
    done = 0

    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.parent / (dst.name + ".part")

    try:
        with open(src, "rb") as fin:
            header = fin.read(_HEADER_SIZE)
            if len(header) < _HEADER_SIZE:
                raise CryptoError(f"{src.name} : fichier tronque (header incomplet).")
            magic, version, _chunk_size = struct.unpack(_HEADER_FMT, header[:_HEADER_FIXED])
            nonce_base = header[_HEADER_FIXED:]
            if magic != MAGIC:
                raise CryptoError(f"{src.name} n'est pas un conteneur VOLCRYPT.")
            if version != VERSION:
                raise CryptoError(f"{src.name} : version de format {version} non supportee.")

            # Bloc 0 : metadonnees
            meta_raw, was_last = _read_block(fin, aesgcm, nonce_base, header, 0, src.name)
            if was_last:
                raise CryptoError(f"{src.name} : bloc de metadonnees marque comme final.")
            meta = json.loads(meta_raw)

            with open(tmp, "wb") as fout:
                index = 1
                trailer = None
                while True:
                    block, is_last = _read_block(fin, aesgcm, nonce_base, header,
                                                 index, src.name)
                    index += 1
                    if is_last:
                        trailer = json.loads(block)
                        break
                    fout.write(block)
                    digest.update(block)
                    done += len(block)
                    if progress:
                        progress(done, total)

        if verify_hash and trailer and trailer.get("sha256"):
            if digest.hexdigest() != trailer["sha256"]:
                raise CryptoError(f"{src.name} : le sha256 du contenu dechiffre ne "
                                  f"correspond pas a celui enregistre.")

        os.replace(tmp, dst)   # <- a partir d'ici le volume est ouvrable
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise

    return Timing(dst, chrono.seconds, done)


def read_metadata(src: str | Path, key: bytes) -> dict:
    """Lit le bloc de metadonnees (nom et taille d'origine) sans tout dechiffrer."""
    src = Path(src)
    aesgcm = AESGCM(key)
    with open(src, "rb") as fin:
        header = fin.read(_HEADER_SIZE)
        if len(header) < _HEADER_SIZE or header[:8] != MAGIC:
            raise CryptoError(f"{src.name} n'est pas un conteneur VOLCRYPT.")
        nonce_base = header[_HEADER_FIXED:]
        meta_raw, _ = _read_block(fin, aesgcm, nonce_base, header, 0, src.name)
    return json.loads(meta_raw)


def original_name(src: str | Path, key: bytes) -> str:
    """Nom du fichier avant chiffrement (stocke chiffre dans le conteneur)."""
    return read_metadata(src, key)["name"]


# ---------------------------------------------------------------------------
# Internes
# ---------------------------------------------------------------------------

def _nonce(nonce_base: bytes, index: int) -> bytes:
    return nonce_base + struct.pack(_LENGTH_FMT, index)


def _aad(header: bytes, index: int, last: bool) -> bytes:
    return header + struct.pack(">IB", index, 1 if last else 0)


def _write_block(fout, aesgcm, nonce_base, header, index, data, last):
    blob = aesgcm.encrypt(_nonce(nonce_base, index), data, _aad(header, index, last))
    fout.write(struct.pack(_LENGTH_FMT, len(blob)))
    fout.write(blob)


def _read_block(fin, aesgcm, nonce_base, header, index, name):
    """Retourne (donnees_en_clair, est_le_dernier_bloc)."""
    raw_len = fin.read(_LENGTH_SIZE)
    if len(raw_len) < _LENGTH_SIZE:
        raise CryptoError(f"{name} : fichier tronque (bloc {index} manquant).")
    (length,) = struct.unpack(_LENGTH_FMT, raw_len)
    if length < _TAG_SIZE:
        raise CryptoError(f"{name} : bloc {index} invalide.")
    blob = fin.read(length)
    if len(blob) < length:
        raise CryptoError(f"{name} : fichier tronque (bloc {index} incomplet).")

    nonce = _nonce(nonce_base, index)
    # On ignore le flag "dernier bloc" : on essaie les deux AAD possibles.
    # Celle qui valide nous dit si ce bloc est final.
    for last in (False, True):
        try:
            return aesgcm.decrypt(nonce, blob, _aad(header, index, last)), last
        except InvalidTag:
            continue
    raise CryptoError(
        f"{name} : bloc {index} illisible. Cause probable : mauvaise cle, "
        f"ou fichier modifie/reordonne."
    )
