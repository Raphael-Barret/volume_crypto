"""Generation, sauvegarde et chargement des cles AES-256.

Une cle = 32 octets aleatoires (os.urandom), stockee dans un petit fichier
JSON lisible, avec les permissions 0600 (proprietaire uniquement).
"""

from __future__ import annotations

import base64
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

KEY_SIZE = 32  # AES-256
KEY_FILE_VERSION = 1


class KeyError_(Exception):
    """Probleme de cle (fichier absent, corrompu, mauvaise taille)."""


def generate_key() -> bytes:
    """Retourne une nouvelle cle AES-256 (32 octets) tiree du CSPRNG systeme."""
    return os.urandom(KEY_SIZE)


def save_key(key: bytes, path: str | Path, label: str = "", overwrite: bool = False) -> Path:
    """Ecrit la cle sur disque en JSON + base64, avec permissions 0600.

    Leve FileExistsError si le fichier existe deja et overwrite est False :
    ecraser une cle rend tous les fichiers deja chiffres illisibles.
    """
    _check_key(key)
    path = Path(path)
    if path.exists() and not overwrite:
        raise FileExistsError(
            f"{path} existe deja. Ecraser cette cle rendrait les fichiers "
            f"deja chiffres avec elle definitivement illisibles."
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": KEY_FILE_VERSION,
        "algorithm": "AES-256-GCM",
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "label": label,
        "key_b64": base64.b64encode(key).decode("ascii"),
    }
    # On cree le fichier deja restreint, pour ne pas exposer la cle entre
    # l'ecriture et le chmod.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    return path


def load_key(path: str | Path) -> bytes:
    """Relit une cle ecrite par save_key()."""
    path = Path(path)
    if not path.exists():
        raise KeyError_(
            f"Cle introuvable : {path}\n"
            f"Genere-la d'abord avec :  python main.py gen-key"
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        key = base64.b64decode(payload["key_b64"], validate=True)
    except Exception as exc:  # JSON casse, champ manquant, base64 invalide
        raise KeyError_(f"Fichier de cle illisible ou corrompu : {path} ({exc})") from exc

    _check_key(key)
    return key


def get_or_create_key(path: str | Path, label: str = "") -> bytes:
    """Charge la cle si elle existe, sinon en genere une et la sauvegarde."""
    path = Path(path)
    if path.exists():
        return load_key(path)
    key = generate_key()
    save_key(key, path, label=label)
    return key


def _check_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_SIZE:
        raise KeyError_(f"Cle invalide : {KEY_SIZE} octets attendus, {len(key)} recus.")
