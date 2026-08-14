"""voltcrypt — chiffrement AES-256-GCM de fichiers volumiques (.vtk, .nii, ...).

Utilisation minimale :

    from voltcrypt import keys, crypto

    key = keys.generate_key()
    keys.save_key(key, "data/keys/master.key")

    crypto.encrypt_file("scan.nii.gz", "scan.nii.gz.enc", key)
    crypto.decrypt_file("scan.nii.gz.enc", "scan_restaure.nii.gz", key)

Ou par dossier :

    from voltcrypt import batch
    batch.encrypt_directory(key=key)
    batch.decrypt_directory(key=key)
"""

from . import audit, batch, config, crypto, keys, timing
from .audit import audit_container
from .crypto import CryptoError, decrypt_file, encrypt_file, original_name, read_metadata
from .keys import generate_key, get_or_create_key, load_key, save_key
from .timing import Chrono, Timing

__version__ = "1.2.0"

__all__ = [
    "audit", "batch", "config", "crypto", "keys", "timing",
    "audit_container", "Timing", "Chrono",
    "encrypt_file", "decrypt_file", "read_metadata", "original_name", "CryptoError",
    "generate_key", "save_key", "load_key", "get_or_create_key",
]
