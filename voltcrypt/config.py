"""Configuration centrale — c'est le seul fichier a modifier au quotidien."""

from pathlib import Path

# ---------------------------------------------------------------------------
# Chemins
# ---------------------------------------------------------------------------
# Racine du projet (le dossier qui contient main.py)
PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = PROJECT_ROOT / "data"

#: Fichiers volumiques en clair, a chiffrer
PLAIN_DIR = DATA_DIR / "to_encrypt"

#: Fichiers chiffres (.enc)
ENCRYPTED_DIR = DATA_DIR / "encrypted"

#: Fichiers dechiffres (restitution)
DECRYPTED_DIR = DATA_DIR / "decrypted"

#: Cles de chiffrement. NE JAMAIS versionner / partager ce dossier.
KEYS_DIR = DATA_DIR / "keys"

#: Cle utilisee par defaut par le CLI
DEFAULT_KEY_PATH = KEYS_DIR / "master.key"

# --- Pipeline client/serveur (voir PIPELINE.md) ------------------------------

#: Cote serveur : ou sont stockes les jobs recus (toujours chiffres)
SERVER_STORAGE_DIR = DATA_DIR / "server_storage"

#: Cote client : ce qu'il doit connaitre a l'avance pour verifier le serveur
#: (cle publique de la racine de confiance, mesure de code attendue).
TRUST_DIR = DATA_DIR / "trust"

TRUST_ROOT_PUBLIC_KEY = TRUST_DIR / "attestation_root.pub"
EXPECTED_MEASUREMENT_FILE = TRUST_DIR / "expected_measurement.txt"

#: Cle privee de signature du serveur — SIMULE une racine materielle.
ATTESTATION_SIGNING_KEY = KEYS_DIR / "attestation_root.key"

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8000


# ---------------------------------------------------------------------------
# Parametres de chiffrement
# ---------------------------------------------------------------------------
#: Taille des blocs lus/chiffres. 4 MiB = bon compromis RAM / vitesse pour
#: des CBCT ou des maillages de plusieurs Go.
CHUNK_SIZE = 4 * 1024 * 1024

#: Extension ajoutee aux fichiers chiffres
ENCRYPTED_SUFFIX = ".enc"

#: Extensions considerees comme "donnee volumique".
#: Sert uniquement de filtre optionnel (--only-volumes) : par defaut le batch
#: chiffre TOUT ce qui se trouve dans le dossier d'entree.
VOLUME_EXTENSIONS = (
    ".vtk", ".vtp", ".vtu", ".vti", ".vtm",   # VTK
    ".nii", ".nii.gz", ".nrrd", ".nhdr",      # imagerie
    ".mha", ".mhd", ".raw", ".gipl",
    ".dcm", ".dicom",
    ".stl", ".obj", ".ply", ".off",           # surfaces
    ".h5", ".npy", ".npz",
)


def ensure_dirs() -> None:
    """Cree l'arborescence data/ si elle n'existe pas encore."""
    for directory in (PLAIN_DIR, ENCRYPTED_DIR, DECRYPTED_DIR, KEYS_DIR,
                      SERVER_STORAGE_DIR, TRUST_DIR):
        directory.mkdir(parents=True, exist_ok=True)
