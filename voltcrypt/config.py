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
    for directory in (PLAIN_DIR, ENCRYPTED_DIR, DECRYPTED_DIR, KEYS_DIR):
        directory.mkdir(parents=True, exist_ok=True)
