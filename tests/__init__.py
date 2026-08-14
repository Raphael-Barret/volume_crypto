"""Tests de voltcrypt.

Lancer depuis le dossier volume_crypto/ :

    python -m unittest discover -s tests -v
    # ou, si pytest est installe :
    pytest tests -v
"""

import sys
from pathlib import Path

# Permet de lancer les tests depuis n'importe quel dossier.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
