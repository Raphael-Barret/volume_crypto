"""Le serveur de traitement, decoupe pour que la revendication soit testable.

    app.py        les routes HTTP. Ne voit que du chiffre.
    jobs.py       les jobs et leur machine a etats.
    enclave.py    la garde des cles, la mesure, l'evidence.
    boundary.py   LA FRONTIERE : le seul module qui manipule du clair.
    measure.py    le manifeste mesure, et ses exclusions declarees.
    runners/      ce qui s'execute une fois la donnee lisible.

Le decoupage n'est pas cosmetique. Il permet a
tests/conformance/test_import_boundary.py de verifier mecaniquement qu'aucun
module hors `boundary` ne peut dechiffrer, ce qui transforme une promesse en
propriete du graphe d'imports.
"""

from .app import Handler, serve

__all__ = ["Handler", "serve"]
