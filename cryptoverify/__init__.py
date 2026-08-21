"""Verifier qu'un deploiement respecte la chaine, sans lire son code source.

`cryptoverify` traite le serveur comme une boite noire et rend un verdict. Il
sert deux publics :

    nous       pour montrer que la methode tient, et regenerer les chiffres
               que le papier cite ;
    un site    pour verifier un deploiement qu'il n'a pas construit.

Le second est le point. Une revendication de securite qu'on ne peut que
croire n'a pas la meme valeur qu'une revendication qu'on peut REJOUER. La
batterie est donc executable par quelqu'un qui n'a acces qu'a une URL.
"""

from .battery import Battery, Finding, Verdict

__all__ = ["Battery", "Finding", "Verdict"]
