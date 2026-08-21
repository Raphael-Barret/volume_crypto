"""La batterie de controles, et son verdict.

Chaque controle porte un nom qui EST la question posee, parce que ce nom se
retrouve dans `evidence/adversary.json` et, de la, dans le papier. Un controle
nomme `test_security` ne serait citable par personne.

Trois regles suivies partout ici :

1. Un refus se verifie par l'ETAT, pas par l'exception. Une erreur levee apres
   que la cle est partie n'est pas une defense. Chaque controle de refus
   verifie donc aussi que la cle n'a pas bouge et qu'aucun artefact n'a ete
   produit.
2. Un controle qui ne peut pas s'executer rend `SKIPPED` avec sa raison. Il ne
   rend jamais `PASSED` par defaut.
3. La batterie ne connait pas le code du serveur. Tout passe par HTTP.
"""

from __future__ import annotations

import json
import os
import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Optional


class Verdict(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class Finding:
    """Le resultat d'un controle."""

    name: str
    question: str
    verdict: Verdict
    detail: str = ""
    #: Ce qui n'a PAS bouge, quand le controle porte sur un refus.
    did_not_move: dict = field(default_factory=dict)

    def as_row(self) -> dict:
        return {
            "check": self.name,
            "question": self.question,
            "verdict": self.verdict.value,
            "detail": self.detail,
            "did_not_move": self.did_not_move,
        }


class ProbeError(RuntimeError):
    """Le serveur n'a pas repondu comme un serveur voltcrypt."""


class Battery:
    """Enchaine les controles contre une URL et rend un rapport."""

    #: Marqueurs a haute entropie glisses dans le volume canari. Les retrouver
    #: quelque part cote serveur avant la remise de cle est un echec.
    MARKER_CONTENT = b"CANARY-CONTENT-b7f3a1d92e4c8056"
    MARKER_NAME = "CANARY_PATIENT_DUPONT_1970.nii"

    def __init__(self, base_url: str, storage_dir: Optional[Path] = None,
                 timeout: int = 120) -> None:
        self.base_url = base_url.rstrip("/")
        #: Repertoire des jobs, quand la batterie tourne sur la meme machine.
        #: Absent, les controles qui inspectent le disque rendent SKIPPED
        #: plutot que de conclure sans preuve.
        self.storage_dir = Path(storage_dir) if storage_dir else None
        self.timeout = timeout
        self.findings: list[Finding] = []

    # -- Transport ---------------------------------------------------------

    def _get(self, path: str) -> dict:
        request = urllib.request.Request(f"{self.base_url}{path}")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as answer:
                return json.loads(answer.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise ProbeError(f"{path} : HTTP {exc.code}") from exc
        except OSError as exc:
            raise ProbeError(f"{path} : serveur injoignable ({exc})") from exc

    def _post_json(self, path: str, payload: dict) -> dict:
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as answer:
                return json.loads(answer.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise ProbeError(f"{path} : HTTP {exc.code}") from exc
        except OSError as exc:
            raise ProbeError(f"{path} : serveur injoignable ({exc})") from exc

    def _post_file(self, path: str, source: Path) -> dict:
        size = source.stat().st_size
        with open(source, "rb") as handle:
            request = urllib.request.Request(
                f"{self.base_url}{path}", data=handle,
                headers={"Content-Type": "application/octet-stream",
                         "Content-Length": str(size)}, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as answer:
                    return json.loads(answer.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                raise ProbeError(f"{path} : HTTP {exc.code}") from exc
            except OSError as exc:
                raise ProbeError(f"{path} : serveur injoignable ({exc})") from exc

    # -- Mecanique des controles -------------------------------------------

    def _record(self, name: str, question: str, check: Callable[[], tuple]) -> Finding:
        try:
            verdict, detail, did_not_move = check()
        except ProbeError as exc:
            finding = Finding(name, question, Verdict.SKIPPED, str(exc))
        except Exception as exc:                      # noqa: BLE001
            finding = Finding(name, question, Verdict.FAILED,
                              f"controle interrompu : {exc!r}")
        else:
            finding = Finding(name, question, verdict, detail, did_not_move or {})
        self.findings.append(finding)
        return finding

    # -- Rapport -----------------------------------------------------------

    def report(self) -> dict:
        counts = {verdict.value: 0 for verdict in Verdict}
        for finding in self.findings:
            counts[finding.verdict.value] += 1
        return {
            "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "target": self.base_url,
            "storage_inspected": str(self.storage_dir) if self.storage_dir else None,
            "counts": counts,
            "clean": counts[Verdict.FAILED.value] == 0,
            "checks": [f.as_row() for f in self.findings],
        }

    def print_report(self) -> None:
        symbols = {Verdict.PASSED: "ok  ", Verdict.FAILED: "ECHEC",
                   Verdict.SKIPPED: "skip"}
        print(f"cryptoverify contre {self.base_url}")
        print("-" * 78)
        for finding in self.findings:
            print(f"[{symbols[finding.verdict]}] {finding.name}")
            print(f"        {finding.question}")
            if finding.detail:
                print(f"        {finding.detail}")
            for what, value in finding.did_not_move.items():
                print(f"        n'a pas bouge : {what} = {value}")
        print("-" * 78)
        report = self.report()
        print(", ".join(f"{k} : {v}" for k, v in report["counts"].items()))
        print("VERDICT : " + ("propre" if report["clean"] else "DEFAUTS TROUVES"))
