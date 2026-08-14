#!/usr/bin/env python3
"""Mini serveur de traitement — demonstration du pipeline complet.

    python server.py                    # ecoute sur 127.0.0.1:8000
    python server.py --port 9000
    python server.py --measurement      # affiche la mesure du code et quitte

Ce que ce serveur illustre, et qui est le point de la demonstration :

    il recoit des volumes CHIFFRES et ne peut RIEN en faire
    tant qu'il n'a pas prouve son identite pour obtenir la cle.

Deroulement d'un job :

    POST /jobs                 le volume chiffre arrive.  Le serveur le stocke
                               tel quel. A ce stade il ne sait meme pas quel
                               est le nom du fichier d'origine.
    GET  /attestation?nonce=   le client demande une preuve. Le serveur mesure
                               son propre code et signe l'ensemble.
    POST /jobs/<id>/key        si le client a ete convaincu, il envoie la cle,
                               chiffree pour la cle publique ephemere du
                               serveur. Le serveur dechiffre EN MEMOIRE,
                               traite, rechiffre, efface.
    GET  /jobs/<id>/result     le resultat, chiffre.

Le "traitement" est volontairement neutre : il renvoie le volume inchange et
un petit rapport. L'objectif est de valider la chaine, pas de calculer.

Limites assumees de cette demo : HTTP en clair (voir PIPELINE.md), stockage
des jobs sur disque, et racine de confiance logicielle (voir voltcrypt/
attestation.py). Ce n'est pas un serveur de production.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

from voltcrypt import attestation, config, crypto, keyexchange
from voltcrypt.timing import Chrono, human_duration, human_size

#: Fichiers dont l'empreinte constitue la mesure du serveur. Modifier l'un
#: d'eux change la mesure, et les clients configures en mode strict refusent
#: alors de livrer leur cle.
MEASURED_FILES = [
    Path(__file__).resolve(),
    Path(__file__).resolve().parent / "voltcrypt" / "crypto.py",
    Path(__file__).resolve().parent / "voltcrypt" / "keyexchange.py",
    Path(__file__).resolve().parent / "voltcrypt" / "attestation.py",
]

#: Taille maximale acceptee pour un envoi (4 Gio).
MAX_UPLOAD = 4 * 1024 * 1024 * 1024

_READ_CHUNK = 1024 * 1024


@dataclass
class Job:
    """Un traitement en cours. Etats : received -> done | failed."""
    job_id: str
    encrypted_path: Path
    size: int
    state: str = "received"
    created_utc: str = ""
    result_path: Optional[Path] = None
    report: dict = field(default_factory=dict)
    error: str = ""


class Store:
    """Jobs en cours. En memoire : redemarrer le serveur les oublie."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def create(self, job_id: str, path: Path, size: int) -> Job:
        job = Job(job_id, path, size,
                  created_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        with self._lock:
            self._jobs[job_id] = job
        return job

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)


class Enclave:
    """Ce qui, en production, vivrait dans la VM confidentielle.

    La cle privee ephemere est generee au demarrage et n'est jamais ecrite sur
    disque ni journalisee. Elle est la seule facon d'ouvrir les cles que les
    clients envoient.
    """

    def __init__(self, signing_key_path: Path) -> None:
        self.private_key, self.public_key = keyexchange.generate_recipient_keypair()
        self.signing_key = attestation.load_or_create_signing_key(signing_key_path)
        self.measurement = attestation.measure_code(MEASURED_FILES)
        self.started_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def policy(self) -> dict:
        """Configuration de securite annoncee au client.

        En production, ces valeurs viendraient du rapport materiel et non du
        programme lui-meme — un serveur ne peut pas s'auto-certifier.
        """
        return {
            "debug": False,
            "swap": False,
            "tee": "SIMULATED — aucune protection materielle",
            "gpu_confidential": False,
        }

    def attest(self, nonce: bytes) -> tuple[attestation.Evidence, bytes]:
        return attestation.produce_evidence(
            public_key=self.public_key,
            nonce=nonce,
            measurement=self.measurement,
            signing_key=self.signing_key,
            policy=self.policy(),
        )


def process_job(job: Job, key: bytes, enclave: Enclave) -> None:
    """Dechiffre, "traite", rechiffre. C'est ici que la donnee est en clair.

    Tout se passe dans un dossier temporaire, et le clair est efface avant le
    retour de la fonction, y compris si le traitement echoue.
    """
    workdir = Path(tempfile.mkdtemp(prefix="voltcrypt_job_"))
    try:
        # --- Frontiere : a partir d'ici, la donnee est lisible -------------
        plain = workdir / "input"
        timing = crypto.decrypt_file(job.encrypted_path, plain, key)
        metadata = crypto.read_metadata(job.encrypted_path, key)

        # --- Le "traitement". Ici : identite + quelques statistiques -------
        content = plain.read_bytes()
        report = {
            "original_name": metadata["name"],
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "decrypt_seconds": round(timing.seconds, 4),
            "processing": "identite (aucune transformation)",
        }
        output = workdir / "output"
        output.write_bytes(content)

        # --- Rechiffrement avant de ressortir de la frontiere --------------
        result_path = job.encrypted_path.parent / f"{job.job_id}.result.enc"
        crypto.encrypt_file(output, result_path, key)

        job.result_path = result_path
        job.report = report
        job.state = "done"
    except Exception as exc:
        job.state = "failed"
        job.error = str(exc)
        raise
    finally:
        # Effacement du clair. Best effort : Python ne garantit pas l'effacement
        # des copies laissees en memoire par l'interpreteur (voir PIPELINE.md).
        shutil.rmtree(workdir, ignore_errors=True)


class Handler(BaseHTTPRequestHandler):
    """Routage minimal. Les instances sont creees par requete."""

    server_version = "voltcrypt-demo/1.0"

    store: Store           # injectes par serve()
    enclave: Enclave
    quiet: bool = False

    # -- Routes ------------------------------------------------------------

    def do_GET(self) -> None:      # noqa: N802  (nom impose par la stdlib)
        route = urlparse(self.path)
        parts = [p for p in route.path.split("/") if p]

        if parts == ["health"]:
            return self._json(HTTPStatus.OK, {
                "status": "ok",
                "measurement": self.enclave.measurement,
                "started_utc": self.enclave.started_utc,
            })

        if parts == ["attestation"]:
            return self._attestation(parse_qs(route.query))

        if len(parts) == 2 and parts[0] == "jobs":
            return self._job_status(parts[1])

        if len(parts) == 3 and parts[0] == "jobs" and parts[2] == "result":
            return self._job_result(parts[1])

        return self._error(HTTPStatus.NOT_FOUND, "route inconnue")

    def do_POST(self) -> None:     # noqa: N802
        parts = [p for p in urlparse(self.path).path.split("/") if p]

        if parts == ["jobs"]:
            return self._upload()

        if len(parts) == 3 and parts[0] == "jobs" and parts[2] == "key":
            return self._receive_key(parts[1])

        return self._error(HTTPStatus.NOT_FOUND, "route inconnue")

    # -- Implementations ---------------------------------------------------

    def _attestation(self, query: dict) -> None:
        raw_nonce = (query.get("nonce") or [""])[0]
        try:
            nonce = bytes.fromhex(raw_nonce)
        except ValueError:
            return self._error(HTTPStatus.BAD_REQUEST, "nonce non hexadecimal")
        if len(nonce) < 16:
            return self._error(HTTPStatus.BAD_REQUEST,
                               "nonce trop court (16 octets minimum)")

        evidence, signature = self.enclave.attest(nonce)
        self._log(f"attestation demandee (nonce {nonce.hex()[:12]}...)")
        return self._json(HTTPStatus.OK, {
            "evidence": evidence.__dict__,
            "signature": signature.hex(),
        })

    def _upload(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._error(HTTPStatus.LENGTH_REQUIRED, "Content-Length requis")
        if length <= 0 or length > MAX_UPLOAD:
            return self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                               f"taille refusee ({length} octets)")

        job_id = uuid.uuid4().hex
        destination = self.store.directory / f"{job_id}.enc"
        chrono = Chrono()

        # Lecture en flux : un volume de plusieurs Go ne passe jamais
        # integralement en memoire.
        remaining = length
        try:
            with open(destination, "wb") as handle:
                while remaining > 0:
                    block = self.rfile.read(min(_READ_CHUNK, remaining))
                    if not block:
                        raise ConnectionError("flux interrompu")
                    handle.write(block)
                    remaining -= len(block)
        except Exception as exc:
            destination.unlink(missing_ok=True)
            return self._error(HTTPStatus.BAD_REQUEST, f"envoi incomplet : {exc}")

        # Controle minimal : est-ce bien un conteneur voltcrypt ?
        with open(destination, "rb") as handle:
            if handle.read(8) != crypto.MAGIC:
                destination.unlink(missing_ok=True)
                return self._error(HTTPStatus.BAD_REQUEST,
                                   "ce n'est pas un conteneur chiffre voltcrypt")

        self.store.create(job_id, destination, length)
        self._log(f"job {job_id[:8]} recu : {human_size(length)} en "
                  f"{human_duration(chrono.seconds)} — contenu illisible, "
                  f"en attente de cle")
        return self._json(HTTPStatus.CREATED, {"job_id": job_id, "size": length})

    def _receive_key(self, job_id: str) -> None:
        job = self.store.get(job_id)
        if job is None:
            return self._error(HTTPStatus.NOT_FOUND, "job inconnu")
        if job.state != "received":
            return self._error(HTTPStatus.CONFLICT,
                               f"job deja dans l'etat '{job.state}'")

        payload = self._read_json()
        if payload is None:
            return
        try:
            packet = bytes.fromhex(payload["wrapped_key"])
        except (KeyError, ValueError):
            return self._error(HTTPStatus.BAD_REQUEST, "champ wrapped_key invalide")

        # Le contexte lie la cle a CE job : un paquet destine a un autre job
        # ne s'ouvre pas ici.
        try:
            key = keyexchange.unwrap_key(packet, self.enclave.private_key,
                                         aad=job_id.encode("ascii"))
        except keyexchange.KeyExchangeError as exc:
            self._log(f"job {job_id[:8]} : cle refusee ({exc})")
            return self._error(HTTPStatus.BAD_REQUEST, f"cle illisible : {exc}")

        self._log(f"job {job_id[:8]} : cle recue, debut du traitement")
        chrono = Chrono()
        try:
            process_job(job, key, self.enclave)
        except Exception as exc:
            self._log(f"job {job_id[:8]} : ECHEC — {exc}")
            return self._error(HTTPStatus.UNPROCESSABLE_ENTITY, str(exc))
        finally:
            del key   # voir PIPELINE.md sur les limites de l'effacement en Python

        self._log(f"job {job_id[:8]} : termine en {human_duration(chrono.seconds)}, "
                  f"clair efface")
        return self._json(HTTPStatus.OK, {"state": job.state, "report": job.report})

    def _job_status(self, job_id: str) -> None:
        job = self.store.get(job_id)
        if job is None:
            return self._error(HTTPStatus.NOT_FOUND, "job inconnu")
        return self._json(HTTPStatus.OK, {
            "job_id": job.job_id,
            "state": job.state,
            "size": job.size,
            "created_utc": job.created_utc,
            "report": job.report,
            "error": job.error,
        })

    def _job_result(self, job_id: str) -> None:
        job = self.store.get(job_id)
        if job is None or job.result_path is None:
            return self._error(HTTPStatus.NOT_FOUND, "resultat indisponible")

        size = job.result_path.stat().st_size
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.end_headers()
        with open(job.result_path, "rb") as handle:
            shutil.copyfileobj(handle, self.wfile, _READ_CHUNK)

    # -- Utilitaires -------------------------------------------------------

    def _read_json(self) -> Optional[dict]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 1_000_000:
                raise ValueError("taille de corps invalide")
            return json.loads(self.rfile.read(length))
        except Exception as exc:
            self._error(HTTPStatus.BAD_REQUEST, f"corps JSON invalide : {exc}")
            return None

    def _json(self, status: HTTPStatus, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: HTTPStatus, message: str) -> None:
        self._json(status, {"error": message})

    def _log(self, message: str) -> None:
        if not self.quiet:
            stamp = datetime.now().strftime("%H:%M:%S")
            print(f"  [{stamp}] {message}", flush=True)

    def log_message(self, fmt: str, *args) -> None:
        """Journal HTTP par defaut : desactive, on log nous-memes."""
        return


def serve(host: str = config.SERVER_HOST, port: int = config.SERVER_PORT,
          storage: Optional[Path] = None, quiet: bool = False) -> ThreadingHTTPServer:
    """Construit le serveur (sans le demarrer). Voir main() pour l'usage direct."""
    config.ensure_dirs()
    enclave = Enclave(config.ATTESTATION_SIGNING_KEY)
    attestation.export_public_key(enclave.signing_key, config.TRUST_ROOT_PUBLIC_KEY)

    handler = type("BoundHandler", (Handler,), {
        "store": Store(storage or config.SERVER_STORAGE_DIR),
        "enclave": enclave,
        "quiet": quiet,
    })
    return ThreadingHTTPServer((host, port), handler)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default=config.SERVER_HOST)
    parser.add_argument("--port", type=int, default=config.SERVER_PORT)
    parser.add_argument("--storage", help="dossier des jobs recus")
    parser.add_argument("--measurement", action="store_true",
                        help="afficher la mesure du code et quitter")
    args = parser.parse_args(argv)

    if args.measurement:
        print(attestation.measure_code(MEASURED_FILES))
        return 0

    httpd = serve(args.host, args.port,
                  Path(args.storage) if args.storage else None)
    enclave = httpd.RequestHandlerClass.enclave

    print(f"Serveur de traitement — http://{args.host}:{args.port}")
    print(f"  mesure du code   : {enclave.measurement}")
    print(f"  cle publique     : {enclave.public_key.hex()[:32]}... (ephemere)")
    print(f"  racine de confiance publiee dans : {config.TRUST_ROOT_PUBLIC_KEY}")
    print(f"  jobs stockes dans : {httpd.RequestHandlerClass.store.directory}")
    print()
    print("  ATTENTION : racine de confiance SIMULEE, HTTP en clair.")
    print("  Demonstration de protocole — ne pas exposer sur un reseau.")
    print()
    print("  Ctrl-C pour arreter.")
    print()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nArret.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
