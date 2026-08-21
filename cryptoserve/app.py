"""Les routes HTTP. Ce module ne voit jamais de clair.

Il deplace des conteneurs chiffres, decide a qui la cle est livree, et delegue
tout le reste : la garde des cles a `enclave`, les transitions a `jobs`, et le
traitement a `boundary`, seul autorise a dechiffrer.

Deroulement d'un job :

    POST /jobs                 le volume chiffre arrive. Le serveur le stocke
                               tel quel. A ce stade il ne sait meme pas quel
                               est le nom du fichier d'origine.
    GET  /attestation?nonce=   le client demande une preuve. Le serveur mesure
                               son propre code et signe l'ensemble.
    POST /jobs/<id>/key        si le client a ete convaincu, il envoie la cle,
                               chiffree pour la cle publique ephemere du
                               serveur. La frontiere dechiffre en memoire,
                               traite, rechiffre, efface.
    GET  /jobs/<id>/result     le resultat, chiffre.

Limites assumees de cette demo : HTTP en clair (voir PIPELINE.md), stockage
des jobs sur disque, et racine de confiance logicielle. Ce n'est pas un
serveur de production.
"""

from __future__ import annotations

import json
import shutil
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

from voltcrypt import attestation, config, crypto, keyexchange
from voltcrypt.timing import Chrono, human_duration, human_size

from . import boundary
from .enclave import Enclave
from .jobs import JobState, Store, TransitionError
from .runners import IdentityRunner

#: Taille maximale acceptee pour un envoi (4 Gio).
MAX_UPLOAD = 4 * 1024 * 1024 * 1024

_READ_CHUNK = 1024 * 1024


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
                "runner": self.enclave.runner.name,
                "started_utc": self.enclave.started_utc,
            })

        if parts == ["manifest"]:
            return self._json(HTTPStatus.OK, self.enclave.manifest.to_dict())

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
                  f"{human_duration(chrono.seconds)}, contenu illisible, "
                  f"en attente de cle")
        return self._json(HTTPStatus.CREATED, {"job_id": job_id, "size": length})

    def _receive_key(self, job_id: str) -> None:
        if self.store.get(job_id) is None:
            return self._error(HTTPStatus.NOT_FOUND, "job inconnu")

        payload = self._read_json()
        if payload is None:
            return
        try:
            packet = bytes.fromhex(payload["wrapped_key"])
        except (KeyError, ValueError):
            return self._error(HTTPStatus.BAD_REQUEST, "champ wrapped_key invalide")

        # Reservation avant tout travail : deux cles concurrentes sur le meme
        # job ne peuvent pas lancer deux traitements, et une cle rejouee
        # trouve un job qui n'est plus en RECEIVED.
        try:
            job = self.store.claim(job_id)
        except TransitionError:
            current = self.store.get(job_id)
            return self._error(HTTPStatus.CONFLICT,
                               f"job deja dans l'etat '{current.state.value}'")
        if job is None:
            return self._error(HTTPStatus.NOT_FOUND, "job inconnu")

        # Le contexte lie la cle a CE job : un paquet destine a un autre job
        # ne s'ouvre pas ici.
        try:
            key = keyexchange.unwrap_key(packet, self.enclave.private_key,
                                         aad=job_id.encode("ascii"))
        except keyexchange.KeyExchangeError as exc:
            job.state = JobState.RECEIVED   # rien n'a ete fait, on rend le job
            self._log(f"job {job_id[:8]} : cle refusee ({exc})")
            return self._error(HTTPStatus.BAD_REQUEST, f"cle illisible : {exc}")

        self._log(f"job {job_id[:8]} : cle recue, debut du traitement")
        chrono = Chrono()
        try:
            outcome = boundary.process(job, key, self.enclave.runner)
        except Exception as exc:
            job.to(JobState.FAILED)
            job.error = str(exc)
            self._log(f"job {job_id[:8]} : ECHEC, {exc}")
            return self._error(HTTPStatus.UNPROCESSABLE_ENTITY, str(exc))
        finally:
            del key   # voir PIPELINE.md sur les limites de l'effacement en Python

        job.result_path = outcome.result_path
        job.report = outcome.report
        job.plaintext_residency_seconds = outcome.residency_seconds
        job.to(JobState.DONE)

        self._log(f"job {job_id[:8]} : termine en {human_duration(chrono.seconds)}, "
                  f"clair efface apres "
                  f"{human_duration(outcome.residency_seconds)} "
                  f"({outcome.workdir_backing})")
        return self._json(HTTPStatus.OK,
                          {"state": job.state.value, "report": job.report})

    def _job_status(self, job_id: str) -> None:
        job = self.store.get(job_id)
        if job is None:
            return self._error(HTTPStatus.NOT_FOUND, "job inconnu")
        return self._json(HTTPStatus.OK, job.public())

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
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("objet JSON attendu")
            return payload
        except Exception as exc:
            self._error(HTTPStatus.BAD_REQUEST, f"corps invalide : {exc}")
            return None

    def _json(self, status: HTTPStatus, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: HTTPStatus, message: str) -> None:
        self._json(status, {"error": message})

    def _log(self, message: str) -> None:
        if not self.quiet:
            print(f"  [serveur] {message}", flush=True)

    def log_message(self, fmt: str, *args) -> None:
        """Silence le journal par defaut de la stdlib."""
        return


def serve(host: str = config.SERVER_HOST, port: int = config.SERVER_PORT,
          storage: Optional[Path] = None, quiet: bool = False,
          runner=None) -> ThreadingHTTPServer:
    """Construit le serveur (sans le demarrer). Voir main() pour l'usage direct."""
    config.ensure_dirs()
    runner = runner if runner is not None else IdentityRunner()
    enclave = Enclave(config.ATTESTATION_SIGNING_KEY, runner)
    attestation.export_public_key(enclave.signing_key, config.TRUST_ROOT_PUBLIC_KEY)

    handler = type("BoundHandler", (Handler,), {
        "store": Store(Path(storage) if storage is not None
                       else config.SERVER_STORAGE_DIR),
        "enclave": enclave,
        "quiet": quiet,
    })
    return ThreadingHTTPServer((host, port), handler)
