#!/usr/bin/env python3
"""Client du pipeline — le poste clinique.

    python client.py data/to_encrypt/scan.nii.gz
    python client.py mon_volume.vtk --server http://127.0.0.1:8000
    python client.py mon_volume.vtk --trust-on-first-use     # 1re utilisation

Les 7 etapes, dans l'ordre ou elles se produisent :

    1. chiffrement local, avec une cle tiree pour CE volume uniquement
    2. envoi du fichier chiffre       <- le serveur ne peut rien en faire
    3. demande d'attestation, avec un nonce aleatoire
    4. VERIFICATION de l'attestation  <- si elle echoue, on s'arrete ICI
                                         et la cle n'est jamais transmise
    5. envoi de la cle, chiffree pour la cle publique attestee du serveur
    6. recuperation du resultat chiffre
    7. dechiffrement local et comparaison avec l'original

L'etape 4 est le coeur du dispositif : c'est le seul moment ou l'on decide de
faire confiance, et cette decision repose sur une preuve verifiable, pas sur
l'adresse du serveur.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Optional
from urllib import error, request

from voltcrypt import attestation, config, crypto, keys, keyexchange
from voltcrypt.timing import Chrono, human_duration, human_size, human_speed

NONCE_SIZE = 32
TIMEOUT = 300


class PipelineError(Exception):
    """Le pipeline s'est arrete. Le message dit a quelle etape et pourquoi."""


# ---------------------------------------------------------------------------
# Appels HTTP
# ---------------------------------------------------------------------------

def _get_json(url: str) -> dict:
    try:
        with request.urlopen(url, timeout=TIMEOUT) as response:
            return json.loads(response.read())
    except error.HTTPError as exc:
        raise PipelineError(f"{url} -> {exc.code} {_extract(exc)}") from exc
    except error.URLError as exc:
        raise PipelineError(
            f"serveur injoignable ({exc.reason}).\n"
            f"       Demarre-le avec :  python server.py") from exc


def _post_json(url: str, payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=body, method="POST",
                          headers={"Content-Type": "application/json"})
    try:
        with request.urlopen(req, timeout=TIMEOUT) as response:
            return json.loads(response.read())
    except error.HTTPError as exc:
        raise PipelineError(f"{url} -> {exc.code} {_extract(exc)}") from exc


def _post_file(url: str, path: Path) -> dict:
    """Envoi en flux : le fichier n'est jamais charge entierement en memoire."""
    size = path.stat().st_size
    with open(path, "rb") as handle:
        req = request.Request(url, data=handle, method="POST", headers={
            "Content-Type": "application/octet-stream",
            "Content-Length": str(size),
        })
        try:
            with request.urlopen(req, timeout=TIMEOUT) as response:
                return json.loads(response.read())
        except error.HTTPError as exc:
            raise PipelineError(f"{url} -> {exc.code} {_extract(exc)}") from exc


def _download(url: str, destination: Path) -> Path:
    try:
        with request.urlopen(url, timeout=TIMEOUT) as response, \
                open(destination, "wb") as handle:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                handle.write(block)
    except error.HTTPError as exc:
        raise PipelineError(f"{url} -> {exc.code} {_extract(exc)}") from exc
    return destination


def _extract(exc: error.HTTPError) -> str:
    try:
        return json.loads(exc.read()).get("error", "")
    except Exception:
        return exc.reason or ""


# ---------------------------------------------------------------------------
# Le pipeline
# ---------------------------------------------------------------------------

def run(
    source: Path,
    server: str,
    output_dir: Path,
    expected_measurement: Optional[str],
    trust_on_first_use: bool = False,
    verbose: bool = True,
) -> dict:
    """Execute les 7 etapes. Retourne un rapport."""
    def say(message: str = "") -> None:
        if verbose:
            print(message, flush=True)

    source = Path(source)
    if not source.is_file():
        raise PipelineError(f"fichier introuvable : {source}")

    workdir = Path(tempfile.mkdtemp(prefix="voltcrypt_client_"))
    total = Chrono()
    try:
        # --- 1. Chiffrement local -----------------------------------------
        say(f"[1/7] Chiffrement local de {source.name}")
        job_key = keys.generate_key()          # une cle pour CE volume
        encrypted = workdir / (source.name + config.ENCRYPTED_SUFFIX)
        timing = crypto.encrypt_file(source, encrypted, job_key)
        original_digest = _sha256(source)
        say(f"      {human_size(timing.size)} chiffres en "
            f"{human_duration(timing.seconds)} "
            f"({human_speed(timing.size, timing.seconds)})")
        say(f"      sha256 original : {original_digest[:32]}...")

        # --- 2. Envoi du volume chiffre -----------------------------------
        say(f"[2/7] Envoi vers {server}")
        chrono = Chrono()
        created = _post_file(f"{server}/jobs", encrypted)
        job_id = created["job_id"]
        sent = encrypted.stat().st_size
        say(f"      job {job_id[:8]} cree — {human_size(sent)} transferes en "
            f"{human_duration(chrono.seconds)} "
            f"({human_speed(sent, chrono.seconds)})")
        say("      le serveur detient un fichier qu'il ne peut pas lire")

        # --- 3. Demande d'attestation -------------------------------------
        nonce = os.urandom(NONCE_SIZE)
        say(f"[3/7] Demande d'attestation (nonce {nonce.hex()[:12]}...)")
        answer = _get_json(f"{server}/attestation?nonce={nonce.hex()}")
        evidence = attestation.Evidence(**answer["evidence"])
        signature = bytes.fromhex(answer["signature"])
        server_key = bytes.fromhex(evidence.public_key)
        say(f"      mesure annoncee : {evidence.measurement[:32]}...")

        # --- 4. Verification ----------------------------------------------
        say("[4/7] Verification de l'attestation")
        if expected_measurement is None:
            if not trust_on_first_use:
                raise PipelineError(
                    "aucune mesure de reference connue.\n"
                    "       Le serveur pourrait executer n'importe quel code.\n"
                    "       Fournis --expect <mesure>, ou accepte celle-ci avec\n"
                    "       --trust-on-first-use (a ne faire qu'en environnement sur).")
            expected_measurement = evidence.measurement
            _remember_measurement(expected_measurement)
            say(f"      PREMIERE UTILISATION : mesure enregistree dans "
                f"{config.EXPECTED_MEASUREMENT_FILE.name}")

        root = attestation.load_public_key(config.TRUST_ROOT_PUBLIC_KEY)
        policy = attestation.Policy(expected_measurement=expected_measurement)
        try:
            attestation.verify_evidence(
                evidence, signature, root,
                expected_nonce=nonce,
                expected_server_key=server_key,
                policy=policy,
            )
        except attestation.AttestationError as exc:
            raise PipelineError(
                f"ATTESTATION REFUSEE — {exc}\n"
                f"       La cle n'a PAS ete transmise. Le serveur conserve un\n"
                f"       fichier chiffre qu'il ne peut pas exploiter.") from exc

        say("      signature valide, nonce correspondant, cle publique liee")
        say("      mesure du code conforme, politique acceptee")

        # --- 5. Remise de la cle ------------------------------------------
        say("[5/7] Remise de la cle, chiffree pour le serveur atteste")
        packet = keyexchange.wrap_key(job_key, server_key,
                                      aad=job_id.encode("ascii"))
        processed = _post_json(f"{server}/jobs/{job_id}/key",
                               {"wrapped_key": packet.hex()})
        report = processed.get("report", {})
        say(f"      traitement termine cote serveur : "
            f"{report.get('processing', '?')}")

        # --- 6. Recuperation ----------------------------------------------
        say("[6/7] Recuperation du resultat")
        chrono = Chrono()
        result_enc = _download(f"{server}/jobs/{job_id}/result",
                               workdir / "result.enc")
        say(f"      {human_size(result_enc.stat().st_size)} recus en "
            f"{human_duration(chrono.seconds)}")

        # --- 7. Dechiffrement et verification ------------------------------
        say("[7/7] Dechiffrement local et verification")
        output_dir.mkdir(parents=True, exist_ok=True)
        final = output_dir / source.name
        timing = crypto.decrypt_file(result_enc, final, job_key)
        final_digest = _sha256(final)
        identical = final_digest == original_digest
        say(f"      {final}")
        say(f"      sha256 restitue : {final_digest[:32]}...")
        say(f"      identique a l'original : {'OUI' if identical else 'NON'}")

        return {
            "job_id": job_id,
            "output": final,
            "identical": identical,
            "original_sha256": original_digest,
            "result_sha256": final_digest,
            "server_report": report,
            "total_seconds": total.seconds,
        }
    finally:
        # Le clair intermediaire et la copie chiffree locale disparaissent.
        for item in workdir.glob("*"):
            item.unlink(missing_ok=True)
        workdir.rmdir()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _remember_measurement(measurement: str) -> None:
    config.TRUST_DIR.mkdir(parents=True, exist_ok=True)
    config.EXPECTED_MEASUREMENT_FILE.write_text(measurement + "\n", encoding="utf-8")


def _known_measurement() -> Optional[str]:
    if config.EXPECTED_MEASUREMENT_FILE.exists():
        return config.EXPECTED_MEASUREMENT_FILE.read_text(encoding="utf-8").strip() or None
    return None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("file", help="volume a traiter")
    parser.add_argument("--server", default=f"http://{config.SERVER_HOST}:{config.SERVER_PORT}")
    parser.add_argument("--output", "-o", help="ou ecrire le resultat "
                                               "(defaut : data/decrypted)")
    parser.add_argument("--expect", help="mesure de code attendue (hex)")
    parser.add_argument("--trust-on-first-use", action="store_true",
                        help="accepter et enregistrer la mesure annoncee "
                             "(premiere utilisation uniquement)")
    args = parser.parse_args(argv)

    config.ensure_dirs()
    expected = args.expect or _known_measurement()
    output = Path(args.output) if args.output else config.DECRYPTED_DIR

    try:
        result = run(Path(args.file), args.server.rstrip("/"), output,
                     expected, trust_on_first_use=args.trust_on_first_use)
    except PipelineError as exc:
        print(f"\n[!] {exc}", file=sys.stderr)
        return 1

    print()
    if result["identical"]:
        print(f"[ok] Aller-retour complet en "
              f"{human_duration(result['total_seconds'])} — "
              f"le fichier restitue est identique a l'original.")
        return 0
    print("[!] Le fichier restitue DIFFERE de l'original.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
