"""Les controles eux-memes. Chaque nom est la question qu'il pose.

Cinq familles, dans l'ordre du plan de developpement :

    canari       ce que le serveur detient avant la cle est-il illisible ?
    refus        la cle reste-t-elle a la maison quand quelque chose cloche ?
    ordre        une sequence interdite laisse-t-elle l'etat intact ?
    residence    combien de temps le clair existe-t-il, et disparait-il ?
    mesure       la mesure annoncee correspond-elle au code publie ?
"""

from __future__ import annotations

import secrets
import tempfile
from pathlib import Path

from voltcrypt import attestation, crypto, keyexchange, keys

from .battery import Battery, ProbeError, Verdict


def _canary_volume(directory: Path) -> Path:
    """Un volume qui se reconnait : contenu marque, nom de patient marque."""
    path = directory / Battery.MARKER_NAME
    path.write_bytes(Battery.MARKER_CONTENT + secrets.token_bytes(60_000))
    return path


def _upload_canary(battery: Battery, directory: Path) -> tuple[str, bytes]:
    plain = _canary_volume(directory)
    key = keys.generate_key()
    container = directory / "canary.enc"
    crypto.encrypt_file(plain, container, key)
    answer = battery._post_file("/jobs", container)
    return answer["job_id"], key


# -- 1. Canari -------------------------------------------------------------

def check_stored_bytes_are_unreadable(battery: Battery):
    """Ce que le serveur detient avant la cle contient-il quoi que ce soit
    de lisible : contenu, nom du patient, nom du fichier ?"""
    if battery.storage_dir is None:
        raise ProbeError("stockage non accessible depuis ici : "
                         "lancer la batterie sur la machine du serveur, "
                         "ou passer --storage")
    with tempfile.TemporaryDirectory() as tmp:
        job_id, _ = _upload_canary(battery, Path(tmp))

    leaks = []
    for path in sorted(battery.storage_dir.glob("*.enc")):
        blob = path.read_bytes()
        if Battery.MARKER_CONTENT in blob:
            leaks.append(f"{path.name} : contenu en clair")
        if b"DUPONT" in blob:
            leaks.append(f"{path.name} : nom du patient")
        if Battery.MARKER_NAME.encode() in blob:
            leaks.append(f"{path.name} : nom du fichier")

    if leaks:
        return Verdict.FAILED, "; ".join(leaks), {}
    return (Verdict.PASSED,
            f"job {job_id[:8]} stocke, aucun marqueur retrouve", {})


# -- 2. Refus --------------------------------------------------------------

def check_key_is_withheld_when_measurement_differs(battery: Battery):
    """Si le code annonce n'est pas celui attendu, la cle part-elle quand meme ?"""
    health = battery._get("/health")
    announced = health["measurement"]
    expected = "00" * 32

    if announced == expected:
        raise ProbeError("mesure de reference degeneree")

    # Le client verifie AVANT d'envoyer. On rejoue sa decision ici.
    nonce = secrets.token_bytes(16)
    answer = battery._get(f"/attestation?nonce={nonce.hex()}")
    evidence = attestation.Evidence(**answer["evidence"])

    would_send = evidence.measurement == expected
    return ((Verdict.FAILED if would_send else Verdict.PASSED),
            f"mesure annoncee {evidence.measurement[:16]}..., "
            f"attendue {expected[:16]}...",
            {"cle": "non transmise", "resultat": "aucun"})


def check_evidence_is_bound_to_the_nonce(battery: Battery):
    """Une attestation d'hier peut-elle servir aujourd'hui ?"""
    mine = secrets.token_bytes(16)
    answer = battery._get(f"/attestation?nonce={mine.hex()}")
    evidence = attestation.Evidence(**answer["evidence"])
    signature = bytes.fromhex(answer["signature"])

    server_key = bytes.fromhex(evidence.public_key)
    root = attestation.load_public_key(_trust_root())

    # Controle de sanite : sous SON nonce, l'evidence doit etre acceptee.
    # Sans lui, un refus generalise passerait pour une bonne nouvelle.
    try:
        attestation.verify_evidence(evidence, signature, root,
                                    expected_nonce=mine,
                                    expected_server_key=server_key)
    except attestation.AttestationError as exc:
        return (Verdict.FAILED,
                f"l'evidence est refusee sous son propre nonce : {exc}", {})

    other = secrets.token_bytes(16)
    try:
        attestation.verify_evidence(evidence, signature, root,
                                    expected_nonce=other,
                                    expected_server_key=server_key)
    except attestation.AttestationError:
        return (Verdict.PASSED,
                "acceptee sous son nonce, refusee sous un autre",
                {"cle": "non transmise"})
    return (Verdict.FAILED,
            "une evidence est acceptee sous un nonce qui n'est pas le sien", {})


def check_wrapped_key_never_contains_the_key(battery: Battery):
    """La cle circule-t-elle en clair sur le reseau ?"""
    _, public = keyexchange.generate_recipient_keypair()
    key = keys.generate_key()
    packet = keyexchange.wrap_key(key, public, aad=b"job")
    if key in packet:
        return Verdict.FAILED, "la cle apparait telle quelle dans le paquet", {}
    return (Verdict.PASSED, f"paquet de {len(packet)} octets, cle absente",
            {"cle": "jamais en clair sur le reseau"})


def check_key_is_bound_to_its_job(battery: Battery):
    """Une cle interceptee sur un job sert-elle sur un autre ?"""
    with tempfile.TemporaryDirectory() as tmp:
        first, key = _upload_canary(battery, Path(tmp))
        second, _ = _upload_canary(battery, Path(tmp))

    health = battery._get("/health")
    nonce = secrets.token_bytes(16)
    answer = battery._get(f"/attestation?nonce={nonce.hex()}")
    server_public = bytes.fromhex(answer["evidence"]["public_key"])

    # Cle enveloppee POUR LE PREMIER job, presentee au second.
    packet = keyexchange.wrap_key(key, server_public, aad=first.encode("ascii"))
    try:
        battery._post_json(f"/jobs/{second}/key", {"wrapped_key": packet.hex()})
    except ProbeError:
        state = battery._get(f"/jobs/{second}")["state"]
        return ((Verdict.PASSED if state == "received" else Verdict.FAILED),
                f"cle du job {first[:8]} refusee sur {second[:8]}, "
                f"etat reste '{state}'",
                {"etat du job vise": state, "resultat": "aucun"})
    return (Verdict.FAILED,
            "une cle destinee a un autre job a ete acceptee", {})


# -- 3. Ordre --------------------------------------------------------------

def check_a_key_cannot_be_replayed_on_the_same_job(battery: Battery):
    """La meme cle, deux fois : le traitement repart-il ?"""
    health = battery._get("/health")
    with tempfile.TemporaryDirectory() as tmp:
        job_id, key = _upload_canary(battery, Path(tmp))

    nonce = secrets.token_bytes(16)
    answer = battery._get(f"/attestation?nonce={nonce.hex()}")
    server_public = bytes.fromhex(answer["evidence"]["public_key"])
    packet = keyexchange.wrap_key(key, server_public, aad=job_id.encode("ascii"))

    battery._post_json(f"/jobs/{job_id}/key", {"wrapped_key": packet.hex()})
    first_state = battery._get(f"/jobs/{job_id}")["state"]

    try:
        battery._post_json(f"/jobs/{job_id}/key", {"wrapped_key": packet.hex()})
    except ProbeError:
        after = battery._get(f"/jobs/{job_id}")["state"]
        return ((Verdict.PASSED if after == first_state else Verdict.FAILED),
                f"seconde remise refusee, etat inchange ('{after}')",
                {"etat": after})
    return Verdict.FAILED, "la cle a ete acceptee deux fois", {}


def check_result_does_not_exist_before_the_key(battery: Battery):
    """Un resultat peut-il exister avant que la cle soit remise ?"""
    with tempfile.TemporaryDirectory() as tmp:
        job_id, _ = _upload_canary(battery, Path(tmp))

    try:
        battery._get(f"/jobs/{job_id}/result")
    except ProbeError:
        state = battery._get(f"/jobs/{job_id}")["state"]
        return ((Verdict.PASSED if state == "received" else Verdict.FAILED),
                f"aucun resultat disponible, etat '{state}'",
                {"resultat": "aucun"})
    return (Verdict.FAILED,
            "un resultat est servi alors que la cle n'a pas ete remise", {})


# -- 4. Residence ----------------------------------------------------------

def check_plaintext_residency_is_bounded_and_reported(battery: Battery):
    """Combien de temps le clair a-t-il existe, et le serveur le dit-il ?"""
    with tempfile.TemporaryDirectory() as tmp:
        job_id, key = _upload_canary(battery, Path(tmp))

    nonce = secrets.token_bytes(16)
    answer = battery._get(f"/attestation?nonce={nonce.hex()}")
    server_public = bytes.fromhex(answer["evidence"]["public_key"])
    packet = keyexchange.wrap_key(key, server_public, aad=job_id.encode("ascii"))
    battery._post_json(f"/jobs/{job_id}/key", {"wrapped_key": packet.hex()})

    status = battery._get(f"/jobs/{job_id}")
    residency = status.get("plaintext_residency_seconds")
    if residency is None:
        return (Verdict.FAILED,
                "le serveur ne declare pas la duree de residence du clair", {})

    backing = status.get("report", {}).get("workdir_backing", "inconnu")
    return (Verdict.PASSED,
            f"clair present {residency} s, support « {backing} »",
            {"repertoire de travail": "detruit"})


# -- 5. Mesure -------------------------------------------------------------

def check_announced_measurement_matches_the_published_manifest(battery: Battery):
    """La mesure annoncee est-elle reconstituable depuis le manifeste publie ?

    C'est le controle qui permet a un SITE de verifier un deploiement qu'il
    n'a pas construit : il recalcule le digest a partir des entrees publiees
    et le compare a ce que /health annonce.
    """
    health = battery._get("/health")
    manifest = battery._get("/manifest")

    from cryptoserve.measure import Manifest, ManifestEntry

    rebuilt = Manifest(entries=[ManifestEntry(**entry)
                                for entry in manifest["entries"]])
    if rebuilt.digest != manifest["digest"]:
        return (Verdict.FAILED,
                "le manifeste publie ne redonne pas son propre digest", {})
    if manifest["digest"] != health["measurement"]:
        return (Verdict.FAILED,
                f"/health annonce {health['measurement'][:16]}... "
                f"mais le manifeste vaut {manifest['digest'][:16]}...", {})

    kinds = {entry["kind"] for entry in manifest["entries"]}
    missing = {"boundary", "runner"} - kinds
    if missing:
        return (Verdict.FAILED,
                f"la mesure ne couvre pas : {', '.join(sorted(missing))}. "
                "Le code qui lit le clair est hors perimetre.", {})

    return (Verdict.PASSED,
            f"{len(manifest['entries'])} entrees, digest reconstitue, "
            f"frontiere et runner couverts", {})


def _trust_root() -> Path:
    from voltcrypt import config
    return config.TRUST_ROOT_PUBLIC_KEY


#: L'ordre d'execution. Il compte : le canari doit passer avant les controles
#: qui remplissent le stockage de jobs traites.
ALL_CHECKS = [
    (check_stored_bytes_are_unreadable,
     "Ce que le serveur detient avant la cle est-il illisible ?"),
    (check_announced_measurement_matches_the_published_manifest,
     "La mesure annoncee est-elle reconstituable, et couvre-t-elle le clair ?"),
    (check_key_is_withheld_when_measurement_differs,
     "Un code inattendu obtient-il la cle ?"),
    (check_evidence_is_bound_to_the_nonce,
     "Une ancienne attestation peut-elle etre rejouee ?"),
    (check_wrapped_key_never_contains_the_key,
     "La cle circule-t-elle en clair sur le reseau ?"),
    (check_key_is_bound_to_its_job,
     "Une cle sert-elle sur un autre job que le sien ?"),
    (check_a_key_cannot_be_replayed_on_the_same_job,
     "Une cle rejouee relance-t-elle un traitement ?"),
    (check_result_does_not_exist_before_the_key,
     "Un resultat existe-t-il avant la remise de la cle ?"),
    (check_plaintext_residency_is_bounded_and_reported,
     "Combien de temps le clair existe-t-il, et le serveur le declare-t-il ?"),
]


def run_all(battery: Battery) -> Battery:
    for function, question in ALL_CHECKS:
        battery._record(function.__name__, question,
                        lambda f=function: f(battery))
    return battery
