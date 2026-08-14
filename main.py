#!/usr/bin/env python3
"""Point d'entree en ligne de commande de voltcrypt.

Usage typique :

    python main.py gen-key                 # 1. genere data/keys/master.key
    python main.py encrypt                 # 2. data/to_encrypt -> data/encrypted
    python main.py decrypt                 # 3. data/encrypted  -> data/decrypted
    python main.py list                    #    inspecte les .enc
    python main.py check                   #    verifie que tout est dechiffrable
    python main.py audit                   #    prouve que le chiffrement est effectif

Toutes les commandes acceptent --key, --input et --output pour sortir des
dossiers par defaut definis dans voltcrypt/config.py.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from voltcrypt import audit, batch, config, crypto, keys, timing


# ---------------------------------------------------------------------------
# Commandes
# ---------------------------------------------------------------------------

def cmd_gen_key(args) -> int:
    path = Path(args.key)
    try:
        key = keys.generate_key()
        keys.save_key(key, path, label=args.label, overwrite=args.overwrite)
    except FileExistsError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        print("    Utilise --overwrite si tu es certain de vouloir la remplacer.",
              file=sys.stderr)
        return 1

    print(f"[ok] Cle AES-256 generee : {path}")
    print("     Permissions 0600 (lisible par toi seul).")
    print()
    print("     ATTENTION : cette cle est le SEUL moyen de relire tes fichiers.")
    print("     Sauvegarde-la ailleurs (gestionnaire de mots de passe, HSM,")
    print("     cle USB hors ligne). Ne la mets JAMAIS dans un depot git.")
    return 0


def cmd_encrypt(args) -> int:
    key = _load_key(args.key)
    if key is None:
        return 1
    src = Path(args.input or config.PLAIN_DIR)
    dst = Path(args.output or config.ENCRYPTED_DIR)
    extensions = config.VOLUME_EXTENSIONS if args.only_volumes else None

    print(f"Chiffrement  {src}  ->  {dst}")
    result = batch.encrypt_directory(
        src, dst, key,
        recursive=not args.no_recursive,
        extensions=extensions,
        overwrite=args.overwrite,
    )
    return _report(result, src)


def cmd_decrypt(args) -> int:
    key = _load_key(args.key)
    if key is None:
        return 1
    src = Path(args.input or config.ENCRYPTED_DIR)
    dst = Path(args.output or config.DECRYPTED_DIR)

    print(f"Dechiffrement  {src}  ->  {dst}")
    result = batch.decrypt_directory(
        src, dst, key,
        recursive=not args.no_recursive,
        overwrite=args.overwrite,
    )
    return _report(result, src)


def cmd_list(args) -> int:
    key = _load_key(args.key)
    if key is None:
        return 1
    src = Path(args.input or config.ENCRYPTED_DIR)

    files = list(batch.iter_files(src, extensions=[config.ENCRYPTED_SUFFIX]))
    if not files:
        print(f"Aucun fichier {config.ENCRYPTED_SUFFIX} dans {src}")
        return 0

    print(f"{len(files)} fichier(s) dans {src} :\n")
    print(f"  {'FICHIER CHIFFRE':<40} {'NOM D ORIGINE':<32} {'TAILLE'}")
    for path in files:
        try:
            meta = crypto.read_metadata(path, key)
            print(f"  {path.relative_to(src).as_posix():<40} "
                  f"{meta['name']:<32} {meta['size']:,} o")
        except Exception as exc:
            print(f"  {path.relative_to(src).as_posix():<40} !! {exc}")
    return 0


def cmd_check(args) -> int:
    """Dechiffre tout en memoire sans rien ecrire : verifie cle + integrite."""
    key = _load_key(args.key)
    if key is None:
        return 1
    src = Path(args.input or config.ENCRYPTED_DIR)

    files = list(batch.iter_files(src, extensions=[config.ENCRYPTED_SUFFIX]))
    if not files:
        print(f"Aucun fichier {config.ENCRYPTED_SUFFIX} dans {src}")
        return 0

    import os
    import tempfile

    failures = 0
    total_size = 0
    chrono = timing.Chrono()
    for path in files:
        name = path.relative_to(src).as_posix()
        tmp = Path(tempfile.gettempdir()) / f"voltcrypt_check_{os.getpid()}.tmp"
        try:
            result = crypto.decrypt_file(path, tmp, key)
            total_size += result.size
            print(f"  ok   {name}  ({timing.human_duration(result.seconds)})")
        except Exception as exc:
            failures += 1
            print(f"  FAIL {exc}")   # le message porte deja le nom du fichier
        finally:
            tmp.unlink(missing_ok=True)

    print()
    print(f"Duree : {timing.human_size(total_size)} verifie(s) en "
          f"{timing.human_duration(chrono.seconds)} "
          f"({timing.human_speed(total_size, chrono.seconds)})")
    if failures:
        print(f"[!] {failures}/{len(files)} fichier(s) illisible(s).")
        return 1
    print(f"[ok] {len(files)} fichier(s) dechiffrable(s) et intact(s).")
    return 0


def cmd_audit(args) -> int:
    """Controles positifs : le contenu est-il vraiment devenu indechiffrable ?"""
    key = _load_key(args.key)
    if key is None:
        return 1
    src = Path(args.input or config.ENCRYPTED_DIR)
    plain_dir = Path(args.plain) if args.plain else Path(config.PLAIN_DIR)

    files = list(batch.iter_files(src, extensions=[config.ENCRYPTED_SUFFIX]))
    if not files:
        print(f"Aucun fichier {config.ENCRYPTED_SUFFIX} dans {src}")
        return 0

    print(f"Audit de {len(files)} conteneur(s) dans {src}\n")
    failed = 0
    compared = 0
    for path in files:
        relative = path.relative_to(src)
        # Si l'original est encore la, on peut faire les controles les plus forts.
        guess = plain_dir / relative.parent / relative.name[: -len(config.ENCRYPTED_SUFFIX)]
        plain = guess if guess.is_file() else None
        if plain:
            compared += 1

        report = audit.audit_container(path, key, plain_path=plain)
        print(report)
        if not report.passed:
            failed += 1

    print()
    if compared:
        print(f"({compared}/{len(files)} compare(s) a leur original dans {plain_dir})")
    if failed:
        print(f"[!] {failed}/{len(files)} conteneur(s) ont echoue a au moins un controle.")
        return 1
    print(f"[ok] Les {len(files)} conteneur(s) passent tous les controles.")
    print("     Rappel : chiffre n'est pas anonymise. Qui detient la cle lit les donnees.")
    return 0


# ---------------------------------------------------------------------------
# Utilitaires
# ---------------------------------------------------------------------------

def _load_key(path):
    try:
        return keys.load_key(path)
    except keys.KeyError_ as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return None


def _report(result: batch.BatchResult, src: Path) -> int:
    if len(result) == 0:
        print(f"\nAucun fichier trouve dans {src}")
        print("Depose tes volumes dedans, puis relance la commande.")
        return 0
    print(f"\n{result.summary()}")
    if result.succeeded:
        print(f"Duree : {result.timing_summary()}")
    for failure in result.failed:
        print(f"  ECHEC {failure.source.name} : {failure.error}", file=sys.stderr)
    return 1 if result.failed else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="voltcrypt",
        description="Chiffrement AES-256-GCM de fichiers volumiques (.vtk, .nii, .nrrd, ...)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p, with_io=True):
        p.add_argument("--key", default=str(config.DEFAULT_KEY_PATH),
                       help=f"chemin de la cle (defaut : {config.DEFAULT_KEY_PATH})")
        if with_io:
            p.add_argument("--input", "-i", help="dossier d'entree")
            p.add_argument("--output", "-o", help="dossier de sortie")
            p.add_argument("--overwrite", action="store_true",
                           help="ecraser les fichiers de sortie existants")
            p.add_argument("--no-recursive", action="store_true",
                           help="ne pas descendre dans les sous-dossiers")
        return p

    p = sub.add_parser("gen-key", help="generer une nouvelle cle AES-256")
    p.add_argument("--key", default=str(config.DEFAULT_KEY_PATH),
                   help=f"ou ecrire la cle (defaut : {config.DEFAULT_KEY_PATH})")
    p.add_argument("--label", default="", help="commentaire libre stocke dans le fichier")
    p.add_argument("--overwrite", action="store_true",
                   help="remplacer une cle existante (DANGEREUX)")
    p.set_defaults(func=cmd_gen_key)

    p = common(sub.add_parser("encrypt", help="chiffrer un dossier"))
    p.add_argument("--only-volumes", action="store_true",
                   help="ne chiffrer que les extensions de config.VOLUME_EXTENSIONS")
    p.set_defaults(func=cmd_encrypt)

    p = common(sub.add_parser("decrypt", help="dechiffrer un dossier"))
    p.set_defaults(func=cmd_decrypt)

    p = common(sub.add_parser("list", help="lister le contenu des .enc"), with_io=False)
    p.add_argument("--input", "-i", help="dossier des fichiers chiffres")
    p.set_defaults(func=cmd_list)

    p = common(sub.add_parser("check", help="verifier l integrite des .enc"), with_io=False)
    p.add_argument("--input", "-i", help="dossier des fichiers chiffres")
    p.set_defaults(func=cmd_check)

    p = common(sub.add_parser("audit", help="prouver que le chiffrement est effectif"),
               with_io=False)
    p.add_argument("--input", "-i", help="dossier des fichiers chiffres")
    p.add_argument("--plain", help="dossier des originaux, pour les controles les "
                                   "plus stricts (defaut : data/to_encrypt)")
    p.set_defaults(func=cmd_audit)

    return parser


def main(argv=None) -> int:
    config.ensure_dirs()
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
