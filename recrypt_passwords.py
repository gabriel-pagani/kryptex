"""
Recriptografa os passwords armazenados em app.models.Logins.password quando você
muda SALT / PBKDF2 iterations (e/ou a senha mestra).

Compatível com a lógica do frontend em [static/js/index.js](static/js/index.js):
- PBKDF2-HMAC-SHA256
- salt = TextEncoder().encode(SALT)  (ou seja: bytes UTF-8 do *texto* do SALT)
- AES-GCM 256
- iv de 12 bytes
- payload salvo como JSON: {"iv": base64(bytes), "data": base64(bytes)}

Uso (exemplos):
  python app/utils/recrypt_passwords.py --old-salt "..." --old-iters 100000 --new-salt "..." --new-iters 200000 --dry-run
  python app/utils/recrypt_passwords.py --old-salt "..." --old-iters 100000 --new-salt "..." --new-iters 200000 --commit
  python app/utils/recrypt_passwords.py --old-salt "..." --old-iters 100000 --new-salt "..." --new-iters 200000 --new-master "novaSenha" --commit

Notas:
- Você PRECISA conhecer a senha mestra (antiga) para descriptografar.
- Por padrão, o script pede a senha mestra via prompt (getpass).
- Não imprime senhas em texto puro.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from dataclasses import dataclass
from getpass import getpass
from typing import Optional

# --- Django bootstrap ---
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "project.settings")

try:
    import django  # type: ignore
    django.setup()
except Exception as e:
    print(f"[ERRO] Falha ao inicializar o Django: {e}", file=sys.stderr)
    raise

from django.db import transaction  # type: ignore
from app.models import Logins  # type: ignore


# --- Crypto primitives (Python) ---
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # type: ignore
    from cryptography.hazmat.primitives import hashes  # type: ignore
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
except Exception as e:
    raise SystemExit(
        "[ERRO] Dependência 'cryptography' não disponível. "
        "Instale/adicione ao requirements e tente novamente.\n"
        f"Detalhes: {e}"
    )


@dataclass(frozen=True)
class CryptoParams:
    salt_text: str
    iterations: int
    master_password: str

    def derive_key_32(self) -> bytes:
        # IMPORTANTE: frontend usa TextEncoder().encode(SALT), então aqui é UTF-8 do texto.
        salt_bytes = self.salt_text.encode("utf-8")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=int(self.iterations),
        )
        return kdf.derive(self.master_password.encode("utf-8"))


def _b64encode_bytes(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64decode_to_bytes(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def decrypt_payload(encrypted_json_str: str, params: CryptoParams) -> str:
    obj = json.loads(encrypted_json_str)
    iv = _b64decode_to_bytes(obj["iv"])
    data = _b64decode_to_bytes(obj["data"])

    key = params.derive_key_32()
    aesgcm = AESGCM(key)
    plain = aesgcm.decrypt(iv, data, None)
    return plain.decode("utf-8")


def encrypt_payload(plain_text: str, params: CryptoParams) -> str:
    iv = os.urandom(12)
    key = params.derive_key_32()
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(iv, plain_text.encode("utf-8"), None)
    return json.dumps({"iv": _b64encode_bytes(iv), "data": _b64encode_bytes(ct)})


def looks_like_payload(s: str) -> bool:
    try:
        obj = json.loads(s)
        return isinstance(obj, dict) and "iv" in obj and "data" in obj
    except Exception:
        return False


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Recriptografa passwords do Kryptex.")
    p.add_argument("--old-salt", required=True, help="SALT antigo (texto).")
    p.add_argument("--old-iters", required=True, type=int, help="PBKDF2 iterations antigo.")
    p.add_argument("--new-salt", required=True, help="SALT novo (texto).")
    p.add_argument("--new-iters", required=True, type=int, help="PBKDF2 iterations novo.")

    p.add_argument(
        "--old-master",
        default=None,
        help="Senha mestra antiga (se omitida, será solicitada via prompt).",
    )
    p.add_argument(
        "--new-master",
        default=None,
        help="Senha mestra nova (opcional). Se omitida, reutiliza a antiga.",
    )

    p.add_argument("--only-id", type=int, action="append", default=[], help="Processa apenas este ID (pode repetir).")
    p.add_argument("--limit", type=int, default=None, help="Limita a quantidade processada.")
    p.add_argument("--commit", action="store_true", help="Aplica alterações no banco.")
    p.add_argument("--dry-run", action="store_true", help="Não grava no banco (padrão recomendado).")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if args.commit and args.dry_run:
        print("[ERRO] Use apenas um: --commit OU --dry-run", file=sys.stderr)
        return 2

    do_commit = bool(args.commit)
    if not do_commit:
        # default seguro
        print("[INFO] Rodando em DRY-RUN (sem gravar). Use --commit para persistir.")

    old_master = args.old_master or getpass("Senha mestra ANTIGA: ")
    if not old_master:
        print("[ERRO] Senha mestra antiga vazia.", file=sys.stderr)
        return 2

    new_master = args.new_master if args.new_master is not None else old_master
    if not new_master:
        print("[ERRO] Senha mestra nova vazia.", file=sys.stderr)
        return 2

    old_params = CryptoParams(
        salt_text=args.old_salt,
        iterations=int(args.old_iters),
        master_password=old_master,
    )
    new_params = CryptoParams(
        salt_text=args.new_salt,
        iterations=int(args.new_iters),
        master_password=new_master,
    )

    qs = Logins.objects.all().only("id", "service", "password")
    if args.only_id:
        qs = qs.filter(id__in=args.only_id)
    qs = qs.order_by("id")
    if args.limit:
        qs = qs[: int(args.limit)]

    total = qs.count()
    if total == 0:
        print("[INFO] Nenhum registro encontrado para processar.")
        return 0

    ok = 0
    skipped = 0
    failed = 0

    # Transação só se for gravar
    ctx = transaction.atomic() if do_commit else transaction.atomic()
    with ctx:
        for item in qs:
            enc = item.password or ""
            if not enc.strip():
                skipped += 1
                continue
            if not looks_like_payload(enc):
                print(f"[SKIP] id={item.id} service={item.service!r} (formato inesperado em password)")
                skipped += 1
                continue

            try:
                plain = decrypt_payload(enc, old_params)
                new_enc = encrypt_payload(plain, new_params)

                if do_commit:
                    item.password = new_enc
                    item.save(update_fields=["password"])

                ok += 1
                if ok % 50 == 0 or ok == total:
                    print(f"[INFO] Progresso: {ok}/{total} ok, {skipped} skip, {failed} fail")
            except Exception as e:
                failed += 1
                print(f"[FAIL] id={item.id} service={item.service!r}: {e}", file=sys.stderr)

        if not do_commit:
            # força rollback no fim do atomic()
            raise transaction.TransactionManagementError("DRY-RUN: rollback intencional")

    # Nunca chega aqui em dry-run (rollback)
    print(f"[DONE] ok={ok} skipped={skipped} failed={failed}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        # No dry-run, o rollback intencional cai aqui
        msg = str(e)
        if "DRY-RUN: rollback intencional" in msg:
            print("[DONE] DRY-RUN finalizado (rollback aplicado).")
            raise SystemExit(0)
        raise