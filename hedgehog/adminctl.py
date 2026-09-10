"""§tls-migration: мелкий admin-CLI Ёžika.

    python -m hedgehog.adminctl fingerprint    # SHA-256 отпечаток TLS-серта
    python -m hedgehog.adminctl token           # текущий bearer-токен
    python -m hedgehog.adminctl rotate-token     # выпустить НОВЫЙ bearer

Используется при миграции на TLS (через SSH/ezhik-client): снять отпечаток для
пиннинга в карточке клиента и, при включении TLS, ротировать токен (старый мог
утечь по plain ws). fingerprint генерит серт при отсутствии (идемпотентно).
"""
from __future__ import annotations

import os
import sys

from . import tls
from .config import Config


def main() -> None:
    cfg = Config()
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "fingerprint":
        print(tls.ensure_cert(cfg.tls_cert_file, cfg.tls_key_file))
    elif cmd == "token":
        print(cfg.load_token())
    elif cmd == "rotate-token":
        # env перекрывает файл (load_token) — тогда ротация файла бесполезна.
        if os.environ.get("HEDGEHOG_TOKEN"):
            print("ВНИМАНИЕ: задан env HEDGEHOG_TOKEN — он перекрывает файл; "
                  "ротация файла НЕ вступит в силу. Меняйте токен на стороне "
                  "env и перезапустите сервер.", file=sys.stderr)
        print(cfg.rotate_token())  # только новый токен в stdout (для скрипта)
        # Токен в памяти сервера не обновляется на лету → нужен рестарт.
        print("ВНИМАНИЕ: старый токен остаётся ВАЛИДНЫМ до РЕСТАРТА сервера "
              "(токен держится в памяти с момента старта). Перезапустите Ёžik, "
              "затем обновите токен в карточке клиента.", file=sys.stderr)
    else:
        print("usage: python -m hedgehog.adminctl "
              "{fingerprint|token|rotate-token}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
