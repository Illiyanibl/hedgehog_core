"""Self-signed TLS для файл-сервера (§7).

Ёжик — единый авторитет: генерит серт+ключ при первом старте (рядом с
токеном), клиент пинит SHA-256 отпечаток (провижининг по bootstrap-SSH).
Домен и CA не нужны — сервер и клиент оба принадлежат пользователю; проверка
хоста заменяется пиннингом отпечатка на клиенте.
"""
from __future__ import annotations

import datetime
import hashlib
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def ensure_cert(cert_path: Path, key_path: Path) -> str:
    """Сгенерить self-signed cert+key, если их ещё нет.

    Возврат — SHA-256 отпечаток DER-сертификата (hex), его пинит клиент.
    """
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    if not (cert_path.exists() and key_path.exists()):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hedgehog")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=3650))  # 10 лет
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("hedgehog")]),
                critical=False)
            .sign(key, hashes.SHA256())
        )
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        key_path.chmod(0o600)
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return fingerprint(cert_path)


def fingerprint(cert_path: Path) -> str:
    """SHA-256 отпечаток DER-сертификата (hex, нижний регистр)."""
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def make_ssl_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    return ctx
