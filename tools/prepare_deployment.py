"""Provision a NEW local deployment directory; never overwrite secrets or serving models.

This signs the reviewed bundled baseline, not an assertion of production accuracy.
Keep model-signing.key offline after provisioning. Replace the lab TLS certificate
with an organization-issued certificate before exposing the operator network.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.x509.oid import NameOID

from engine.models.integrity import ARTIFACTS, verify_bundle

ROOT = Path(__file__).resolve().parents[1]


def private_write(path: Path, raw: bytes) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def provision(destination: Path, hostname: str = "localhost", source: Path | None = None) -> dict:
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    secret_dir = destination / "secrets"
    secret_dir.mkdir(mode=0o700)
    (destination / "state").mkdir(mode=0o700)
    models = destination / "models"
    models.mkdir(mode=0o700)
    source = source or ROOT / "data/models"
    for name in ARTIFACTS:
        shutil.copyfile(source / name, models / name)
    signing = ed25519.Ed25519PrivateKey.generate()
    private_write(secret_dir / "model-signing.key", signing.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public = signing.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    private_write(secret_dir / "model-trust.pub", (public + "\n").encode())
    manifest = {"version": 1, "scope": "bundled baseline; accuracy not certified", "sha256": {
        name: hashlib.sha256((models / name).read_bytes()).hexdigest() for name in ARTIFACTS}}
    raw = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    private_write(models / "serving-manifest.json", raw)
    private_write(models / "serving-manifest.sig", (signing.sign(raw).hex() + "\n").encode())
    users, credentials = [], {}
    for role in ("viewer", "operator", "admin"):
        token = secrets.token_urlsafe(32)
        credentials[role] = token
        users.append({"id": "local-" + role, "role": role, "token_sha256": hashlib.sha256(token.encode()).hexdigest()})
    private_write(secret_dir / "gateway-users.json", json.dumps(users, indent=2).encode())
    private_write(secret_dir / "operator-credentials.json", json.dumps(credentials, indent=2).encode())
    private_write(secret_dir / "backend-token", (secrets.token_urlsafe(48) + "\n").encode())
    tls_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.now(timezone.utc)
    sans = [x509.DNSName(hostname), x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(tls_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(tls_key, hashes.SHA256()))
    private_write(secret_dir / "tls.key", tls_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    private_write(secret_dir / "tls.crt", certificate.public_bytes(serialization.Encoding.PEM))
    verify_bundle(models, secret_dir / "model-trust.pub")
    return {"directory": str(destination.resolve()), "signed_files": len(ARTIFACTS),
            "credentials": str((secret_dir / "operator-credentials.json").resolve()),
            "tls": "self-signed lab certificate, expires in 30 days; replace for production"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--hostname", default="localhost")
    args = parser.parse_args()
    print(json.dumps(provision(args.directory, args.hostname), indent=2))
