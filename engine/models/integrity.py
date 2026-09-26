"""Fail-closed artifact verification. Keep the trusted public key outside the model mount."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ARTIFACTS = ("tier1_lgbm.txt", "tier1_meta.json", "tier1_calibration.json",
             "anomaly_iforest.pkl", "anomaly_meta.json")


def verify_bundle(directory: str | Path, public_key: str | Path) -> dict:
    directory = Path(directory)
    raw = (directory / "serving-manifest.json").read_bytes()
    signature = bytes.fromhex((directory / "serving-manifest.sig").read_text().strip())
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(Path(public_key).read_text().strip()))
    key.verify(signature, raw)
    manifest = json.loads(raw)
    if manifest.get("version") != 1 or set(manifest.get("sha256", {})) != set(ARTIFACTS):
        raise ValueError("Invalid serving manifest")
    for name in ARTIFACTS:
        digest = hashlib.sha256()
        with (directory / name).open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        if digest.hexdigest() != manifest["sha256"][name]:
            raise ValueError(f"Model artifact integrity failed: {name}")
    return manifest


def require_verified_bundle(directory: str | Path) -> None:
    if os.environ.get("SIH_PRODUCTION") == "1":
        key = os.environ.get("SIH_MODEL_PUBLIC_KEY")
        if not key:
            raise ValueError("SIH_MODEL_PUBLIC_KEY is required in production mode")
        verify_bundle(directory, key)
