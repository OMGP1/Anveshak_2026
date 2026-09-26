from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from engine.alerts.schema import GENESIS_HASH, validate_alert

HASH_PREFIX = "sha256:"
ANCHOR_EVERY = 100
ANCHOR_TYPE = "anchor"
LINE_FIELDS = ("record", "prev_hash", "hash")
ANCHOR_FIELDS = ("type", "count", "chain_head", "ts", "pubkey")


def canonical_json(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


def chain_hash(record: dict, prev_hash: str) -> str:
    digest = hashlib.sha256()
    digest.update(canonical_json(record))
    digest.update(prev_hash.encode("ascii"))
    return HASH_PREFIX + digest.hexdigest()


def anchor_paths(path: str) -> tuple[str, str, str]:
    stem = path[:-6] if path.endswith(".jsonl") else path
    return stem + ".anchors.jsonl", stem + ".key", stem + ".pub"


def load_or_create_key(key_path: str, pub_path: str) -> Ed25519PrivateKey:
    if os.path.exists(key_path):
        with open(key_path, "rb") as handle:
            loaded = serialization.load_pem_private_key(handle.read(), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError("%s is not an Ed25519 private key" % key_path)
        return loaded
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    with os.fdopen(os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
        handle.write(pem)
        handle.flush()
        os.fsync(handle.fileno())
    with open(pub_path, "w", encoding="ascii", newline="\n") as handle:
        handle.write(public_key_hex(key) + "\n")
    return key


def public_key_hex(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw.hex()


def anchor_body(anchor: dict) -> dict:
    return {key: value for key, value in anchor.items() if key != "sig"}


def verify_anchor(anchor: dict, pubkey_hex: str | None = None) -> bool:
    for field in ANCHOR_FIELDS + ("sig",):
        if field not in anchor:
            return False
    key_hex = pubkey_hex or anchor["pubkey"]
    if anchor["pubkey"] != key_hex:
        return False
    try:
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
        public.verify(bytes.fromhex(anchor["sig"]), canonical_json(anchor_body(anchor)))
    except Exception:
        return False
    return True


def read_head(path: str) -> tuple[str, int]:
    head, count = GENESIS_HASH, 0
    if not os.path.exists(path):
        return head, count
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            count += 1
            head = json.loads(line)["hash"]
    return head, count


class Ledger:
    def __init__(self, path: str, anchor_every: int = ANCHOR_EVERY, validate: bool = True,
                 key: Ed25519PrivateKey | None = None) -> None:
        self.path = path
        self.anchors_path, self.key_path, self.pub_path = anchor_paths(path)
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.anchor_every = int(anchor_every)
        self.validate = validate
        self.key = key or load_or_create_key(self.key_path, self.pub_path)
        self.pubkey = public_key_hex(self.key)
        self._head, self._count = read_head(path)
        self._anchors = 0
        self._handle = open(path, "a", encoding="utf-8", newline="\n")

    @property
    def head(self) -> str:
        return self._head

    @property
    def records(self) -> int:
        return self._count

    @property
    def anchors(self) -> int:
        return self._anchors

    def append(self, alert: dict) -> dict:
        record = dict(alert)
        record["x_prev_hash"] = self._head
        if self.validate:
            validate_alert(record)
        line = {"record": record, "prev_hash": self._head, "hash": chain_hash(record, self._head)}
        self._handle.write(json.dumps(line, ensure_ascii=True, separators=(",", ":")) + "\n")
        self._handle.flush()
        os.fsync(self._handle.fileno())
        self._head = line["hash"]
        self._count += 1
        if self.anchor_every and self._count % self.anchor_every == 0:
            self.anchor()
        return line

    def anchor(self) -> dict:
        body = {
            "type": ANCHOR_TYPE,
            "count": self._count,
            "chain_head": self._head,
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "pubkey": self.pubkey,
        }
        record = dict(body)
        record["sig"] = self.key.sign(canonical_json(body)).hex()
        with open(self.anchors_path, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._anchors += 1
        return record

    def close(self) -> None:
        if not self._handle.closed:
            self._handle.close()

    def __enter__(self) -> "Ledger":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
