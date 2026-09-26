from __future__ import annotations

import hashlib
from typing import Sequence

from engine.types import TLSMeta

REC_HANDSHAKE = 0x16
HS_CLIENT_HELLO = 0x01
HS_SERVER_HELLO = 0x02

EXT_SNI = 0x0000
EXT_ALPN = 0x0010
EXT_SIG_ALGS = 0x000D
EXT_SUPPORTED_VERSIONS = 0x002B

GREASE = frozenset(
    (0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
     0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA)
)

VERSION_CODES = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
    0x0200: "s2",
    0x0100: "s1",
}

EMPTY_HASH = "000000000000"
MAX_TLS_BYTES = 16384


def ja4_string(
    version: int,
    sni_present: bool,
    ciphers: Sequence[int],
    extensions: Sequence[int],
    sig_algs: Sequence[int] = (),
    alpn: str = "",
    transport: str = "t",
) -> str:
    cs = [c for c in ciphers if c not in GREASE]
    ex = [e for e in extensions if e not in GREASE]
    sa = [s for s in sig_algs if s not in GREASE]
    head = "{0}{1}{2}{3:02d}{4:02d}{5}".format(
        transport,
        VERSION_CODES.get(version, "00"),
        "d" if sni_present else "i",
        min(len(cs), 99),
        min(len(ex), 99),
        alpn_code(alpn),
    )
    cipher_hash = _sha12(",".join(sorted("%04x" % c for c in cs))) if cs else EMPTY_HASH
    hashed_exts = sorted("%04x" % e for e in ex if e not in (EXT_SNI, EXT_ALPN))
    sig_part = ",".join("%04x" % s for s in sa)
    if not hashed_exts and not sig_part:
        ext_hash = EMPTY_HASH
    else:
        joined = ",".join(hashed_exts)
        ext_hash = _sha12(joined + "_" + sig_part if sig_part else joined)
    return "{0}_{1}_{2}".format(head, cipher_hash, ext_hash)


def ja4s_string(
    version: int,
    cipher: int,
    extensions: Sequence[int],
    alpn: str = "",
    transport: str = "t",
) -> str:
    ex = [e for e in extensions if e not in GREASE]
    head = "{0}{1}{2:02d}{3}".format(
        transport, VERSION_CODES.get(version, "00"), min(len(ex), 99), alpn_code(alpn)
    )
    ext_hash = _sha12(",".join("%04x" % e for e in ex)) if ex else EMPTY_HASH
    return "{0}_{1:04x}_{2}".format(head, cipher, ext_hash)


def alpn_code(alpn: str) -> str:
    if not alpn:
        return "00"
    first, last = alpn[0], alpn[-1]
    if first.isascii() and first.isalnum() and last.isascii() and last.isalnum():
        return first + last
    raw = alpn.encode("utf-8", "replace")
    return ("%02x" % raw[0])[-1] + ("%02x" % raw[-1])[-1]


def parse_tls(payload: bytes) -> TLSMeta | None:
    if len(payload) < 9 or payload[0] != REC_HANDSHAKE or payload[1] != 0x03:
        return None
    buf = payload[:MAX_TLS_BYTES]
    rec_len = int.from_bytes(buf[3:5], "big")
    body = buf[5:5 + rec_len] if rec_len else buf[5:]
    if len(body) < 4:
        return None
    hs_type = body[0]
    hs_len = int.from_bytes(body[1:4], "big")
    hs = body[4:4 + hs_len] if hs_len else body[4:]
    try:
        if hs_type == HS_CLIENT_HELLO:
            return _client_hello(hs)
        if hs_type == HS_SERVER_HELLO:
            return _server_hello(hs)
    except (IndexError, ValueError):
        return None
    return None


def _client_hello(hs: bytes) -> TLSMeta | None:
    if len(hs) < 38:
        return None
    legacy_version = int.from_bytes(hs[0:2], "big")
    pos = 34
    pos += 1 + hs[pos]
    if pos + 2 > len(hs):
        return None
    cs_len = int.from_bytes(hs[pos:pos + 2], "big")
    pos += 2
    ciphers = _u16_list(hs[pos:pos + cs_len])
    pos += cs_len
    if pos >= len(hs):
        return None
    pos += 1 + hs[pos]
    exts, sig_algs, alpn, sni, negotiated = _extensions(hs, pos)
    version = negotiated or legacy_version
    ja4 = ja4_string(version, sni, ciphers, exts, sig_algs, alpn)
    return TLSMeta(
        ja4=ja4,
        version=version,
        alpn=alpn,
        sni_present=sni,
        ext_count=len([e for e in exts if e not in GREASE]),
        is_client_hello=True,
    )


def _server_hello(hs: bytes) -> TLSMeta | None:
    if len(hs) < 38:
        return None
    legacy_version = int.from_bytes(hs[0:2], "big")
    pos = 34
    pos += 1 + hs[pos]
    if pos + 3 > len(hs):
        return None
    cipher = int.from_bytes(hs[pos:pos + 2], "big")
    pos += 3
    exts, _sig, alpn, sni, negotiated = _extensions(hs, pos)
    version = negotiated or legacy_version
    return TLSMeta(
        ja4=ja4s_string(version, cipher, exts, alpn),
        version=version,
        alpn=alpn,
        sni_present=sni,
        ext_count=len([e for e in exts if e not in GREASE]),
        is_client_hello=False,
    )


def _extensions(hs: bytes, pos: int) -> tuple[list[int], list[int], str, bool, int]:
    exts: list[int] = []
    sig_algs: list[int] = []
    alpn = ""
    sni = False
    negotiated = 0
    if pos + 2 > len(hs):
        return exts, sig_algs, alpn, sni, negotiated
    total = int.from_bytes(hs[pos:pos + 2], "big")
    pos += 2
    end = min(len(hs), pos + total)
    while pos + 4 <= end:
        etype = int.from_bytes(hs[pos:pos + 2], "big")
        elen = int.from_bytes(hs[pos + 2:pos + 4], "big")
        data = hs[pos + 4:pos + 4 + elen]
        pos += 4 + elen
        exts.append(etype)
        if etype == EXT_SNI:
            sni = True
        elif etype == EXT_ALPN and not alpn:
            alpn = _first_alpn(data)
        elif etype == EXT_SIG_ALGS and len(data) >= 2:
            sig_algs = _u16_list(data[2:2 + int.from_bytes(data[0:2], "big")])
        elif etype == EXT_SUPPORTED_VERSIONS:
            negotiated = _best_version(data)
    return exts, sig_algs, alpn, sni, negotiated


def _best_version(data: bytes) -> int:
    if len(data) == 2:
        value = int.from_bytes(data, "big")
        return 0 if value in GREASE else value
    if not data:
        return 0
    offered = [v for v in _u16_list(data[1:1 + data[0]]) if v not in GREASE]
    return max(offered) if offered else 0


def _first_alpn(data: bytes) -> str:
    if len(data) < 3:
        return ""
    size = data[2]
    if size == 0 or 3 + size > len(data):
        return ""
    return data[3:3 + size].decode("ascii", "replace")


def _u16_list(buf: bytes) -> list[int]:
    return [int.from_bytes(buf[i:i + 2], "big") for i in range(0, len(buf) - 1, 2)]


def _sha12(text: str) -> str:
    return hashlib.sha256(text.encode("ascii")).hexdigest()[:12]
