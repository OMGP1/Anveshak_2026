from __future__ import annotations

from engine.types import PacketMeta, SYN

TTL_BUCKETS = (32, 64, 128, 255)

OPT_NAMES = {0: "eol", 1: "nop", 2: "mss", 3: "ws", 4: "sok", 5: "sack", 8: "ts"}

OS_FAMILIES = ("linux", "windows", "bsd", "unknown")

LINUX_OPTS = frozenset(("mss,sok,ts,nop,ws", "mss,sok,ts", "mss,nop,nop,sok,nop,ws"))
WINDOWS_OPTS = frozenset(("mss,nop,ws,nop,nop,sok", "mss,nop,nop,sok", "mss,nop,ws,sok,ts"))
BSD_PREFIX = "mss,nop,ws,nop,nop,ts"


def initial_ttl(ttl: int) -> int:
    for bucket in TTL_BUCKETS:
        if ttl <= bucket:
            return bucket
    return 255


def tcp_fingerprint(meta: PacketMeta) -> str:
    if not meta.tcp_flags & SYN:
        return ""
    names = ",".join(OPT_NAMES.get(kind, str(kind)) for kind in meta.tcp_opts)
    return "{0}:{1}:{2}:{3}".format(initial_ttl(meta.ttl), meta.tcp_window, meta.tcp_mss, names)


def fingerprint_family(fp: str) -> str:
    parts = fp.split(":")
    if len(parts) != 4:
        return "unknown"
    try:
        ittl = int(parts[0])
    except ValueError:
        return "unknown"
    opts = parts[3]
    if opts in WINDOWS_OPTS:
        return "windows"
    if opts in LINUX_OPTS:
        return "linux"
    if opts.startswith(BSD_PREFIX):
        return "bsd"
    if ittl in (32, 128):
        return "windows"
    if ittl == 64:
        return _family_from_opts_64(opts)
    return "unknown"


def _family_from_opts_64(opts: str) -> str:
    fields = opts.split(",") if opts else []
    if fields[:2] == ["mss", "sok"]:
        return "linux"
    if fields[:2] == ["mss", "nop"] and "ts" in fields:
        return "bsd"
    return "unknown"
