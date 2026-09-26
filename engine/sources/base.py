from __future__ import annotations

from typing import Iterator

from engine.types import PacketMeta


class ReplaySource:
    name: str = "source"
    approximate_count: int | None = None

    def __iter__(self) -> Iterator[PacketMeta]:
        raise NotImplementedError

    def stats(self) -> dict:
        return {"name": self.name, "approximate_count": self.approximate_count}

    def __repr__(self) -> str:
        return f"<{type(self).__name__} name={self.name!r} count={self.approximate_count}>"


def monotonic_ns(ts_ns: int, last_ns: int) -> int:
    return ts_ns if ts_ns >= last_ns else last_ns
