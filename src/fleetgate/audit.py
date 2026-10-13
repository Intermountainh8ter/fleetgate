"""Append-only, hash-chained audit log (tamper-evident, not tamper-proof)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class AuditLog:
    GENESIS = "0" * 64

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.entries: list[dict[str, Any]] = []
        if self.path and self.path.exists():
            self.entries = [json.loads(line) for line in self.path.read_text().splitlines() if line]

    @staticmethod
    def _digest(prev: str, body: dict[str, Any]) -> str:
        return hashlib.sha256((prev + json.dumps(body, sort_keys=True)).encode()).hexdigest()

    def append(self, kind: str, **fields: Any) -> dict[str, Any]:
        prev = self.entries[-1]["hash"] if self.entries else self.GENESIS
        body = {"seq": len(self.entries), "kind": kind, **fields}
        entry = {**body, "prev": prev, "hash": self._digest(prev, body)}
        self.entries.append(entry)
        if self.path:
            with self.path.open("a") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def verify(self) -> tuple[bool, int | None]:
        """Return (ok, first_bad_seq)."""
        prev = self.GENESIS
        for e in self.entries:
            body = {k: v for k, v in e.items() if k not in ("prev", "hash")}
            if e["prev"] != prev or e["hash"] != self._digest(prev, body):
                return False, e["seq"]
            prev = e["hash"]
        return True, None
