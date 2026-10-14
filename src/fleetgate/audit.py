"""Append-only audit log: hash chain + HMAC signatures + Merkle checkpoints + external anchors.

Each entry's `hash` covers its body and the previous hash, so editing, deleting or reordering any
entry breaks every later hash. `sig` is an HMAC-SHA256 of the hash under a key from
`$FLEETGATE_AUDIT_KEY` (or passed explicitly), so an attacker who can rewrite the file cannot
recompute a valid chain without the key. Every `checkpoint_every` entries a checkpoint entry
records the Merkle root of the block; an `anchor` hook can ship that root somewhere the log
writer cannot touch (a ticket, a timestamping service, another machine), which also detects
truncation. `replay()` rebuilds operational state from the entries alone.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ENV_KEY = "FLEETGATE_AUDIT_KEY"
_SKIP = ("prev", "hash", "sig")


def canonical(body: dict[str, Any]) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return "0" * 64
    level = [hashlib.sha256(x.encode()).hexdigest() for x in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256((level[i] + level[i + 1]).encode()).hexdigest() for i in range(0, len(level), 2)]
    return level[0]


@dataclass
class VerifyResult:
    ok: bool
    first_bad_seq: int | None = None
    entries: int = 0
    checkpoints: int = 0
    signed: bool = False
    unchecked_signatures: int = 0  # entries carrying a signature that could not be checked (no key supplied)
    problems: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "first_bad_seq": self.first_bad_seq, "entries": self.entries,
                "checkpoints": self.checkpoints, "signed": self.signed,
                "unchecked_signatures": self.unchecked_signatures, "problems": self.problems}


class AuditLog:
    GENESIS = "0" * 64

    def __init__(self, path: str | Path | None = None, key: bytes | str | None = None,
                 checkpoint_every: int = 32, anchor: Callable[[dict[str, Any]], None] | None = None):
        self.path = Path(path) if path else None
        env = os.environ.get(ENV_KEY)
        raw = key if key is not None else env
        self.key: bytes | None = raw.encode() if isinstance(raw, str) else raw
        self.checkpoint_every = max(0, checkpoint_every)
        self.anchor = anchor
        self.entries: list[dict[str, Any]] = []
        self._since_checkpoint = 0
        if self.path and self.path.exists():
            self.entries = [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line]
            self._since_checkpoint = _entries_since_checkpoint(self.entries)

    # ---- writing -----------------------------------------------------------------------------
    @staticmethod
    def _digest(prev: str, body: dict[str, Any]) -> str:
        return hashlib.sha256((prev + canonical(body)).encode()).hexdigest()

    def _sign(self, h: str) -> str | None:
        return hmac.new(self.key, h.encode(), hashlib.sha256).hexdigest() if self.key else None

    def append(self, kind: str, **fields: Any) -> dict[str, Any]:
        entry = self._append_raw(kind, fields)
        if self.checkpoint_every:
            self._since_checkpoint += 1
            if self._since_checkpoint >= self.checkpoint_every:
                self.checkpoint()
        return entry

    def _append_raw(self, kind: str, fields: dict[str, Any]) -> dict[str, Any]:
        prev = self.entries[-1]["hash"] if self.entries else self.GENESIS
        body = {"seq": len(self.entries), "kind": kind, **fields}
        h = self._digest(prev, body)
        entry = {**body, "prev": prev, "hash": h}
        sig = self._sign(h)
        if sig:
            entry["sig"] = sig
        self.entries.append(entry)
        if self.path:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def checkpoint(self) -> dict[str, Any]:
        """Append a Merkle checkpoint over the entries since the previous checkpoint."""
        start = _last_checkpoint_end(self.entries)
        end = len(self.entries)  # exclusive; the checkpoint itself is not in its own block
        leaves = [e["hash"] for e in self.entries[start:end]]
        prev_root = next((e["merkle_root"] for e in reversed(self.entries) if e["kind"] == "checkpoint"), self.GENESIS)
        entry = self._append_raw("checkpoint", {"block_start": start, "block_end": end, "count": end - start,
                                                "merkle_root": merkle_root(leaves), "prev_root": prev_root})
        self._since_checkpoint = 0
        if self.anchor:
            self.anchor(entry)
        return entry

    # ---- verification -----------------------------------------------------------------------
    def verify(self) -> tuple[bool, int | None]:
        """Return (ok, first_bad_seq). See `verify_full` for details."""
        r = self.verify_full()
        return r.ok, r.first_bad_seq

    def verify_full(self, require_signatures: bool = False, anchors: dict[int, str] | None = None) -> VerifyResult:
        res = VerifyResult(True, None, len(self.entries), 0, bool(self.key))
        prev, prev_root = self.GENESIS, self.GENESIS
        last_cp_end = 0

        def fail(seq: int | None, msg: str) -> VerifyResult:
            res.ok = False
            res.problems.append(msg)
            if res.first_bad_seq is None:
                res.first_bad_seq = seq
            return res

        if require_signatures and not self.key:
            return fail(None, "signatures required but no key available")
        for i, e in enumerate(self.entries):
            body = {k: v for k, v in e.items() if k not in _SKIP}
            if e.get("seq") != i:
                return fail(i, f"entry {i}: seq {e.get('seq')} out of order")
            if e.get("prev") != prev:
                return fail(i, f"entry {i}: prev hash mismatch")
            if e.get("hash") != self._digest(prev, body):
                return fail(i, f"entry {i}: hash mismatch (content altered)")
            if self.key:
                # With a key configured every entry must be signed: otherwise an attacker who rewrites the file
                # could strip the signatures and recompute a plain hash chain.
                if "sig" not in e:
                    return fail(i, f"entry {i}: unsigned (signature stripped?)")
                if not hmac.compare_digest(str(e["sig"]), self._sign(e["hash"]) or ""):
                    return fail(i, f"entry {i}: bad signature (wrong key or forged entry)")
            elif "sig" in e:
                res.unchecked_signatures += 1
            if e["kind"] == "checkpoint":
                res.checkpoints += 1
                block = [x["hash"] for x in self.entries[e["block_start"]:e["block_end"]]]
                if e["block_start"] != last_cp_end or e["block_end"] != i:
                    return fail(i, f"entry {i}: checkpoint covers wrong block")
                if merkle_root(block) != e["merkle_root"]:
                    return fail(i, f"entry {i}: merkle root mismatch")
                if e["prev_root"] != prev_root:
                    return fail(i, f"entry {i}: checkpoint chain broken")
                if anchors is not None and anchors.get(i) not in (None, e["merkle_root"]):
                    return fail(i, f"entry {i}: merkle root differs from external anchor")
                prev_root, last_cp_end = e["merkle_root"], i + 1
            prev = e["hash"]
        if anchors:
            latest = max(anchors)
            if latest >= len(self.entries) or self.entries[latest].get("kind") != "checkpoint":
                return fail(None, f"anchored checkpoint at seq {latest} is missing (log truncated?)")
        return res

    # ---- helpers -----------------------------------------------------------------------------
    @property
    def head(self) -> str:
        return self.entries[-1]["hash"] if self.entries else self.GENESIS

    def of_kind(self, kind: str) -> list[dict[str, Any]]:
        return [e for e in self.entries if e["kind"] == kind]

    def for_incident(self, incident_id: str) -> list[dict[str, Any]]:
        return [e for e in self.entries if e.get("id") == incident_id or e.get("incident_id") == incident_id]

    @classmethod
    def load(cls, path: str | Path, key: bytes | str | None = None) -> AuditLog:
        return cls(path, key=key, checkpoint_every=0)


def _last_checkpoint_end(entries: list[dict[str, Any]]) -> int:
    for i in range(len(entries) - 1, -1, -1):
        if entries[i]["kind"] == "checkpoint":
            return i + 1
    return 0


def _entries_since_checkpoint(entries: list[dict[str, Any]]) -> int:
    return len(entries) - _last_checkpoint_end(entries)


class FileAnchor:
    """Anchor hook that appends (seq, merkle_root) lines to a separate file (a stand-in for an external service)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def __call__(self, checkpoint: dict[str, Any]) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(f"{checkpoint['seq']} {checkpoint['merkle_root']}\n")

    def read(self) -> dict[int, str]:
        if not self.path.exists():
            return {}
        out: dict[int, str] = {}
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                seq, root = line.split()
                out[int(seq)] = root
        return out


class MemoryAnchor:
    def __init__(self) -> None:
        self.roots: dict[int, str] = {}

    def __call__(self, checkpoint: dict[str, Any]) -> None:
        self.roots[checkpoint["seq"]] = checkpoint["merkle_root"]


# --------------------------------------------------------------------------------------------
# Replay
# --------------------------------------------------------------------------------------------


@dataclass
class ReplayState:
    incidents: dict[str, dict[str, Any]] = field(default_factory=dict)
    executed: list[dict[str, Any]] = field(default_factory=list)
    denied: list[dict[str, Any]] = field(default_factory=list)
    approvals: dict[str, dict[str, Any]] = field(default_factory=dict)
    verifications: list[dict[str, Any]] = field(default_factory=list)
    pages: list[dict[str, Any]] = field(default_factory=list)
    drained: set[str] = field(default_factory=set)
    ticketed: set[str] = field(default_factory=set)
    decisions: dict[str, int] = field(default_factory=dict)
    runbook_counts: dict[str, int] = field(default_factory=dict)
    scenario_events: list[dict[str, Any]] = field(default_factory=list)
    last_tick: int = 0
    checkpoints: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"incidents": self.incidents, "executed": self.executed, "denied": self.denied,
                "approvals": self.approvals, "verifications": self.verifications, "pages": self.pages,
                "drained": sorted(self.drained), "ticketed": sorted(self.ticketed), "decisions": self.decisions,
                "runbook_counts": self.runbook_counts, "scenario_events": self.scenario_events,
                "last_tick": self.last_tick, "checkpoints": self.checkpoints}


def replay(entries: list[dict[str, Any]]) -> ReplayState:
    """Reconstruct operational state purely from audit entries (no simulator needed)."""
    s = ReplayState()
    for e in entries:
        k = e["kind"]
        if "tick" in e:
            s.last_tick = max(s.last_tick, int(e["tick"]))
        if k in ("incident", "group_incident"):
            s.incidents[e["id"]] = {"id": e["id"], "kind": k, "host": e.get("host"), "hosts": e.get("hosts"),
                                    "signal": e.get("signal"), "opened_tick": e.get("tick"), "status": "open",
                                    "severity": None, "root_cause": None, "executed": [], "denied": [],
                                    "closed_tick": None}
        elif k == "triage" and e.get("id") in s.incidents:
            s.incidents[e["id"]]["severity"] = e.get("severity")
        elif k == "root_cause" and e.get("id") in s.incidents:
            s.incidents[e["id"]]["root_cause"] = e.get("hypothesis")
        elif k == "policy":
            s.decisions[e.get("code", "?")] = s.decisions.get(e.get("code", "?"), 0) + 1
            if e.get("decision") == "DENY" and not e.get("provisional"):
                s.denied.append({"incident": e.get("id"), "runbook": e.get("runbook"), "host": e.get("host"),
                                 "code": e.get("code")})
                if e.get("id") in s.incidents:
                    s.incidents[e["id"]]["denied"].append(f"{e.get('runbook')}@{e.get('host')}")
        elif k == "approval_request":
            s.approvals[e["request_id"]] = {"runbook": e.get("runbook"), "host": e.get("host"), "status": "pending",
                                            "required": e.get("required"), "roles": e.get("roles"), "votes": []}
        elif k == "approval" and e.get("request_id") in s.approvals:
            s.approvals[e["request_id"]]["votes"].append({"approver": e.get("approver"), "role": e.get("role"),
                                                           "approved": e.get("approved")})
        elif k == "approval_resolved" and e.get("request_id") in s.approvals:
            s.approvals[e["request_id"]]["status"] = e.get("status")
        elif k == "executed":
            rec = {"tick": e.get("tick"), "incident": e.get("id"), "runbook": e.get("runbook"), "host": e.get("host"),
                   "hosts": e.get("hosts", [e.get("host")]), "request_id": e.get("request_id")}
            s.executed.append(rec)
            s.runbook_counts[e["runbook"]] = s.runbook_counts.get(e["runbook"], 0) + 1
            for ch in e.get("changes", []):
                if ch.endswith("drained: False -> True"):
                    s.drained.add(ch.split(".")[0])
                elif ch.endswith("drained: True -> False"):
                    s.drained.discard(ch.split(".")[0])
                elif ch.endswith("ticketed: False -> True"):
                    s.ticketed.add(ch.split(".")[0])
            if e.get("id") in s.incidents:
                s.incidents[e["id"]]["executed"].append(f"{e.get('runbook')}@{e.get('host')}")
        elif k == "verify":
            s.verifications.append({"tick": e.get("tick"), "runbook": e.get("runbook"), "host": e.get("host"),
                                    "ok": e.get("ok"), "failed": e.get("failed", [])})
        elif k == "page":
            s.pages.append({"tick": e.get("tick"), "incident": e.get("id"), "reason": e.get("reason")})
        elif k == "closed" and e.get("id") in s.incidents:
            s.incidents[e["id"]]["status"] = e.get("status")
            s.incidents[e["id"]]["closed_tick"] = e.get("tick")
        elif k == "scenario_event":
            s.scenario_events.append({k2: v for k2, v in e.items() if k2 not in _SKIP and k2 != "kind"})
        elif k == "checkpoint":
            s.checkpoints += 1
    return s
