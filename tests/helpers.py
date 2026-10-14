"""Plain helpers shared by test modules (importable because pytest puts tests/ on sys.path)."""
from __future__ import annotations

from fleetgate.fleet import Fleet
from fleetgate.topology import PROTECTED_ROLES


def first_host(fleet: Fleet, role: str | None = None, exclude_protected: bool = True) -> str:
    for h in fleet.hosts.values():
        if role is not None and h.role != role:
            continue
        if role is None and exclude_protected and h.role in PROTECTED_ROLES:
            continue
        return h.id
    raise LookupError(f"no host with role {role!r}")


def hosts_with_role(fleet: Fleet, role: str) -> list[str]:
    return [h.id for h in fleet.hosts.values() if h.role == role]
