"""Closed catalogue of actions. Agents can only select from this list."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum

from .fleet import Fleet


class Risk(IntEnum):
    REVERSIBLE = 1
    DESTRUCTIVE = 2


@dataclass(frozen=True)
class Runbook:
    id: str
    risk: Risk
    description: str
    apply: Callable[[Fleet, str], None]


def _fan(f: Fleet, h: str) -> None:
    f.clear(h, "thermal")


def _restart(f: Fleet, h: str) -> None:
    f.clear(h, "service_down")


def _nic(f: Fleet, h: str) -> None:
    f.clear(h, "nic_errors")


def _drain(f: Fleet, h: str) -> None:
    f.hosts[h].drained = True


def _ticket(f: Fleet, h: str) -> None:
    f.hosts[h].ticketed = True


def _replace_disk(f: Fleet, h: str) -> None:
    f.clear(h, "disk_failing")


def _reboot(f: Fleet, h: str) -> None:
    f.clear(h, "service_down")


CATALOG: dict[str, Runbook] = {r.id: r for r in [
    Runbook("set_fan_profile_max", Risk.REVERSIBLE, "Pin fans to max RPM via BMC", _fan),
    Runbook("restart_service", Risk.REVERSIBLE, "Restart the workload service", _restart),
    Runbook("reset_nic", Risk.REVERSIBLE, "Bounce the NIC link", _nic),
    Runbook("drain_host", Risk.REVERSIBLE, "Cordon and drain workloads off the host", _drain),
    Runbook("open_ticket", Risk.REVERSIBLE, "Open a DC-ops hardware ticket", _ticket),
    Runbook("replace_disk", Risk.DESTRUCTIVE, "Pull and replace the failing disk (data loss on that disk)", _replace_disk),
    Runbook("reboot_host", Risk.DESTRUCTIVE, "Hard reboot the host", _reboot),
]}

PLAYBOOK: dict[str, list[str]] = {
    "thermal": ["set_fan_profile_max"],
    "service_down": ["restart_service"],
    "nic_errors": ["reset_nic"],
    "ecc_correctable": ["drain_host", "open_ticket"],
    "ecc_uncorrectable": ["drain_host", "open_ticket"],
    "disk_failing": ["drain_host", "replace_disk"],
}
