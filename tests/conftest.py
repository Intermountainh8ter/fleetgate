"""Shared fixtures for the test-suite. Everything here is offline and seeded."""
from __future__ import annotations

import pytest
from helpers import first_host

from fleetgate.fleet import Fleet


@pytest.fixture
def fleet30() -> Fleet:
    return Fleet(30, seed=2)


@pytest.fixture
def worker(fleet30: Fleet) -> str:
    return first_host(fleet30, "worker")
