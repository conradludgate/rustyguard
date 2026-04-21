from __future__ import annotations

import os

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("rustyguard-e2e")
    group.addoption(
        "--vm-backend",
        action="store",
        default=os.environ.get("RG_VM_BACKEND", "auto"),
        choices=("auto", "orb", "lima", "multipass"),
        help="VM backend to use. 'auto' picks the first available on PATH.",
    )
    group.addoption(
        "--keep-vms",
        action="store_true",
        default=False,
        help="Skip VM teardown so failures can be inspected.",
    )
