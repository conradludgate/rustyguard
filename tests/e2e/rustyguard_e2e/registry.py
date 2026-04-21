"""Backend selection.

Auto-detection picks the first backend whose CLI is on `PATH`.
Order: orb -> lima -> multipass.
"""

from __future__ import annotations

import os

from .provider import Provider
from .providers import lima, multipass, orb

_BACKENDS: dict[str, type[Provider]] = {
    orb.OrbProvider.name: orb.OrbProvider,
    lima.LimaProvider.name: lima.LimaProvider,
    multipass.MultipassProvider.name: multipass.MultipassProvider,
}

_AUTO_ORDER: tuple[str, ...] = ("orb", "lima", "multipass")


class NoBackendAvailable(RuntimeError):
    pass


class UnknownBackend(RuntimeError):
    pass


def available_backends() -> list[str]:
    return [name for name in _AUTO_ORDER if _BACKENDS[name].is_available()]


def select(name: str | None = None) -> Provider:
    """Resolve a backend by name, env var, or auto-detection."""
    requested = name or os.environ.get("RG_VM_BACKEND") or "auto"

    if requested == "auto":
        for candidate in _AUTO_ORDER:
            if _BACKENDS[candidate].is_available():
                return _BACKENDS[candidate]()
        raise NoBackendAvailable(
            "no supported VM backend found on PATH; install one of: "
            + ", ".join(_AUTO_ORDER)
        )

    if requested not in _BACKENDS:
        raise UnknownBackend(
            f"unknown backend {requested!r}; choose one of: "
            + ", ".join(_BACKENDS)
        )

    cls = _BACKENDS[requested]
    if not cls.is_available():
        raise NoBackendAvailable(
            f"backend {requested!r} requested but its CLI is not on PATH"
        )
    return cls()
