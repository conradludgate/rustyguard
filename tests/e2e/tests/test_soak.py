"""Long-running validation that the tunnel survives a WireGuard rekey.

`REKEY_AFTER_TIME` in rustyguard-core is 120s; with continuous traffic the
sending side re-initiates a handshake at that boundary. This test sends
~150s of pings across the boundary and asserts (a) no meaningful loss and
(b) the latest-handshake timestamp advanced, proving the rekey actually
completed mid-flight.

Marked @pytest.mark.slow so it stays opt-in (`pytest --run-slow`).
"""

from __future__ import annotations

import re

import pytest

from rustyguard_e2e import config
from rustyguard_e2e.provider import Peer, Provider


_PING_LOSS_RE = re.compile(r"(\d+(?:\.\d+)?)\s*%\s*packet\s*loss")


@pytest.mark.slow
def test_rekey_survives_traffic(
    provider: Provider, peers: tuple[Peer, Peer]
) -> None:
    wg, rg = peers
    t0 = _latest_handshake(provider, wg.name)
    assert t0 > 0, "fixture should have produced an initial handshake"

    result = provider.exec(
        rg.name,
        ["ping", "-c", "150", "-i", "1", "-W", "2", "-q", config.WG_TUN_ADDR],
        root=True,
        capture=True,
    )
    assert result.returncode == 0, (
        f"soak ping failed:\n{result.stdout}\n{result.stderr}"
    )
    match = _PING_LOSS_RE.search(result.stdout or "")
    assert match, f"could not parse ping output:\n{result.stdout}"
    loss_pct = float(match.group(1))
    assert loss_pct < 1.0, f"soak ping loss {loss_pct}% above 1% threshold"

    t1 = _latest_handshake(provider, wg.name)
    assert t1 > t0, (
        f"latest-handshake did not advance during 150s soak "
        f"(t0={t0}, t1={t1}); rekey did not complete"
    )


def _latest_handshake(provider: Provider, vm: str) -> int:
    """Return the most recent handshake timestamp (unix seconds) on `vm`."""
    result = provider.exec(
        vm, ["wg", "show", "wg0", "latest-handshakes"], root=True, capture=True
    )
    best = 0
    for line in (result.stdout or "").splitlines():
        parts = line.split()
        if len(parts) == 2:
            best = max(best, int(parts[1]))
    return best
