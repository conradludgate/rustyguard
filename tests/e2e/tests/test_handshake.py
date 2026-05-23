"""Bidirectional connectivity over the rustyguard <-> kernel WireGuard tunnel."""

from __future__ import annotations

from rustyguard_e2e import config
from rustyguard_e2e.provider import Peer, Provider


def _ping(provider: Provider, vm: str, target: str, count: int = 20) -> None:
    result = provider.exec(
        vm,
        ["ping", "-c", str(count), "-i", "0.1", "-q", target],
        root=True,
        capture=True,
    )
    assert result.returncode == 0, (
        f"ping {target} from {vm} failed:\n{result.stdout}\n{result.stderr}"
    )


def test_ping_rg_to_wg(provider: Provider, peers: tuple[Peer, Peer]) -> None:
    _, rg = peers
    _ping(provider, rg.name, config.WG_TUN_ADDR)


def test_ping_wg_to_rg(provider: Provider, peers: tuple[Peer, Peer]) -> None:
    wg, _ = peers
    _ping(provider, wg.name, config.RG_TUN_ADDR)


def test_handshake_complete(provider: Provider, peers: tuple[Peer, Peer]) -> None:
    """`wg show` should report a non-zero handshake timestamp on the kernel side."""
    wg, _ = peers
    result = provider.exec(
        wg.name,
        ["wg", "show", "wg0", "latest-handshakes"],
        root=True,
        capture=True,
    )
    rows = [line.split() for line in (result.stdout or "").splitlines() if line.strip()]
    assert rows, f"no handshake rows reported by wg:\n{result.stdout}"
    timestamps = [int(parts[1]) for parts in rows if len(parts) == 2]
    assert any(ts > 0 for ts in timestamps), (
        f"no handshake completed:\n{result.stdout}"
    )
