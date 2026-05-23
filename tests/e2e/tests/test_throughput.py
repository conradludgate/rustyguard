"""Throughput, loss, and counter sanity over the rustyguard tunnel.

These tests sit a layer above `test_handshake`: instead of just confirming a
single packet round-trips, they push real volumes of TCP and UDP traffic
through the tunnel and assert the data path behaved reasonably.

Each test is self-contained (its own iperf3 server, its own counter delta)
so the suite tolerates reordering or being run with `-k <name>`.
"""

from __future__ import annotations

import re

from rustyguard_e2e import config, iperf
from rustyguard_e2e.provider import Peer, Provider


_TYPICAL_TCP_MSS = 1448
_PING_LOSS_RE = re.compile(r"(\d+(?:\.\d+)?)\s*%\s*packet\s*loss")


def test_iperf3_tcp(provider: Provider, peers: tuple[Peer, Peer]) -> None:
    wg, rg = peers
    with iperf.serve(provider, wg.name, bind=config.WG_TUN_ADDR):
        result = iperf.run_client(provider, rg.name, config.WG_TUN_ADDR)

    end = result["end"]
    bytes_received = end["sum_received"]["bytes"]
    retransmits = end["sum_sent"]["retransmits"]
    bytes_sent = end["sum_sent"]["bytes"]

    assert bytes_received > 1_000_000, (
        f"iperf3 TCP only moved {bytes_received} bytes in 10s; tunnel is broken or stalled"
    )
    # Crude segment estimate; iperf3 doesn't report TCP packet counts directly.
    est_segments = max(bytes_sent // _TYPICAL_TCP_MSS, 1)
    retransmit_ratio = retransmits / est_segments
    assert retransmit_ratio < 0.05, (
        f"TCP retransmit ratio {retransmit_ratio:.3%} too high "
        f"({retransmits} retransmits over ~{est_segments} segments)"
    )


def test_iperf3_udp(provider: Provider, peers: tuple[Peer, Peer]) -> None:
    wg, rg = peers
    with iperf.serve(provider, wg.name, bind=config.WG_TUN_ADDR):
        # 5M is comfortably below what any healthy slirp+QEMU+userspace path
        # can sustain, so loss should be near zero on a working tunnel.
        result = iperf.run_client(
            provider, rg.name, config.WG_TUN_ADDR, udp=True, bandwidth="5M"
        )

    summary = result["end"]["sum"]
    loss_pct = summary["lost_percent"]
    jitter_ms = summary["jitter_ms"]

    assert loss_pct < 1.0, f"UDP loss {loss_pct:.2f}% above 1% threshold"
    assert jitter_ms < 50.0, f"UDP jitter {jitter_ms:.2f}ms above 50ms threshold"


def test_large_packet_ping_loss(
    provider: Provider, peers: tuple[Peer, Peer]
) -> None:
    """Ping with 1200-byte payloads to exercise the data path under load.

    1200 stays safely under the WireGuard tunnel's default 1420 MTU (1500 -
    ~80 bytes encryption overhead), so we measure the data path under load
    without conflating with fragmentation behavior.
    """
    _, rg = peers
    result = provider.exec(
        rg.name,
        [
            "ping",
            "-c", "500",
            "-i", "0.01",
            "-W", "2",
            "-s", "1200",
            "-q",
            config.WG_TUN_ADDR,
        ],
        root=True,
        capture=True,
    )
    assert result.returncode == 0, (
        f"ping flood failed:\n{result.stdout}\n{result.stderr}"
    )
    match = _PING_LOSS_RE.search(result.stdout or "")
    assert match, f"could not parse ping output:\n{result.stdout}"
    loss_pct = float(match.group(1))
    assert loss_pct < 1.0, f"near-MTU ping loss {loss_pct}% above 1% threshold"


def test_transfer_counters_advance(
    provider: Provider, peers: tuple[Peer, Peer]
) -> None:
    """`wg show transfer` rx/tx should grow when traffic flows."""
    wg, rg = peers
    before_rx, before_tx = _wg_transfer(provider, wg.name)

    provider.exec(
        rg.name,
        ["ping", "-c", "100", "-i", "0.05", "-s", "100", "-q", config.WG_TUN_ADDR],
        root=True,
        capture=True,
    )

    after_rx, after_tx = _wg_transfer(provider, wg.name)
    delta_rx = after_rx - before_rx
    delta_tx = after_tx - before_tx

    # 100 pings * 100 bytes * 2 (echo + reply) = ~20kB plus WG overhead, so
    # 10kB on each direction is a safe floor.
    assert delta_rx > 10_000, f"wg rx counter only advanced by {delta_rx} bytes"
    assert delta_tx > 10_000, f"wg tx counter only advanced by {delta_tx} bytes"


def _wg_transfer(provider: Provider, vm: str) -> tuple[int, int]:
    result = provider.exec(
        vm, ["wg", "show", "wg0", "transfer"], root=True, capture=True
    )
    for line in (result.stdout or "").splitlines():
        parts = line.split()
        if len(parts) == 3:
            return int(parts[1]), int(parts[2])
    raise RuntimeError(f"could not parse wg show transfer output:\n{result.stdout}")
