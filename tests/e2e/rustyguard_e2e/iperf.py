"""iperf3 driver helpers shared by the throughput tests.

The helpers shell out to `iperf3` inside the guests via `provider.exec`,
keeping the test bodies focused on assertions instead of subprocess plumbing.
"""

from __future__ import annotations

import contextlib
import json
import time
from collections.abc import Iterator

from .provider import Provider


DEFAULT_PORT = 5201


@contextlib.contextmanager
def serve(provider: Provider, vm: str, *, bind: str) -> Iterator[None]:
    """Run an iperf3 server inside `vm`, bound to `bind`, for one connection.

    `-1` exits the server after the first client finishes, so the only cleanup
    work on exit is best-effort: if the test crashed before a client connected,
    `pkill` clears the stranded process.
    """
    _kill_iperf(provider, vm)
    provider.exec(
        vm,
        [
            "sh",
            "-c",
            f"nohup iperf3 -s -1 -B {bind} >/tmp/iperf-server.log 2>&1 &",
        ],
        root=True,
    )
    # iperf3 typically opens the listening socket in <100ms; the client
    # retries connect for a few seconds anyway, so a tiny sleep is enough.
    time.sleep(0.5)
    try:
        yield
    finally:
        _kill_iperf(provider, vm)


def run_client(
    provider: Provider,
    vm: str,
    target: str,
    *,
    udp: bool = False,
    bandwidth: str | None = None,
    duration: int = 10,
) -> dict:
    """Run an iperf3 client and return its parsed `--json` output."""
    cmd = ["iperf3", "-c", target, "--json", "-t", str(duration)]
    if udp:
        cmd.append("-u")
    if bandwidth is not None:
        cmd += ["-b", bandwidth]
    result = provider.exec(vm, cmd, root=True, capture=True)
    return json.loads(result.stdout)


def _kill_iperf(provider: Provider, vm: str) -> None:
    provider.exec(vm, ["pkill", "-f", "iperf3"], root=True, check=False)
