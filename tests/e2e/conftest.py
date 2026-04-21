from __future__ import annotations

import logging
import os
import pathlib
import tempfile
import time
from collections.abc import Iterator

import pytest

from rustyguard_e2e import build, config, registry
from rustyguard_e2e.provider import Peer, Provider


WG_VM = "wg-kernel"
RG_VM = "rg-kernel"

log = logging.getLogger(__name__)


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


@pytest.fixture(scope="session")
def provider(request: pytest.FixtureRequest) -> Provider:
    backend = request.config.getoption("--vm-backend")
    return registry.select(backend)


@pytest.fixture(scope="session")
def peers(
    request: pytest.FixtureRequest,
    provider: Provider,
) -> Iterator[tuple[Peer, Peer]]:
    keep = request.config.getoption("--keep-vms")

    provider.create(WG_VM)
    provider.create(RG_VM)

    try:
        provider.install_packages(WG_VM, "wireguard")

        binary = build.build(provider.target_triple)
        provider.copy_in(RG_VM, binary, "/tmp/rustyguard-tun")
        provider.exec(RG_VM, ["chmod", "+x", "/tmp/rustyguard-tun"], root=True)

        wg_addr = provider.address(WG_VM)
        rg_addr = provider.address(RG_VM)

        cfg = config.render(
            wg_endpoint=f"{wg_addr}:{config.LISTEN_PORT}",
            rg_endpoint=f"{rg_addr}:{config.LISTEN_PORT}",
        )

        with tempfile.TemporaryDirectory() as tmp:
            wg_path, rg_path = config.write_to(pathlib.Path(tmp), cfg)
            _bring_up_kernel_peer(provider, wg_path)
            _bring_up_rustyguard_peer(provider, rg_path)

        # Allow the handshake to complete before returning.
        _wait_for_handshake(provider, WG_VM)

        yield Peer(WG_VM, wg_addr), Peer(RG_VM, rg_addr)
    finally:
        if not keep:
            _teardown(provider)


def _bring_up_kernel_peer(provider: Provider, wg_conf: pathlib.Path) -> None:
    provider.copy_in(WG_VM, wg_conf, "/tmp/wg.conf")
    provider.exec(WG_VM, ["mkdir", "-p", "/etc/wireguard"], root=True)
    provider.exec(WG_VM, ["mv", "/tmp/wg.conf", "/etc/wireguard/wg0.conf"], root=True)
    provider.exec(WG_VM, ["chmod", "600", "/etc/wireguard/wg0.conf"], root=True)
    provider.exec(WG_VM, ["wg-quick", "up", "wg0"], root=True)


def _bring_up_rustyguard_peer(provider: Provider, rg_conf: pathlib.Path) -> None:
    provider.copy_in(RG_VM, rg_conf, "/tmp/rg.conf")
    # Detach with systemd-run so the binary survives the exec connection.
    provider.exec(
        RG_VM,
        [
            "systemd-run",
            "--unit=rustyguard-tun",
            "--quiet",
            "--",
            "/tmp/rustyguard-tun",
            "/tmp/rg.conf",
        ],
        root=True,
    )
    _wait_for_tun_device(provider, RG_VM)


def _wait_for_tun_device(provider: Provider, vm: str, *, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = provider.exec(
            vm,
            ["ip", "-br", "link", "show"],
            root=True,
            check=False,
            capture=True,
        )
        if "tun" in (result.stdout or ""):
            return
        time.sleep(0.5)
    raise RuntimeError(f"timed out waiting for tun device on {vm!r}")


def _wait_for_handshake(provider: Provider, vm: str, *, timeout: float = 30.0) -> None:
    """Trigger and observe a wg handshake from the kernel side."""
    deadline = time.monotonic() + timeout
    # Send a single low-volume ping to nudge wg into handshaking; ignore
    # the result here, we'll assert on `wg show` below.
    provider.exec(
        vm,
        ["ping", "-c", "1", "-W", "2", config.RG_TUN_ADDR],
        root=True,
        check=False,
    )
    while time.monotonic() < deadline:
        result = provider.exec(
            vm,
            ["wg", "show", "wg0", "latest-handshakes"],
            root=True,
            check=False,
            capture=True,
        )
        for line in (result.stdout or "").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] != "0":
                return
        time.sleep(1.0)
    raise RuntimeError(f"wg handshake did not complete on {vm!r} within {timeout}s")


def _teardown(provider: Provider) -> None:
    for vm in (WG_VM, RG_VM):
        try:
            provider.delete(vm)
        except Exception:
            log.exception("failed to delete vm %s", vm)
