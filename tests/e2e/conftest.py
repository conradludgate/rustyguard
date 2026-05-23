from __future__ import annotations

import logging
import os
import pathlib
import tempfile
import time
from collections.abc import Iterator

import pytest

from rustyguard_e2e import build, config, registry
from rustyguard_e2e.provider import GuestOS, Peer, Provider


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
        "--rg-os",
        action="store",
        default=os.environ.get("RG_OS", "linux"),
        choices=("linux", "darwin"),
        help=(
            "Guest OS for the rustyguard peer. 'darwin' requires the lima backend "
            "and an Apple Silicon macOS host."
        ),
    )
    group.addoption(
        "--keep-vms",
        action="store_true",
        default=False,
        help="Skip VM teardown so failures can be inspected.",
    )
    group.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="Include tests marked @pytest.mark.slow (e.g. multi-minute soaks).",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "slow: tests that take >1 minute; opt in with --run-slow"
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if config.getoption("--run-slow"):
        return
    skip_slow = pytest.mark.skip(reason="requires --run-slow")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip_slow)


@pytest.fixture(scope="session")
def provider(request: pytest.FixtureRequest) -> Provider:
    backend = request.config.getoption("--vm-backend")
    return registry.select(backend)


@pytest.fixture(scope="session")
def rg_os(request: pytest.FixtureRequest, provider: Provider) -> GuestOS:
    requested: GuestOS = request.config.getoption("--rg-os")
    if requested not in provider.supported_guest_os():
        pytest.skip(
            f"backend {provider.name!r} cannot run {requested!r} guests on this host"
        )
    return requested


@pytest.fixture(scope="session")
def peers(
    request: pytest.FixtureRequest,
    provider: Provider,
    rg_os: GuestOS,
) -> Iterator[tuple[Peer, Peer]]:
    keep = request.config.getoption("--keep-vms")

    provider.create(WG_VM, os="linux")
    provider.create(RG_VM, os=rg_os)

    try:
        provider.install_packages(WG_VM, "wireguard", "iperf3")
        provider.install_packages(RG_VM, "iperf3")

        binary = build.build(provider.target_triple(rg_os))
        rg_binary_path = "/tmp/rustyguard-tun"
        provider.copy_in(RG_VM, binary, rg_binary_path)
        provider.exec(RG_VM, ["chmod", "+x", rg_binary_path], root=True)

        wg_addr = provider.address(WG_VM)
        rg_addr = provider.address(RG_VM)

        cfg = config.render(
            wg_endpoint=f"{wg_addr}:{config.LISTEN_PORT}",
            rg_endpoint=f"{rg_addr}:{config.LISTEN_PORT}",
        )

        with tempfile.TemporaryDirectory() as tmp:
            wg_path, rg_path = config.write_to(pathlib.Path(tmp), cfg)
            _bring_up_kernel_peer(provider, wg_path)
            _bring_up_rustyguard_peer(provider, rg_path, rg_os)

        # Allow the handshake to complete before returning.
        _wait_for_handshake(provider, WG_VM)

        yield Peer(WG_VM, wg_addr, "linux"), Peer(RG_VM, rg_addr, rg_os)
    finally:
        if not keep:
            _teardown(provider)


def _bring_up_kernel_peer(provider: Provider, wg_conf: pathlib.Path) -> None:
    provider.copy_in(WG_VM, wg_conf, "/tmp/wg.conf")
    provider.exec(WG_VM, ["mkdir", "-p", "/etc/wireguard"], root=True)
    provider.exec(WG_VM, ["mv", "/tmp/wg.conf", "/etc/wireguard/wg0.conf"], root=True)
    provider.exec(WG_VM, ["chmod", "600", "/etc/wireguard/wg0.conf"], root=True)
    provider.exec(WG_VM, ["wg-quick", "up", "wg0"], root=True)


def _bring_up_rustyguard_peer(
    provider: Provider, rg_conf: pathlib.Path, rg_os: GuestOS
) -> None:
    provider.copy_in(RG_VM, rg_conf, "/tmp/rg.conf")
    if rg_os == "linux":
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
    else:
        # macOS guest: launchd would be overkill; nohup the binary and route
        # its output into /tmp so we can read it back if something fails.
        provider.exec(
            RG_VM,
            [
                "sh",
                "-c",
                "nohup /tmp/rustyguard-tun /tmp/rg.conf "
                ">/tmp/rustyguard-tun.log 2>&1 &",
            ],
            root=True,
        )
    _wait_for_tun_device(provider, RG_VM, rg_os)
    if rg_os == "darwin":
        _install_darwin_allowed_ips_route(provider, RG_VM)


def _install_darwin_allowed_ips_route(provider: Provider, vm: str) -> None:
    """Install a /sbin/route entry for the WG peer on macOS.

    rustyguard-tun on macOS does not auto-install routes for AllowedIPs, so
    without this step the kernel has no path back through utun for replies.
    """
    iface = _find_utun_for_addr(provider, vm, config.RG_TUN_ADDR)
    provider.exec(
        vm,
        [
            "/sbin/route",
            "-n",
            "add",
            "-inet",
            f"{config.WG_TUN_ADDR}/32",
            "-interface",
            iface,
        ],
        root=True,
    )


def _find_utun_for_addr(provider: Provider, vm: str, addr: str) -> str:
    """Return the utun interface whose `inet` matches `addr`."""
    result = provider.exec(vm, ["ifconfig"], capture=True)
    current: str | None = None
    needle = f"inet {addr} "
    for line in (result.stdout or "").splitlines():
        if line and not line.startswith((" ", "\t")):
            current = line.split(":", 1)[0]
        elif current and current.startswith("utun") and needle in line:
            return current
    raise RuntimeError(f"no utun on {vm!r} has inet {addr}")


def _wait_for_tun_device(
    provider: Provider, vm: str, vm_os: GuestOS, *, timeout: float = 15.0
) -> None:
    deadline = time.monotonic() + timeout
    if vm_os == "linux":
        cmd = ["ip", "-br", "link", "show"]
        needle = "tun"
    else:
        cmd = ["ifconfig", "-l"]
        needle = "utun"
    while time.monotonic() < deadline:
        result = provider.exec(
            vm,
            cmd,
            root=True,
            check=False,
            capture=True,
        )
        if needle in (result.stdout or ""):
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
