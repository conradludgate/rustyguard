"""Lima backend.

Lima isolates VMs from each other on its default user-mode network, so we
provision instances on the `lima:user-v2` slirp4netns network. Unlike
`lima:shared`, `user-v2` doesn't need socket_vmnet/sudo - sibling VMs
talk to each other via virtual L2 segments managed by lima itself.
"""

from __future__ import annotations

import json
import pathlib
import platform
import shutil
import subprocess

from ..provider import Provider

# `lima:shared` and `lima:user-v2` use the slirp 192.168.5.0/24 range only
# for the host-to-guest SSH bridge; a sibling-reachable IP lives on a
# different interface.
_SLIRP_PREFIX = "192.168.5."


def _host_target_triple() -> str:
    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        return "aarch64-unknown-linux-gnu"
    if machine in ("x86_64", "amd64"):
        return "x86_64-unknown-linux-gnu"
    raise RuntimeError(f"unsupported host arch for lima backend: {machine!r}")


class LimaProvider(Provider):
    name = "lima"

    def __init__(self) -> None:
        self.target_triple = _host_target_triple()

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which("limactl") is not None

    def _instances(self) -> dict[str, dict]:
        # `limactl list --format json` emits one JSON object per line.
        result = subprocess.run(
            ["limactl", "list", "--format", "json"],
            check=True,
            capture_output=True,
            text=True,
        )
        out: dict[str, dict] = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            out[obj["name"]] = obj
        return out

    def create(self, vm: str, *, image: str = "ubuntu:noble") -> None:
        instances = self._instances()
        if vm in instances:
            if instances[vm].get("status") != "Running":
                subprocess.run(["limactl", "start", vm], check=True)
            return
        subprocess.run(
            [
                "limactl",
                "start",
                "--name",
                vm,
                "--tty=false",
                "--network",
                "lima:user-v2",
                "template://ubuntu",
            ],
            check=True,
        )

    def exec(
        self,
        vm: str,
        cmd: list[str],
        *,
        root: bool = False,
        check: bool = True,
        capture: bool = False,
    ) -> subprocess.CompletedProcess:
        argv = ["limactl", "shell", vm]
        if root:
            argv += ["sudo"]
        argv += cmd
        return subprocess.run(
            argv,
            check=check,
            capture_output=capture,
            text=capture,
        )

    def copy_in(self, vm: str, src: pathlib.Path, dst: str) -> None:
        subprocess.run(
            ["limactl", "copy", str(src), f"{vm}:{dst}"],
            check=True,
        )

    def address(self, vm: str) -> str:
        result = self.exec(
            vm,
            ["ip", "-j", "-4", "addr", "show"],
            capture=True,
        )
        for iface in json.loads(result.stdout):
            if iface.get("ifname") == "lo":
                continue
            for addr in iface.get("addr_info", []):
                ip = addr.get("local", "")
                if ip and not ip.startswith(_SLIRP_PREFIX):
                    return ip
        raise RuntimeError(
            f"no sibling-reachable IPv4 found in lima vm {vm!r}; "
            "is the 'lima:user-v2' network configured?"
        )

    def delete(self, vm: str) -> None:
        if vm not in self._instances():
            return
        subprocess.run(["limactl", "delete", "-f", vm], check=True)
