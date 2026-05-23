"""Multipass backend.

Multipass provisions Ubuntu VMs on a shared bridge, so VM-to-VM
reachability typically works without extra host configuration.
"""

from __future__ import annotations

import json
import pathlib
import platform
import shutil
import subprocess

from ..provider import GuestOS, Provider


def _linux_target_triple() -> str:
    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        return "aarch64-unknown-linux-gnu"
    if machine in ("x86_64", "amd64"):
        return "x86_64-unknown-linux-gnu"
    raise RuntimeError(f"unsupported host arch for multipass backend: {machine!r}")


class MultipassProvider(Provider):
    name = "multipass"

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which("multipass") is not None

    def supported_guest_os(self) -> tuple[GuestOS, ...]:
        return ("linux",)

    def target_triple(self, os: GuestOS) -> str:
        if os != "linux":
            raise NotImplementedError(f"multipass cannot run {os!r} guests")
        return _linux_target_triple()

    def vm_os(self, vm: str) -> GuestOS:
        return "linux"

    def _info(self, vm: str) -> dict | None:
        result = subprocess.run(
            ["multipass", "info", vm, "--format", "json"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return None
        data = json.loads(result.stdout or "{}")
        return data.get("info", {}).get(vm)

    def create(self, vm: str, *, os: GuestOS = "linux") -> None:
        if os != "linux":
            raise NotImplementedError(f"multipass cannot run {os!r} guests")
        if self._info(vm) is not None:
            return
        subprocess.run(
            ["multipass", "launch", "noble", "--name", vm],
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
        argv = ["multipass", "exec", vm, "--"]
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
            ["multipass", "transfer", str(src), f"{vm}:{dst}"],
            check=True,
        )

    def address(self, vm: str) -> str:
        info = self._info(vm)
        if info is None:
            raise RuntimeError(f"multipass vm {vm!r} not found")
        addrs = info.get("ipv4") or []
        if not addrs:
            raise RuntimeError(f"multipass vm {vm!r} has no IPv4 address yet")
        return addrs[0]

    def delete(self, vm: str) -> None:
        if self._info(vm) is None:
            return
        subprocess.run(["multipass", "delete", vm], check=True)
        subprocess.run(["multipass", "purge"], check=True)
