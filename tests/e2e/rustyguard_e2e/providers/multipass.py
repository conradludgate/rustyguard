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

from ..provider import Provider


def _host_target_triple() -> str:
    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        return "aarch64-unknown-linux-gnu"
    if machine in ("x86_64", "amd64"):
        return "x86_64-unknown-linux-gnu"
    raise RuntimeError(f"unsupported host arch for multipass backend: {machine!r}")


class MultipassProvider(Provider):
    name = "multipass"

    def __init__(self) -> None:
        self.target_triple = _host_target_triple()

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which("multipass") is not None

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

    def create(self, vm: str, *, image: str = "ubuntu:noble") -> None:
        if self._info(vm) is not None:
            return
        # `image` for multipass is a release alias like "noble"; strip the
        # ubuntu: prefix used by the orb-style spec.
        release = image.split(":", 1)[1] if ":" in image else image
        subprocess.run(
            ["multipass", "launch", release, "--name", vm],
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
