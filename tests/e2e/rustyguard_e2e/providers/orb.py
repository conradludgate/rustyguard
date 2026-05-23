"""OrbStack backend.

Mirrors the original Makefile flow. Orb machines share a network and
resolve `<name>.orb.local`, so cross-VM addressing comes for free.
"""

from __future__ import annotations

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
    raise RuntimeError(f"unsupported host arch for orb backend: {machine!r}")


class OrbProvider(Provider):
    name = "orb"

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which("orb") is not None

    def supported_guest_os(self) -> tuple[GuestOS, ...]:
        return ("linux",)

    def target_triple(self, os: GuestOS) -> str:
        if os != "linux":
            raise NotImplementedError(f"orb cannot run {os!r} guests")
        return _linux_target_triple()

    def vm_os(self, vm: str) -> GuestOS:
        return "linux"

    def _machines(self) -> set[str]:
        result = subprocess.run(
            ["orb", "list", "--format", "json"],
            check=True,
            capture_output=True,
            text=True,
        )
        import json

        data = json.loads(result.stdout or "[]")
        return {entry["name"] for entry in data}

    def create(self, vm: str, *, os: GuestOS = "linux") -> None:
        if os != "linux":
            raise NotImplementedError(f"orb cannot run {os!r} guests")
        if vm in self._machines():
            return
        subprocess.run(["orb", "create", "ubuntu:noble", vm], check=True)

    def exec(
        self,
        vm: str,
        cmd: list[str],
        *,
        root: bool = False,
        check: bool = True,
        capture: bool = False,
    ) -> subprocess.CompletedProcess:
        argv = ["orb", "-m", vm]
        if root:
            argv += ["-u", "root"]
        argv += cmd
        return subprocess.run(
            argv,
            check=check,
            capture_output=capture,
            text=capture,
        )

    def copy_in(self, vm: str, src: pathlib.Path, dst: str) -> None:
        # `orb push` was added in modern orbstack; fall back to the shared
        # ~/OrbStack/<vm>/ mount for older versions if it isn't present.
        if shutil.which("orb"):
            try:
                subprocess.run(
                    ["orb", "push", str(src), f"{vm}:{dst}"],
                    check=True,
                    capture_output=True,
                )
                return
            except subprocess.CalledProcessError:
                pass
        raise RuntimeError(f"orb push failed for {src} -> {vm}:{dst}")

    def address(self, vm: str) -> str:
        return f"{vm}.orb.local"

    def delete(self, vm: str) -> None:
        if vm not in self._machines():
            return
        subprocess.run(["orb", "delete", "-f", vm], check=True)
