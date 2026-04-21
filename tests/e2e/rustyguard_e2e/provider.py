"""Backend-agnostic VM provider interface.

Each `Provider` implementation drives a particular VM/container tool
(orb, lima, multipass, ...). Tests only ever talk to the abstract
interface defined here, so swapping backends is a matter of selecting
a different implementation in `registry.py`.
"""

from __future__ import annotations

import abc
import dataclasses
import pathlib
import subprocess


@dataclasses.dataclass(frozen=True)
class Peer:
    """Logical identity of a VM under test."""

    name: str
    address: str


class Provider(abc.ABC):
    """Drives a concrete VM tool."""

    name: str
    target_triple: str

    @classmethod
    @abc.abstractmethod
    def is_available(cls) -> bool:
        """True iff this backend's CLI is installed and usable on the host."""

    @abc.abstractmethod
    def create(self, vm: str, *, image: str = "ubuntu:noble") -> None:
        """Provision a VM. Idempotent: re-creating an existing VM is a no-op."""

    @abc.abstractmethod
    def exec(
        self,
        vm: str,
        cmd: list[str],
        *,
        root: bool = False,
        check: bool = True,
        capture: bool = False,
    ) -> subprocess.CompletedProcess:
        """Run a command inside the VM. `root` runs via the backend's sudo path."""

    @abc.abstractmethod
    def copy_in(self, vm: str, src: pathlib.Path, dst: str) -> None:
        """Copy a host file into the VM."""

    @abc.abstractmethod
    def address(self, vm: str) -> str:
        """An address (IP or DNS name) reachable from the *other* VM."""

    @abc.abstractmethod
    def delete(self, vm: str) -> None:
        """Tear down the VM. Idempotent."""

    def install_packages(self, vm: str, *packages: str) -> None:
        """Default apt-based install path; backends may override."""
        self.exec(vm, ["apt-get", "update", "-qq"], root=True)
        self.exec(
            vm,
            ["apt-get", "install", "-y", "-qq", *packages],
            root=True,
        )
