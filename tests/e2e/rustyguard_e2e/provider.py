"""Backend-agnostic VM provider interface.

Each `Provider` implementation drives a particular VM/container tool
(orb, lima, multipass, ...). Tests only ever talk to the abstract
interface defined here, so swapping backends is a matter of selecting
a different implementation in `registry.py`.

Guest OS may differ from VM to VM (Linux for the kernel-WG peer, optionally
Darwin for the rustyguard peer), so calls that depend on OS specifics take
the VM name as input and consult `vm_os()` for the right code path.
"""

from __future__ import annotations

import abc
import dataclasses
import pathlib
import subprocess
from typing import Literal


GuestOS = Literal["linux", "darwin"]


@dataclasses.dataclass(frozen=True)
class Peer:
    """Logical identity of a VM under test."""

    name: str
    address: str
    os: GuestOS = "linux"


class Provider(abc.ABC):
    """Drives a concrete VM tool."""

    name: str

    @classmethod
    @abc.abstractmethod
    def is_available(cls) -> bool:
        """True iff this backend's CLI is installed and usable on the host."""

    @abc.abstractmethod
    def supported_guest_os(self) -> tuple[GuestOS, ...]:
        """Guest OSes this backend can provision on the current host."""

    @abc.abstractmethod
    def target_triple(self, os: GuestOS) -> str:
        """Rust target triple for binaries that will run inside a `os` guest."""

    @abc.abstractmethod
    def create(self, vm: str, *, os: GuestOS = "linux") -> None:
        """Provision a VM. Idempotent: re-creating an existing VM is a no-op."""

    @abc.abstractmethod
    def vm_os(self, vm: str) -> GuestOS:
        """Guest OS of a previously-created VM."""

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
        """Install OS packages inside the guest, dispatching on guest OS."""
        if self.vm_os(vm) == "linux":
            self.exec(vm, ["apt-get", "update", "-qq"], root=True)
            self.exec(
                vm,
                ["apt-get", "install", "-y", "-qq", *packages],
                root=True,
            )
            return
        # Lima's macOS template installs Homebrew at /opt/homebrew for the
        # default unprivileged guest user. `limactl shell` runs a non-login
        # shell, so brew is not guaranteed to be on PATH; call it by absolute
        # path to avoid depending on the shell rc files.
        self.exec(vm, ["/opt/homebrew/bin/brew", "install", "--quiet", *packages])
