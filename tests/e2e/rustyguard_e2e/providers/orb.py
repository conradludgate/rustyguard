from __future__ import annotations

import pathlib
import shutil
import subprocess

from ..provider import Provider


class OrbProvider(Provider):
    name = "orb"
    target_triple = ""

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which("orb") is not None

    def create(self, vm: str, *, image: str = "ubuntu:noble") -> None:
        raise NotImplementedError

    def exec(
        self,
        vm: str,
        cmd: list[str],
        *,
        root: bool = False,
        check: bool = True,
        capture: bool = False,
    ) -> subprocess.CompletedProcess:
        raise NotImplementedError

    def copy_in(self, vm: str, src: pathlib.Path, dst: str) -> None:
        raise NotImplementedError

    def address(self, vm: str) -> str:
        raise NotImplementedError

    def delete(self, vm: str) -> None:
        raise NotImplementedError
