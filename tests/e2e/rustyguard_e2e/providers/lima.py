"""Lima backend.

Supports both Linux and macOS guests (the latter only on Apple Silicon
hosts via lima's `template://macos`, which requires Virtualization.framework
and downloads an IPSW on first use - expect ~14GB and several minutes).

Both guest types are placed on the `lima:user-v2` slirp network so siblings
can talk to each other without socket_vmnet/sudo on the host.
"""

from __future__ import annotations

import json
import pathlib
import platform
import shutil
import subprocess

from ..provider import GuestOS, Provider

# `lima:user-v2` uses the slirp 192.168.5.0/24 range for the SSH bridge only;
# the sibling-reachable IP lives on a separate interface.
_SLIRP_PREFIX = "192.168.5."


def _arch() -> str:
    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        return "aarch64"
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    raise RuntimeError(f"unsupported host arch for lima backend: {machine!r}")


class LimaProvider(Provider):
    name = "lima"

    def __init__(self) -> None:
        # Track guest OS per VM; populated by create() and back-filled from
        # `limactl list` for any pre-existing instances we encounter.
        self._os_cache: dict[str, GuestOS] = {}

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which("limactl") is not None

    def supported_guest_os(self) -> tuple[GuestOS, ...]:
        # macOS guests are aarch64-only and need a macOS host (Virtualization.framework).
        if platform.system() == "Darwin" and _arch() == "aarch64":
            return ("linux", "darwin")
        return ("linux",)

    def target_triple(self, os: GuestOS) -> str:
        arch = _arch()
        if os == "linux":
            return f"{arch}-unknown-linux-gnu"
        if os == "darwin":
            return f"{arch}-apple-darwin"
        raise NotImplementedError(f"lima cannot run {os!r} guests")

    def vm_os(self, vm: str) -> GuestOS:
        if vm in self._os_cache:
            return self._os_cache[vm]
        info = self._instances().get(vm)
        if info is None:
            raise RuntimeError(f"vm {vm!r} not provisioned")
        # `limactl list --format json` nests guest OS under .config.os.
        os_str = (info.get("config", {}).get("os") or "linux").lower()
        guest_os: GuestOS = "darwin" if os_str == "darwin" else "linux"
        self._os_cache[vm] = guest_os
        return guest_os

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

    def create(self, vm: str, *, os: GuestOS = "linux") -> None:
        if os not in self.supported_guest_os():
            raise NotImplementedError(
                f"lima cannot run {os!r} guests on this host"
            )
        self._os_cache[vm] = os
        instances = self._instances()
        if vm in instances:
            if instances[vm].get("status") != "Running":
                subprocess.run(["limactl", "start", vm], check=True)
        else:
            template = "template://ubuntu" if os == "linux" else "template://macos"
            argv = [
                "limactl",
                "start",
                "--name",
                vm,
                "--tty=false",
                "--network",
                "lima:user-v2",
            ]
            # macOS template defaults to `video.display=default` (a vz window
            # pops up at boot). Force headless to match the Linux template.
            if os == "darwin":
                argv += ["--set", ".video.display = \"none\""]
            argv.append(template)
            subprocess.run(argv, check=True)
        if os == "darwin":
            self._enable_passwordless_sudo_darwin(vm)

    def _enable_passwordless_sudo_darwin(self, vm: str) -> None:
        """Install a NOPASSWD sudoers entry for the default `lima` user.

        Lima's macOS template generates a random first-login password and stores
        it in the guest's home dir; we use it once to drop a sudoers file so all
        subsequent `sudo` calls run without prompts.
        """
        check = subprocess.run(
            ["limactl", "shell", vm, "test", "-f", "/etc/sudoers.d/00-lima-nopasswd"],
        )
        if check.returncode == 0:
            return
        pw = subprocess.run(
            ["limactl", "shell", vm, "cat", "/Users/lima.guest/password"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        subprocess.run(
            [
                "limactl",
                "shell",
                vm,
                "sudo",
                "-S",
                "sh",
                "-c",
                "echo 'lima ALL=(ALL) NOPASSWD: ALL' "
                ">/etc/sudoers.d/00-lima-nopasswd "
                "&& chmod 440 /etc/sudoers.d/00-lima-nopasswd",
            ],
            input=pw + "\n",
            check=True,
            capture_output=True,
            text=True,
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
        if self.vm_os(vm) == "darwin":
            return self._darwin_address(vm)
        return self._linux_address(vm)

    def _linux_address(self, vm: str) -> str:
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

    def _darwin_address(self, vm: str) -> str:
        # macOS doesn't ship `ip`; scrape `ifconfig` for the first non-loopback,
        # non-slirp IPv4 on any utun-less interface.
        result = self.exec(vm, ["ifconfig"], capture=True)
        current: str | None = None
        for line in (result.stdout or "").splitlines():
            if line and not line.startswith((" ", "\t")):
                # Lines like `en0: flags=...` start an interface block.
                current = line.split(":", 1)[0]
                continue
            stripped = line.strip()
            if current in (None, "lo0") or not stripped.startswith("inet "):
                continue
            ip = stripped.split()[1]
            if not ip.startswith(_SLIRP_PREFIX) and not ip.startswith("127."):
                return ip
        raise RuntimeError(
            f"no sibling-reachable IPv4 found in lima darwin vm {vm!r}; "
            "is the 'lima:user-v2' network configured?"
        )

    def delete(self, vm: str) -> None:
        self._os_cache.pop(vm, None)
        if vm not in self._instances():
            return
        subprocess.run(["limactl", "delete", "-f", vm], check=True)
