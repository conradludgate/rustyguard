"""Build the rustyguard-tun binary for the target VM.

Uses `cross` for cross-architecture builds; falls back to plain `cargo`
when the host arch matches the VM and `cross` is not available.
"""

from __future__ import annotations

import pathlib
import platform
import shutil
import subprocess


REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]


def _host_target_triple() -> str | None:
    machine = platform.machine().lower()
    system = platform.system().lower()
    if system != "linux":
        return None
    if machine in ("arm64", "aarch64"):
        return "aarch64-unknown-linux-gnu"
    if machine in ("x86_64", "amd64"):
        return "x86_64-unknown-linux-gnu"
    return None


def build(target_triple: str, *, repo_root: pathlib.Path = REPO_ROOT) -> pathlib.Path:
    """Build rustyguard-tun for `target_triple` and return the binary path."""

    use_cross = shutil.which("cross") is not None and target_triple != _host_target_triple()
    cmd = (
        ["cross"] if use_cross else ["cargo"]
    ) + [
        "build",
        "--bin",
        "rustyguard-tun",
        "--target",
        target_triple,
        "--release",
    ]
    subprocess.run(cmd, cwd=repo_root, check=True)

    binary = repo_root / "target" / target_triple / "release" / "rustyguard-tun"
    if not binary.exists():
        raise RuntimeError(f"build succeeded but binary missing at {binary}")
    return binary
