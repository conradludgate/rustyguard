"""Build the rustyguard-tun binary for the target VM.

Linux targets use `cross` for cross-architecture builds (falling back to
`cargo` when the host arch matches). Darwin targets use plain `cargo`
since `cross` doesn't support darwin-on-darwin.
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
    arch = None
    if machine in ("arm64", "aarch64"):
        arch = "aarch64"
    elif machine in ("x86_64", "amd64"):
        arch = "x86_64"
    if arch is None:
        return None
    if system == "linux":
        return f"{arch}-unknown-linux-gnu"
    if system == "darwin":
        return f"{arch}-apple-darwin"
    return None


def build(target_triple: str, *, repo_root: pathlib.Path = REPO_ROOT) -> pathlib.Path:
    """Build rustyguard-tun for `target_triple` and return the binary path."""

    is_darwin_target = target_triple.endswith("-apple-darwin")
    use_cross = (
        not is_darwin_target
        and shutil.which("cross") is not None
        and target_triple != _host_target_triple()
    )
    cmd = (["cross"] if use_cross else ["cargo"]) + [
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
