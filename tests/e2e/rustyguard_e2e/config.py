"""Render WireGuard config files for the two test peers.

The static peer keys, addresses, and ports come from the on-disk
templates in `rustyguard-tun/test-data/`; only the peer endpoint
(`<addr>:<port>`) varies per backend.
"""

from __future__ import annotations

import dataclasses
import pathlib

from .build import REPO_ROOT


TEST_DATA = REPO_ROOT / "rustyguard-tun" / "test-data"

WG_TUN_ADDR = "10.1.1.20"
RG_TUN_ADDR = "10.1.1.40"
LISTEN_PORT = 51820


@dataclasses.dataclass(frozen=True)
class RenderedConfig:
    wg_conf: str
    rg_conf: str


def render(wg_endpoint: str, rg_endpoint: str) -> RenderedConfig:
    """Substitute peer endpoints into the on-disk templates."""

    wg_tmpl = (TEST_DATA / "wg.conf.tmpl").read_text()
    rg_tmpl = (TEST_DATA / "rg.conf.tmpl").read_text()
    return RenderedConfig(
        wg_conf=wg_tmpl.format(peer_endpoint=rg_endpoint),
        rg_conf=rg_tmpl.format(peer_endpoint=wg_endpoint),
    )


def write_to(target_dir: pathlib.Path, cfg: RenderedConfig) -> tuple[pathlib.Path, pathlib.Path]:
    target_dir.mkdir(parents=True, exist_ok=True)
    wg = target_dir / "wg.conf"
    rg = target_dir / "rg.conf"
    wg.write_text(cfg.wg_conf)
    rg.write_text(cfg.rg_conf)
    return wg, rg
