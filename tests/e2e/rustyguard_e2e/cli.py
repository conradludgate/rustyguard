"""Out-of-band entry points for the e2e harness.

Currently exposes:

  python -m rustyguard_e2e.cli clean   - delete leftover test VMs
  python -m rustyguard_e2e.cli doctor  - report which backends are usable
"""

from __future__ import annotations

import argparse
import sys

from . import registry


WG_VM = "wg-kernel"
RG_VM = "rg-kernel"


def _cmd_clean(args: argparse.Namespace) -> int:
    provider = registry.select(args.backend)
    print(f"using backend: {provider.name}")
    for vm in (WG_VM, RG_VM):
        try:
            provider.delete(vm)
            print(f"  deleted {vm}")
        except Exception as exc:
            print(f"  skipped {vm}: {exc}", file=sys.stderr)
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    available = registry.available_backends()
    if not available:
        print("no supported VM backends detected on PATH", file=sys.stderr)
        return 1
    print("available backends:")
    for name in available:
        print(f"  - {name}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rustyguard_e2e.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)

    clean = sub.add_parser("clean", help="remove leftover test VMs")
    clean.add_argument("--backend", default="auto")
    clean.set_defaults(func=_cmd_clean)

    doctor = sub.add_parser("doctor", help="report installed VM backends")
    doctor.set_defaults(func=_cmd_doctor)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
