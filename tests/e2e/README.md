# rustyguard end-to-end tests

VM-based suite that runs the kernel WireGuard implementation against
`rustyguard-tun` across two VMs and exercises the resulting tunnel.

The default run covers handshake completion, bidirectional ICMP, near-MTU
ping flood, iperf3 TCP throughput and UDP loss/jitter, and `wg show transfer`
counter sanity. A multi-minute rekey soak is available under `--run-slow`.

## Quick start

```sh
uv run --directory tests/e2e pytest
```

The harness auto-detects an available VM backend on `PATH`. Override with
either the CLI flag or the env var:

```sh
uv run --directory tests/e2e pytest --vm-backend=lima
RG_VM_BACKEND=multipass uv run --directory tests/e2e pytest
```

## Supported backends

| Backend    | macOS | Linux | Notes                                          |
|------------|-------|-------|------------------------------------------------|
| `orb`      | yes   | no    | OrbStack; preserves the original test flow.    |
| `lima`     | yes   | yes   | `limactl` from the Lima project.               |
| `multipass`| yes   | yes   | Canonical's Multipass.                         |

Colima users: install `lima` directly and use the `lima` backend.

## Useful flags

- `--keep-vms` - leave VMs running after the suite for debugging.
- `--rg-os=darwin` - run the rustyguard peer in a macOS guest (lima backend only,
  Apple Silicon host required, ~14 GB IPSW download on first use).
- `--run-slow` - include `@pytest.mark.slow` tests (currently the ~150s rekey
  soak in `tests/test_soak.py`).
- `pytest -k <pattern>` - select a subset of tests.

## CI

This suite does not run on every PR. Trigger the linux-guest job by adding the
`e2e` label to a PR, or by pushing to `main`.

macOS guest tests (`--rg-os=darwin`) are not run in CI. GitHub-hosted macOS
runners don't expose Apple's Virtualization framework to user code, so
`limactl start template:macos` fails with
`VZErrorDomain Code=2 "Virtualization is not available on this hardware."`.
Run them locally on an Apple Silicon Mac instead.

## Cleanup

```sh
uv run --directory tests/e2e python -m rustyguard_e2e.cli clean
```

Removes any `wg-kernel` / `rg-kernel` VMs left behind by previous runs.
