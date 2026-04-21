# rustyguard end-to-end tests

VM-based ping/handshake suite that runs the kernel WireGuard implementation
against `rustyguard-tun` across two Linux VMs.

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
- `pytest -k <pattern>` - select a subset of tests.

## Cleanup

```sh
uv run --directory tests/e2e python -m rustyguard_e2e.cli clean
```

Removes any `wg-kernel` / `rg-kernel` VMs left behind by previous runs.
