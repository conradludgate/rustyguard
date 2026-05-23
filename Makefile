.PHONY: test clean doctor build-tun

test:
	uv run --directory tests/e2e pytest

clean:
	uv run --directory tests/e2e python -m rustyguard_e2e.cli clean

doctor:
	uv run --directory tests/e2e python -m rustyguard_e2e.cli doctor

build-tun:
	cross build --bin rustyguard-tun --target aarch64-unknown-linux-gnu --release
