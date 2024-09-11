target/test/wg-kernel.phony:
	orb create ubuntu:noble wg-kernel
	orb -m wg-kernel -u root apt install -y wireguard
	mkdir -p target/test
	touch target/test/wg-kernel.phony

target/test/rg-kernel.phony:
	orb create ubuntu:noble rg-kernel
	mkdir -p target/test
	touch target/test/rg-kernel.phony

target/test/wg-kernel.key: target/test/wg-kernel.phony
	orb -m wg-kernel -u root sh -c "wg genkey | tee private.key | wg pubkey" > target/test/wg-kernel.key
	orb -m wg-kernel -u root ip link add dev wg0 type wireguard
	orb -m wg-kernel -u root ip address add dev wg0 10.1.1.20/24
	orb -m wg-kernel -u root ip link set up dev wg0

.PHONY: build-tun
build-tun:
	cross build --bin rustyguard-tun --target aarch64-unknown-linux-gnu --release

.PHONY: wg-kernel
wg-kernel: target/test/wg-kernel.key
	orb -m wg-kernel -u root wg setconf wg0 rustyguard-tun/test-data/wg.conf
	orb -m wg-kernel -u root wg show

.PHONY: rg-kernel
rg-kernel: target/test/rg-kernel.phony build-tun
	orb -m rg-kernel -u root ./target/aarch64-unknown-linux-gnu/release/rustyguard-tun

clean:
	[ -f target/test/wg-kernel.phony ] && orb delete -f wg-kernel && rm target/test/wg-kernel.phony
	[ -f target/test/rg-kernel.phony ] && orb delete -f rg-kernel && rm target/test/rg-kernel.phony

.PHONY: test
test:
	orb -m rg-kernel -u root ping 10.1.1.20 -c 100 -i 0.01 -q
	orb -m wg-kernel -u root ping 10.1.1.40 -c 100 -i 0.01 -q
