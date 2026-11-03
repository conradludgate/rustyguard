# RustyGuard

A [WireGuard(R)](https://www.wireguard.com/) implementation in pure Rust.

## Project Goals

- [x] `#![forbid(unsafe_code)]`
- [x] zerocopy/sans-io API design.
- [x] blazingly fast, low overhead.
- [x] works as a tun virtual network device.
- [x] embeddable into applications:
    * Like how you might terminate TLS at the application level.
- [x] embeddable into microcontrollers:
    - [x] no-std compatible.
    - [ ] no-alloc compatible.
- [ ] hard to fuck up.
- [ ] clean code, for my definition of clean.

## What is this?

WireGuard(R) is a protocol for secure tunnels, as a building block for Virtual Private Networks.

This project, RustyGuard, is an "unmanaged" memory safe implementation of the WireGuard.

Unmanaged in this context means it is an application developer's responsibility to
process UDP packets going in and out of the RustyGuard interface - as well as manage IP routing etc.
RustyGuard will only take care of the byte processing and the cryptography.

You can see the [tun](rustyguard-tun/src/main.rs) example codebase to see what that looks like. In that file we:
1. Manage the IP routing rules with the [`iptrie`](https://docs.rs/iptrie) crate.
2. Manage the UDP socket
3. Manage the TUN interface using the [`tun`](https://docs.rs/tun) crate.

This library is zero-copy where possible. WireGuard(R) has been designed with this in mind.
The only parsing we need to do is:
1. Check the first byte for the message type.
2. Check the message length.

This makes it very easy to avoid both buffer exploits, as well as reducing bounds-check overhead as we only
need to perform 1 bounds check. This comes courtesy of [`zerocopy`](https://docs.rs/zerocopy).

This also means we can focus on the things that actually matter, the cryptography, the key schedule, and the
timing system.

## Embedding into applications

> [!NOTE]
> This article is a stub

Much like with rustls or openssl, you can embed rustyguard into your applications. Unlike TLS, WireGuard(R) is not
a client-server architecture but is instead peer-to-peer. However, WireGuard(R) can support client-server models
just fine - the client will configure the server peer to have a known endpoint, whereas the server will not specify
any known endpoints for the client peers.

To effectively make use of this crate in an application setting, you will likely need to provide your own userspace TCP stack.
See [`smoltcp`](https://docs.rs/smoltcp) for a possible crate to provide this. I would like to eventually provide a wrapper
library that provides a simple Read/Write wrapper on top of rustyguard that does this for you.

## Embedding into microcontrollers

The default `graviola` crypto backend uses `std`. For a portable `no_std` build,
disable default features and select `rustcrypto` on `rustyguard-core` (and on
`rustyguard-crypto` if depending on it directly):

```toml
rustyguard-core = { version = "0.1", default-features = false, features = ["rustcrypto"] }
rustyguard-crypto = { version = "0.1", default-features = false, features = ["rustcrypto"] }
```

This configuration is cross-checked for the Pico 2's Cortex-M33 target,
`thumbv8m.main-none-eabihf`. It still requires an allocator.

All the allocations currently performed by rustyguard could be replaced with [`heapless`](https://docs.rs/heapless) to
truly be no-alloc and support most embedded targets.
However, It is still necessary for the application developer to provide:
1. UDP Network
2. Time
3. Cryptographic RNG

## Crypto providers

Both providers implement WireGuard's fixed crypto suite. `Config::new` selects
Graviola when its feature is enabled, otherwise RustCrypto. Both features may be
enabled together; select a provider explicitly when needed:

```rust
use rustyguard_core::Config;
use rustyguard_crypto::{CryptoPrimatives, StaticPrivateKey};
use rustyguard_crypto::providers::RustCrypto;

let private_key = StaticPrivateKey([1; 32]);
let config = Config::<RustCrypto>::with_crypto(RustCrypto::x25519_pubkey(&private_key));
```

The key above is only an example; use a securely generated private key in an
application. `Sessions::new(config, rng)` infers the provider. Peer configuration
can be built with `StaticPeerConfig::with_crypto::<RustCrypto>(...)`.

Custom providers implement `rustyguard_crypto::CryptoPrimatives` and use the same
typed constructors. With both built-in features disabled, an explicit provider
is required. Selection uses static dispatch and adds no provider allocation.

### Caller-driven static-key agreement

The crypto crate exposes owned DH requests so the caller can keep its long-term
private key or HSM handle entirely outside Rustyguard. Each request provides
`peer_key()` and consumes itself in `complete(SharedSecret)`. The caller decides
whether to compute agreement immediately, queue it, or await a device; no key trait,
future type, executor or device error is imposed by the library.

Receiving an initiation has two dependent agreements. For example, caller code
can await its own device between steps:

```rust
let request = DecryptHandshakeInit::<RustCrypto>::new(
    packet, HandshakeState::default(), &local_public_key,
);
let bytes = device.agree(request.peer_key()).await?;
let request = request.complete(SharedSecret::new(bytes)?)?;
let bytes = device.agree(request.peer_key()).await?;
let initiation = request.complete(SharedSecret::new(bytes)?)?;
```

`EncryptHandshakeInit` prepares outgoing initiations, and `DecryptHandshakeResp`
handles responses. Requests own their packet, transcript and required peer
snapshots; they borrow no key, configuration or receive buffer while waiting.
`SharedSecret` rejects all-zero output and clears its own bytes on drop. Dropping
an unfinished request clears its transcript; cancelling hardware work remains
the caller's responsibility. The authenticated initiation owns its transcript;
after checking its peer and timestamp, consume `initiation.respond(...)` to produce the response and final
transcript. These state transitions are the handshake API. Core, tests and
benchmarks drive the same states. Static-key agreement always belongs to the caller.
Ephemeral DH and packet protection still use C.

These are low-level operations. Before starting device work, verify admission
with `HasMac::verify_with`, using a MAC1 key cached from the local public key via
`mac1_key_with`. The first incoming DH step exposes only a claimed identity;
check the known peer, authenticated timestamp ordering and live job before
installing completed results. The session engine handles these checks when
using the session API below.
Response candidates own a snapshot of the outstanding initiation, so a failed
attempt leaves that initiation available for a later valid response.

### Caller-managed keys in the session engine

`Config::new(local_public_key)` or `Config::<Provider>::with_crypto(local_public_key)`
configures only the public identity. Core never stores a static private key.
`send_message` and `recv_message` return
`SendMessage::Handshake(work)` or `Message::Handshake(work)`. Continue servicing
packets and calling `turn` while the caller's device is busy. Each work item
owns its message/transcript; it borrows no engine or reusable receive buffer.

Supply the agreement from the matching local static key with
`work.complete(&sessions, SharedSecret::new(bytes)?)`. The returned `Event` is:

- `Handshake(next)`: another DH operation, using `next.peer_key()`.
- `Write(message)`: send `message.data()` to `message.to()`.
- `HandshakeComplete(encrypter)`: the initiator can send its first transport packet.

`turn` returns owned `Event` values too: writes or pending handshake work.
`start_handshake(peer)` directly returns owned work. Every static key follows this
same API. For a software key, the application computes the agreement immediately;
for a device it can wait, while continuing to service the engine. No executor,
key trait or library-owned future is required. A !Send caller-owned key is supported.
The TUN example services requests using its own software key; it has no privileged
path through core.

Core verifies MAC/cookie admission before issuing DH work. Jobs default to a limit of 64, adjustable through `with_max_pending_handshakes`;
saturation returns `Error::HandshakeLimit` and timer rekeys retry later. Drop a
request on device error or cancellation. Its transcript is released and its slot
is reusable; an outgoing placeholder session is reaped by the existing timer.
Use `start_handshake(peer)` to retry explicitly while transport is established.
Core rejects results at or beyond `work.deadline()`, on another engine, or after
the original handshake was replaced. Keep advancing protocol time with `turn`.
Physical HSM cancellation and device result/request correlation remain the
caller's responsibility.

Every job allocates an identity token; send/receive requests are boxed to keep
ordinary data result enums small. The bounded weak registry reuses its capacity.
Neither transport send nor receive starts a DH job for an established session.
See the core delayed-key test for traffic continuing during a suspended rekey.
No actual HSM hardware is tested.

## Project TODO:

- [ ] Overload detection for DDoS mitigation
- [x] Reject data packet replay with sliding counter window bitset
- [ ] More efficient timer management
- [ ] Optional multithreadding support
- [ ] Live peer updating

---

> [!NOTE]
> "WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld.
