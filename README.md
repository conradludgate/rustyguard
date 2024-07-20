# RustyGuard

A WireGuard(R) implementation in pure-rust.

## Project Goals

- [x] `#![forbid(unsafe_code)]`
- [x] zerocopy/sans-io API design.
- [x] blazingly fast, low overhead.
- [x] works as a tun virtual network device.
- [x] embeddable into applications:
    * Like how you might terminate TLS at the application level.
- [x] embeddable into microcontrollers:
    - [x] no-std compatible.
    - [_] no-alloc compatible.
- [_] hard to fuck up.
- [_] clean code, for my definition of clean.

## What is this?

WireGuard(R) is a protocol for secure tunnels, as a building block for Virtual Private Networks.

This project, RustyGuard, is an "unmanaged" memory safe implementation of the WireGuard.

Unmanaged in this context means it is an application developer's responsibility to
process UDP packets going in and out of the RustyGuard interface - as well as manage IP routing etc.
RustyGuard will only take care of the byte processing and the cryptography.
