## ue-rs

`ue-rs` aims to be a drop-in reimplementation of [update_engine](https://github.com/flacar/update_engine/), written in Rust.

*Note*: this project is still proof-of-concept, highly experimental, not production-ready yet.

## Why ue-rs?

Goal of `ue-rs` is to have a minimal, secure and robust implementation of update engine, required by A/B update mechanism of Flatcar Container Linux.
Just like the existing update engine, it downloads OS update payloads from a [Nebraska](https://github.com/flatcar/nebraska/) server, parses its [Omaha](https://github.com/google/omaha/) protocol, verifies signatures, etc.

This project, however, is different from the original update engine in the following aspects.

* It aims to be as minimal as possible. Since `update_engine` has a long history of multiple forks of a [ChromiumOS project](https://chromium.googlesource.com/aosp/platform/system/update_engine/), its code base is inherently heavy and complicated. To address that, it is made by rewriting only essential parts like parsing Omaha protocol from scratch, and use pure Rust RSA libraries instead of relying on openssl.
* Written in Rust, a huge advantage for security, especially memory safety, in contrast to the previous `update_engine`, which is written mainly in C++ and bash.
* In addition to traditional OS update payloads, it supports systemd-sysext OEM, which recently started to be included in the Alpha channel of Flatcar Container Linux.

## Getting started

Build.

```
cargo build
```

Run binaries under `target/debug` or examples under `examples`.

