# net-tools-rs

[![CI Status][ci-badge]][ci-link] [![Crate][crate-badge]][crate-link]
[![License: GPL-2.0-or-later][license-badge]][license-link]
[![Compliance Tests][compliance-badge]][compliance-link]

**A memory-safe, Rust implementation of the classic Linux
[net-tools](https://sourceforge.net/projects/net-tools/) networking
utilities.**

net-tools has been the foundation of Linux networking administration
for decades, providing essential utilities like `ifconfig`, `route`,
`netstat`, and others. This project reimplements these tools in Rust,
bringing memory safety and modern development practices to these
critical system utilities.

---

## Goals

net-tools-rs aims to be a drop-in replacement for the original
net-tools for common use cases, leveraging Rust's memory safety
guarantees to prevent entire classes of vulnerabilities present in C
implementations. The project emphasizes modern development practices
with comprehensive testing, including compliance tests against the
original implementation. We strive to build an active contributor base
and welcoming community around maintaining these fundamental Linux
networking utilities.

See [issue #3](https://github.com/rust-swifties/net-tools-rs/issues/3)
for detailed implementation status on individual command flags and
features.

## Installation

Currently, net-tools-rs can be installed from crates.io or built
from source. We aim to package it for various Linux distributions in
the future.

### From crates.io

```bash
cargo install net-tools-rs
```

### From Source

```bash
git clone https://github.com/rust-swifties/net-tools-rs
cd net-tools-rs
cargo build --release
```

The compiled binaries will be available in `target/release/`.

## Compliance Testing

We maintain comprehensive compliance tests to ensure net-tools-rs
behaves identically to the original net-tools implementation. See
[compliance-tests/README.md](compliance-tests/README.md) for detailed
testing documentation.

## Contributing

We welcome contributions! Please see
[CONTRIBUTING.md](CONTRIBUTING.md) for details on how to get started,
development setup, and our code quality standards.

## License

This project is licensed under the **GNU General Public License v2.0
or later** ([GPL-2.0-or-later](LICENSE)).

This matches the licensing of the original net-tools project, ensuring
compatibility and legal compliance.

[ci-badge]: https://github.com/rust-swifties/net-tools-rs/actions/workflows/ci.yml/badge.svg
[ci-link]: https://github.com/rust-swifties/net-tools-rs/actions/workflows/ci.yml
[crate-badge]: https://img.shields.io/crates/v/net-tools-rs?logo=rust
[crate-link]: https://crates.io/crates/net-tools-rs
[license-badge]: https://img.shields.io/badge/license-GPL--2.0--or--later-blue.svg
[license-link]: LICENSE
[compliance-badge]: https://github.com/rust-swifties/net-tools-rs/actions/workflows/compliance-tests.yml/badge.svg
[compliance-link]: https://github.com/rust-swifties/net-tools-rs/actions/workflows/compliance-tests.yml
