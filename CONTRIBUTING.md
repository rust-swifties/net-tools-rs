# Contributing to net-tools-rs

Thanks for your interest in contributing to net-tools-rs!

## What We're Looking For

- **New command implementations**: See the implementation status tracked in [issue
  #3](https://github.com/rust-swifties/net-tools-rs/issues/3) for what's missing
- **Missing flags and options**: Complete partially implemented commands
- **Bug fixes**: Especially when behavior differs from original net-tools
- **Compliance tests**: Expand test coverage
- **Documentation**: The project currently has minimal documentation;
  contributions for man pages, usage guides, or other docs are welcome

## Code Quality

All submissions must:

- Pass `cargo fmt` (formatting)
- Pass `cargo clippy` with no warnings
- Build without errors or warnings
- Pass all tests (`cargo test`)
- Include compliance tests for new commands/flags

## Unsafe Code

net-tools-rs cannot be entirely safe because we must interface with the Linux kernel's
networking APIs through `libc` syscalls and ioctl operations. However, we want to limit
and carefully control our use of `unsafe`.

### When Unsafe is Acceptable

- FFI with `libc`: Calling C functions, manipulating C structures (e.g., `arpreq`,
  `ifreq`, `sockaddr`)
- Kernel interfaces: ioctl calls, socket operations, raw pointer manipulation for system
  calls
- Performance: Only in exceptional cases with clear justification and benchmarks

### Requirements for Unsafe Code

1. Every unsafe block must include a `// SAFETY:` comment explaining:
   - Why the operation is sound
   - What invariants are being maintained
   - What preconditions are required
2. Minimize scope: Keep unsafe blocks as small as possible
3. Encapsulation: Wrap unsafe operations in safe abstractions when practical
4. Testing: Add unit tests for code containing unsafe blocks

Before writing unsafe code, consider reading the
[Rustonomicon](https://doc.rust-lang.org/nomicon/).

## Compliance Testing

net-tools-rs must behave identically to original net-tools for compatibility. When adding
features:

1. Implement the functionality
2. Add compliance tests in `compliance-tests/`
3. Verify tests pass against both implementations
4. Document any intentional differences

See [compliance-tests/README.md](compliance-tests/README.md) for details.

## Pull Requests

- Keep commits atomic and well-described
- Link to related issues
- Explain what problem you're solving and how
- Be responsive to review feedback

## License

By contributing, you agree that your contributions will be licensed under
[GPL-2.0-or-later](LICENSE), matching the original net-tools license.

## Code of Conduct

All contributors must follow our [Code of Conduct](CODE_OF_CONDUCT.md).
