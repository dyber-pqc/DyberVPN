# Contributing to DyberVPN

Thank you for your interest in contributing to DyberVPN! This document provides
guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Security](#security)
- [License](#license)

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to
follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

**In summary**: Be respectful, inclusive, and professional. We're building
critical security infrastructure together.

## Getting Started

### Prerequisites

- Rust 1.75 or later
- Linux (primary), macOS (experimental)
- Git
- Docker (optional, for container builds)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/DyberVPN.git
   cd DyberVPN
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/dyber-pqc/DyberVPN.git
   ```

## Development Setup

### Build

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test --all

# Run benchmarks
cargo bench
```

### Project Structure

```
DyberVPN/
├── boringtun/              # Core WireGuard + PQ extensions
│   └── src/noise/          # Handshake protocol
├── crates/
│   ├── dybervpn-protocol/  # Crypto backend, types, config
│   ├── dybervpn-tunnel/    # TUN device, daemon
│   ├── dybervpn-cli/       # Command-line interface
│   ├── dybervpn-metrics/   # Prometheus metrics
│   └── dybervpn-ffi/       # C/FFI bindings
├── deploy/                 # Docker, systemd, install scripts
├── docs/                   # Documentation
└── test-configs/           # Example configurations
```

## Making Changes

### Branch Naming

Use descriptive branch names:

- `feature/add-qrng-support` - New features
- `fix/handshake-timeout` - Bug fixes
- `docs/improve-readme` - Documentation
- `refactor/crypto-backend` - Code refactoring
- `test/add-pqonly-tests` - Test additions

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting (no code change)
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance tasks
- `security`: Security improvements

**Examples**:
```
feat(protocol): add ML-DSA-87 support for higher security levels

fix(tunnel): resolve race condition in peer reconnection

docs(readme): add Docker deployment instructions

security(crypto): update ml-kem to patched version
```

## Pull Request Process

### Before Submitting

1. **Sync with upstream**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run all checks**:
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   cargo test --all
   ```

3. **Update documentation** if needed

4. **Add tests** for new functionality

### Submitting a PR

1. Push your branch to your fork
2. Open a Pull Request against `dyber-pqc/DyberVPN:main`
3. Fill out the PR template completely
4. Link any related issues

### PR Requirements

- [ ] All CI checks pass
- [ ] Code is formatted with `cargo fmt`
- [ ] No clippy warnings
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Changelog updated (for user-facing changes)
- [ ] Commits are signed (GPG or SSH)

### Review Process

1. A maintainer will review your PR
2. Address any feedback
3. Once approved, a maintainer will merge
4. Delete your branch after merge

## Coding Standards

### Rust Style

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Document all public APIs with doc comments

### Cryptography Guidelines

⚠️ **Critical**: DyberVPN is security-critical software.

- **Never** implement cryptographic primitives yourself
- Use audited, well-maintained libraries (ml-kem, ml-dsa, dalek)
- All crypto changes require extra review
- Follow constant-time programming practices
- Use `zeroize` for sensitive data

### Error Handling

- Use `anyhow::Result` for application errors
- Use custom error types for library code
- Provide context with `.context()` or `.with_context()`
- Never `unwrap()` in library code

### Performance

- Profile before optimizing
- Document performance-critical sections
- Consider memory allocation patterns
- Use `#[inline]` judiciously

## Testing

### Running Tests

```bash
# All tests
cargo test --all

# Specific crate
cargo test -p boringtun
cargo test -p dybervpn-protocol

# With output
cargo test --all -- --nocapture

# Single test
cargo test test_name
```

### Writing Tests

- Place unit tests in the same file as the code
- Place integration tests in `tests/`
- Use descriptive test names
- Test both success and failure cases
- Test edge cases and boundaries

### Test Categories

```rust
#[test]
fn test_mlkem_encapsulation() {
    // Unit test
}

#[test]
#[ignore] // Requires root/sudo
fn test_tun_device_creation() {
    // Integration test
}

#[test]
fn test_pqonly_wrong_signature_rejected() {
    // Security test
}
```

## Documentation

### Code Documentation

- Document all public items
- Include examples in doc comments
- Use `# Examples` sections

```rust
/// Generates a hybrid key pair for DyberVPN.
///
/// This generates both classical (X25519/Ed25519) and post-quantum
/// (ML-KEM-768) key pairs suitable for hybrid mode operation.
///
/// # Examples
///
/// ```
/// let keypair = generate_hybrid_keypair()?;
/// println!("Public key: {}", keypair.public_key_base64());
/// ```
///
/// # Errors
///
/// Returns an error if the random number generator fails.
pub fn generate_hybrid_keypair() -> Result<HybridKeyPair> {
    // ...
}
```

### Markdown Documentation

- Keep README.md up to date
- Update CHANGELOG.md for releases
- Add guides to `docs/`

## Security

### Reporting Vulnerabilities

**Do NOT open public issues for security vulnerabilities.**

Email: security@dyber.org

See [SECURITY.md](SECURITY.md) for our security policy.

### Security Considerations

When contributing security-sensitive code:

1. Request review from security team
2. Consider timing attacks
3. Ensure proper key zeroization
4. Test against known attack vectors
5. Document security assumptions

## License

By contributing to DyberVPN, you agree that your contributions will be licensed
under the Apache 2.0 License (for new code) or BSD-3-Clause (for BoringTun-derived
modifications).

### Developer Certificate of Origin

By making a contribution, you certify that:

1. The contribution was created by you
2. You have the right to submit it under the project's license
3. You understand the contribution is public and recorded

We recommend signing your commits:

```bash
git config --global commit.gpgsign true
```

---

## Questions?

- Open a [Discussion](https://github.com/dyber-pqc/DyberVPN/discussions)
- Join our community chat (coming soon)
- Email: developers@dyber.org

Thank you for contributing to DyberVPN! 🔐

---

Copyright 2026 Dyber, Inc.
