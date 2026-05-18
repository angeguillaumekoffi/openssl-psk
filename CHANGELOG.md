# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-18

### Added
- Initial release of `openssl-psk`
- TLS-PSK (pre-shared key) socket wrapper for Python 3.10+
- Pure Python implementation with no compiled extensions
- Support for Python 3.10, 3.11, 3.12, and 3.13
- Native `ssl.SSLContext.set_psk_*_callback()` API on Python 3.13+
- Fallback to `libssl` ctypes calls on Python 3.10–3.12
- Client-side PSK support with flexible PSK shapes (bytes, tuple, callable)
- Server-side PSK callback support with dynamic PSK database lookup
- Full test suite with loopback socket integration tests
- Comprehensive documentation and quick-start examples
- GitHub Actions workflow for automated testing and PyPI publishing

### Fixed
- Resolves limitations of existing `sslpsk` library on Python 3.12+ where `check_hostname=True` raises `ValueError` on server-side sockets

### Project Details
- License: MIT
- Repository: https://github.com/angekoffi/openssl-psk
- Author: Ange Guillaume Koffi
