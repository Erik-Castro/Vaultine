# Changelog

<p align="center">
  <img src="https://img.shields.io/badge/version-0.2.0--beta-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/keep%20a%20changelog-✅-brightgreen?style=flat-square" alt="Keep a Changelog">
</p>

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — v0.2.0-beta

### Added

#### Password Validation
- `ssm_set_password_validator()` API — register a callback for custom password strength validation
- Default validator rejects passwords < 4 characters
- Triggered on `ssm_user_register` and `ssm_user_change_password`

#### Secure Memory (mlock)
- `secure_alloc(size_t)` — `malloc` + `mlock` to prevent swapping of sensitive data
- `secure_free(ptr, size)` — `secure_erase` + `munlock` + `free`
- `secure_buffer<T>` — RAII wrapper with automatic zeroing on destruction
- `secure_vector<T>` — RAII vector with secure erase on clear/destroy

#### Cache Statistics
- `ssm_cache_get_stats()` — query hit/miss counters and slot usage
- Cache stats counters since handle creation (thread-safe)
- CLI: `ssm-cli cache-stats` with `--json` output
- TUI: "Cache Statistics" screen with hit rate visualization

#### Audit Log Enhancement
- `audit_log.operation_target` — secret name or operation target populated on all paths
- `audit_log.details` — contextual error messages ("user not found", "password mismatch", "KEK expired", "GCM integrity check failed", etc.)
- `operation_target` and `details` now populated on error paths (expired KEK, integrity failures, auth failures)

#### CLI
- `ssm-cli cache-stats` — display cache statistics with formatted output

#### TUI
- New "Cache Statistics" screen showing total slots, valid entries, hit/miss counts, and hit rate (color-coded)

#### Build System
- `SSM_VISIBILITY_HIDDEN` forced `ON` in Release builds
- `-Wpedantic`, `-Wextra` warning flags for stricter compilation
- Sanitizer support via `-DSSM_SANITIZER=address|undefined|thread`

### Tests

- 13 audit log integration tests (all operations, error paths, details/target verification)
- 6 secure_alloc/secure_free tests (null safety, writability, multiple allocs)
- 7 secure_buffer<T> tests (default ctor, alloc, moves, iteration)
- Cache statistics integration test
- Password validator integration tests (custom validator, blocks weak passwords)
- `secure_vector` tests (moves, resize, access)
- `secure_erase` tests (template, null safety, zero-length)

### Documentation

- `SECURITY.md` — vulnerability reporting, security considerations, deployment recommendations
- `CONTRIBUTING.md` — development setup, submission guidelines, testing requirements

### Security

- `memset_s`-style `secure_erase` with compiler barrier across all sensitive buffers
- Audit log now records detailed context for every operation and error
- `ssm_cache_stats` exposes cache effectiveness for performance monitoring

### Changed

- `ssm_user_authenticate` audit log now includes `details = "password mismatch"` on wrong password
- All error-path audit_write calls now include `operation_target` where the target is known

## [0.1.0] — 2026-06-01

### Added

- Core API: `ssm_init`, `ssm_destroy`, `ssm_user_register`, `ssm_user_authenticate`, `ssm_user_delete`
- Secret operations: `ssm_secret_store`, `ssm_secret_get`, `ssm_secret_delete`, `ssm_secret_list`
- Key management: `ssm_kek_rotate`, `ssm_user_change_password`
- CLI with commands for all operations
- TUI (ncurses) with menus for user/secret management, KEK rotation, database info
- Python bindings (ctypes)
- Rust, Go, Node.js FFI examples in README
- Hierarchical key architecture: per-tenant AES-256 KEK wrapped with AES-KW-256
- AES-GCM-256 authenticated encryption for secrets
- Argon2id hashing for passwords and wrapping key derivation
- LRU wrapping key cache (256 entries)
- KEK rotation with atomic SQLite transaction
- Audit logging for all operations
- Thread safety via `SQLITE_OPEN_FULLMUTEX` + `std::shared_mutex`
- SQLCipher support for database encryption at rest
