# Contributing to Vaultine

<p align="center">
  <img src="https://img.shields.io/badge/version-0.3.1--beta-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square" alt="PRs Welcome">
  <img src="https://img.shields.io/badge/build-passing-brightgreen?style=flat-square" alt="Build">
</p>

## Code of Conduct

Be respectful, inclusive, and professional.

## Development Setup

```bash
git clone https://github.com/Erik-Castro/Vaultine.git
cd Vaultine
cmake -B build -DSSM_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build
```

## Submission Guidelines

1. **Create an issue** describing the problem or feature
2. **Create a branch**: `git checkout -b feature/my-feature`
3. **Write tests** for new code (TDD — tests first)
4. **Format code**: `clang-format -i src/**/*.cc src/**/*.h include/**/*.h`
5. **Run linter**: `run-clang-tidy -p build src/`
6. **Create a PR** with a clear description

## Testing Requirements

All PRs must pass:

- ✅ Unit tests (`ctest --test-dir build`)
- ✅ Integration tests
- ✅ `clang-format` check
- ✅ `clang-tidy` check
- ✅ Valgrind memory check (if modifying memory management)

## Security Guidelines

- No hardcoded secrets or passwords
- Use `secure_erase` / `secure_buffer` for sensitive data
- Document new cryptographic algorithms
- Run through the threat model checklist for new features
- Never vail internal error details to callers (opaque errors only)
