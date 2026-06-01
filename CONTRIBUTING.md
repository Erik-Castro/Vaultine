# Contributing to Vaultine

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
