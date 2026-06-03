## Summary

<!-- Describe the change and the problem it solves -->

## Type of Change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change
- [ ] Documentation / meta

## SDD (Security Driven Development) Checklist

- [ ] `secure_erase` / `secure_buffer` used for all sensitive data on the stack/heap
- [ ] No hardcoded secrets, keys, or passwords added
- [ ] Error paths do not leak sensitive information in messages
- [ ] Thread safety: shared state protected by mutex/rwlock
- [ ] Memory: no raw `delete`/`free` without RAII wrapper
- [ ] Input validation: all public API parameters checked

## Testing Checklist

- [ ] New tests added for the change
- [ ] Existing tests still pass: `ctest --test-dir build --output-on-failure`
- [ ] Builds cleanly: `cmake -B build && cmake --build build`
- [ ] Code formatted: `find src/ include/ tests/ cli/ -name '*.cc' -o -name '*.h' | xargs clang-format -i`
- [ ] Memory check clean (if modifying memory management): `valgrind --leak-check=full ./build/tests/ssm_test`

## Related Issues

<!-- Link to any related issues via Closes #123 or Fixes #456 -->
