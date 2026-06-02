## Summary

<!-- Describe the change and the problem it solves -->

## Type of Change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change
- [ ] Documentation / meta

## Checklist

- [ ] Builds cleanly: `cmake -B build && cmake --build build`
- [ ] All tests pass: `ctest --test-dir build --output-on-failure`
- [ ] Code formatted: `find src/ include/ tests/ cli/ -name '*.cc' -o -name '*.h' | xargs clang-format -i`
- [ ] clang-tidy clean: `run-clang-tidy -p build src/` (if applicable)
- [ ] Memory check clean: `valgrind --leak-check=full --suppressions=tests/valgrind.supp ./build/tests/ssm_test` (if modifying memory management)
- [ ] No hardcoded secrets or passwords added
- [ ] `secure_erase` / `secure_buffer` used for sensitive data

## Related Issues

<!-- Link to any related issues via Closes #123 or Fixes #456 -->
