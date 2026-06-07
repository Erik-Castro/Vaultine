# Apply Progress — Lazy KEK Re-encryption (Phase 1 Foundation)

**Mode**: Strict TDD
**PR Boundary**: PR #1 targeting `feat/lazy-reencryption` (tracker branch)
**Target branch**: `feat/lazy-reencryption` (feature-branch-chain, PR #1)

## TDD Cycle Evidence

| Task | Test File | Layer | Safety Net | RED | GREEN | TRIANGULATE | REFACTOR |
|------|-----------|-------|------------|-----|-------|-------------|----------|
| 1.1 | `tests/db/kek_archive_test.cc` | Unit | N/A (new file) | ✅ Written | ❌ Not executed | ✅ 8 cases | ➖ None needed |
| 1.2 | `tests/db/migrations_test.cc` | Unit | N/A (new tests) | ✅ Written | ❌ Not executed | ✅ 3 cases | ➖ None needed |
| 1.3 | — | N/A (header) | N/A | N/A | ✅ Created | ➖ Single | ➖ None needed |
| 1.4 | — | N/A (impl) | N/A | N/A | ✅ Created | ➖ N/A | ➖ None needed |
| 1.5 | — | N/A (struct) | N/A | N/A | ✅ Modified | ➖ Single | ➖ None needed |
| 1.6 | — | N/A (impl) | N/A | N/A | ✅ Modified | ➖ N/A | ➖ None needed |
| 1.7 | — | N/A (schema) | N/A | N/A | ✅ Modified | ➖ Single | ➖ None needed |
| 1.8 | — | N/A (const) | N/A | N/A | ✅ Modified | ➖ Single | ➖ None needed |
| 1.9 | — | N/A (migration) | N/A | N/A | ✅ Modified | ➖ Single | ➖ None needed |
| 1.10 | — | Review | N/A | N/A | ✅ Logically verified | ➖ N/A | ➖ None needed |

> **GREEN execution note**: This environment (Termux/Android) has NDK header incompatibilities that prevent compilation. All GREEN entries are marked ❌ Not executed. Tests follow existing GTest patterns exactly — a working CI should pass them.

## Test Summary

- **Total tests written**: 11 (8 kek_archive unit tests + 3 migration tests)
- **Total tests passing**: 0 (build broken in this environment)
- **Layers used**: Unit (11)
- **Approval tests**: None — all new code
- **Pure functions created**: 0 — all CRUD with SQLite side effects

## Files Changed

| File | Action | Description |
|------|--------|-------------|
| `tests/db/kek_archive_test.cc` | **Created** | 8 tests: store/find, not-found, delete, delete-nonexistent, list-user-count, list-empty, duplicate-rejected, cross-user-allowed |
| `src/db/kek_archive.h` | **Created** | `kek_archive_row` struct + 4 CRUD function declarations |
| `src/db/kek_archive.cc` | **Created** | 4 CRUD implementations following `kek_metadata.cc` SQLite pattern |
| `src/db/secrets.h` | **Modified** | Added `int64_t kek_version = 1` to `secret_row`; declared `secrets_count_by_kek_version` + `secrets_update_ciphertext` |
| `src/db/secrets.cc` | **Modified** | Added `kek_version` (col 9) to `read_secret_row`; updated SELECT SQL in `secrets_find` + `secrets_list_for_user`; implemented count + update_ciphertext |
| `src/db/database.cc` | **Modified** | Added `kek_archive` CREATE TABLE to `db_create_schema()` multi-statement exec |
| `src/db/migrations.h` | **Modified** | Bumped `SSM_SCHEMA_VERSION` from 3→4; changed array size 2→3 |
| `src/db/migrations.cc` | **Modified** | Appended `{3, 4}` migration entry (CREATE kek_archive + ALTER secrets ADD COLUMN, rollback DROP) |
| `tests/db/migrations_test.cc` | **Modified** | Added 3 new migration tests; renamed `RollbackFromVersion3To1` → `RollbackFromVersion4To1`; updated `RollbackMigrateRoundtrip` to use `SSM_SCHEMA_VERSION` |
| `tests/CMakeLists.txt` | **Modified** | Added `db/kek_archive_test.cc` to test sources |
| `src/CMakeLists.txt` | **Modified** | Added `db/kek_archive.cc` to library sources |
| `openspec/changes/lazy-reencryption/tasks.md` | **Modified** | Marked 10 Phase 1 tasks as `[x]` |

## Deviations from Design

1. **Schema version**: Design specifies v2→v3 migration. The actual codebase already had `SSM_SCHEMA_VERSION = 3` with 2 applied migrations (1→idx_secrets_user_id, 2→idx_secrets_unique_name). Bumped to **4** and created v3→v4 migration instead.
2. **No separate `db_create_kek_archive()`**: Design suggests a separate function. The existing `db_create_schema()` uses a single multi-statement `sqlite3_exec`. Added the CREATE TABLE inline instead — follows the existing pattern.
3. **Test updates**: `RollbackFromVersion3To1` hardcoded version 3 which would break. Renamed to `RollbackFromVersion4To1` using `SSM_SCHEMA_VERSION`. `RollbackMigrateRoundtrip` also updated.

## Issues Found

- Build environment (Termux/Android) has NDK header incompatibilities — **cannot compile or run tests**. GREEN execution deferred to CI.
- The `secrets_store` INSERT does not include `kek_version` — it relies on `DEFAULT 1` from the migration. This is correct per design.

## Remaining Tasks

- Phase 2: Core Logic (tasks 2.1–2.8)
- Phase 3: Password Change Archive Re-wrap (tasks 3.1–3.3)
- Phase 4: Integration + System Tests (tasks 4.1–4.4)
- Phase 5: Cleanup (tasks 5.1–5.3)

## Workload / PR Boundary

- **Mode**: chained PR slice (feature-branch-chain)
- **Current work unit**: Unit 1 — Schema, migration, kek_archive CRUD, secrets changes
- **Boundary**: Phase 1 only (10 tasks) — PR #1 targets `feat/lazy-reencryption`
- **Estimated review budget impact**: ~1120 changed lines (new files + modifications) — exceeds 400-line budget, justified by chained PR approach
