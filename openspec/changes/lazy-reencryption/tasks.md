# Tasks: Lazy KEK Re-encryption

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~760 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1 (Foundation) → PR 2 (Core + Tests) |
| Delivery strategy | ask-on-risk |
| Chain strategy | feature-branch-chain |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: feature-branch-chain
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Schema, migration, kek_archive CRUD, secrets changes | PR 1 | base=main; tests for CRUD + migration |
| 2 | O(1) rotation, lazy-migrate, safe-purge, pw re-wrap | PR 2 | depends on PR 1; all integration tests |

## Phase 1: Foundation

- [x] 1.1 (RED) Test `kek_archive_store/find_by_version/delete_version/list_for_user` round-trips
- [x] 1.2 (RED) Test migration v3→v4 forward + rollback
- [x] 1.3 (GREEN) Create `src/db/kek_archive.h` — `kek_archive_row` struct + CRUD declarations
- [x] 1.4 (GREEN) Create `src/db/kek_archive.cc` — all 4 CRUD implementations
- [x] 1.5 (GREEN) Add `int64_t kek_version` to `secret_row` in `src/db/secrets.h`
- [x] 1.6 (GREEN) Add `secrets_count_by_kek_version()` + `secrets_update_ciphertext()` in `src/db/secrets.cc`
- [x] 1.7 (GREEN) Add `kek_archive` CREATE TABLE to `src/db/database.cc` schema
- [x] 1.8 (GREEN) Bump `SSM_SCHEMA_VERSION` to 4 in `src/db/migrations.h`
- [x] 1.9 (GREEN) Append v3→v4 migration in `src/db/migrations.cc` (CREATE kek_archive + ALTER secrets ADD COLUMN, rollback DROP)
- [x] 1.10 (GREEN) All CRUD + migration tests pass

## Phase 2: Core Logic

- [ ] 2.1 (RED) Test O(1) rotation: archive current KEK, generate new, no secrets scan
- [ ] 2.2 (RED) Test lazy-migrate path in `ssm_secret_get`: stale kek_version → decrypt→re-encrypt→update
- [ ] 2.3 (RED) Test safe-purge: COUNT after UPDATE, DELETE archive when zero, preserve when >0
- [ ] 2.4 (RED) Test `ssm_kek_purge_archive` — purge only versions with zero secrets
- [ ] 2.5 (GREEN) Rewrite `kek_rotate()` in `src/kek/kek.cc`: archive→generate→update, no secrets loop
- [ ] 2.6 (GREEN) Add lazy-migrate block in `ssm_secret_get()` in `src/ssm.cc` — compare kek_version, lookup archive, decrypt, re-encrypt, update row
- [ ] 2.7 (GREEN) Add safe-purge after migrate: COUNT + conditional DELETE archive in same transaction
- [ ] 2.8 (GREEN) Add `ssm_kek_purge_archive` to `include/ssm/ssm.h` + implement in `src/ssm.cc`

## Phase 3: Password Change Archive Re-wrap

- [ ] 3.1 (RED) Test password change with 3 archived KEKs — all re-wrapped atomically
- [ ] 3.2 (RED) Test password change with 0 archive entries — no-op, no error
- [ ] 3.3 (GREEN) Modify `ssm_user_change_password()` in `src/ssm.cc`: loop `kek_archive_list_for_user()`, re-wrap each, all in one transaction

## Phase 4: Integration + System Tests

- [ ] 4.1 Integration: full cycle register → rotate (O(1)) → get stale secret (lazy-migrate) → purge archive
- [ ] 4.2 Integration: password change with archived KEKs, verify all re-wrap on login
- [ ] 4.3 Concurrency: 10 threads on stale secrets, verify atomic migration under write lock
- [ ] 4.4 Migration test: DB at v2 → migrate to v3 → verify schema → rollback to v2

## Phase 5: Cleanup

- [ ] 5.1 Full build + `ctest` — all pass, valgrind-clean in Debug
- [ ] 5.2 Verify `sodium_memzero` / `secure_erase` on all temporary KEK buffers in new paths
- [ ] 5.3 Consistency: new KEK archive entries get wiped on handle destroy (CASCADE)
