# Proposal: Lazy KEK Re-encryption

## Intent

KEK rotation is O(n) in secrets per user — decrypts all secrets, re-encrypts with new KEK, holds write lock for seconds. Make it O(1) by archiving old KEKs and lazy-migrating secrets on read.

## Scope

### In Scope
- O(1) rotation: archive old KEK, generate new KEK, no per-secret work
- Lazy-migrate on decrypt: detect stale kek_version, re-encrypt with current KEK
- Password change re-wraps all archived KEK entries automatically
- Safe-purge: delete archived KEK version when no secrets reference it
- Schema migration v2→v3: add kek_version column, kek_archive table
- Public API: `ssm_kek_purge_archive()`

### Out of Scope
- Periodic background migration (rely on read-triggered migration only)
- Multi-KEK-per-secret (one secret always uses exactly one KEK version)
- KEK rotation rollback (irreversible by design)

## Capabilities

### New Capabilities
- `kek-archive`: store, query, and delete archived KEK versions with CRUD — table + in-memory struct + SQL helpers
- `lazy-reencryption`: decrypt with archived KEK + re-encrypt with current KEK atomically on read
- `safe-purge`: automatic cleanup of archived KEK versions once all secrets have migrated

### Modified Capabilities
- `kek-rotation`: rewritten from full re-encrypt loop to O(1) archive-and-switch; speed no longer depends on secret count
- `password-change`: extended to re-wrap all archived KEK entries after password hash change
- `secret-decrypt`: added lazy-migrate path — if `secret.kek_version < current`, transparently decrypt via archive and re-encrypt

## Approach

1. **Rotation**: archive current KEK row → generate new KEK → switch `kek_metadata` — O(1), no per-secret work
2. **Decrypt with lazy-migrate**: detect stale version → look up archived KEK → decrypt → re-encrypt with current KEK → UPDATE row (all in one transaction)
3. **Password change**: after re-wrapping current KEK, iterate archive entries, re-wrap each with new password hash
4. **Safe-purge**: after lazy-migrate, `COUNT(*) WHERE kek_version=N`; if 0, DELETE archive row

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `src/db/kek_archive.h/.cc` | New | Archive CRUD |
| `src/db/secrets.h/.cc` | Modified | Add kek_version field |
| `src/kek/kek.h/.cc` | Modified | O(1) rotation, archive decrypt helpers |
| `src/ssm.cc` | Modified | Lazy-migrate in get; re-wrap in password change |
| `src/db/database.cc` | Modified | Create kek_archive table |
| `src/db/migrations.h/.cc` | Modified | v2→v3 migration |
| `include/ssm/ssm.h` | Modified | Add `ssm_kek_purge_archive()` |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Password change orphans archive KEKs | Low | Re-wrap all archived KEKs during password change |
| Lock contention in lazy-migrate path | Med | Shared_mutex + single-row UPDATE; test with 10 threads |
| DBs with v2 schema break on v3 code | Low | Migration guards + `SSM_SCHEMA_VERSION` check |
| Safe-purge misses race condition | Low | Inline count check after migrate; caller holds write lock |

## Rollback Plan

1. Downgrade schema to v2 (DROP `kek_archive`, remove `kek_version` column)
2. Re-run old `kek_rotate()` to eagerly re-encrypt all secrets
3. Revert all code changes

## Dependencies

None beyond existing (SQLCipher, libsodium, OpenSSL)

## Success Criteria

- [ ] Rotation completes in O(1) regardless of secret count
- [ ] Secret decrypt succeeds with archived KEK when `kek_version < current`
- [ ] Lazy-migrate updates the secret row + `kek_version` atomically
- [ ] Password change re-wraps all archive KEKs
- [ ] Safe-purge deletes archive entry only when `COUNT=0`; preserves if any secret remains
- [ ] Migration v2→v3 preserves all existing data
- [ ] Thread safety: concurrent reads/writes don't corrupt archive or secrets
