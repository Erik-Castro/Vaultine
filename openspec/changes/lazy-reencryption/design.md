# Design: Lazy KEK Re-encryption

## Technical Approach

Replace O(n) full-re-encrypt rotation with O(1) archive-and-switch. Old KEKs preserved in `kek_archive`; secrets lazy-migrated on read: decrypt with archived KEK, re-encrypt with current, update row + safe-purge — all under existing write lock, single transaction.

## Architecture Decisions

| Option | Tradeoff | Decision |
|--------|----------|----------|
| `kek_version` in `secrets` vs mapping table | Column avoids JOIN on every decrypt | Column on `secrets` |
| Archive as separate table vs extra rows in `kek_metadata` | Separate keeps current row simple, allows CASCADE | Separate `kek_archive` with FK + CASCADE |
| Safe-purge inline vs background job | Inline: no orphan window; Background: less write-work | Inline in same transaction |
| Always-on vs opt-in lazy-migrate | Always-on: simpler, no branch | Always-on |
| Password change re-wrap vs forced rotation | Re-wrap: O(n_archive); Forced-rotate: same + no archive | Re-wrap (n is low) |

## Data Structures

```cpp
// New — src/db/kek_archive.h
struct kek_archive_row {
    int64_t id;
    int64_t user_id;
    int64_t kek_version;
    std::vector<unsigned char> wrapped_kek;
    std::vector<unsigned char> salt;
    std::string expires_at;
    std::string created_at;
};

// Modified — src/db/secrets.h
struct secret_row {
    // ... existing fields unchanged ...
    int64_t kek_version = 1;  // NEW
};
```

## SQL Schemas

```sql
CREATE TABLE IF NOT EXISTS kek_archive (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kek_version INTEGER NOT NULL,
    wrapped_kek BLOB NOT NULL,
    salt BLOB NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE(user_id, kek_version)
);

ALTER TABLE secrets ADD COLUMN kek_version INTEGER NOT NULL DEFAULT 1;
```

## Migration v2→v3

`SSM_SCHEMA_VERSION` bumped to 3. Append to `migrations` array:

```cpp
{2, 3,
 "CREATE TABLE IF NOT EXISTS kek_archive ("
 "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
 "  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
 "  kek_version INTEGER NOT NULL,"
 "  wrapped_kek BLOB NOT NULL,"
 "  salt BLOB NOT NULL,"
 "  expires_at TEXT NOT NULL,"
 "  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),"
 "  UNIQUE(user_id, kek_version)"
 ");"
 "ALTER TABLE secrets ADD COLUMN kek_version INTEGER NOT NULL DEFAULT 1;",
 "DROP TABLE IF EXISTS kek_archive;"
 "ALTER TABLE secrets DROP COLUMN kek_version;"},
```

## Function Signatures

### New: `src/db/kek_archive.h`

```cpp
bool kek_archive_store(sqlite3* db, int64_t user_id, int64_t kek_version,
                       const unsigned char* wrapped_kek, size_t wrapped_kek_len,
                       const unsigned char* salt, size_t salt_len,
                       const char* expires_at);

bool kek_archive_find_by_version(sqlite3* db, int64_t user_id, int64_t kek_version,
                                 kek_archive_row* out);

bool kek_archive_delete_version(sqlite3* db, int64_t user_id, int64_t kek_version);

bool kek_archive_list_for_user(sqlite3* db, int64_t user_id,
                               std::vector<kek_archive_row>* out);
```

### New: `src/db/secrets.h`

```cpp
bool secrets_count_by_kek_version(sqlite3* db, int64_t user_id, int64_t kek_version,
                                  int64_t* count);

bool secrets_update_ciphertext(sqlite3* db, int64_t secret_id,
                               const unsigned char* private_key, size_t private_key_len,
                               const unsigned char* nonce, size_t nonce_len,
                               const unsigned char* tag, size_t tag_len,
                               int64_t kek_version);
```

### New: `src/db/database.h` / `src/db/database.cc`

```cpp
// Called after db_create_schema() for new DBs, skipped in migration
void db_create_kek_archive(sqlite3* db);  // idempotent CREATE TABLE + ALTER
```

### Rewritten: `src/kek/kek.h` / `src/kek/kek.cc`

`kek_rotate()` rewritten to O(1): archive current kek_row → generate new → UPDATE kek_metadata. Signature unchanged.

### New: `include/ssm/ssm.h`

```c
SSM_EXPORT ssm_status ssm_kek_purge_archive(ssm_handle* h, const char* username);
```

## Transaction Flow Diagrams

### Lazy Rotation (O(1))

```
BEGIN IMMEDIATE
  kek_archive_store(db, user_id, old_kek_version, ...)  -- archive old KEK
  kek_generate(...)                                       -- new KEK + salt
  kek_update(db, user_id, new_wrapped, ..., old_kek_version)  -- increment version
COMMIT
cache_invalidate(h, user_id)
```

### Lazy-Migrate on Decrypt

```
BEGIN IMMEDIATE  (inside ssm_secret_get, already under unique_lock)
  kek_archive_find_by_version(db, user_id, secret.kek_version, &archived)
  kek_unwrap(archived.wrapped_kek, ...)         -- derive wrapping key from current auth_hash + archived salt
  aes_gcm_decrypt(...)                           -- decrypt with unwrapped archived KEK
  aes_gcm_encrypt(...) with current KEK          -- re-encrypt, fresh random nonce
  secrets_update_ciphertext(db, secret.id, ..., current_kek_version)
  secrets_count_by_kek_version(db, user_id, old_version, &count)
  if count == 0:
    kek_archive_delete_version(db, user_id, old_version)
COMMIT
```

### Password Change with Archive Re-wrap

```
BEGIN IMMEDIATE
  UPDATE users SET password_hash = ? WHERE id = ?
  -- re-wrap current KEK with new password hash
  kek_unwrap(current_kek, old_auth_hash, ...)
  kek_derive_wrapping_key(new_hash, current_salt, ...)
  aes_kw_wrap(kek_raw, new_wrapping_key, ...)
  UPDATE kek_metadata SET wrapped_kek = ? WHERE user_id = ?
  -- re-wrap each archive entry
  kek_archive_list_for_user(db, user_id, &entries)
  for each entry:
    kek_unwrap(entry.wrapped_kek, old_auth_hash, ...)
    aes_kw_wrap(kek_raw, new_wrapping_key, ...)
    UPDATE kek_archive SET wrapped_kek = ? WHERE id = ?
COMMIT
cache_invalidate(h, user_id)
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `src/db/kek_archive.h` | Create | kek_archive_row struct, CRUD function declarations |
| `src/db/kek_archive.cc` | Create | CRUD implementations (SQL queries) |
| `src/db/secrets.h` | Modify | Add `kek_version` to `secret_row`; new function declarations |
| `src/db/secrets.cc` | Modify | Add `kek_version` column read; implement `count_by_kek_version` and `update_ciphertext` |
| `src/db/database.cc` | Modify | Add `kek_archive` CREATE TABLE to schema; add ALTER for existing DBs |
| `src/db/migrations.h` | Modify | Bump `SSM_SCHEMA_VERSION` to 3 |
| `src/db/migrations.cc` | Modify | Append v2→v3 migration entry |
| `src/kek/kek.cc` | Modify | Rewrite `kek_rotate` to O(1) archive-and-switch |
| `src/ssm.cc` | Modify | Lazy-migrate path in `ssm_secret_get`; archive re-wrap in `ssm_user_change_password`; implement `ssm_kek_purge_archive` |
| `include/ssm/ssm.h` | Modify | Add `ssm_kek_purge_archive` declaration |
| `src/db/kek_metadata.cc` | Modify | Add `kek_version` to `kek_find_by_user` SELECT (already present) |

## Testing Strategy

| Layer | What to Test | Approach |
|-------|-------------|----------|
| Unit | `kek_archive_store`, `find`, `delete`, `list` | GTest fixtures in `:memory:`, verify SQL round-trips, unique constraint, not-found |
| Unit | `secrets_count_by_kek_version`, `secrets_update_ciphertext` | Insert test secrets with known kek_version, verify counts and updates |
| Unit | `kek_rotate` O(1) | 10,000 fake secrets, assert rotation time < 100ms, no secret table scan |
| Integration | Full cycle: rotate → decrypt → lazy-migrate → purge | Rotate twice, decrypt oldest secret, verify it auto-migrates, archive purged |
| Integration | Password change with archive | Rotate twice, change password, verify all 3 KEKs re-wrappable after login |
| Integration | Migration v2→v3 | Create v2 DB, run migration, verify kek_archive table + kek_version column |
| Concurrency | Concurrent decrypt on stale secrets | 10 threads, each decrypts a stale secret, verify no deadlock, all migrated cleanly |
| Security | Key material lifetime | Verify wrapping_key, kek_raw wiped after each scoped operation; nonces unique per re-encrypt |
| Integration | `ssm_kek_purge_archive` | Insert mixed archive entries, purge, verify only zero-count deleted |

## Security Analysis

- **Key material lifetime**: `wrapping_key` and `kek_raw` are `secure_buffer` (mlock + auto-wipe). In lazy-migrate path, the archived unwrapped KEK lives only for the decrypt scope.
- **Nonce generation**: Every re-encrypt (both rotation and lazy-migrate) calls `random_bytes()` for a fresh nonce. AES-GCM nonce reuse with same key is impossible: each re-encrypt uses the current KEK which is unique per version.
- **Archived KEK wrapping**: Archived entries are wrapped with auth_hash-derived key — same protection as current KEK. Password change re-wraps them with the new auth_hash so old hash compromise doesn't expose archive.
- **Wiping patterns**: `secure_erase()` on all stack buffers — wrapping_key, kek_raw, plaintext after copy to output.
- **Safe-purge timing**: COUNT runs AFTER the UPDATE so the current transaction sees the decremented count. No window for races (write lock held).
- **Crash safety**: Archive-before-generate in rotation means crash after archive insert but before generate rolls back the transaction entirely (BEGIN IMMEDIATE → ROLLBACK on recovery).

## Open Questions

- [ ] Does the CI environment have SQLite ≥3.35.0 for `ALTER TABLE DROP COLUMN` in rollback? Fallback: recreate secrets table.
- [ ] Should existing secrets get `kek_version` set to the user's current version during migration (data fill) or left at default 1?
