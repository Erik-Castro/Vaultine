# safe-purge Specification

## Purpose

Automatically delete archived KEK versions once all secrets referencing them have been migrated to the current KEK, preventing unbounded archive growth.

## Requirements

### Requirement: Count After Migrate

After a lazy-migrate UPDATE, the system MUST run `SELECT COUNT(*) FROM secrets WHERE user_id=? AND kek_version=?` for the old version, in the same transaction.

#### Scenario: Count after migration

- GIVEN a secret was just migrated from `kek_version=3` to `kek_version=5`
- WHEN the transaction runs the count query for `(user_id=42, kek_version=3)`
- THEN the system returns the exact count of remaining secrets at that version

### Requirement: Delete When Zero

If the count is 0, the system MUST `DELETE FROM kek_archive WHERE user_id=? AND kek_version=?` in the same transaction.

#### Scenario: All secrets migrated — archive deleted

- GIVEN a user had 1 secret at `kek_version=3` and it just migrated
- WHEN the count query returns 0
- THEN the archive entry for `(user_id=42, kek_version=3)` is deleted

### Requirement: Preserve When Secrets Remain

If the count is greater than 0, the system MUST NOT delete the archive entry.

#### Scenario: Some secrets still reference old version

- GIVEN a user has 3 secrets at `kek_version=3` and only 1 just migrated
- WHEN the count query returns 2
- THEN the archive entry for `(user_id=42, kek_version=3)` is preserved

### Requirement: Purge All for User (Public API)

The system MUST expose `ssm_kek_purge_archive(user_id)` that deletes all archive entries for a user where `COUNT(*) = 0` for each version. This SHOULD be used for explicit cleanup.

#### Scenario: Purge all zero-count entries

- GIVEN a user with versions 2 (0 secrets), 3 (0 secrets), and 4 (2 secrets) in the archive
- WHEN `ssm_kek_purge_archive(42)` is called
- THEN versions 2 and 3 are deleted from the archive
- AND version 4 is preserved

### Requirement: Race Condition Safety

The count-and-delete runs inside the same transaction as the migrate UPDATE, under the write lock. This prevents a concurrent thread from inserting a new secret with the old version between the count and the delete.

#### Scenario: Concurrent insert before delete prevented

- GIVEN thread A is in the migrate transaction and the count returned 0
- WHEN thread B attempts to insert a new secret with `kek_version=3` for the same user
- THEN thread B blocks on the write lock held by thread A
- AND when thread A commits, thread B's insert uses the current version, not version 3
