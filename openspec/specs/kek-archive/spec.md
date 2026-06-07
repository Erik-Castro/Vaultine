# kek-archive Specification

## Purpose

Store, query, and delete archived KEK versions so lazy-migrate can decrypt secrets encrypted under old KEKs. Each archive entry binds a `(user_id, kek_version)` pair to the wrapped KEK and salt used at that version.

## Requirements

### Requirement: Store Archived KEK

The system MUST insert a new row into `kek_archive` with `user_id`, `kek_version`, `wrapped_kek`, `salt`, `expires_at`, and `created_at`.

#### Scenario: Store new archive entry

- GIVEN a user with current KEK version N
- WHEN the system archives KEK version N during rotation
- THEN a row is inserted into `kek_archive` with `kek_version=N`, the wrapped KEK blob, and its salt
- AND the `(user_id, kek_version)` pair is unique

#### Scenario: Duplicate version rejected

- GIVEN an archive entry exists for `(user_id=42, kek_version=5)`
- WHEN the system attempts to insert another entry with the same pair
- THEN the UNIQUE constraint fails and the transaction rolls back

### Requirement: Find Archived KEK by Version

The system MUST return the archived KEK entry for a given `(user_id, kek_version)`.

#### Scenario: Lookup existing archive entry

- GIVEN an archive entry exists for `(user_id=42, kek_version=3)`
- WHEN `find_archived_kek(42, 3)` is called
- THEN the system returns the `wrapped_kek` and `salt`

#### Scenario: Lookup non-existent version

- GIVEN no archive entry exists for `(user_id=42, kek_version=99)`
- WHEN `find_archived_kek(42, 99)` is called
- THEN the system returns `SSM_ERR_NOT_FOUND`

### Requirement: Delete Archived KEK

The system MUST delete an archive entry by `(user_id, kek_version)`.

#### Scenario: Delete existing entry

- GIVEN an archive entry exists for `(user_id=42, kek_version=3)`
- WHEN `delete_archived_kek(42, 3)` is called
- THEN the entry is removed from `kek_archive`

#### Scenario: Delete non-existent entry

- GIVEN no archive entry exists for `(user_id=42, kek_version=99)`
- WHEN `delete_archived_kek(42, 99)` is called
- THEN the system returns `SSM_ERR_NOT_FOUND`

### Requirement: List Archive for User

The system SHOULD return all archive entries for a given `user_id`, ordered by `kek_version` ascending.

#### Scenario: List entries

- GIVEN a user with 3 archive entries for versions 2, 3, and 4
- WHEN `list_archive_entries(42)` is called
- THEN the system returns 3 entries in version order

#### Scenario: No entries for user

- GIVEN a user with no archive entries
- WHEN `list_archive_entries(99)` is called
- THEN the system returns an empty list (not an error)

### Requirement: Count Secrets Referencing Version

The system MUST return the count of secrets for a user that still use a given `kek_version`.

#### Scenario: Count secrets with old version

- GIVEN a user with 5 secrets using `kek_version=3`
- WHEN `count_secrets_for_version(42, 3)` is called
- THEN the system returns 5

### Requirement: CASCADE on User Delete

The system MUST delete all archive entries for a user when the user row is deleted. The system MAY implement this via `ON DELETE CASCADE` or explicit cleanup in the delete-user transaction.

#### Scenario: User deletion removes archive

- GIVEN a user with 3 archive entries
- WHEN the user is deleted
- THEN all 3 archive entries are removed from `kek_archive`
