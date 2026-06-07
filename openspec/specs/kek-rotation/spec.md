# kek-rotation Specification

## Purpose

Replace the O(n) full-re-encrypt KEK rotation with an O(1) archive-and-switch: archive the current KEK, generate a new one, increment the version — all in a single ACID transaction.

## Requirements

### Requirement: O(1) Rotation — No Per-Secret Work

The system MUST NOT iterate over secrets during rotation. Rotation MUST complete in constant time regardless of the number of secrets.

#### Scenario: Rotation with many secrets

- GIVEN a user with 10,000 secrets
- WHEN `ssm_kek_rotate()` is called
- THEN rotation completes without reading or writing any secret row

### Requirement: Atomic Archive-and-Switch

The system MUST archive the current KEK and update `kek_metadata` in a single `BEGIN IMMEDIATE ... COMMIT` transaction. If any step fails, the entire rotation MUST roll back.

#### Scenario: Successful rotation

- GIVEN a user with `kek_version=5`
- WHEN `ssm_kek_rotate()` is called
- THEN the current KEK is archived to `kek_archive` with `kek_version=5`
- AND a new KEK is generated with a new salt
- AND `kek_metadata.kek_version` is incremented to 6
- AND all changes commit atomically

#### Scenario: Mid-rotation failure rolls back

- GIVEN archive insert succeeds
- WHEN the new KEK generation fails (e.g., sodium error)
- THEN the transaction rolls back
- AND the archive insert is reverted
- AND `kek_version` remains unchanged

### Requirement: Archive Before Generate (Crash Safety)

The system MUST insert the archived KEK into `kek_archive` BEFORE generating the new KEK. If the process crashes after the archive insert but before the archive + new KEK commit, the old KEK is safely archived and the current KEK is unchanged.

#### Scenario: Crash after archive insert

- GIVEN the archival insert completed but the transaction has not committed
- WHEN a crash occurs before the new KEK is generated
- THEN the transaction is rolled back on recovery
- AND the old KEK remains the active KEK

### Requirement: Version Increment

The system MUST increment `kek_metadata.kek_version` by exactly 1 after archiving the old KEK and generating the new one.

#### Scenario: Version increments correctly

- GIVEN `kek_metadata.kek_version=5`
- WHEN rotation succeeds
- THEN `kek_metadata.kek_version=6`

### Requirement: First Rotation

The system MUST handle the case where `kek_archive` has no prior entries for the user. The first archived entry gets `kek_version=N` (the current version before increment).

#### Scenario: First rotation with no prior archive

- GIVEN a user with `kek_version=1` and no archive entries
- WHEN `ssm_kek_rotate()` is called
- THEN the archive entry is created with `kek_version=1`
- AND `kek_metadata.kek_version=2`
