# password-change Specification

## Purpose

Extend password change to re-wrap all archived KEK entries with the new password hash, preventing orphaned archive entries that are unrecoverable after the old password hash is lost.

## Requirements

### Requirement: Re-wrap Current KEK Wrapping Key

The system MUST derive a new wrapping key from the new password hash and AES-KW re-wrap the current KEK, exactly as before.

#### Scenario: Normal password change

- GIVEN a user with a current KEK
- WHEN the password is changed
- THEN the current KEK is re-wrapped with the new password-derived wrapping key
- AND `kek_metadata` is updated

### Requirement: Re-wrap All Archive Entries

The system MUST iterate all archive entries for the user and re-wrap each archived KEK with the new password-derived wrapping key.

#### Scenario: Password change with archive entries

- GIVEN a user with 3 archived KEK entries (versions 2, 3, 4)
- WHEN the password is changed
- THEN each archive entry's `wrapped_kek` is re-wrapped with the new wrapping key
- AND each row is updated in `kek_archive`

### Requirement: Atomicity Across All Re-wraps

The system MUST perform the current KEK re-wrap AND all archive entry re-wraps in a single `BEGIN IMMEDIATE ... COMMIT` transaction. If any re-wrap fails, the entire transaction rolls back.

#### Scenario: All-or-nothing re-wrap

- GIVEN a user with 2 archive entries
- WHEN re-wrap succeeds for the current KEK but the second archive entry re-wrap fails
- THEN the entire transaction rolls back
- AND no entries are updated
- AND the caller receives `SSM_ERR_CRYPTO`

### Requirement: Zero Archive Entries (No-op)

If the user has no archive entries, the system MUST skip the archive iteration without error.

#### Scenario: Password change with no archive

- GIVEN a user with no `kek_archive` entries
- WHEN the password is changed
- THEN only the current KEK wrapping key is re-wrapped
- AND the function succeeds normally

### Requirement: Detect Archive Re-wrap Failure

If re-wrapping a single archive entry fails (e.g., AES-KW failure), the system MUST fail the entire password change and roll back.

#### Scenario: Single archive entry re-wrap failure

- GIVEN a user with 2 archive entries
- WHEN re-wrap fails on the second entry due to a crypto error
- THEN the current KEK re-wrap is also rolled back
- AND the old password is still valid
