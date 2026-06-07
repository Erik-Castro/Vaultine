# lazy-reencryption Specification

## Purpose

Enable transparent O(1) KEK rotation by decrypting secrets with their archived KEK version and re-encrypting with the current KEK on read, all within a single atomic transaction.

## Requirements

### Requirement: Detect Stale KEK Version on Decrypt

The system MUST compare `secret.kek_version` against `current_kek_version` before every decrypt. If they match, the normal decrypt path runs. If `secret.kek_version < current_kek_version`, the system MUST execute the lazy-migrate path.

#### Scenario: Version matches — no migration

- GIVEN a secret with `kek_version=5` and `current_kek_version=5`
- WHEN `ssm_secret_get()` is called
- THEN the system decrypts directly with the current KEK
- AND no archive lookup or re-encrypt occurs

#### Scenario: Version stale — triggers migration

- GIVEN a secret with `kek_version=3` and `current_kek_version=5`
- WHEN `ssm_secret_get()` is called
- THEN the system initiates the lazy-migrate path

### Requirement: Lookup Archived KEK by Version

When lazy-migrate is triggered, the system MUST look up the archived KEK for `(user_id, secret.kek_version)`.

#### Scenario: Archive entry found

- GIVEN an archived KEK entry exists for `(user_id=42, kek_version=3)`
- WHEN the system looks up the archive for version 3
- THEN the system retrieves `wrapped_kek` and `salt` for decryption

#### Scenario: Archive entry missing

- GIVEN no archived KEK entry exists for `(user_id=42, kek_version=3)`
- WHEN the system looks up the archive for version 3
- THEN the system returns `SSM_ERR_INTEGRITY` and the secret is not modified
- AND the caller receives an error

### Requirement: Decrypt with Archived KEK

The system MUST derive the wrapping key from the archived `salt`, AES-KW unwrap the archived KEK, then AES-GCM decrypt the secret.

#### Scenario: Successful decrypt with archived KEK

- GIVEN a valid archived KEK entry for version 3
- WHEN the system derives the wrapping key and unwraps
- THEN AES-GCM decrypt succeeds and returns plaintextplaintext

#### Scenario: GCM tag mismatch on archived decrypt

- GIVEN the archived KEK is valid but the secret data is corrupted (tag mismatch)
- WHEN the system attempts AES-GCM decrypt
- THEN `SSM_ERR_INTEGRITY` is returned
- AND the original secret row is NOT modified

### Requirement: Re-encrypt with Current KEK

After successful decrypt with the archived KEK, the system MUST re-encrypt the plaintext with the current KEK, generate a new nonce, and store the result with `kek_version=current_kek_version`.

#### Scenario: Successful re-encrypt and update

- GIVEN decryption succeeded with archived KEK version 3
- WHEN the system re-encrypts with current KEK version 5
- THEN the secret row is updated with new `private_key`, `nonce`, `tag`, `kek_version=5`, and `updated_at`
- AND all changes happen in one transaction

### Requirement: Atomic Migration Transaction

The system MUST perform archive lookup, decrypt, re-encrypt, and secret UPDATE in a single SQL transaction. If any step fails, the transaction MUST roll back.

#### Scenario: Rollback on re-encrypt failure

- GIVEN decryption with archived KEK succeeded
- WHEN re-encrypt with current KEK fails (e.g., crypto error)
- THEN the transaction rolls back
- AND the original secret with `kek_version=3` is preserved
- AND the caller receives `SSM_ERR_CRYPTO`

### Requirement: Concurrent Access Safety

The lazy-migrate path MUST operate under the existing write lock (`unique_lock`). No lock escalation is needed.

#### Scenario: Concurrent migrate blocks correctly

- GIVEN thread A is mid-migrate on secret X and holds the write lock
- WHEN thread B attempts to read secret X
- THEN thread B blocks until thread A completes
- AND thread B sees the migrated state
