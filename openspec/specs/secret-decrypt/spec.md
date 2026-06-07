# secret-decrypt Specification

## Purpose

Extend `ssm_secret_get()` with a transparent lazy-migrate path: if the secret was encrypted under an older KEK version, decrypt using the archived KEK, re-encrypt with the current KEK, and return the plaintext — all atomically and invisibly to the caller.

## Requirements

### Requirement: Normal Decrypt Path (Version Match)

When `secret.kek_version == current_kek_version`, the system MUST decrypt directly with the current KEK — unchanged from existing behavior.

#### Scenario: Direct decrypt with current KEK

- GIVEN a secret with `kek_version=5` and `current_kek_version=5`
- WHEN `ssm_secret_get()` is called
- THEN the system derives the wrapping key from the current password hash
- THEN AES-KW unwraps the current KEK
- THEN AES-GCM decrypts the secret
- AND the plaintext is returned

### Requirement: Lazy-Migrate Path (Version Mismatch)

When `secret.kek_version < current_kek_version`, the system MUST decrypt via the archived KEK and re-encrypt with the current KEK, then return the plaintext.

#### Scenario: Transparent migration on read

- GIVEN a secret with `kek_version=3` and `current_kek_version=5`
- WHEN `ssm_secret_get()` is called
- THEN the system looks up the archived KEK for version 3
- THEN decrypts the secret with the archived KEK
- THEN re-encrypts with the current KEK version 5
- THEN updates the secret row with `kek_version=5`
- AND the plaintext is returned to the caller
- AND the caller has no indication a migration occurred

### Requirement: Return Plaintext After Migrate

The system MUST return the decrypted plaintext to the caller even when the lazy-migrate path was executed. The migrate is a side effect.

#### Scenario: Migrate returns plaintext

- GIVEN a successful lazy-migrate from version 3 to 5
- WHEN `ssm_secret_get()` returns
- THEN the plaintext is identical to what direct decrypt with version 3 would have returned

### Requirement: GCM Integrity Check

The system MUST verify the AES-GCM authentication tag on every decrypt, both in the normal path and in the lazy-migrate path. A tag mismatch MUST return `SSM_ERR_INTEGRITY`.

#### Scenario: Corrupted secret on lazy-migrate path

- GIVEN a stale secret with corrupted ciphertext (GCM tag mismatch)
- WHEN the system attempts lazy-migrate decrypt with the archived KEK
- THEN `SSM_ERR_INTEGRITY` is returned
- AND the secret row is NOT modified
- AND the archive entry is preserved

### Requirement: Rollback on Re-encrypt Failure

If re-encrypt with the current KEK fails after a successful archived decrypt, the system MUST roll back the transaction. The original secret with the old `kek_version` MUST be preserved.

#### Scenario: Re-encrypt fails after successful decrypt

- GIVEN a successful decrypt with archived KEK version 3
- WHEN AES-GCM encrypt with current KEK fails (crypto error)
- THEN the transaction rolls back
- AND the secret still has `kek_version=3`
- AND the caller receives `SSM_ERR_CRYPTO`
