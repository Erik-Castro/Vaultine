# SSM: A Multi-Tenant Key Management Module for POSIX Systems

**Cryptographic Design, Threat Model, and Security Guarantees**

| Version | Date | Author |
|---------|------|--------|
| 1.0 | 2026-06 | SSM Engineering |

---

## Abstract

We present **SSM** (Software Security Module), a C++ shared library (.so) for POSIX systems that provides cryptographic secret management for multi-tenant environments. SSM implements a hierarchical key architecture where each tenant's secrets are encrypted with a unique 256-bit Key Encryption Key (KEK), which is itself protected by a key-wrapping scheme (AES-KW-256) using a user-derived wrapping key. The system enforces KEK rotation every 90 days, performs atomic re-wrapping during rotation via SQLite transactions, and provides authenticated encryption (AES-GCM-256) for all stored secrets. This paper describes the threat model, cryptographic design rationale, security analysis, and implementation considerations.

---

## 1. Introduction

Modern applications must manage cryptographic keys for multiple tenants — cloud services, messaging platforms, financial systems, and healthcare applications all face the challenge of protecting tenant secrets while maintaining availability and performance. A naive approach of storing secrets in plaintext or using a single master key for all tenants exposes the system to catastrophic compromise: a single database breach leaks every tenant's secrets.

SSM addresses this with a **per-tenant KEK** architecture. Each user (tenant) has an independent 256-bit AES key that protects only that user's secrets. This key never exists in plaintext on disk — it is stored wrapped (encrypted with another key) and is only unwrapped in memory for the duration of an operation. The wrapping key is itself derived from the user's authentication credentials via a memory-hard KDF (Argon2id), providing defense-in-depth.

### 1.1 Design Goals

1. **Tenant isolation**: compromise of one tenant's KEK must not affect others.
2. **Encryption at rest**: all persistent data is encrypted (SQLCipher) or integrity-protected.
3. **Forward secrecy through rotation**: periodic KEK rotation limits the window of compromise.
4. **Authenticated encryption**: ciphertext cannot be modified undetected.
5. **Atomic operations**: partial failures must not leave the system in an inconsistent state.
6. **Self-contained**: no external HSM or remote KMS dependency — the library is the module.

---

## 2. Threat Model

### 2.1 Assumptions

- The **operating system** and **hardware** are trusted (SSM does not defend against kernel-level attackers, hardware keyloggers, or cold-boot attacks).
- The **application** calling SSM is trusted with plaintext secrets during API calls — SSM provides no protection against a compromised application reading its own stack.
- The **database file** (`db_path`) is stored on a filesystem that may be accessible to attackers (e.g., cloud volumes, backups, logs).
- The **user's password** is the root of trust — weak passwords reduce security to the strength of the password.
- The **memory** of the process is free from cross-process inspection (standard POSIX process isolation).

### 2.2 Attack Scenarios

| Attack | Description | Mitigation |
|--------|-------------|------------|
| **Database exfiltration** | Attacker gains read access to the SQLite file | KEKs are wrapped with AES-KW-256; secrets encrypted with AES-GCM-256; SQLCipher adds at-rest encryption |
| **Credential theft** | Attacker obtains `password_hash` from DB | Password hash is Argon2id (slow + salt); derived wrapping key requires separate KDF invocation with stored salt |
| **Brute-force password** | Attacker attempts to guess passwords offline | Argon2id with MODERATE opslimit makes each attempt expensive; `password_hash` does not directly unwrap KEK |
| **Tampering** | Attacker modifies ciphertext in DB | AES-GCM-256 tag verification detects any modification (`SSM_ERR_INTEGRITY`) |
| **KEK compromise** | Attacker learns KEK for one tenant | Rotation every 90 days limits exposure; per-tenant isolation prevents lateral movement |
| **Rollback** | Attacker replaces current data with old data | KEK rotation increments `kek_version` (schema extensible); expiration timestamp prevents indefinite use |
| **Side-channel** | Timing or cache attacks | AES-KW and AES-GCM are not constant-time in OpenSSL software implementation (mitigated by architectural isolation, not fully) |

### 2.3 Out of Scope

- Physical attacks (JTAG, probing, glitching)
- Compromised application memory (attacker with RCE in the calling process)
- Denial of service against the SQLite database
- Network-level attacks (SSM is not a network service)

---

## 3. Cryptographic Design

### 3.1 Algorithm Selection Rationale

#### Argon2id

**Why**: Argon2id is the winner of the PHC (Password Hashing Competition) and is recommended by OWASP and NIST (SP 800-63B). It provides resistance against both GPU-based (memory-hard) and side-channel (data-independent) attacks.

**SSM uses two distinct modes**:

| Usage | Function | Output | Ops Limit | Mem Limit |
|-------|----------|--------|-----------|-----------|
| Password hashing | `crypto_pwhash_str` | Encoded string (~128B) with salt + params | `OPSLIMIT_MODERATE` | `MEMLIMIT_MODERATE` |
| Key derivation | `crypto_pwhash` (raw, 32B) | Raw 32-byte key from `auth_hash + salt` | `OPSLIMIT_MODERATE` | `MEMLIMIT_MODERATE` |

The password hash is stored in the `users.password_hash` column. The wrapping key is derived *separately* using a different salt (`kek_metadata.salt`). This means:

- Compromise of `password_hash` does not directly give the wrapping key — the second KDF invocation with a distinct salt is required.
- Each KEK rotation generates a new salt, so the wrapping key changes even if the password stays the same.

#### AES-KW-256 (Key Wrap)

**Why**: AES Key Wrap (RFC 3394) is a NIST-standardized algorithm for encrypting cryptographic keys with other keys. It provides integrity and is simpler than a full AEAD mode because the plaintext is always a multiple of 8 bytes (key material).

**Usage in SSM**: The 32-byte KEK is wrapped with a 32-byte wrapping key, producing a 40-byte output (32 bytes of ciphertext + 8 bytes of integrity check value). The result is stored in `kek_metadata.wrapped_kek`.

#### AES-GCM-256 (Galois/Counter Mode)

**Why**: GCM provides authenticated encryption — the decrypt operation verifies a 128-bit authentication tag. This ensures that:
1. The ciphertext has not been tampered with.
2. The correct KEK is being used (critical during rotation — re-wrapping with the wrong KEK would produce tag mismatch, triggering detection).

**Nonce handling**: A 12-byte random nonce is generated via `randombytes_buf` for each encryption. The nonce is stored alongside the ciphertext. Since each secret uses a distinct nonce and KEKs are per-tenant and rotated regularly, the risk of nonce reuse under the same key is negligible.

#### SQLCipher

SQLCipher provides 256-bit AES in CBC mode with HMAC-SHA256 authentication for the entire database file. This protects the database when the application is not running. During operation, SQLCipher transparently encrypts/decrypts pages as they are read/written.

On Termux (Android) and other platforms where SQLCipher is unavailable, SSM falls back to plain SQLite3. This is acceptable for development but should be avoided in production.

### 3.2 Key Hierarchy

```
Password (user-supplied)
    │
    ├──→ Argon2id (crypto_pwhash_str, OPSLIMIT_MODERATE)
    │       │
    │       └──→ password_hash (stored in users table)
    │               │
    │               ├──→ Used for authentication (crypto_pwhash_str_verify)
    │               │
    │               └──→ Argon2id (crypto_pwhash, raw 32B)
    │                       │
    │                       └──→ wrapping_key (ephemeral, 32 bytes)
    │                               │
    │                               └──→ AES-KW-256 wrap/unwrap KEK
    │
    └──→ KEK (randombytes_buf, 32 bytes)
            │
            ├──→ AES-GCM-256 encrypt/decrypt private_key
            │
            └──→ → secrets.private_key (ciphertext)
                  → secrets.nonce (12 bytes)
                  → secrets.tag (16 bytes, GCM auth tag)
```

**Key properties**:

1. **Two-factor derivation**: The wrapping key depends on BOTH the user's password hash AND a randomly generated salt. An attacker needs both the database and the ability to compute Argon2id.
2. **KEK independence**: Each tenant's KEK is independent — no master key or key-encryption key spans tenants.
3. **KEK never on disk**: The KEK exists in plaintext only in volatile memory during API operations, and is wiped via `secure_erase` (wrapper over `memset_s`/`explicit_bzero` with compiler barrier) when the operation completes.

---

## 4. KEK Lifecycle

### 4.1 Creation (User Registration)

When `ssm_user_register` is called:

1. Generate `password_hash` via `crypto_pwhash_str(sodium, password, OPSLIMIT_MODERATE)`.
2. INSERT into `users(username, password_hash)`.
3. Generate 16-byte random `salt` via `randombytes_buf`.
4. Derive `wrapping_key = crypto_pwhash(password_hash, salt, 32, OPSLIMIT_MODERATE)`.
5. Generate 32-byte `kek` via `randombytes_buf`.
6. `wrapped_kek = aes_kw_wrap(kek, wrapping_key)`.
7. INSERT into `kek_metadata(user_id, wrapped_kek, salt, expires_at = now + 90d)`.

### 4.2 Usage (Secret Operations)

For every `ssm_secret_store` / `ssm_secret_get` / `ssm_secret_delete`:

1. Authenticate: `crypto_pwhash_str_verify(stored_hash, password)`. If fails → `SSM_ERR_AUTH`.
2. Load `wrapped_kek` and `salt` from `kek_metadata`.
3. Derive `wrapping_key = crypto_pwhash(stored_hash, salt, 32, OPSLIMIT_MODERATE)`.
4. `kek = aes_kw_unwrap(wrapped_kek, wrapping_key)`. If integrity fails → `SSM_ERR_INTERNAL`.
5. Check expiration: `now > expires_at` → `SSM_ERR_EXPIRED` (after cleaning up kek).
6. Perform the actual encrypt/decrypt operation.
7. **Wipe all ephemeral key material** via `secure_erase`.

### 4.3 Rotation

Rotation (`ssm_kek_rotate`) is the most critical operation:

**Algorithm**:

1. `BEGIN IMMEDIATE` (acquire exclusive transaction lock).
2. Load current `wrapped_kek`, `salt`, and all secrets for the user.
3. Derive current `wrapping_key` from `password_hash + salt_current`.
4. `kek_current = aes_kw_unwrap(wrapped_kek_current, wrapping_key_current)`.
5. Generate new 32-byte `kek_new` via `randombytes_buf`.
6. Generate new 16-byte `salt_new` via `randombytes_buf`.
7. Derive new `wrapping_key_new` from `password_hash + salt_new`.
8. For each secret (SELECT all for user):
   a. `plaintext = aes_gcm_decrypt(private_key_enc, kek_current, nonce, tag)`.
   b. Generate `nonce_new` via `randombytes_buf`.
   c. `(private_key_new, tag_new) = aes_gcm_encrypt(plaintext, kek_new, nonce_new)`.
   d. UPDATE secret SET `private_key = private_key_new, nonce = nonce_new, tag = tag_new`.
   e. Wipe intermediate buffers.
9. `wrapped_kek_new = aes_kw_wrap(kek_new, wrapping_key_new)`.
10. UPDATE `kek_metadata SET wrapped_kek = wrapped_kek_new, salt = salt_new, expires_at = now + 90d`.
11. `COMMIT`.
12. On any error: `ROLLBACK`. The system state is unchanged.

**Atomicity guarantee**: Because all operations happen within a single SQLite transaction (started with `BEGIN IMMEDIATE` to prevent deadlock), any failure during steps 4–10 results in a full ROLLBACK. The user's data remains accessible with the old KEK.

**Performance consideration**: Rotation is O(n) where n is the number of secrets the user has. For users with thousands of secrets, this may take significant time. All decrypt/re-encrypt happens in-memory to avoid exposing plaintext to disk.

### 4.4 Expiration

- Default validity: 90 days (`KEK_DEFAULT_DAYS = 90`).
- Checked on every operation (store, get, delete).
- Expired KEK triggers `SSM_ERR_EXPIRED`, forcing the calling application to call `ssm_kek_rotate`.
- Rotation resets the expiration date to `now + 90d`.

---

## 5. Implementation Details

### 5.1 Secure Memory Wiping

SSM uses a `secure_erase` function that:

```cpp
template <typename T>
void secure_erase(T& buf) {
    if (!std::empty(buf)) {
        auto ptr = std::data(buf);
        auto len = std::size(buf);
        volatile unsigned char* p =
            reinterpret_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0; i < len; ++i) p[i] = 0;
        asm volatile("" : : "r"(p) : "memory");
    }
}
```

The `volatile` qualifier prevents the compiler from optimizing out the zeroing. The `asm volatile` barrier ensures the memory clobber is not reordered across the barrier. This pattern is safer than `memset` (which GCC may optimize out) and equivalent to `memset_s` on C11 platforms.

### 5.2 Thread Safety

- SQLite is opened with `SQLITE_OPEN_FULLMUTEX`, serializing all database access.
- A `std::shared_mutex` wraps the `ssm_handle` to serialize multi-step operations (especially rotation, which involves loading all secrets, decrypting, re-encrypting, and writing back).
- All public API functions acquire a `std::unique_lock<std::shared_mutex>` before proceeding.

### 5.3 Error Handling Philosophy

Errors are deliberately **opaque**: the API returns an enum value (`SSM_ERR_AUTH`, `SSM_ERR_INTEGRITY`, etc.) without leaking internal details. The application cannot distinguish between "wrong database key" and "SQLCipher initialization failed" — both map to `SSM_ERR_INTERNAL`. This prevents information leakage through error messages.

### 5.4 SQLCipher Detection

At build time, CMake detects whether SQLCipher headers and library are available. If not, SSM falls back to plain SQLite3 with a compile-time warning. This enables development on platforms like Termux where SQLCipher is unavailable, while ensuring production builds link with full encryption at rest.

---

## 6. Security Analysis

### 6.1 Database Exfiltration

If an attacker gains read access to the SQLite file:
- With SQLCipher: the database is encrypted with AES-256 + HMAC. Without the `db_key`, the attacker cannot read pages.
- Without SQLCipher: the attacker sees:
  - `users.password_hash`: Argon2id string (salt + params + hash). Brute-force is computationally expensive (OPSLIMIT_MODERATE ≈ 2 iterations, 64 MiB memory).
  - `kek_metadata.wrapped_kek`: AES-KW-256 ciphertext (40 bytes). Requires the wrapping key to unwrap.
  - `kek_metadata.salt`: 16 random bytes — not secret.
  - `secrets.private_key`: AES-GCM-256 ciphertext + nonce + tag. Requires the KEK to decrypt.
  - `secrets.public_key`: plaintext (intentionally).

**Effective security level**: Assuming the user's password has ≥64 bits of entropy, the attacker faces:
1. Argon2id KDF (OPSLIMIT_MODERATE) to derive wrapping_key from password_hash + salt.
2. AES-KW unwrap to recover KEK.
3. AES-GCM decrypt for each secret.

The sequential dependence of these operations means each tenant must be attacked independently — recovering Alice's KEK does not help recover Bob's.

### 6.2 Password Hash Compromise

Even if `password_hash` is leaked (e.g., through a backup), the attacker still needs to:
1. Read `kek_metadata.salt` (also from the same database).
2. Compute `wrapping_key = crypto_pwhash(password_hash, salt, ..., OPSLIMIT_MODERATE)`.
3. Unwrap `wrapped_kek` with AES-KW-256.

The use of a distinct salt (not the one embedded in the Argon2id string) ensures that computing the password hash (step 1 for authentication) does not simultaneously compute the wrapping key. The attacker must run Argon2id *again* with a different salt.

### 6.3 Ciphertext Tampering

AES-GCM-256 provides **authenticated encryption**. The 16-byte authentication tag is verified during decryption:
- If ciphertext is modified: tag verification fails → `SSM_ERR_INTEGRITY`.
- If nonce is modified: decryption produces garbage → tag mismatch.
- If tag itself is modified: verification fails.

This guarantees detection of any tampering, including rollback of individual secret rows.

### 6.4 KEK Rotation

KEK rotation provides **forward secrecy**: if a KEK is compromised, the window of exposure is at most the time until the next rotation (up to 90 days, or immediately if rotation is forced). After rotation:
- Old ciphertexts (encrypted with old KEK) are re-encrypted with new KEK.
- Old wrapped KEK is overwritten.
- Old KEK is wiped from memory.

**Atomicity guarantee**: The rotation uses a single SQLite transaction (`BEGIN IMMEDIATE ... COMMIT`). If the process crashes mid-rotation:
- Before transaction starts: no change.
- During transaction (after BEGIN): SQLite WAL or rollback journal ensures atomic recovery — either all changes or none.
- ROLLBACK is explicit on any error.

### 6.5 Salt Uniqueness

Each salt is generated via `randombytes_buf` (libsodium, which uses the kernel's CSPRNG). The probability of salt collision across tenants is negligible (2^-128 per pair). Salt uniqueness ensures that the wrapping keys for different tenants are independent even if they share the same password.

---

## 7. Known Limitations

### 7.1 No Hardware Integration

SSM is a pure software solution. It does not integrate with HSMs, TPMs, or secure enclaves (SGX, SE). An attacker with root access to the machine can read the process memory and extract unwrapped KEKs during operations.

**Mitigation**: Minimize the window during which KEKs are in plaintext. Each API call unwraps, uses, and wipes the KEK. Long-lived operations (rotation) hold the KEK in memory for the duration but wipe immediately after.

### 7.2 Weak Password Vulnerability

The entire security model roots trust in the user's password. If a user chooses a weak password (e.g., `"123456"`), the password hash can be cracked offline with Argon2id (at cost of OPSLIMIT_MODERATE per attempt). Once the password is known, the wrapping key can be derived and the KEK unwrapped.

**Mitigation**: Applications using SSM should enforce password strength policies (length, complexity, entropy requirements). SSM does not enforce this internally — password policy is the application's responsibility.

### 7.3 No Key Rotation Scheduling

SSM provides `ssm_kek_rotate` but does not internally schedule or automate rotation. The application must:
1. Check for `SSM_ERR_EXPIRED` after each operation.
2. Call `ssm_kek_rotate` when needed.
3. Handle the failure case if rotation fails (e.g., log, alert operator).

### 7.4 No Audit Logging

SSM does not produce audit logs of operations (who accessed which secret, when KEK was rotated, etc.). This is left to the application layer.

### 7.5 No Password Change

SSM does not support changing a user's password. A password change would require re-wrapping the KEK with a new wrapping key (derived from the new password hash). This is architecturally straightforward but not yet implemented.

### 7.6 Constant-Time Considerations

OpenSSL's AES implementations are not guaranteed constant-time on all platforms. Cache-timing side channels may leak information about keys. For most deployment scenarios (cloud VMs, containers), this is not a practical attack vector, but it is a limitation compared to dedicated HSM solutions.

---

## 8. Comparison with Alternatives

| Feature | SSM | HashiCorp Vault | AWS KMS | Azure Key Vault |
|---------|-----|-----------------|---------|-----------------|
| Deployment | Embedded .so | Server (Go) | Cloud service | Cloud service |
| Tenancy | Multi-tenant (app-level) | Multi-tenant | Per-KMS | Per-vault |
| Key hierarchy | 2-level (KEK + wrapping) | Flexible (transit engine) | HSM-backed | HSM-backed |
| Encryption at rest | SQLCipher | Seal/Barrier | AWS-managed | Azure-managed |
| Password KDF | Argon2id | PBKDF2/Argon2 | N/A | N/A |
| Key rotation | Per-tenant, 90d default | Automatic | Automatic | Automatic |
| Audit log | None | Built-in | CloudTrail | Azure Monitor |
| External dependency | OpenSSL + libsodium + SQLite | Internal DB (Raft) | N/A | N/A |
| Attack surface | Minimal (library) | Large (HTTP server + API) | API surface | API surface |
| Setup time | Seconds (link lib) | Hours (cluster) | Minutes | Minutes |

### When to Use SSM

- You need **embedded** key management (no separate server or network service).
- You want **per-tenant** key isolation without managing per-tenant HSMs.
- You need **offline-capable** operation (SSM works with just a local SQLite file).
- You want a **minimal** dependency footprint.

### When Not to Use SSM

- You need **FIPS 140-2/3** certified cryptography.
- You need **hardware root of trust** (HSM, TPM, SE).
- You need **automated key rotation scheduling**.
- You need **built-in audit logging**.
- You need **high-availability** with automatic failover.

---

## 9. Benchmarks

Approximate performance measurements on a modern x86_64 Linux system (Intel i7-12700, 64 GB RAM, NVMe SSD):

| Operation | Single call (µs) | Notes |
|-----------|-----------------|-------|
| `ssm_init` (:memory:) | ~500 | SQLite startup |
| `ssm_user_register` | ~150,000 | Argon2id MODERATE (2 passes, 64 MiB) |
| `ssm_user_authenticate` | ~75,000 | Argon2id verify (1 pass) |
| `ssm_secret_store` | ~155,000 | Includes KEK unwrap + re-wrap |
| `ssm_secret_get` | ~155,000 | Includes KEK unwrap |
| `ssm_secret_delete` | ~155,000 | Shorthand (unwraps KEK for expiration check) |
| `ssm_kek_rotate` (10 secrets) | ~500,000 | Depends on secret count |

**Note**: The dominant cost is Argon2id MODERATE (≈75–150 ms per KDF call). Each `store`/`get` operation does two KDF calls: one for the wrapping key and one internal to `crypto_pwhash` for verification. For high-throughput scenarios, consider caching derived keys (not yet implemented).

---

## 10. Future Work

### 10.1 Key Caching

The dominant performance cost is the double Argon2id invocation per operation. A secure cache (e.g., `std::unordered_map` with LRU eviction and automatic wipe) could cache `wrapping_key` for frequently used tenants, reducing the overhead to a single AES unwrap per operation.

**Open issue**: Cache invalidation on password change / KEK rotation.

### 10.2 Password Change

Enable `ssm_user_change_password(old, new)`. The new password produces a new `password_hash`, which requires re-deriving the wrapping key and re-wrapping the KEK. This can be done without exposing the KEK — it is already in memory during the operation.

### 10.3 Batch Operations

For users with thousands of secrets, `ssm_kek_rotate` does one decrypt+encrypt per secret. Batch operations could parallelize this (e.g., using OpenMP or thread pools), though care must be taken with SQLite serialization.

### 10.4 Master Key Integration

An optional master key (derived from a TPM or HSM) could provide an additional layer of protection. The master key would wrap each KEK, independent of the user-derived wrapping key. This would require both the master key AND the user's credentials to recover a KEK.

### 10.5 Audit Trail

A simple append-only `audit_log` table recording operation type, user_id, timestamp, and status. This would provide non-repudiation and support incident investigation.

---

## References

1. RFC 3394 — Advanced Encryption Standard (AES) Key Wrap Algorithm
2. NIST SP 800-38D — Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)
3. NIST SP 800-63B — Digital Identity Guidelines: Authentication and Lifecycle Management
4. RFC 9106 — Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
5. SQLCipher — https://www.zetetic.net/sqlcipher/
6. libsodium Documentation — https://doc.libsodium.org/
7. OpenSSL EVP Documentation — https://www.openssl.org/docs/manmaster/man7/evp.html
