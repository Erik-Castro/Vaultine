# Security Policy

## Reporting a Vulnerability

Please **DO NOT** open a public issue for security vulnerabilities.

Instead, email: **erik@vaultine.dev** with:

- Description of the vulnerability
- Affected versions
- Steps to reproduce
- Proof of concept (if available)

We will:
1. Confirm receipt within **24 hours**
2. Investigate within **72 hours**
3. Release a patch within **5 days**
4. Credit the reporter (unless declined)

## Security Considerations

### What Vaultine Protects

- ✅ **Secrets at rest** — AES-GCM-256 encryption with per-tenant KEK
- ✅ **Multi-tenant isolation** — independent KEK per user, no master key
- ✅ **Integrity verification** — AES-GCM authentication tags detect tampering
- ✅ **Forward secrecy** — KEK rotation re-encrypts all secrets
- ✅ **Memory cleanup** — `secure_erase` (volatile memset + compiler barrier)
- ✅ **Atomic operations** — KEK rotation uses single SQLite transaction

### What Vaultine Does NOT Protect

- ❌ **Secrets in application memory** — after decryption, plaintext is in the caller's buffer
- ❌ **Root-level attacks** — kernel compromise bypasses all software protections
- ❌ **Weak passwords** — security is rooted in password strength
- ❌ **Side-channel attacks** — OpenSSL AES is not guaranteed constant-time
- ❌ **Physical attacks** — JTAG, cold boot, memory probing

### Recommendations for Deployment

1. **Use `mlock()`** — prevent KEK from being swapped to disk (see `secure_buffer`)
2. **Enforce password policy** — ≥12 characters, 3+ character categories (lowercase, uppercase, digits, special)
3. **Enable SELinux/AppArmor** — confine the process
4. **Monitor audit logs** — watch for `SSM_ERR_AUTH` spikes
5. **Rotate KEK periodically** — every 90 days minimum
6. **Use SQLCipher** — enable encrypt-at-rest with a strong `--db-key`
7. **Keep system patched** — no secrets in kernel logs or core dumps

## Supported Versions

| Version | Release | Supported |
|---------|---------|-----------|
| 0.2.x   | TBD     | ✅ Yes    |
| 0.1.x   | 2026-06 | ❌ No     |
