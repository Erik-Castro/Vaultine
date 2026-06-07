#include "kek/kek.h"

#include <sodium.h>

#include <cstring>
#include <ctime>

#include "crypto/aes_gcm.h"
#include "crypto/aes_kw.h"
#include "crypto/random.h"
#include "db/kek_archive.h"
#include "db/kek_metadata.h"
#include "utils/secure_memory.h"

namespace ssm::v1 {

bool kek_derive_wrapping_key(const unsigned char* auth_hash, size_t auth_hash_len,
                             const unsigned char* salt, size_t salt_len,
                             unsigned char* wrapping_key_out, size_t wrapping_key_len) {
    if (!auth_hash || !salt || !wrapping_key_out)
        return false;
    if (auth_hash_len == 0 || salt_len < KEK_SALT_LEN)
        return false;
    if (wrapping_key_len != KEK_KEY_LEN)
        return false;

    return crypto_pwhash(wrapping_key_out, wrapping_key_len,
                         reinterpret_cast<const char*>(auth_hash), auth_hash_len, salt,
                         crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE,
                         crypto_pwhash_ALG_ARGON2ID13) == 0;
}

bool kek_generate(const unsigned char* auth_hash, size_t auth_hash_len,
                  unsigned char* wrapped_kek_out, size_t* wrapped_kek_len, unsigned char* salt_out,
                  size_t* salt_len, char* expires_at_out, size_t expires_at_size) {
    if (!auth_hash || !wrapped_kek_out || !wrapped_kek_len || !salt_out || !salt_len ||
        !expires_at_out)
        return false;
    if (*salt_len < KEK_SALT_LEN)
        return false;

    secure_buffer<unsigned char> kek(KEK_KEY_LEN);
    secure_buffer<unsigned char> wrapping_key(KEK_KEY_LEN);
    if (!kek || !wrapping_key)
        return false;

    bool ok = false;
    do {
        random_bytes(kek.data(), kek.size());
        random_bytes(salt_out, KEK_SALT_LEN);
        *salt_len = KEK_SALT_LEN;

        if (!kek_derive_wrapping_key(auth_hash, auth_hash_len, salt_out, KEK_SALT_LEN,
                                     wrapping_key.data(), wrapping_key.size()))
            break;

        if (!aes_kw_wrap(kek.data(), kek.size(), wrapping_key.data(), wrapping_key.size(),
                         wrapped_kek_out, wrapped_kek_len))
            break;

        if (!kek_expires_at(KEK_DEFAULT_DAYS, expires_at_out, expires_at_size))
            break;

        ok = true;
    } while (false);

    return ok;
}

bool kek_unwrap(const unsigned char* wrapped_kek, size_t wrapped_kek_len,
                const unsigned char* auth_hash, size_t auth_hash_len, const unsigned char* salt,
                size_t salt_len, unsigned char* kek_out, size_t* kek_len) {
    if (!wrapped_kek || !auth_hash || !salt || !kek_out || !kek_len)
        return false;
    if (salt_len < KEK_SALT_LEN)
        return false;

    secure_buffer<unsigned char> wrapping_key(KEK_KEY_LEN);
    if (!wrapping_key)
        return false;

    bool ok = false;

    do {
        if (!kek_derive_wrapping_key(auth_hash, auth_hash_len, salt, KEK_SALT_LEN,
                                     wrapping_key.data(), wrapping_key.size()))
            break;

        if (!aes_kw_unwrap(wrapped_kek, wrapped_kek_len, wrapping_key.data(), wrapping_key.size(),
                           kek_out, kek_len))
            break;

        ok = true;
    } while (false);

    return ok;
}

bool kek_is_expired(const char* expires_at) {
    if (!expires_at)
        return true;

    struct tm tm = {};
    if (!strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ", &tm))
        return true;

    time_t expiry = timegm(&tm);

    time_t now;
    time(&now);

    return now >= expiry;
}

bool kek_expires_at(int days, char* out, size_t out_size) {
    if (!out || out_size < 22)
        return false;

    time_t now;
    time(&now);

    now += static_cast<time_t>(days) * 86400;

    struct tm tm;
    gmtime_r(&now, &tm);

    strftime(out, out_size, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return true;
}

// O(1) KEK rotation: archive current KEK → generate new → update kek_metadata
// No secrets loop — secrets are lazy-migrated on read.
bool kek_rotate(sqlite3* db, int64_t user_id, const unsigned char* auth_hash,
                size_t auth_hash_len) {
    if (!db || !auth_hash)
        return false;

    bool ok = false;
    do {
        if (sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) != SQLITE_OK)
            break;

        // --- load current KEK ---
        kek_row old_kek;
        if (!kek_find_by_user(db, user_id, &old_kek))
            break;

        // --- archive current KEK before generating new one (crash safety) ---
        if (!kek_archive_store(db, user_id, old_kek.kek_version,
                               old_kek.wrapped_kek.data(), old_kek.wrapped_kek.size(),
                               old_kek.salt.data(), old_kek.salt.size(),
                               old_kek.expires_at.c_str()))
            break;

        // --- generate new KEK + salt ---
        unsigned char new_wrapped[64];
        size_t new_wrapped_len = sizeof(new_wrapped);
        unsigned char new_salt[KEK_SALT_LEN];
        size_t new_salt_len = sizeof(new_salt);
        char new_expires[24];

        if (!kek_generate(auth_hash, auth_hash_len, new_wrapped, &new_wrapped_len,
                          new_salt, &new_salt_len, new_expires, sizeof(new_expires)))
            break;

        // --- update kek_metadata (increment kek_version atomically) ---
        if (!kek_update(db, user_id, new_wrapped, new_wrapped_len,
                        new_salt, new_salt_len, new_expires, old_kek.kek_version))
            break;

        ok = true;
    } while (false);

    if (ok)
        sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr);
    else
        sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);

    return ok;
}

}  // namespace ssm::v1
